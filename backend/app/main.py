"""
Bantay-Bait Backend — FastAPI
=============================
Free-tier production backend for the Bantay-Bait smishing detector.

Stack (all $0):
  - Hosting:  Render.com free Web Service
  - NLP:      Hugging Face Inference Providers router (serverless) — no
              model hosting, no GPU, no training/fine-tuning.
  - Storage:  NONE. RA 10173 (Data Privacy Act) compliance = no database,
              no request logging of raw SMS text, nothing persisted.

Model note (read this before deploying)
----------------------------------------
The thesis assumes a pre-trained "RoBERTa-Tagalog" model that already ships
a 3-class (Safe/Spam/Malicious) classification head. No public Hugging Face
model is fine-tuned specifically for Philippine SMS-smishing 3-class
classification, and the scope explicitly forbids training/fine-tuning one.

IMPORTANT (as of Nov 2025): Hugging Face fully retired the old serverless
"api-inference.huggingface.co" endpoint -- including the zero-shot-classification
pipeline this file originally used -- in favor of "Inference Providers", a
router at https://router.huggingface.co/v1 that speaks the OpenAI-compatible
Chat Completions format. The practical free, no-training-required equivalent
is to prompt a small instruction-following chat model to return a strict
JSON verdict.

IMPORTANT #2 (discovered during deployment): Inference Providers is now a
metered marketplace -- nearly every model listed at
https://router.huggingface.co/v1/models is priced per-token ("is_free":
false), and a bare model id like "Qwen/Qwen2.5-7B-Instruct" can fail with
"not supported by any provider you have enabled" if that model has been
dropped from the provider network entirely (providers add/remove models
over time). As of this writing, the only models confirmed to carry literal
$0 pricing on the router are `prism-ml/Ternary-Bonsai-27B-gguf` and
`prism-ml/Ternary-Bonsai-27B-AWQ-4bit`, both served via the "together"
provider.

Because provider-model availability and pricing can change at any time --
and demonstrably has, mid-project, without warning -- this backend does not
hard-code a single model. HF_MODELS (plural) is a comma-separated fallback
chain tried in order on every request until one responds successfully.
Add/remove candidates via the HF_MODELS environment variable without a
code change. Re-check https://router.huggingface.co/v1/models (no auth
required) periodically for current $0-priced or newly-added models to
extend the chain.
"""
import os
import re
import json
import time
import logging
from pathlib import Path
from typing import Literal, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ----------------------------------------------------------------------
# Config (all from environment variables -- nothing secret hardcoded)
# ----------------------------------------------------------------------
HF_TOKEN = os.getenv("HUGGINGFACE_TOKEN", "")
# Fallback chain: comma-separated list, tried in order until one succeeds.
# Why a list instead of one model: Hugging Face's Inference Providers is a
# live marketplace -- each third-party provider (Together, Novita, etc.)
# can add/drop individual models from their own lineup at any time, with
# no notice. A model that works today can silently disappear weeks later
# (this happened to Qwen/Qwen2.5-7B-Instruct during this project's own
# development). Trying several candidates in order makes the system
# self-healing against that churn instead of hard-failing on one model.
HF_MODELS = [
    m.strip() for m in os.getenv(
        "HF_MODELS",
        "prism-ml/Ternary-Bonsai-27B-gguf:together,"
        "prism-ml/Ternary-Bonsai-27B-AWQ-4bit:together,"
        "meta-llama/Llama-3.1-8B-Instruct:novita,"
        "Qwen/Qwen3-8B:nscale"
    ).split(",") if m.strip()
]
HF_API_URL = "https://router.huggingface.co/v1/chat/completions"

# Comma-separated list, e.g. "https://bantay-bait.vercel.app,https://bantay-bait.netlify.app"
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if o.strip()]

MIN_LEN = 5
MAX_LEN = 1600
MALICIOUS_THRESHOLD = 0.75          # PR-03
API_TIMEOUT_SECONDS = 4.5           # PR-04 (leaves headroom under the 5s budget)

CLASSIFIER_SYSTEM_PROMPT = (
    "You are an SMS smishing (SMS phishing) detector for Filipino mobile users. "
    "Classify the message the user sends into exactly one of three classes:\n"
    "- \"malicious\": a scam trying to steal money, passwords, OTPs/PINs, or impersonating "
    "a bank/e-wallet/courier/employer with urgency or a suspicious link.\n"
    "- \"spam\": promotional/advertising content with no direct fraud attempt.\n"
    "- \"safe\": a normal, legitimate message (including real OTPs, official notices).\n"
    "Reply with ONLY a compact JSON object, no markdown, no explanation outside the JSON: "
    '{"verdict": "malicious"|"spam"|"safe", "confidence": <0.0-1.0>, "reason": "<one short sentence>"}'
)

# ----------------------------------------------------------------------
# Logging -- NEVER log raw message text (RA 10173 / PR-05)
# ----------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bantay-bait")


class RedactTextFilter(logging.Filter):
    """Safety net: strips any 'text=' payloads that slip into log calls."""
    def filter(self, record):
        record.msg = re.sub(r"text=.*", "text=[REDACTED]", str(record.msg))
        return True


logger.addFilter(RedactTextFilter())

# ----------------------------------------------------------------------
# Tagalog stopwords (stopwords-iso/stopwords-tl) -- bundled locally
# ----------------------------------------------------------------------
STOPWORDS_PATH = Path(__file__).parent / "data" / "stopwords_tl.txt"
TAGALOG_STOPWORDS = set()
if STOPWORDS_PATH.exists():
    TAGALOG_STOPWORDS = {w.strip().lower() for w in STOPWORDS_PATH.read_text(encoding="utf-8").splitlines() if w.strip()}

TAGALOG_MARKERS = {"ang", "ng", "mga", "sa", "ay", "na", "ko", "mo", "niya", "namin", "natin", "ito", "iyan", "hindi", "opo", "po"}

REGIONAL_MARKERS = {
    "unsa", "asa", "diri", "dinhi", "wala", "kaayo", "ngano", "kanimo", "nimo",
    "mao", "kini", "kana", "gikan", "buhaton", "salamat kaayo",
    "adda", "awan", "wen", "saan", "kayat", "apay", "ania", "isu",
    "bala", "wala sing", "diin", "abi", "ano bala",
}


def normalize_text(raw: str) -> str:
    t = raw.replace("\r", " ").replace("\n", " ")
    t = re.sub(r"\s+", " ", t).strip()
    return t


def detect_regional_dialect(text: str) -> bool:
    lower = f" {text.lower()} "
    return any(f" {marker} " in lower for marker in REGIONAL_MARKERS)


def detect_language(text: str) -> str:
    lower = text.lower()
    has_tagalog = any(f" {m} " in f" {lower} " for m in TAGALOG_MARKERS)
    has_ascii_english = bool(re.search(r"\b(the|is|are|you|your|please|click|account)\b", lower))
    if has_tagalog and has_ascii_english:
        return "taglish"
    if has_tagalog:
        return "tagalog"
    return "english"


# ----------------------------------------------------------------------
# Request / response schemas
# ----------------------------------------------------------------------
class DetectRequest(BaseModel):
    text: str = Field(..., description="Raw SMS text pasted by the user")
    lang: Optional[str] = Field(default="auto", description="UI language hint (not used for classification)")


class DetectResponse(BaseModel):
    verdict: Literal["safe", "spam", "malicious"]
    confidence: float
    detectedLanguage: str
    isRegionalDialect: bool
    reducedConfidence: bool
    reasons: list[str]
    modelLatencyMs: int
    modelUsed: str


# ----------------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------------
app = FastAPI(
    title="Bantay-Bait API",
    description="Free-tier smishing detection API for Filipino mobile users.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.get("/health")
async def health():
    return {"status": "ok", "models_in_priority_order": HF_MODELS, "provider_router": HF_API_URL}


@app.get("/api/v1/samples")
async def get_samples(limit: int = 6):
    import csv
    path = Path(__file__).parent / "data" / "bantay_bait_test_set.csv"
    if not path.exists():
        return {"samples": []}
    samples = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            samples.append({"text": row["text"], "label": row["label"]})
    import random
    random.seed(7)
    by_label: dict[str, list] = {}
    for s in samples:
        by_label.setdefault(s["label"], []).append(s)
    out = []
    per_class = max(1, limit // 3)
    for label in ["safe", "spam", "malicious"]:
        pool = by_label.get(label, [])
        out.extend(random.sample(pool, min(per_class, len(pool))))
    return {"samples": out[:limit]}


def _extract_json_object(raw: str) -> dict:
    """Chat models sometimes wrap JSON in markdown fences or add stray text.
    Pull out the first {...} block and parse it."""
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in model output: {raw[:200]!r}")
    return json.loads(match.group(0))


async def _try_one_model(client: httpx.AsyncClient, headers: dict, model: str, text: str) -> tuple[str, float]:
    """Single attempt against one model. Raises on any failure so the
    caller can move on to the next candidate."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": CLASSIFIER_SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        "temperature": 0.1,
        "max_tokens": 150,
    }
    resp = await client.post(HF_API_URL, headers=headers, json=payload)
    resp.raise_for_status()
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    parsed = _extract_json_object(content)

    verdict = str(parsed.get("verdict", "spam")).strip().lower()
    if verdict not in ("safe", "spam", "malicious"):
        verdict = "spam"
    confidence = float(parsed.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))
    return verdict, confidence


async def call_huggingface(text: str) -> tuple[str, float, int, str]:
    """Tries each model in HF_MODELS in order until one succeeds. Returns
    (verdict_label, confidence, latency_ms, model_used). Raises
    HTTPException only if every candidate in the list fails."""
    if not HF_TOKEN:
        raise HTTPException(status_code=503, detail="Server misconfigured: HUGGINGFACE_TOKEN not set.")

    headers = {"Authorization": f"Bearer {HF_TOKEN}", "Content-Type": "application/json"}
    start = time.monotonic()
    last_error = "no models configured"

    async with httpx.AsyncClient(timeout=API_TIMEOUT_SECONDS) as client:
        for model in HF_MODELS:
            try:
                verdict, confidence = await _try_one_model(client, headers, model, text)
                latency_ms = int((time.monotonic() - start) * 1000)
                return verdict, confidence, latency_ms, model
            except httpx.TimeoutException:
                last_error = f"{model}: timed out"
                continue
            except httpx.HTTPStatusError as e:
                try:
                    msg = e.response.json().get("error", {}).get("message", "")
                except Exception:
                    msg = e.response.text[:150]
                last_error = f"{model}: HTTP {e.response.status_code} {msg}"
                logger.warning(f"Model candidate failed, trying next: {last_error}")
                continue
            except (KeyError, IndexError, ValueError, json.JSONDecodeError) as e:
                last_error = f"{model}: unparseable response ({type(e).__name__})"
                continue
            except Exception as e:
                last_error = f"{model}: {type(e).__name__}"
                continue

    # Every candidate failed.
    logger.error(f"All HF model candidates failed. Last error: {last_error}")
    raise HTTPException(
        status_code=502,
        detail=f"All classification models are currently unavailable. Last error: {last_error}",
    )


@app.post("/api/v1/detect", response_model=DetectResponse)
async def detect(req: DetectRequest):
    raw = req.text or ""

    if len(raw.strip()) < MIN_LEN:
        raise HTTPException(status_code=422, detail=f"Message must be at least {MIN_LEN} characters.")
    if len(raw) > MAX_LEN:
        raise HTTPException(status_code=422, detail=f"Message must not exceed {MAX_LEN} characters.")

    text = normalize_text(raw)

    is_regional = detect_regional_dialect(text)
    detected_lang = detect_language(text)

    verdict, confidence, latency_ms, model_used = await call_huggingface(text)

    reasons: list[str] = []
    reduced_confidence = is_regional
    if verdict == "malicious" and confidence < MALICIOUS_THRESHOLD:
        verdict = "spam"
        reasons.append("Confidence below the 0.75 threshold required for a Malicious verdict; downgraded to Spam/Suspicious.")

    if is_regional:
        reasons.append("Message may contain a regional Philippine dialect (Cebuano/Ilocano/Hiligaynon) outside the Tagalog/English/Taglish scope -- confidence is reduced.")

    if verdict == "malicious":
        reasons.append("Detected credential-harvesting or brand-impersonation language typical of Philippine smishing (e.g. urgent account/OTP/verification requests).")
    elif verdict == "spam":
        reasons.append("Detected promotional/advertising language without a direct fraud request.")
    else:
        reasons.append("No smishing or spam indicators detected.")

    return DetectResponse(
        verdict=verdict,  # type: ignore
        confidence=round(confidence, 4),
        detectedLanguage=detected_lang,
        isRegionalDialect=is_regional,
        reducedConfidence=reduced_confidence,
        reasons=reasons,
        modelLatencyMs=latency_ms,
        modelUsed=model_used,
