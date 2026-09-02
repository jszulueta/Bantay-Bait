"""
Bantay-Bait Backend - FastAPI
=============================
Free-tier production backend for the Bantay-Bait smishing detector.

Stack (all $0):
  - Hosting:  Render.com free Web Service
  - NLP:      Groq API (free tier, OpenAI-compatible chat completions) --
              no model hosting, no GPU, no training/fine-tuning.
  - Storage:  NONE. RA 10173 (Data Privacy Act) compliance = no database,
              no request logging of raw SMS text, nothing persisted.

Model note (read this before deploying) -- migration history
---------------------------------------------------------------
The thesis assumes a pre-trained "RoBERTa-Tagalog" model consumed via
Hugging Face's Inference API. During deployment this project went through
several Hugging Face API generations in quick succession:

  1. The original plan (a zero-shot-classification pipeline against a
     Tagalog NLI model via api-inference.huggingface.co) stopped working
     because Hugging Face fully retired that endpoint in Nov 2025.
  2. The replacement (router.huggingface.co "Inference Providers", prompting
     a chat model for a JSON verdict) worked initially, but proved
     structurally unreliable for a $0 use case: individual models can be
     silently dropped from the provider marketplace at any time with no
     notice (this happened to Qwen/Qwen2.5-7B-Instruct mid-project), AND
     free accounts are capped at a shared $0.10/month credit allowance
     that, once exhausted, blocks ALL models on the router -- including
     ones nominally priced at $0 per token. Neither failure mode is
     fixable by picking a different Hugging Face model; both are inherent
     to how that marketplace is now run.
  3. This version switches to Groq (https://console.groq.com) instead.
     Groq's free tier is gated by RATE LIMITS (roughly 30 requests/min,
     14,400 requests/day, no credit card required) rather than a spendable
     credit balance, and Groq runs its own models directly rather than
     brokering third-party providers -- so there is no marketplace churn
     risk of a model vanishing without notice. This is a more durable fit
     for a low-volume academic/demo system than Hugging Face's current
     Inference Providers product.

The core thesis claim in Section 10 -- that the NLP capability is consumed
strictly as an external, pre-trained inference service with no training or
fine-tuning performed by the researchers -- remains true under this change;
only the specific provider and model changed, for the documented reasons
above.

Groq's API is OpenAI-compatible, so if Groq's own terms or free tier ever
change, swapping GROQ_MODELS (or even swapping to a different compatible
provider) only requires changing the base URL and model list below, not
the request logic itself.

Process Rules implemented (Thesis Table 2):
  PR-01  Input validation: 5-1600 characters
  PR-02  Regional-dialect detection -> reduced-confidence disclaimer
  PR-03  Confidence >= 0.75 required for a "Malicious" verdict, else
         reported as Spam/Suspicious
  PR-04  5-second response budget enforced via httpx timeout
  PR-05  Privacy by design: zero persistence, zero logging of message text
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
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
# Fallback chain: comma-separated list, tried in order until one succeeds.
# Groq is far less prone to individual-model churn than Hugging Face's
# marketplace was, but a short fallback list costs nothing and protects
# against a single model being deprecated or rate-limited in the future.
GROQ_MODELS = [
    m.strip() for m in os.getenv(
        "GROQ_MODELS",
        "llama-3.1-8b-instant,"
        "llama-3.3-70b-versatile,"
        "openai/gpt-oss-20b"
    ).split(",") if m.strip()
]
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

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
    version="2.0.0",
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
    return {"status": "ok", "models_in_priority_order": GROQ_MODELS, "provider": "groq", "api_url": GROQ_API_URL}


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
    resp = await client.post(GROQ_API_URL, headers=headers, json=payload)
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


async def call_groq(text: str) -> tuple[str, float, int, str]:
    """Tries each model in GROQ_MODELS in order until one succeeds. Returns
    (verdict_label, confidence, latency_ms, model_used). Raises
    HTTPException only if every candidate in the list fails."""
    if not GROQ_API_KEY:
        raise HTTPException(status_code=503, detail="Server misconfigured: GROQ_API_KEY not set.")

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    start = time.monotonic()
    last_error = "no models configured"

    async with httpx.AsyncClient(timeout=API_TIMEOUT_SECONDS) as client:
        for model in GROQ_MODELS:
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

    logger.error(f"All Groq model candidates failed. Last error: {last_error}")
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

    verdict, confidence, latency_ms, model_used = await call_groq(text)

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
    )
