"""
Bantay-Bait Backend — FastAPI
=============================
Free-tier production backend for the Bantay-Bait smishing detector.

Stack (all $0):
  - Hosting:  Render.com free Web Service
  - NLP:      Hugging Face Inference API (serverless, free tier) — no
              model hosting, no GPU, no training/fine-tuning.
  - Storage:  NONE. RA 10173 (Data Privacy Act) compliance = no database,
              no request logging of raw SMS text, nothing persisted.

Model note (read this before deploying)
----------------------------------------
The thesis assumes a pre-trained "RoBERTa-Tagalog" model that already ships
a 3-class (Safe/Spam/Malicious) classification head. In practice, no public
Hugging Face model is fine-tuned specifically for Philippine SMS-smishing
3-class classification, and the scope explicitly forbids training/fine-tuning
one. The free, no-training-required way to hit the same behavior is a
**zero-shot classification** call against a multilingual NLI model
(`joeddav/xlm-roberta-large-xnli` by default — handles Tagalog/Taglish/English
code-switching reasonably well) using natural-language candidate labels.
This is still "an existing, pre-trained model consumed strictly as an
external inference service" — consistent with the thesis's Section 10 scope.
If a purpose-built Tagalog smishing classifier becomes available on the Hub
later, swap HF_MODEL and set ZERO_SHOT=false to use it as a direct
text-classification pipeline instead — no other code changes needed.

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
import time
import logging
from pathlib import Path
from typing import Literal, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ----------------------------------------------------------------------
# Config (all from environment variables — nothing secret hardcoded)
# ----------------------------------------------------------------------
HF_TOKEN = os.getenv("HUGGINGFACE_TOKEN", "")
HF_MODEL = os.getenv("HF_MODEL", "joeddav/xlm-roberta-large-xnli")
ZERO_SHOT = os.getenv("ZERO_SHOT", "true").lower() == "true"
HF_API_URL = f"https://api-inference.huggingface.co/models/{HF_MODEL}"

# Comma-separated list, e.g. "https://bantay-bait.vercel.app,https://bantay-bait.netlify.app"
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if o.strip()]

MIN_LEN = 5
MAX_LEN = 1600
MALICIOUS_THRESHOLD = 0.75          # PR-03
API_TIMEOUT_SECONDS = 4.5           # PR-04 (leaves headroom under the 5s budget)

CANDIDATE_LABELS = {
    "malicious": "a scam message trying to steal money, passwords, or one-time PINs",
    "spam": "a promotional or advertising message",
    "safe": "a normal, legitimate message",
}

# ----------------------------------------------------------------------
# Logging — NEVER log raw message text (RA 10173 / PR-05)
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
# Tagalog stopwords (stopwords-iso/stopwords-tl) — bundled locally
# ----------------------------------------------------------------------
STOPWORDS_PATH = Path(__file__).parent / "data" / "stopwords_tl.txt"
TAGALOG_STOPWORDS = set()
if STOPWORDS_PATH.exists():
    TAGALOG_STOPWORDS = {w.strip().lower() for w in STOPWORDS_PATH.read_text(encoding="utf-8").splitlines() if w.strip()}

# Common Tagalog function words used for lightweight language detection
TAGALOG_MARKERS = {"ang", "ng", "mga", "sa", "ay", "na", "ko", "mo", "niya", "namin", "natin", "ito", "iyan", "hindi", "opo", "po"}

# Non-Taglish regional dialect markers (PR-02) — Cebuano/Bisaya, Ilocano, Hiligaynon
REGIONAL_MARKERS = {
    # Cebuano / Bisaya
    "unsa", "asa", "diri", "dinhi", "wala", "kaayo", "ngano", "kanimo", "nimo",
    "mao", "kini", "kana", "gikan", "buhaton", "salamat kaayo",
    # Ilocano
    "adda", "awan", "wen", "saan", "kayat", "apay", "ania", "isu",
    # Hiligaynon
    "bala", "wala sing", "diin", "abi", "ano bala",
}


def normalize_text(raw: str) -> str:
    """Whitespace/casing normalization + light cleanup. No PII stripping
    needed since we never persist the text regardless."""
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
    allow_origins=ALLOWED_ORIGINS,     # strict allowlist — set via env var
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.get("/health")
async def health():
    return {"status": "ok", "model": HF_MODEL, "zero_shot": ZERO_SHOT}


@app.get("/api/v1/samples")
async def get_samples(limit: int = 6):
    """Returns a handful of labeled sample SMS from the consolidated
    Philippine corpus, for the frontend's 'Try Sample SMS' quick-test
    buttons. Reads a static CSV — no user data involved."""
    import csv

    path = Path(__file__).parent / "data" / "bantay_bait_test_set.csv"
    if not path.exists():
        return {"samples": []}
    samples = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            samples.append({"text": row["text"], "label": row["label"]})
    # crude stratified pick: a few of each class
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


async def call_huggingface(text: str) -> tuple[str, float, int]:
    """Calls the HF Inference API and returns (verdict_label, confidence, latency_ms).
    Raises HTTPException on timeout / API error."""
    if not HF_TOKEN:
        raise HTTPException(status_code=503, detail="Server misconfigured: HUGGINGFACE_TOKEN not set.")

    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    start = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT_SECONDS) as client:
            if ZERO_SHOT:
                payload = {
                    "inputs": text,
                    "parameters": {
                        "candidate_labels": list(CANDIDATE_LABELS.values()),
                        "multi_label": False,
                    },
                }
                resp = await client.post(HF_API_URL, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                # {"labels": [...], "scores": [...]}
                top_label_text = data["labels"][0]
                top_score = float(data["scores"][0])
                # map the natural-language label back to safe/spam/malicious
                inv_map = {v: k for k, v in CANDIDATE_LABELS.items()}
                verdict = inv_map.get(top_label_text, "spam")
            else:
                payload = {"inputs": text}
                resp = await client.post(HF_API_URL, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                # Expected: [[{"label": "...", "score": ...}, ...]]
                top = max(data[0], key=lambda x: x["score"])
                verdict = top["label"].lower()
                top_score = float(top["score"])
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Classification timed out. Please try again.")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 503:
            raise HTTPException(status_code=503, detail="Model is loading on Hugging Face, please retry in ~20s.")
        raise HTTPException(status_code=502, detail=f"Upstream model error: {e.response.status_code}")
    except Exception as e:
        logger.error(f"HF call failed: {type(e).__name__}")
        raise HTTPException(status_code=502, detail="Classification service unavailable.")

    latency_ms = int((time.monotonic() - start) * 1000)
    return verdict, top_score, latency_ms


@app.post("/api/v1/detect", response_model=DetectResponse)
async def detect(req: DetectRequest):
    raw = req.text or ""

    # ---- PR-01: input length validation ----
    if len(raw.strip()) < MIN_LEN:
        raise HTTPException(status_code=422, detail=f"Message must be at least {MIN_LEN} characters.")
    if len(raw) > MAX_LEN:
        raise HTTPException(status_code=422, detail=f"Message must not exceed {MAX_LEN} characters.")

    text = normalize_text(raw)

    # ---- PR-02: regional dialect check ----
    is_regional = detect_regional_dialect(text)
    detected_lang = detect_language(text)

    # ---- Call the model (PR-04: timeout enforced inside) ----
    verdict, confidence, latency_ms = await call_huggingface(text)

    reasons: list[str] = []

    # ---- PR-03: confidence threshold gate for "malicious" ----
    reduced_confidence = is_regional
    if verdict == "malicious" and confidence < MALICIOUS_THRESHOLD:
        verdict = "spam"
        reasons.append("Confidence below the 0.75 threshold required for a Malicious verdict; downgraded to Spam/Suspicious.")

    if is_regional:
        reasons.append("Message may contain a regional Philippine dialect (Cebuano/Ilocano/Hiligaynon) outside the Tagalog/English/Taglish scope — confidence is reduced.")

    if verdict == "malicious":
        reasons.append("Detected credential-harvesting or brand-impersonation language typical of Philippine smishing (e.g. urgent account/OTP/verification requests).")
    elif verdict == "spam":
        reasons.append("Detected promotional/advertising language without a direct fraud request.")
    else:
        reasons.append("No smishing or spam indicators detected.")

    # PR-05: nothing about `text` is logged or stored below this line.

    return DetectResponse(
        verdict=verdict,  # type: ignore
        confidence=round(confidence, 4),
        detectedLanguage=detected_lang,
        isRegionalDialect=is_regional,
        reducedConfidence=reduced_confidence,
        reasons=reasons,
        modelLatencyMs=latency_ms,
    )
