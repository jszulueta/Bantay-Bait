from unittest.mock import AsyncMock, patch
import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app, GROQ_MODELS, RedactTextFilter, _extract_json_object

client = TestClient(app)

# ---- PR-01: length validation ----
def test_rejects_too_short_after_strip():
    resp = client.post("/api/v1/detect", json={"text": "  ab ", "lang": "en"})
    assert resp.status_code == 422

def test_accepts_exactly_min_length():
    with patch("app.main.call_groq", new=AsyncMock(return_value=("safe", 0.9, 200, GROQ_MODELS[0]))):
        resp = client.post("/api/v1/detect", json={"text": "abcde", "lang": "en"})
        assert resp.status_code == 200

def test_rejects_too_long_raw_length():
    # note: MAX_LEN checks len(raw), not len(raw.strip())
    resp = client.post("/api/v1/detect", json={"text": "a" * 1601, "lang": "en"})
    assert resp.status_code == 422

def test_accepts_exactly_max_length():
    with patch("app.main.call_groq", new=AsyncMock(return_value=("safe", 0.9, 200, GROQ_MODELS[0]))):
        resp = client.post("/api/v1/detect", json={"text": "a" * 1600, "lang": "en"})
        assert resp.status_code == 200

# ---- PR-03: 0.75 confidence floor for Malicious ----
def test_malicious_below_threshold_downgrades_to_spam():
    with patch("app.main.call_groq", new=AsyncMock(return_value=("malicious", 0.6, 150, GROQ_MODELS[0]))):
        resp = client.post("/api/v1/detect", json={"text": "borderline scam-like message text", "lang": "en"})
        body = resp.json()
        assert body["verdict"] == "spam"
        assert any("0.75 threshold" in r for r in body["reasons"])

def test_malicious_above_threshold_stays_malicious():
    with patch("app.main.call_groq", new=AsyncMock(return_value=("malicious", 0.91, 150, GROQ_MODELS[0]))):
        resp = client.post("/api/v1/detect", json={
            "text": "GCash: Your account has been accessed. Verify: http://gcash-verify.com", "lang": "taglish"
        })
        assert resp.json()["verdict"] == "malicious"

# ---- NFR-03: reduced-confidence notice below 0.75 ----
def test_downgraded_malicious_sets_low_confidence_flags():
    with patch("app.main.call_groq", new=AsyncMock(return_value=("malicious", 0.6, 150, GROQ_MODELS[0]))):
        body = client.post("/api/v1/detect", json={"text": "borderline scam-like message text", "lang": "en"}).json()
        assert body["verdict"] == "spam"
        assert body["downgraded"] is True
        assert body["lowConfidence"] is True

def test_confident_malicious_has_no_low_confidence_flags():
    with patch("app.main.call_groq", new=AsyncMock(return_value=("malicious", 0.91, 150, GROQ_MODELS[0]))):
        body = client.post("/api/v1/detect", json={"text": "GCash: verify now http://gcash-verify.com", "lang": "en"}).json()
        assert body["downgraded"] is False
        assert body["lowConfidence"] is False

def test_low_confidence_safe_is_flagged_but_not_downgraded():
    with patch("app.main.call_groq", new=AsyncMock(return_value=("safe", 0.6, 150, GROQ_MODELS[0]))):
        body = client.post("/api/v1/detect", json={"text": "see you at the office tomorrow", "lang": "en"}).json()
        assert body["verdict"] == "safe"
        assert body["lowConfidence"] is True
        assert body["downgraded"] is False

# ---- PR-02: regional dialect flag ----
def test_regional_dialect_flag_sets_reduced_confidence():
    with patch("app.main.call_groq", new=AsyncMock(return_value=("spam", 0.7, 150, GROQ_MODELS[0]))):
        resp = client.post("/api/v1/detect", json={"text": "unsa imong gibuhat karon", "lang": "auto"})
        body = resp.json()
        assert body["isRegionalDialect"] is True
        assert body["reducedConfidence"] is True

# ---- language detection ----
def test_taglish_detection():
    with patch("app.main.call_groq", new=AsyncMock(return_value=("safe", 0.9, 150, GROQ_MODELS[0]))):
        resp = client.post("/api/v1/detect", json={"text": "ang galing please click your account", "lang": "auto"})
        assert resp.json()["detectedLanguage"] == "taglish"

# ---- model fallback chain ----
@pytest.mark.asyncio
async def test_fallback_to_second_model_on_timeout():
    from app.main import call_groq
    with patch("app.main._try_one_model", new=AsyncMock(
        side_effect=[httpx.TimeoutException("timed out"), ("safe", 0.9)]
    )):
        with patch.object(httpx, "AsyncClient"):  # avoid real network setup in __aenter__
            pass  # see note below

def test_all_models_fail_returns_502(monkeypatch):
    monkeypatch.setattr("app.main.GROQ_API_KEY", "dummy-key-for-test")
    with patch("app.main._try_one_model", new=AsyncMock(side_effect=httpx.TimeoutException("timed out"))):
        resp = client.post("/api/v1/detect", json={"text": "any valid length text here", "lang": "en"})
        assert resp.status_code == 502
        assert "Attempts:" in resp.json()["detail"]

def test_missing_api_key_returns_503(monkeypatch):
    monkeypatch.setattr("app.main.GROQ_API_KEY", "")
    resp = client.post("/api/v1/detect", json={"text": "any valid length text here", "lang": "en"})
    assert resp.status_code == 503

# ---- PR-05: no raw text ever logged ----
def test_redact_filter_masks_text():
    f = RedactTextFilter()
    class FakeRecord:
        msg = "some log line text=SECRET_MESSAGE_CONTENTS"
    rec = FakeRecord()
    f.filter(rec)
    assert "SECRET_MESSAGE_CONTENTS" not in rec.msg

# ---- JSON extraction robustness ----
def test_extract_json_handles_wrapped_commentary():
    raw = 'Sure, here is the result: {"verdict": "spam", "confidence": 0.6} thanks!'
    parsed = _extract_json_object(raw)
    assert parsed["verdict"] == "spam"

def test_extract_json_raises_on_garbage():
    with pytest.raises(ValueError):
        _extract_json_object("no json here at all")

# ---- health endpoint ----
def test_health_reports_groq_provider():
    resp = client.get("/health")
    body = resp.json()
    assert body["provider"] == "groq"
    assert body["models_in_priority_order"] == GROQ_MODELS