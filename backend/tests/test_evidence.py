"""Tests for the evidence-based classification added in v2.2.0.

No network access: the Groq call is replaced with a fake client / mock, so
these verify OUR code (link extraction, prompt assembly, response parsing,
response shaping). Whether the live model reaches the right verdict is
checked separately by scripts/check_prompt_cases.py against the deployed API.

Run from the backend/ directory:  python -m pytest tests
"""
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import (
    CLASSIFIER_SYSTEM_PROMPT,
    Evidence,
    GROQ_MODELS,
    _try_one_model,
    app,
    build_user_message,
    extract_links,
)

client = TestClient(app)

MAYA_NOTICE = (
    "Apple iPhone 13 Pro Max was trusted for your account +630**?840 at Quezon City, "
    "Philippines on September 15, 2026 07:20:22 AM PHT. Not you? Call +632 8845-7744 now. "
    "Never share your OTP."
)


# ---- link extraction ------------------------------------------------------
@pytest.mark.parametrize("text", [
    MAYA_NOTICE,
    "Your account is locked.Click here to call us",   # missing space after period
    "Load PHP15.00 valid for 7 days, Ref 12.34.56",
    "Ok see you at 7.30 pm",
])
def test_no_link_in_plain_text(text):
    assert extract_links(text) == []


@pytest.mark.parametrize("text,expected", [
    ("Verify now https://gcash-security-check.com/verify OTP: 884920", "https://gcash-security-check.com/verify"),
    ("BDO Advisory: verify here my-bdo-online.com", "my-bdo-online.com"),
    ("Claim: tinyurl.com/5euvpskm", "tinyurl.com/5euvpskm"),
    ("Visit www.example.ph.", "www.example.ph"),   # trailing period stripped
])
def test_links_are_found(text, expected):
    assert extract_links(text) == [expected]


def test_duplicate_links_reported_once():
    assert extract_links("go to a-b.com or A-B.com") == ["a-b.com"]


# ---- prompt assembly --------------------------------------------------------
def test_user_message_reports_no_links_and_language():
    msg = build_user_message(MAYA_NOTICE, "english")
    assert "Reply language: English" in msg
    assert "Links found by code: none" in msg
    assert MAYA_NOTICE in msg


def test_user_message_lists_links_and_defaults_language():
    msg = build_user_message("verify at my-bdo-online.com", "auto")
    assert "Links found by code: my-bdo-online.com" in msg
    assert "same language as the SMS" in msg


# ---- model output parsing -----------------------------------------------------
class _FakeResponse:
    def __init__(self, content):
        self._content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


class _FakeClient:
    def __init__(self, content):
        self.content = content
        self.sent = None

    async def post(self, url, headers, json):   # noqa: A002 - mirrors httpx signature
        self.sent = json
        return _FakeResponse(self.content)


@pytest.mark.asyncio
async def test_parses_evidence_and_sends_static_system_prompt():
    content = json.dumps({
        "red_flags": [],
        "safe_signs": ["Reports a trusted device", "Warns never to share OTP", "No link"],
        "verdict": "safe", "confidence": 0.93,
        "reason": "Informational device notice; asks for nothing.",
    })
    fake = _FakeClient(content)
    verdict, confidence, ev = await _try_one_model(fake, {}, "m", MAYA_NOTICE, "english")
    assert (verdict, confidence) == ("safe", 0.93)
    assert ev.red_flags == [] and len(ev.safe_signs) == 3
    assert fake.sent["messages"][0] == {"role": "system", "content": CLASSIFIER_SYSTEM_PROMPT}
    assert MAYA_NOTICE in fake.sent["messages"][1]["content"]


@pytest.mark.asyncio
async def test_tolerates_sloppy_model_output():
    content = json.dumps({
        "red_flags": "Link to a lookalike domain",      # string instead of list
        "safe_signs": None,
        "verdict": "MALICIOUS", "confidence": 7,        # wrong case, out of range
        "reason": "x" * 1000,
    })
    verdict, confidence, ev = await _try_one_model(_FakeClient(content), {}, "m", "some text here", "auto")
    assert verdict == "malicious" and confidence == 1.0
    assert ev.red_flags == ["Link to a lookalike domain"] and ev.safe_signs == []
    assert len(ev.reason) == 300


@pytest.mark.asyncio
async def test_old_style_output_without_evidence_still_works():
    content = json.dumps({"verdict": "spam", "confidence": 0.7, "reason": "Promo."})
    verdict, _, ev = await _try_one_model(_FakeClient(content), {}, "m", "50% off today", "auto")
    assert verdict == "spam" and ev.red_flags == [] and ev.reason == "Promo."


# ---- endpoint shaping ----------------------------------------------------------
def test_detect_returns_model_explanation_and_forwards_lang():
    ev = Evidence(red_flags=[], safe_signs=["No link"], reason="Informational device notice.")
    mock = AsyncMock(return_value=("safe", 0.93, 200, GROQ_MODELS[0], ev))
    with patch("app.main.call_groq", new=mock):
        resp = client.post("/api/v1/detect", json={"text": MAYA_NOTICE, "lang": "english"})
    body = resp.json()
    assert body["verdict"] == "safe"
    assert body["explanation"] == "Informational device notice."
    assert body["safeSignals"] == ["No link"] and body["redFlags"] == []
    assert "Informational device notice." in body["reasons"]
    assert "Detected credential-harvesting" not in " ".join(body["reasons"])
    mock.assert_awaited_once()
    assert mock.await_args.args[1] == "english"


def test_low_confidence_downgrade_still_reported_with_evidence():
    ev = Evidence(red_flags=["Urgent wording"], reason="Possibly a scam.")
    with patch("app.main.call_groq", new=AsyncMock(return_value=("malicious", 0.6, 100, GROQ_MODELS[0], ev))):
        body = client.post("/api/v1/detect", json={"text": "borderline scam-like message", "lang": "en"}).json()
    assert body["verdict"] == "spam"
    assert any("0.75 threshold" in r for r in body["reasons"])
    assert body["redFlags"] == ["Urgent wording"]
