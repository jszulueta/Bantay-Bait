from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app import admin, store
from app.main import GROQ_MODELS, app

client = TestClient(app)
SCAM = "GCash: Your account is locked. Verify now at gcash-security-check.com or call 09171234567. OTP 482913"


def _detect(text, verdict, conf=0.95):
    with patch("app.main.call_groq", new=AsyncMock(return_value=(verdict, conf, 120, GROQ_MODELS[0]))):
        return client.post("/api/v1/detect", json={"text": text, "lang": "en"})


def _token():
    return client.post("/api/v1/admin/login", json={"password": "test-password"}).json()["token"]


def _auth():
    return {"Authorization": f"Bearer {_token()}"}


# ---- Check log (recording) ----
def test_every_check_is_counted_by_verdict():
    _detect("Hello, see you at dinner later", "safe")
    _detect("MEGA SALE this weekend only at our store", "spam")
    _detect(SCAM, "malicious")
    s = store.stats(30)
    assert s["total"] == 3
    assert s["byVerdict"] == {"safe": 1, "spam": 1, "malicious": 1}


def test_safe_message_text_is_never_stored():
    _detect("Ma, nasa bahay na ako. Salamat po.", "safe")
    _detect(SCAM, "malicious")
    msgs = store.flagged_messages(None, 30)
    assert len(msgs) == 1 and msgs[0]["verdict"] == "malicious"


def test_stored_scam_text_is_masked():
    _detect(SCAM, "malicious")
    m = store.flagged_messages("malicious", 30)[0]
    assert "09171234567" not in m["message"] and "[PHONE]" in m["message"]
    assert "482913" not in m["message"] and "[NUMBER]" in m["message"]
    assert m["linkDomains"] == ["gcash-security-check.com"]


def test_downgraded_check_is_recorded_as_spam():
    _detect("borderline scam-like message text", "malicious", conf=0.6)
    s = store.stats(30)
    assert s["byVerdict"]["spam"] == 1 and s["downgraded"] == 1


def test_recording_failure_does_not_break_detection():
    with patch("app.store.engine", side_effect=RuntimeError("database down")):
        resp = _detect(SCAM, "malicious")
    assert resp.status_code == 200 and resp.json()["verdict"] == "malicious"


def test_brand_and_domain_summary():
    _detect(SCAM, "malicious")
    s = store.stats(30)
    assert ("GCash", 1) in [tuple(x) for x in s["topBrands"]]
    assert ("gcash-security-check.com", 1) in [tuple(x) for x in s["topDomains"]]


# ---- Admin access (OWASP A01 / A07) ----
def test_dashboard_requires_login():
    assert client.get("/api/v1/admin/stats").status_code == 401
    assert client.get("/api/v1/admin/messages").status_code == 401
    assert client.get("/api/v1/admin/report.csv").status_code == 401


def test_wrong_password_is_rejected():
    assert client.post("/api/v1/admin/login", json={"password": "nope"}).status_code == 401


def test_forged_or_expired_token_is_rejected():
    assert client.get("/api/v1/admin/stats", headers={"Authorization": "Bearer forged"}).status_code == 401
    old = admin.make_token(now=0)  # expired long ago
    assert client.get("/api/v1/admin/stats", headers={"Authorization": f"Bearer {old}"}).status_code == 401


def test_login_locks_after_repeated_failures():
    for _ in range(admin.MAX_FAILURES):
        client.post("/api/v1/admin/login", json={"password": "nope"})
    resp = client.post("/api/v1/admin/login", json={"password": "test-password"})
    assert resp.status_code == 429


def test_lockout_is_per_visitor_not_global():
    for _ in range(admin.MAX_FAILURES):
        client.post("/api/v1/admin/login", json={"password": "nope"}, headers={"CF-Connecting-IP": "203.0.113.7"})
    blocked = client.post("/api/v1/admin/login", json={"password": "test-password"}, headers={"CF-Connecting-IP": "203.0.113.7"})
    other = client.post("/api/v1/admin/login", json={"password": "test-password"}, headers={"CF-Connecting-IP": "198.51.100.9"})
    assert blocked.status_code == 429 and other.status_code == 200


def test_dashboard_disabled_when_not_configured(monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD")
    assert client.post("/api/v1/admin/login", json={"password": "x"}).status_code == 503


def test_admin_sees_stats_messages_and_report():
    _detect(SCAM, "malicious")
    _detect("Hello there friend", "safe")
    h = _auth()
    stats = client.get("/api/v1/admin/stats?days=30", headers=h).json()
    assert stats["total"] == 2 and stats["byVerdict"]["malicious"] == 1
    msgs = client.get("/api/v1/admin/messages?verdict=malicious", headers=h).json()["messages"]
    assert len(msgs) == 1
    csv_text = client.get("/api/v1/admin/report.csv", headers=h).text
    assert "Malicious,1" in csv_text and "09171234567" not in csv_text
