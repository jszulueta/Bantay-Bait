"""
Administrator API for the dashboard (panel revision, final defense).

One administrator account, configured on the server:
  ADMIN_PASSWORD  the administrator's password (Render environment variable)
  ADMIN_SECRET    a long random string used to sign login tokens

Login returns a signed token valid for 8 hours. After 5 wrong passwords from
the same address, login is locked for 15 minutes (OWASP A07).
"""
import base64
import csv
import hashlib
import hmac
import io
import os
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from app import store

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

TOKEN_TTL_SECONDS = 8 * 3600
MAX_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60
_failures: dict = {}  # client address -> (failure count, first failure time)


def _secret() -> bytes:
    s = os.getenv("ADMIN_SECRET", "")
    if not s or not os.getenv("ADMIN_PASSWORD"):
        raise HTTPException(status_code=503, detail="Admin dashboard is not configured on the server.")
    return s.encode()


def make_token(now: Optional[float] = None) -> str:
    expires = str(int((time.time() if now is None else now) + TOKEN_TTL_SECONDS))
    sig = hmac.new(_secret(), expires.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{expires}.{sig}".encode()).decode()


def verify_token(token: str) -> bool:
    try:
        expires, sig = base64.urlsafe_b64decode(token.encode()).decode().split(".", 1)
    except Exception:
        return False
    good = hmac.new(_secret(), expires.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, good) and int(expires) > time.time()


def require_admin(authorization: str = Header(default="")) -> None:
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    if not token or not verify_token(token):
        raise HTTPException(status_code=401, detail="Please log in again.")


class LoginRequest(BaseModel):
    password: str


@router.post("/login")
def login(req: LoginRequest, request: Request):
    _secret()  # 503 if not configured
    who = request.client.host if request.client else "unknown"
    count, first = _failures.get(who, (0, time.time()))
    if count >= MAX_FAILURES and time.time() - first < LOCKOUT_SECONDS:
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")
    if time.time() - first >= LOCKOUT_SECONDS:
        count, first = 0, time.time()
    if not hmac.compare_digest(req.password.encode(), os.environ["ADMIN_PASSWORD"].encode()):
        _failures[who] = (count + 1, first)
        raise HTTPException(status_code=401, detail="Wrong password.")
    _failures.pop(who, None)
    return {"token": make_token(), "expiresInSeconds": TOKEN_TTL_SECONDS}


def _days(days: int) -> Optional[int]:
    return None if days <= 0 else days


@router.get("/stats", dependencies=[Depends(require_admin)])
def get_stats(days: int = Query(30, ge=0, le=3650)):
    return store.stats(_days(days))


@router.get("/messages", dependencies=[Depends(require_admin)])
def get_messages(verdict: Optional[str] = Query(None), days: int = Query(30, ge=0, le=3650),
                 limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    return {"messages": store.flagged_messages(verdict, _days(days), limit, offset)}


@router.get("/report.csv", dependencies=[Depends(require_admin)], response_class=PlainTextResponse)
def report_csv(days: int = Query(30, ge=0, le=3650)):
    """Report for authorities or awareness campaigns: daily counts, then the
    flagged messages (personal details already masked)."""
    s = store.stats(_days(days))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Bantay-Bait report", f"last {days} days" if days else "all time"])
    w.writerow(["Total checks", s["total"]])
    for v in ("safe", "spam", "malicious"):
        w.writerow([v.capitalize(), s["byVerdict"][v]])
    w.writerow([])
    w.writerow(["Date (PH time)", "Safe", "Spam", "Malicious"])
    for d in s["daily"]:
        w.writerow([d["date"], d["safe"], d["spam"], d["malicious"]])
    w.writerow([])
    w.writerow(["Most impersonated brands", "Count"])
    w.writerows(s["topBrands"])
    w.writerow([])
    w.writerow(["Most common link domains", "Count"])
    w.writerows(s["topDomains"])
    w.writerow([])
    w.writerow(["Time (UTC)", "Verdict", "Confidence", "Language", "Link domains", "Message (masked)"])
    for m in store.flagged_messages(None, _days(days), 500, 0):
        w.writerow([m["createdAt"], m["verdict"], m["confidence"], m["language"], " ".join(m["linkDomains"]), m["message"]])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=bantay-bait-report.csv"})
