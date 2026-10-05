"""
Check log for the admin dashboard (panel revision, final defense).

Every classification is recorded so an administrator can track and report how
many Safe / Spam / Malicious messages the system has caught. What is stored:

  - for EVERY check: time, verdict, confidence, detected language, dialect
    flag, downgrade flag, model used, latency, and whether a link was present;
  - for Spam and Malicious checks only: the message text with phone numbers,
    e-mail addresses and long digit runs (OTPs, account numbers) masked, plus
    the domains of any links. Safe messages are never stored as text, because
    those are the ones most likely to be personal.

Storage is a free hosted Postgres database in production (DATABASE_URL) and a
local SQLite file otherwise. Recording runs after the response is sent and
never blocks or breaks a classification.
"""
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import (Boolean, Column, DateTime, Float, Integer, MetaData, String, Table, Text,
                        create_engine, func, select)
from sqlalchemy.engine import Engine

logger = logging.getLogger("bantay-bait")

metadata = MetaData()
checks = Table(
    "checks", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("created_at", DateTime(timezone=True), nullable=False, index=True),
    Column("verdict", String(12), nullable=False, index=True),
    Column("confidence", Float, nullable=False),
    Column("language", String(12), nullable=False),
    Column("regional_dialect", Boolean, nullable=False, default=False),
    Column("downgraded", Boolean, nullable=False, default=False),
    Column("has_link", Boolean, nullable=False, default=False),
    Column("link_domains", String(400), nullable=True),
    Column("model_used", String(80), nullable=True),
    Column("latency_ms", Integer, nullable=True),
    Column("message_masked", Text, nullable=True),
)

# Brands most often impersonated in Philippine smishing (Ch 1.6 scope).
BRANDS = ["GCash", "Maya", "BDO", "BPI", "Landbank", "Metrobank", "Security Bank", "UnionBank", "LBC", "J&T",
          "Shopee", "Lazada", "PCSO", "PAGCOR", "Globe", "Smart", "DITO", "SSS", "Pag-IBIG", "PhilHealth"]

_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_PHONE = re.compile(r"(?:\+?63|0)9\d{2}[\s-]?\d{3}[\s-]?\d{4}\b|\(0\d{1,2}\)\s?\d{3,4}[\s-]?\d{4}")
_DIGITS = re.compile(r"\b\d{4,}\b")

_engine: Optional[Engine] = None


def mask_message(text: str) -> str:
    """Remove the personal parts of a message before it is stored."""
    t = _EMAIL.sub("[EMAIL]", text)
    t = _PHONE.sub("[PHONE]", t)
    t = _DIGITS.sub("[NUMBER]", t)
    return t[:1600]


def link_domain(link: str) -> str:
    d = re.sub(r"^(?:https?://)?(?:www\.)?", "", link.strip(), flags=re.I)
    return d.split("/")[0].lower()[:80]


def _normalize_url(url: str) -> str:
    # Hosted Postgres providers hand out postgres:// or postgresql:// URLs;
    # SQLAlchemy needs the driver named explicitly for psycopg 3.
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


def configure(url: Optional[str] = None) -> Engine:
    """Create (or replace) the engine and make sure the table exists."""
    global _engine
    url = url or os.getenv("DATABASE_URL") or "sqlite:///./bantay_bait_checks.db"
    url = _normalize_url(url)
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)
    metadata.create_all(_engine)
    return _engine


def engine() -> Engine:
    return _engine or configure()


def recording_enabled() -> bool:
    return os.getenv("RECORD_CHECKS", "true").lower() == "true"


def record_check(*, text: str, verdict: str, confidence: float, language: str, regional: bool,
                 downgraded: bool, links: list, model_used: str, latency_ms: int) -> None:
    """Store one classification. Never raises: a storage problem must not
    affect the user's result."""
    if not recording_enabled():
        return
    try:
        flagged = verdict in ("spam", "malicious")
        row = dict(
            created_at=datetime.now(timezone.utc),
            verdict=verdict,
            confidence=float(confidence),
            language="dialect" if regional else language,
            regional_dialect=bool(regional),
            downgraded=bool(downgraded),
            has_link=bool(links),
            link_domains=",".join(sorted({link_domain(l) for l in links}))[:400] if (flagged and links) else None,
            model_used=(model_used or "")[:80],
            latency_ms=int(latency_ms or 0),
            message_masked=mask_message(text) if flagged else None,
        )
        with engine().begin() as conn:
            conn.execute(checks.insert().values(**row))
    except Exception as e:  # pragma: no cover - logged, never surfaced
        logger.warning(f"Could not record check: {type(e).__name__}")


def _since(days: Optional[int]):
    return datetime.now(timezone.utc) - timedelta(days=days) if days else None


def stats(days: Optional[int] = 30) -> dict:
    since = _since(days)
    where = [checks.c.created_at >= since] if since else []
    with engine().connect() as conn:
        by_verdict = dict(conn.execute(select(checks.c.verdict, func.count()).where(*where).group_by(checks.c.verdict)).all())
        by_language = dict(conn.execute(select(checks.c.language, func.count()).where(*where).group_by(checks.c.language)).all())
        downgraded = conn.execute(select(func.count()).where(checks.c.downgraded.is_(True), *where)).scalar() or 0
        with_link = conn.execute(select(func.count()).where(checks.c.has_link.is_(True), *where)).scalar() or 0
        rows = conn.execute(select(checks.c.created_at, checks.c.verdict, checks.c.message_masked, checks.c.link_domains)
                            .where(*where)).all()
    daily: dict = {}
    brands: dict = {}
    domains: dict = {}
    for created, verdict, msg, doms in rows:
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        day = created.astimezone(timezone(timedelta(hours=8))).date().isoformat()  # Philippine time
        daily.setdefault(day, {"safe": 0, "spam": 0, "malicious": 0})[verdict] += 1
        if msg:
            low = msg.lower()
            for b in BRANDS:
                if re.search(r"(?<![a-z])" + re.escape(b.lower()) + r"(?![a-z])", low):
                    brands[b] = brands.get(b, 0) + 1
        for d in (doms or "").split(","):
            if d:
                domains[d] = domains.get(d, 0) + 1
    total = sum(by_verdict.values())
    return {
        "days": days,
        "total": total,
        "byVerdict": {v: by_verdict.get(v, 0) for v in ("safe", "spam", "malicious")},
        "byLanguage": by_language,
        "downgraded": downgraded,
        "withLink": with_link,
        "daily": [{"date": k, **v} for k, v in sorted(daily.items())],
        "topBrands": sorted(brands.items(), key=lambda x: -x[1])[:10],
        "topDomains": sorted(domains.items(), key=lambda x: -x[1])[:10],
    }


def flagged_messages(verdict: Optional[str] = None, days: Optional[int] = 30, limit: int = 50, offset: int = 0) -> list:
    since = _since(days)
    q = select(checks).where(checks.c.message_masked.is_not(None))
    if verdict in ("spam", "malicious"):
        q = q.where(checks.c.verdict == verdict)
    if since:
        q = q.where(checks.c.created_at >= since)
    q = q.order_by(checks.c.created_at.desc()).limit(max(1, min(limit, 500))).offset(max(0, offset))
    with engine().connect() as conn:
        out = []
        for r in conn.execute(q).mappings():
            created = r["created_at"]
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            out.append({
                "id": r["id"], "createdAt": created.isoformat(), "verdict": r["verdict"],
                "confidence": r["confidence"], "language": r["language"], "downgraded": r["downgraded"],
                "linkDomains": [d for d in (r["link_domains"] or "").split(",") if d],
                "model": r["model_used"], "message": r["message_masked"],
            })
        return out
