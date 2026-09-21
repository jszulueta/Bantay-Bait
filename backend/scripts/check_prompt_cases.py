"""Live regression check for the classifier prompt.

Sends a small set of hand-written messages to a running Bantay-Bait API and
compares each verdict with what a careful human reader would say. Unlike the
pytest suite (which replaces the model with test doubles), this exercises the
REAL model, so it needs the API to have a valid GROQ_API_KEY.

    python scripts/check_prompt_cases.py                         # http://localhost:8000
    python scripts/check_prompt_cases.py --url https://bantay-bait-api.onrender.com
    python scripts/check_prompt_cases.py --repeat 3              # stability across the fallback chain

All messages below are synthetic, written for this check. None comes from the
held-out test set (bantay_bait_test_set.csv), so tuning the prompt against
them does not contaminate the Chapter 4 evaluation.
"""
import argparse
import sys
import time

import httpx

# (label, message, verdicts that count as correct)
CASES = [
    # --- legitimate: must NOT be flagged as a scam -------------------------
    ("safe: e-wallet trusted-device notice (the reported false positive)",
     "Apple iPhone 13 Pro Max was trusted for your account +630**?840 at Quezon City, Philippines on "
     "September 15, 2026 07:20:22 AM PHT. Not you? Call +632 8845-7744 now. Never share your OTP.",
     {"safe"}),
    ("safe: OTP with warning",
     "Your GCash login code is 482913. Never share this code with anyone, including GCash staff. "
     "If you did not request this, ignore this message.",
     {"safe"}),
    ("safe: Tagalog OTP with warning",
     "Ang iyong OTP ay 928374. Huwag ibahagi ang code na ito kaninuman. Mag-e-expire ito sa loob ng 5 minuto.",
     {"safe"}),
    ("safe: bank transfer notice",
     "BDO: You transferred PHP 1,500.00 to J. DELA CRUZ on 21Sep2026 10:14. If you did not make this "
     "transaction, call the hotline printed on your card or visit any branch.",
     {"safe"}),
    ("safe: personal Taglish",
     "Uy, nasa labas na ako ng bahay niyo. Pababa ka na ba? Traffic kasi kanina.",
     {"safe"}),

    # --- scams: must stay flagged, INCLUDING ones that copy the warning ----
    ("malicious: classic link + OTP",
     "GCash: Your account has been accessed from a new device. Verify immediately to avoid suspension: "
     "https://gcash-security-check.com/verify OTP: 884920",
     {"malicious"}),
    ("malicious: scam that copies 'never share your OTP'",
     "MAYA ALERT: Unusual login detected on your account. Confirm your identity now at "
     "https://maya-secure-verify.top/login or your wallet will be locked. Never share your OTP with anyone.",
     {"malicious"}),
    ("malicious: asks you to reply with the code (no link)",
     "GCash: We sent you a code by mistake. Please reply with the 6-digit code you received to cancel "
     "the charge of PHP 4,999.",
     {"malicious"}),
    ("malicious: prize + processing fee",
     "CONGRATULATIONS! You won PHP 500,000 in the PCSO Lucky Draw. To release your prize, send a PHP 2,500 "
     "processing fee to GCash 0917-555-0123.",
     {"malicious"}),
    ("malicious: fake job -> Telegram",
     "Shopee hiring: earn P3,000/day just liking products. Message our HR on Telegram @shopee_hr_ph to start today.",
     {"malicious"}),

    # --- promotional: not a scam, not a personal message -------------------
    ("spam: retail sale",
     "SM Supermalls Mega Sale this weekend only! Up to 70% off on selected items. Show this SMS at the "
     "counter. Reply STOP to opt out.",
     {"spam"}),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:8000", help="API base URL")
    ap.add_argument("--lang", default="english", choices=["english", "tagalog", "taglish"], help="UI language hint")
    ap.add_argument("--repeat", type=int, default=1, help="times to run each case")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between requests (free-tier rate limits)")
    args = ap.parse_args()

    failures = 0
    with httpx.Client(timeout=60) as client:
        for n, (label, text, ok) in enumerate(CASES):
            got = []
            for i in range(args.repeat):
                if n or i:
                    time.sleep(args.delay)
                r = client.post(f"{args.url}/api/v1/detect", json={"text": text, "lang": args.lang})
                if r.status_code != 200:
                    print(f"ERROR {label}: HTTP {r.status_code} {r.text[:200]}")
                    failures += 1
                    break
                got.append(r.json())
            else:
                bad = [g for g in got if g["verdict"] not in ok]
                failures += bool(bad)
                last = got[-1]
                print(f"{'FAIL' if bad else 'ok  '} {label}")
                print(f"       expected {sorted(ok)}, got {[g['verdict'] for g in got]} "
                      f"(conf {last['confidence']:.2f}, model {last['modelUsed']})")
                if last.get("explanation"):
                    print(f"       why: {last['explanation']}")
                for flag in last.get("redFlags", []):
                    print(f"       - red flag: {flag}")
                for sign in last.get("safeSignals", []):
                    print(f"       + safe sign: {sign}")

    print(f"\n{len(CASES) - failures}/{len(CASES)} cases matched expectations")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
