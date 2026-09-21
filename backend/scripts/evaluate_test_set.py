"""Evaluate the deployed Bantay-Bait API on the held-out test set (thesis Section 4.1).

MEASUREMENT ONLY. Do not edit the classifier prompt after seeing these results:
the test set must never be used to tune the system. Whatever the numbers are,
they are what Chapter 4 reports.

What it does
  1. Sends every message in backend/app/data/bantay_bait_test_set.csv (2,805 rows)
     to POST /api/v1/detect, one at a time, and appends the answer to a results CSV.
     The message text is NOT written to the results file (only the row id and
     the labels), so nothing about the messages is stored twice.
  2. Can be stopped and restarted: rows already answered are skipped.
  3. Computes accuracy, the confusion matrix, per-class precision/recall/F1,
     macro and weighted averages, Cohen's kappa, the Malicious-verdict count,
     model usage, latency and per-language accuracy, and writes them to a
     Markdown file you can paste into Section 4.1.

Usage (from the backend/ folder)
  python scripts/evaluate_test_set.py --limit 20            # quick smoke test first
  python scripts/evaluate_test_set.py                       # the full run (about 1.5-2 hours)
  python scripts/evaluate_test_set.py --report-only         # recompute metrics from the CSV

Options
  --api URL     default https://bantay-bait.onrender.com
  --out PATH    results CSV, default evaluation_results.csv
  --delay SEC   pause between requests, default 0.5 (raise it if you see many 429s)
  --retries N   retries for a failed request, default 4 (waits longer each time)
"""
import argparse
import csv
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import httpx

CLASSES = ["safe", "spam", "malicious"]
TEST_SET = Path(__file__).resolve().parent.parent / "app" / "data" / "bantay_bait_test_set.csv"
FIELDS = ["id", "label", "source", "pred", "confidence", "downgraded", "lowConfidence",
          "detectedLanguage", "isRegionalDialect", "modelUsed", "latencyMs", "status", "error"]


def load_rows(limit):
    with open(TEST_SET, newline="", encoding="utf-8") as f:
        rows = [{"id": i, **r} for i, r in enumerate(csv.DictReader(f))]
    return rows[:limit] if limit else rows


def read_results(path):
    """Read the results CSV. Tolerates a missing/empty file or a missing header
    row (for example after an interrupted first run)."""
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.reader(f) if r]
    if rows and rows[0][0] == "id":
        rows = rows[1:]
    return {int(r[0]): dict(zip(FIELDS, r)) for r in rows if len(r) == len(FIELDS)}


def classify(client, api, text, retries):
    last_error = ""
    for attempt in range(retries + 1):
        try:
            resp = client.post(f"{api}/api/v1/detect", json={"text": text, "lang": "english"})
            if resp.status_code == 200:
                return resp.json(), ""
            last_error = f"HTTP {resp.status_code}: {resp.text[:120]}"
        except httpx.HTTPError as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(min(2 ** attempt * 2, 30))
    return None, last_error


def run(args):
    out = Path(args.out)
    rows = load_rows(args.limit)
    done = {i: r for i, r in read_results(out).items() if r["status"] == "ok"}
    todo = [r for r in rows if r["id"] not in done]
    print(f"{len(rows)} rows selected, {len(done)} already done, {len(todo)} to run", flush=True)
    new_file = not out.exists() or out.stat().st_size == 0
    with open(out, "a", newline="", encoding="utf-8") as f, httpx.Client(timeout=60) as client:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()
        started = time.time()
        for n, row in enumerate(todo, 1):
            data, error = classify(client, args.api, row["text"], args.retries)
            rec = {"id": row["id"], "label": row["label"], "source": row["source"]}
            if data is not None:
                rec.update(pred=data["verdict"], confidence=data["confidence"],
                           downgraded=data.get("downgraded", ""), lowConfidence=data.get("lowConfidence", ""),
                           detectedLanguage=data["detectedLanguage"], isRegionalDialect=data["isRegionalDialect"],
                           modelUsed=data["modelUsed"], latencyMs=data["modelLatencyMs"], status="ok", error="")
            else:
                rec.update(status="error", error=error)
            writer.writerow(rec)
            f.flush()
            if n % 25 == 0 or n == len(todo):
                rate = n / (time.time() - started)
                print(f"  {n}/{len(todo)} done, ~{(len(todo) - n) / rate / 60:.0f} min left", flush=True)
            time.sleep(args.delay)


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def report(args):
    results = read_results(Path(args.out))
    ok = [r for r in results.values() if r["status"] == "ok"]
    bad = [r for r in results.values() if r["status"] != "ok"]
    if not ok:
        sys.exit("No successful results yet.")
    matrix = {a: Counter() for a in CLASSES}
    for r in ok:
        matrix[r["label"]][r["pred"]] += 1
    n = len(ok)
    correct = sum(matrix[c][c] for c in CLASSES)
    lines = ["# Section 4.1 metrics (generated by scripts/evaluate_test_set.py)", "",
             f"Messages scored: **{n}**; unclassified (request failed): **{len(bad)}**; accuracy: **{correct / n:.4f}**", "",
             "## Confusion matrix (rows = actual, columns = predicted)", "",
             "| Actual \\ Predicted | safe | spam | malicious | Total |", "|---|---|---|---|---|"]
    for a in CLASSES:
        lines.append(f"| {a} | " + " | ".join(str(matrix[a][p]) for p in CLASSES) + f" | {sum(matrix[a].values())} |")
    lines += ["", "## Per-class metrics", "", "| Class | Precision | Recall | F1 | Support |", "|---|---|---|---|---|"]
    stats = {}
    for c in CLASSES:
        tp = matrix[c][c]
        fp = sum(matrix[a][c] for a in CLASSES if a != c)
        fn = sum(matrix[c][p] for p in CLASSES if p != c)
        stats[c] = (*prf(tp, fp, fn), sum(matrix[c].values()))
        lines.append(f"| {c} | {stats[c][0]:.4f} | {stats[c][1]:.4f} | {stats[c][2]:.4f} | {stats[c][3]} |")
    macro = [statistics.mean(stats[c][i] for c in CLASSES) for i in range(3)]
    weighted = [sum(stats[c][i] * stats[c][3] for c in CLASSES) / n for i in range(3)]
    lines.append(f"| Macro average | {macro[0]:.4f} | {macro[1]:.4f} | {macro[2]:.4f} | {n} |")
    lines.append(f"| Weighted average | {weighted[0]:.4f} | {weighted[1]:.4f} | {weighted[2]:.4f} | {n} |")
    pe = sum((sum(matrix[c].values()) / n) * (sum(matrix[a][c] for a in CLASSES) / n) for c in CLASSES)
    kappa = (correct / n - pe) / (1 - pe) if pe != 1 else 0.0
    mal_issued = sum(matrix[a]["malicious"] for a in CLASSES)
    lines += ["", f"Cohen's kappa: **{kappa:.4f}**", "",
              f"Malicious verdicts issued: **{mal_issued}**, of which correct: **{matrix['malicious']['malicious']}** "
              f"(precision {matrix['malicious']['malicious'] / mal_issued:.4f})" if mal_issued else "No Malicious verdicts issued.", ""]
    flags = Counter()
    for r in ok:
        flags["downgraded"] += r["downgraded"] == "True"
        flags["lowConfidence"] += r["lowConfidence"] == "True"
        flags["regional dialect"] += r["isRegionalDialect"] == "True"
    lines += ["## Notices and models", "",
              f"- Results downgraded from Malicious under PR-03: {flags['downgraded']}",
              f"- Results below 0.75 confidence (notice shown): {flags['lowConfidence']}",
              f"- Regional-dialect flags (PR-02): {flags['regional dialect']}", "",
              "| Model | Requests served | Share |", "|---|---|---|"]
    for m, c in Counter(r["modelUsed"] for r in ok).most_common():
        lines.append(f"| {m} | {c} | {100 * c / n:.1f}% |")
    lat = sorted(int(r["latencyMs"]) for r in ok)
    lines += ["", f"Latency (ms): mean {statistics.mean(lat):.0f}, median {statistics.median(lat):.0f}, "
              f"p95 {lat[int(0.95 * (len(lat) - 1))]}, max {lat[-1]}", "",
              "## Accuracy by detected language", "", "| Detected language | Messages | Accuracy |", "|---|---|---|"]
    by_lang = defaultdict(lambda: [0, 0])
    for r in ok:
        by_lang[r["detectedLanguage"]][0] += 1
        by_lang[r["detectedLanguage"]][1] += r["label"] == r["pred"]
    for lang, (total, right) in sorted(by_lang.items()):
        lines.append(f"| {lang} | {total} | {right / total:.4f} |")
    if bad:
        lines += ["", f"## Failed requests ({len(bad)})", ""] + [f"- id {r['id']}: {r['error'][:100]}" for r in bad[:15]]
    out_md = Path(args.out).with_suffix(".md")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWritten to {out_md}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="https://bantay-bait.onrender.com")
    ap.add_argument("--out", default="evaluation_results.csv")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--retries", type=int, default=4)
    ap.add_argument("--report-only", action="store_true")
    a = ap.parse_args()
    if not a.report_only:
        run(a)
    report(a)
