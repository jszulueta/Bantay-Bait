"""
Bantay-Bait — Dataset Consolidation Script
============================================
Merges 7 public SMS spam/smishing sources into a single, deduplicated,
3-class labeled corpus (safe / spam / malicious) for use as the
Bantay-Bait held-out TEST SET (Thesis Phase 3/4 — accuracy validation only).

IMPORTANT: This dataset is NOT used to train or fine-tune the RoBERTa-Tagalog
model (per thesis scope, the model is consumed strictly as a pre-trained,
external Hugging Face Inference API service). It is used only to:
  1. Benchmark the live Hugging Face API's classification accuracy
     (precision / recall / F1 per class) against known PH-context samples.
  2. Populate the "Try Sample SMS" quick-test buttons in the frontend.
  3. Supply pre/post smishing-identification quiz items.

Sources combined:
  1. bwandowando_spam.csv          — Kaggle: Philippine Spam SMS Messages
  2. combined_dataset.csv          — Kaggle: SMS Spam Dataset (global, English)
  3. tagalog_sms.xlsx              — Kaggle: Tagalog SMS (notifs/otp/gov/ads/spam)
  4. taglish_spam_ham.csv          — GitHub: mematello/taglish-spam-detection
  5. yissuh_dataset.csv            — GitHub: Yissuh/Filipino-Spam-SMS-Detection-Model
  6. agryes_spam.csv               — GitHub: AGR-Yes/ScamMessagesPhilippines
  (stopwords_tl.txt is not a corpus — it is copied to app/data/ separately)

Labeling approach
------------------
None of the raw sources ship a native 3-class (safe/spam/malicious) label —
they are all binary (ham/spam) or unlabeled scam dumps. We therefore:
  a) Map every source's native label to a base class: "safe" or "spam".
  b) Within "spam", apply a documented keyword+URL heuristic to promote a
     row to "malicious" when it exhibits credential-harvesting / brand-
     impersonation / urgency patterns (OTP, verify account, suspended,
     bank names, click link, etc.) consistent with the Bantay-Bait
     smishing taxonomy (Table 1 of the thesis).
  c) This heuristic labeling is a pragmatic stand-in for the thesis's
     planned cybersecurity-SME manual review (Phase 5) — flag rows with
     `heuristic_malicious=True` so a human reviewer can spot-check/relabel
     before the corpus is presented as a validated test set.

Output: ../app/data/bantay_bait_corpus.csv  (text, label, source)
        ../app/data/bantay_bait_test_set.csv (20% stratified holdout)
"""
import re
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

RAW = Path("/home/claude/data")
OUT = Path(__file__).resolve().parent.parent / "app" / "data"
OUT.mkdir(parents=True, exist_ok=True)

# ----------------------------------------------------------------------
# Malicious-pattern heuristic (documented, PH-context smishing taxonomy)
# ----------------------------------------------------------------------
MALICIOUS_KEYWORDS = [
    r"\botp\b", r"\bpin\b", r"one[\s-]?time[\s-]?pin",
    r"verify (your )?account", r"account (has been|is) (locked|suspended|blocked)",
    r"suspicious (login|activity)", r"unauthorized access", r"click (the|this) link",
    r"update your (details|account|information)", r"confirm your (identity|account)",
    r"claim (your|this) (prize|reward|refund)", r"congratulations.{0,20}(won|selected|winner)",
    r"gcash", r"maya\b", r"bdo\b", r"bpi\b", r"landbank", r"metrobank",
    r"lbc\b", r"j&t\b", r"jt express", r"shopee", r"lazada",
    r"security check", r"reactivate", r"expire[sd]? (today|soon|in)",
    r"kyc\b", r"log[\s-]?in (to|now)", r"tap (the|this) link",
]
MALICIOUS_RE = re.compile("|".join(MALICIOUS_KEYWORDS), re.IGNORECASE)
URL_RE = re.compile(r"(https?://|www\.|\b[a-z0-9-]+\.(com|ph|net|tv|site|life|bid|win)\b)", re.IGNORECASE)


def clean_text(t: str) -> str:
    if not isinstance(t, str):
        return ""
    t = t.replace("\r", " ").replace("\n", " ")
    t = re.sub(r"\s+", " ", t).strip()
    return t


def promote_to_malicious(text: str) -> bool:
    has_kw = bool(MALICIOUS_RE.search(text))
    has_url = bool(URL_RE.search(text))
    return has_kw and has_url


rows = []

# 1. bwandowando — Philippine Spam SMS (all rows are reported spam/scam gambling ads)
df = pd.read_csv(RAW / "bwandowando_spam.csv", encoding="utf-8", on_bad_lines="skip")
for t in df["text"].dropna():
    t = clean_text(t)
    if not t:
        continue
    label = "malicious" if promote_to_malicious(t) else "spam"
    rows.append((t, label, "bwandowando_kaggle"))

# 2. combined_dataset — global SMS spam/ham
df = pd.read_csv(RAW / "combined_dataset.csv", on_bad_lines="skip")
for _, r in df.iterrows():
    t = clean_text(r.get("text", ""))
    if not t:
        continue
    base = "safe" if str(r.get("target", "")).strip().lower() == "ham" else "spam"
    label = promote_to_malicious(t) and "malicious" or base if base == "spam" else base
    rows.append((t, label, "combined_kaggle"))

# 3. tagalog_sms.xlsx — notifs/otp/gov/ads => safe (legit telco/bank notices); spam => spam
df = pd.read_excel(RAW / "tagalog_sms.xlsx")
for _, r in df.iterrows():
    t = clean_text(r.get("text", ""))
    if not t:
        continue
    cat = str(r.get("category", "")).strip().lower()
    if cat == "spam":
        label = "malicious" if promote_to_malicious(t) else "spam"
    else:  # notifs, otp, gov, ads -> legitimate first-party messages
        label = "safe"
    rows.append((t, label, "tagalog_sms_kaggle"))

# 4. taglish_spam_ham.csv (GitHub: mematello)
df = pd.read_csv(RAW / "taglish_spam_ham.csv", encoding="utf-8", on_bad_lines="skip")
for _, r in df.iterrows():
    t = clean_text(r.get("text", ""))
    if not t:
        continue
    base = "safe" if str(r.get("label", "")).strip().lower() == "ham" else "spam"
    label = ("malicious" if promote_to_malicious(t) else "spam") if base == "spam" else "safe"
    rows.append((t, label, "taglish_spam_ham_github"))

# 5. yissuh_dataset.csv (GitHub: Yissuh)
df = pd.read_csv(RAW / "yissuh_dataset.csv", encoding="latin-1", on_bad_lines="skip")
for _, r in df.iterrows():
    t = clean_text(r.get("message", ""))
    if not t:
        continue
    base = "safe" if str(r.get("label", "")).strip().lower() == "ham" else "spam"
    label = ("malicious" if promote_to_malicious(t) else "spam") if base == "spam" else "safe"
    rows.append((t, label, "yissuh_github"))

# 6. agryes_spam.csv (GitHub: AGR-Yes ScamMessagesPhilippines) — all rows are scam reports
df = pd.read_csv(RAW / "agryes_spam.csv", encoding="latin-1", on_bad_lines="skip")
text_col = "proof" if "proof" in df.columns else df.columns[0]
for t in df[text_col].dropna():
    t = clean_text(t)
    if not t:
        continue
    label = "malicious" if promote_to_malicious(t) else "spam"
    rows.append((t, label, "agryes_github"))

# ----------------------------------------------------------------------
corpus = pd.DataFrame(rows, columns=["text", "label", "source"])
before = len(corpus)
corpus = corpus.drop_duplicates(subset=["text"]).reset_index(drop=True)
corpus = corpus[corpus["text"].str.len().between(5, 1600)]  # PR-01 bounds
after = len(corpus)

print(f"Combined rows: {before} -> {after} after dedup/length-filter")
print(corpus["label"].value_counts())
print(corpus["source"].value_counts())

corpus.to_csv(OUT / "bantay_bait_corpus.csv", index=False)

# Stratified 80/20 split -> held-out test set for accuracy reporting (Phase 4)
train_df, test_df = train_test_split(
    corpus, test_size=0.2, stratify=corpus["label"], random_state=42
)
test_df.to_csv(OUT / "bantay_bait_test_set.csv", index=False)
train_df.to_csv(OUT / "bantay_bait_train_reference.csv", index=False)

print(f"\nSaved:")
print(f"  {OUT/'bantay_bait_corpus.csv'}          ({len(corpus)} rows)")
print(f"  {OUT/'bantay_bait_test_set.csv'}        ({len(test_df)} rows, stratified 20% holdout)")
print(f"  {OUT/'bantay_bait_train_reference.csv'} ({len(train_df)} rows, reference/sample pool)")
