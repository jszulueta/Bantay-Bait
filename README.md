# Bantay-Bait — Free-Tier Deployment Package

A $0-to-run smishing detection system: React frontend + FastAPI backend +
Hugging Face Inference API, evaluated against a consolidated Philippine
SMS corpus built from 6 public datasets.

```
bantay-bait/
├── backend/
│   ├── app/
│   │   ├── main.py                 <- FastAPI app (/api/v1/detect, /api/v1/samples)
│   │   └── data/
│   │       ├── stopwords_tl.txt
│   │       ├── bantay_bait_corpus.csv        (14,023 labeled rows)
│   │       ├── bantay_bait_test_set.csv      (20% stratified holdout)
│   │       └── bantay_bait_train_reference.csv
│   ├── scripts/
│   │   └── build_dataset.py        <- re-run this to rebuild the corpus
│   ├── requirements.txt
│   └── .env.example
└── frontend/
    └── src/App.jsx                 <- your UI, handleAnalyze() now calls the API
```

---

## 1. What changed vs. the thesis draft

The thesis assumes a Hugging Face model that ships an out-of-the-box 3-class
(Safe/Spam/Malicious) classification head. No such Tagalog-specific model is
publicly available for free, and the thesis explicitly rules out training one.
So the backend instead calls a **zero-shot classification** model
(`joeddav/xlm-roberta-large-xnli`) — still "an existing pre-trained model
consumed strictly as an external inference service," zero training required,
and it understands Tagalog/English/Taglish code-switching reasonably well.
Swap `HF_MODEL` in the environment variables any time a better free option
shows up — no code changes needed.

## 2. Dataset consolidation (Chapter 3 — Treatment of Data)

`backend/scripts/build_dataset.py` merges these 6 sources into one
deduplicated, 3-class corpus:

| Source | Rows (post-filter) | Native labels |
|---|---|---|
| bwandowando — Philippine Spam SMS (Kaggle) | 945 | unlabeled scam dump |
| Kaggle SMS Spam Dataset (combined_dataset.csv) | 9,338 | ham/spam |
| Tagalog SMS (Kaggle, tagalog-sms.xlsx) | 2,656 | notifs/otp/gov/ads/spam |
| mematello/taglish-spam-detection (GitHub) | 438 | ham/spam |
| Yissuh/Filipino-Spam-SMS-Detection-Model (GitHub) | 574 | ham/spam |
| AGR-Yes/ScamMessagesPhilippines (GitHub) | 72 | unlabeled scam dump |
| **Total after dedup + PR-01 length filter** | **14,023** | — |

Class balance after the malicious-pattern heuristic promotion:
`safe: 10,043 · spam: 3,807 · malicious: 173`.

**Labeling method:** each source's native ham/spam label is mapped to a base
class, then rows are promoted from `spam` → `malicious` when they match both
a credential-harvesting/brand-impersonation keyword pattern (OTP, "verify
your account", GCash/BDO/BPI/Shopee names, etc.) **and** contain a URL — see
`MALICIOUS_KEYWORDS` / `URL_RE` in `build_dataset.py` for the exact patterns.
This is a documented heuristic standing in for the thesis's planned
cybersecurity-SME manual review (Phase 5); treat `bantay_bait_test_set.csv`
as a *draft* validated test set to be spot-checked, not a final ground truth.

To rebuild after adding new source files:
```bash
cd backend
pip install pandas openpyxl scikit-learn
python scripts/build_dataset.py
```

## 3. Backend — `POST /api/v1/detect`

Request:
```json
{ "text": "GCash: Your account has been accessed... Verify: http://gcash-verify.com", "lang": "taglish" }
```

Response:
```json
{
  "verdict": "malicious",
  "confidence": 0.91,
  "detectedLanguage": "taglish",
  "isRegionalDialect": false,
  "reducedConfidence": false,
  "reasons": ["Detected credential-harvesting or brand-impersonation language..."],
  "modelLatencyMs": 812
}
```

Process rules enforced server-side: PR-01 (5–1600 chars), PR-02 (regional
dialect flag), PR-03 (0.75 confidence floor for a Malicious verdict), PR-04
(4.5s internal timeout, leaving headroom under the 5s target), PR-05 (no
database, no logging of message text — see `RedactTextFilter` in `main.py`).

## 4. Free deployment — $0 total

### a) Hugging Face token (free)
1. Create an account at https://huggingface.co
2. Go to **Settings → Access Tokens → New token** (Read role is enough)
3. Copy the token (starts with `hf_...`)

### b) Backend on Render.com (free Web Service)
1. Push the `backend/` folder to a GitHub repo.
2. On https://render.com → **New → Web Service** → connect the repo.
3. Settings:
   - **Root Directory:** `backend`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type:** Free
4. Under **Environment**, add:
   - `HUGGINGFACE_TOKEN` = your token from step (a)
   - `HF_MODEL` = `joeddav/xlm-roberta-large-xnli`
   - `ZERO_SHOT` = `true`
   - `ALLOWED_ORIGINS` = your frontend URL(s), comma-separated (add these
     after step (c) once you know the Vercel/Netlify domain)
5. Deploy. Render gives you a URL like `https://bantay-bait-api.onrender.com`.
   Test it: `curl https://bantay-bait-api.onrender.com/health`

   Note: Render's free tier spins down after ~15 minutes of inactivity — the
   first request after idle can take 30–50 seconds to wake up. This is
   normal and does not cost anything.

### c) Frontend on Vercel (free)
1. Push `frontend/` to a GitHub repo (or the same repo, different folder).
2. On https://vercel.com → **Add New → Project** → import the repo.
3. Add an environment variable:
   - `VITE_API_BASE_URL` = `https://bantay-bait-api.onrender.com`
     (use `NEXT_PUBLIC_API_BASE_URL` instead if this is a Next.js app)
4. Deploy. Vercel gives you a URL like `https://bantay-bait.vercel.app`.
5. Go back to Render → Environment → update `ALLOWED_ORIGINS` to include
   this exact Vercel URL, then redeploy the backend.

(Netlify works the same way: **Add new site → Import from Git**, same env
var, Build command `npm run build`, Publish directory `dist`.)

### d) Smoke test
```bash
curl -X POST https://bantay-bait-api.onrender.com/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"text":"GCash: Your account has been locked. Verify now: http://gcash-verify.com OTP 12345"}'
```
Then open the Vercel URL, paste a sample SMS, and confirm the verdict panel
renders with a live (non-mocked) result.

## 5. Cost summary
| Service | Tier | Cost |
|---|---|---|
| Render Web Service | Free | $0 |
| Vercel / Netlify hosting | Free (Hobby) | $0 |
| Hugging Face Inference API | Free (rate-limited, fine for thesis testing/demo traffic) | $0 |
| GitHub (source + raw dataset hosting) | Free | $0 |

**Total: $0/month.** The only real constraints are the Render free-tier
cold-start delay and Hugging Face's free-tier rate limits — both fine for a
thesis demo/defense but worth mentioning as a limitation if you scale to
real public traffic.
