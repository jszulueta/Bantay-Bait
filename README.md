# Bantay-Bait

A web-based smishing (SMS phishing) checker for Filipino mobile users. Paste a
suspicious SMS and get one of three verdicts, **Safe**, **Spam** (promotional
but non-malicious) or **Malicious** (smishing), with a confidence score and a
short explanation of what in the message led to that verdict.

Bantay-Bait is an IT thesis project. The language analysis is consumed as an
external, pre-trained inference service (the Groq API). **No model is trained
or fine-tuned by this project, and no message text is stored or logged.**

| Layer | Technology | Hosting |
|---|---|---|
| Frontend | React, Vite, Tailwind CSS | Vercel |
| Backend | FastAPI (Python 3.11) | Render |
| Classification | Groq API, pre-trained LLM, driven by a system prompt | external |

```
.
├── backend/
│   ├── app/
│   │   ├── main.py                        FastAPI app: /api/v1/detect, /api/v1/samples, /health
│   │   └── data/
│   │       ├── stopwords_tl.txt           Filipino stopwords (stopwords-iso)
│   │       ├── bantay_bait_corpus.csv     consolidated corpus (14,023 rows)
│   │       ├── bantay_bait_test_set.csv   held-out test set (2,805 rows)
│   │       └── bantay_bait_reference_pool.csv   remaining rows (11,218)
│   ├── scripts/
│   │   ├── build_dataset.py               rebuilds the corpus and the split
│   │   └── check_prompt_cases.py          live check of the classifier on hand-written messages
│   ├── tests/                             pytest suite (Process Rules, response shaping)
│   ├── locustfile.py                      Locust load-test script
│   ├── requirements.txt, runtime.txt, .python-version
│   └── .env.example                       environment variable reference
└── frontend/                              Vite + React app (src/App.jsx), vercel.json
```

## How it works

1. The frontend sends the pasted text to `POST /api/v1/detect`.
2. The backend validates the length (PR-01), normalizes the text, and detects
   the language and regional-dialect markers (PR-02).
3. It asks the Groq model to classify the message. The rules live in
   `CLASSIFIER_SYSTEM_PROMPT` in `backend/app/main.py`: the model judges what the
   message *asks the reader to do* (open a link, send an OTP, pay a fee) rather
   than which words it contains, and lists the evidence it sees before giving a
   verdict. Links in the text are found by the backend with a plain pattern match
   and handed to the model as a fact; no URL is ever visited or looked up.
4. Models are tried in order (`GROQ_MODELS`); if one is rate-limited or fails, the
   next is used.
5. A Malicious verdict below 0.75 confidence is reported as Spam/Suspicious (PR-03).
6. The frontend shows the color-coded verdict, the confidence, the explanation
   and recommended actions.

### Response

```json
{
  "verdict": "safe",
  "confidence": 0.93,
  "detectedLanguage": "english",
  "isRegionalDialect": false,
  "reducedConfidence": false,
  "reasons": ["Informational device notice that asks for nothing."],
  "modelLatencyMs": 812,
  "modelUsed": "openai/gpt-oss-20b",
  "explanation": "Informational device notice that asks for nothing.",
  "redFlags": [],
  "safeSignals": ["Reports a trusted device", "Warns never to share the OTP", "No link"]
}
```

`verdict` is always one of `safe`, `spam`, `malicious`. `explanation`, `redFlags`
and `safeSignals` describe the specific message and are written in the UI language
(English or Tagalog).

## Process Rules

| ID | Rule | Where |
|---|---|---|
| PR-01 | Accept 5 to 1,600 characters only | backend, mirrored in the frontend |
| PR-02 | Filipino, English and Taglish; messages with regional-dialect markers (Cebuano, Ilocano, Hiligaynon) get a reduced-confidence disclaimer | backend (language and dialect detection) |
| PR-03 | A Malicious verdict needs at least 0.75 confidence, otherwise it is reported as Spam/Suspicious | backend |
| PR-04 | No retention: no database, and message text is never written to storage or logs | backend (`RedactTextFilter`) |
| PR-05 | Verdict display on screens 360 px and wider, meeting WCAG 2.1 AA contrast | frontend |

## Scope and limits

Not covered: email phishing, voice phishing (vishing), image-based or QR-code
fraud, regional dialects (Visayan, Cebuano, Hiligaynon, Ilocano), automatic
interception of incoming SMS, sender-level network verification or SIM-swap
detection, and legal recourse for victims. The tool judges only the text a user
pastes. A model verdict is guidance, not proof: always verify sensitive banking
matters through the official app or website.

## Dataset

`backend/scripts/build_dataset.py` merges six public sources into one
deduplicated corpus of 14,023 messages (safe 10,043, spam 3,807, malicious 173):

| Source | Rows |
|---|---|
| Kaggle SMS Spam Dataset (`combined_dataset.csv`) | 9,338 |
| Tagalog SMS (Kaggle) | 2,656 |
| bwandowando, Philippine Spam SMS (Kaggle) | 945 |
| Yissuh/Filipino-Spam-SMS-Detection-Model (GitHub) | 574 |
| mematello/taglish-spam-detection (GitHub) | 438 |
| AGR-Yes/ScamMessagesPhilippines (GitHub) | 72 |

A stratified 80/20 split (`random_state=42`) produces the **test set** (20%, used
only to measure the accuracy of the deployed system) and the **reference pool**
(the remaining 80%). Nothing is trained on either file.

The sources use their own labels (mostly ham/spam) or are unlabeled scam dumps, so
the three-class labels are approximate: each source's label is mapped to safe or spam, and spam messages are
promoted to malicious when they match the keyword and URL patterns in
`MALICIOUS_KEYWORDS` and `URL_RE`. Because of this, some corpus labels differ from
the classifier's definitions (for example, online-gambling promotions are labeled
malicious in the corpus). Keep the test set for evaluation only and do not tune the
prompt against it.

Re-running the build script needs `pandas`, `openpyxl` and `scikit-learn` plus the
raw source files listed in the script header, and it regenerates the split. The
thesis results were computed on the committed test set, so do not overwrite it
casually.

## Run locally

Backend (the app reads environment variables directly and does not load a `.env`
file, so set them in your shell; `backend/.env.example` lists the names):

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

# PowerShell: $env:GROQ_API_KEY="gsk_..."   bash: export GROQ_API_KEY=gsk_...
# Vite serves on 5173, so allow that origin for CORS:
# PowerShell: $env:ALLOWED_ORIGINS="http://localhost:5173"
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
# point the app at your local backend (otherwise it uses its built-in default URL)
# PowerShell: $env:VITE_API_BASE_URL="http://localhost:8000"
npm run dev
```

### Tests

```bash
cd backend
pip install pytest pytest-asyncio
python -m pytest                                   # no network or API key needed
python scripts/check_prompt_cases.py --url http://localhost:8000   # real model; needs GROQ_API_KEY
```

The pytest suite replaces the Groq call with test doubles, so it verifies the
backend's own rules. `check_prompt_cases.py` sends a small set of synthetic
messages to a running API to see how the real model behaves.

### Load testing

```bash
cd backend
pip install locust
# Start the API with MOCK_MODE=true (PowerShell: $env:MOCK_MODE="true") so the
# Groq call is skipped and only the backend itself is measured.
# Use it only for load tests; never enable it in production.
locust -f locustfile.py --host http://localhost:8000
```

Avoid load-testing with real inference: the Groq free tier has per-minute and
daily limits that a sustained test will exhaust.

## Deployment (free tiers)

### Backend on Render

1. Create a **Web Service** from this GitHub repo.
2. Settings: **Root Directory** `backend`, **Build Command** `pip install -r requirements.txt`,
   **Start Command** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`, **Instance Type** Free.
3. Environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `GROQ_API_KEY` | yes | Key from console.groq.com |
| `ALLOWED_ORIGINS` | yes | Frontend origin(s), comma-separated, e.g. `https://bantay-bait.vercel.app` |
| `GROQ_MODELS` | no | Comma-separated fallback chain; the default is set in `main.py` |
| `MOCK_MODE` | no | `true` skips the Groq call (load testing only) |

Render's free tier sleeps after about 15 minutes idle, so the first request after
a pause can take 30 to 50 seconds. Check the service with `GET /health`.

### Frontend on Vercel

1. Import the repo with **Root Directory** `frontend`.
2. Set `VITE_API_BASE_URL` to the backend URL.
3. `frontend/vercel.json` sets the security headers. Its Content-Security-Policy
   `connect-src` must list the exact backend origin, so update it if the backend URL changes.

## Limitations of the free tiers

Cold starts on Render, and Groq's rate and daily token limits, which can slow
or block requests under sustained traffic. Both are fine for a thesis demo and
worth stating if usage grows.
