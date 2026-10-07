<div align="center">

<img src="https://img.shields.io/badge/PhishShield%20X-v2.1-6366f1?style=for-the-badge&logo=shield&logoColor=white"/>
<img src="https://img.shields.io/badge/Python-3.10%2B-3b82f6?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Flask-3.x-22c55e?style=for-the-badge&logo=flask&logoColor=white"/>
<img src="https://img.shields.io/badge/scikit--learn-explainable-f59e0b?style=for-the-badge"/>
<img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge"/>

# PhishShield X

**Explainable Phishing Detection and Risk Scoring — URLs and multilingual messages**

</div>

PhishShield X analyses **URLs** and **suspicious messages** (SMS, email, chat). It gives each one a
0–100 risk score and explains it, keeping **machine-learning evidence** separate from **rule-based
(heuristic) evidence** and **threat-intelligence evidence**. The model and rules run locally. Live threat
intelligence comes from a separate service, the *Real-Time Phishing URL Collection & Threat Intelligence
API*, over REST ([integration](#threat-intelligence-integration)). Without that service, everything still works offline.

| | URL analysis | Message analysis |
|:--|:--|:--|
| Model | Logistic regression on 22 lexical URL features, trained on a public phishing-URL dataset | TF-IDF + Naive Bayes SMS spam classifier; optional zero-shot NLI model |
| Rules | 16 URL indicators with fixed, documented points | Keyword / regex rules for urgency, threats, credential requests, legit notifications, … |
| Explanation | Exact per-feature model contributions + fired rules + score breakdown | Highlighted words, attack flow, evidence tagged *model* / *rules* / *url analysis* |
| Multilingual | n/a | Language detection (`langdetect`); optional translation (Google Translate, network) |

---

## Contents

1. [What changed in 2.1](#what-changed-in-21)
2. [Architecture](#architecture)
3. [URL analysis](#url-analysis)
4. [Risk scoring](#risk-scoring)
5. [Explanations](#explanations)
6. [Model performance (measured)](#model-performance-measured)
7. [Message analysis](#message-analysis)
8. [Setup](#setup)
9. [Configuration](#configuration)
10. [HTTP API](#http-api)
11. [Tests](#tests)
12. [Threat-intelligence integration](#threat-intelligence-integration)
13. [Limitations](#limitations)
14. [Data sources and licences](#data-sources-and-licences)

---

## What changed in 2.1

**New**
- A dedicated **URL phishing detector** (`phishshield/` package) with a URL-specific model, rule-based
  indicators, a transparent risk engine and structured explanations.
- A **URL tab** in the UI, plus `POST /api/analyze-url`, `POST /api/analyze-message` and `GET /api/health`.
- Links inside messages are now scored by the URL engine. A message is at least as risky as a
  High Risk link it contains.
- Evidence in the message view is tagged by source: `model`, `rules` or `url analysis`.
- Configuration through environment variables, input validation, error handlers and a 122-test pytest suite.

**Fixed**
- **The SMS spam model was used where it gives no information.** It returns its class prior (≈0.50
  "spam") for any text with no known words, which covers every URL and most untranslated non-English
  text. That case is now reported as *no signal*. The spam model is not used for URL detection.
- **Lookalike domains were trusted.** The old check `"google.com" in url` treated
  `http://google.com.evil.xyz/login` as a *known legitimate domain* with risk 0. Domains are now
  compared by their registered domain (Public Suffix List).
- **URLs were analysed after leet-speak decoding**, which turned `amaz0n.com` into `amazon.com`
  (an official domain). URLs are now taken from the original text.
- **Inflated spam-model accuracy.** `train_model.py` upsampled spam *before* the train/test split,
  copying test messages into training. It now removes duplicates, splits first and reports precision,
  recall and F1. It also drops a corrupt last row of `emails.csv`.
- **A "99.2% Detection Rate" was shown in the UI** without being measured anywhere. The stats band
  now shows the URL model's held-out ROC-AUC (from its metrics file) and the user-feedback agreement rate.
- Missing optional packages (`deep-translator`, `langdetect`, `urlextract`, `transformers`) no
  longer crash the app; each feature degrades on its own. Flask debug mode is now off by default.

The message-analysis modules, UI design, adversarial normalisation, highlighting, attack flow,
robustness test and feedback loop are kept.

---

## Architecture

```
                         ┌─────────────────────────── app.py (Flask) ───────────────────────────┐
  Message ──────────────►│ normalise → language → legit rules → SMS spam model → SE / intent →  │
                         │ highlights → risk fusion → evidence (tagged model / rules / url)     │
                         │        │ every link in the message                                    │
                         └────────┼──────────────────────────────────────────────────────────────┘
                                  ▼
  URL ──────► phishshield.service.URLAnalysisService
                 │
                 ├─ url_analysis/parser.py      parse + normalise (offline PSL, IDN, defanged URLs)
                 ├─ url_analysis/features.py    22 lexical features  ── shared with training script
                 ├─ detection/url_model.py      logistic regression → P(phishing) + exact contributions
                 ├─ url_analysis/heuristics.py  16 rule indicators with fixed points
                 ├─ threat_intel/               REST client for the threat-intel API + evidence policy
                 │                              (NullThreatIntelProvider when not configured)
                 ├─ scoring/risk_engine.py      weighted combination + documented adjustments
                 └─ explain/url_explainer.py    summary, model / rule / external evidence, limits
```

Each part can be changed on its own. To swap the model, retrain it or replace `detection/`. To tune
the rules, edit `heuristics.py` and `reference_data.py`. To change the weighting, set environment
variables or edit `scoring/`. To add a threat-intel source, implement one class (see below).

```
phishshield/
├── config.py                  Settings from environment variables (validated)
├── service.py                 Orchestrates one URL analysis; isolates component failures
├── url_analysis/
│   ├── parser.py              ParsedURL, InvalidURLError
│   ├── features.py            FEATURE_SPECS, extract_features()  (single source of truth)
│   ├── heuristics.py          run_heuristics() → HeuristicResult
│   └── reference_data.py      Official brand domains, shorteners, TLD list, keywords
├── detection/url_model.py     load_url_model(), URLPhishingModel.predict()
├── scoring/risk_engine.py     score_url(), risk_band()
├── explain/url_explainer.py   explain_url()
└── threat_intel/
    ├── base.py                ThreatIndicator, ThreatIntelProvider, NullThreatIntelProvider
    ├── threat_intel_client.py REST client for the threat-intel API (HTTP, validation, normalisation)
    └── api_provider.py        API records → ThreatIndicator (evidence policy)
app.py                         Flask app + message-analysis modules
train_url_model.py             Trains/evaluates the URL model → models/url_model.joblib + metrics JSON
train_model.py                 Trains/evaluates the SMS spam model → spam_pipeline.joblib + metrics JSON
scripts/download_url_dataset.py  Downloads + checksum-verifies the public URL dataset
models/                        Trained URL model and its metrics (small, committed)
templates/index.html           UI
tests/                         pytest suite
```

---

## URL analysis

### Why a separate model

The original classifier is TF-IDF + Naive Bayes trained on the **SMS Spam Collection** (`emails.csv`,
English SMS texts). The app strips non-letters before calling it, so a URL becomes one unknown
token. Tested on `https://www.google.com`, `http://192.168.4.2/bank/login.php` and
`http://paypal-secure-login.verify-account.xyz/signin`, it returned **exactly 0.5026 for all
three**, which is its class prior. It cannot detect phishing URLs, so URL detection uses its own model.

### Features (`phishshield/url_analysis/features.py`)

22 features computed from the URL string only: host / query length, subdomain depth, hyphens, digit
ratios, special characters, path depth, query parameters, host entropy, longest host token,
credential-related words, brand name outside the registered domain, HTTPS, IP host, `@`,
non-standard port, punycode, shortener, embedded URL, executable extension and TLD length.
Lengths and counts are log-transformed.

Design choices made to avoid misleading explanations:
- **Leading `www.` is ignored.** In the training data `www.` is far more common on legitimate URLs (67% vs 21%).
  That mostly reflects how the data was collected, and learning it would penalise hosts like `github.com`.
- **Near-duplicate features were removed** (total URL length, path length, host dot count). With them
  in, the linear model gave collinear copies opposite signs, and explanations contradicted themselves.

### Model (`train_url_model.py`)

`StandardScaler → LogisticRegression(class_weight="balanced")`. Regularisation `C` is chosen by
5-fold cross-validation **grouped by registered domain**. A linear model was chosen so explanations
are *exact*, not approximated (see [Explanations](#explanations)).

### Rule-based indicators (`phishshield/url_analysis/heuristics.py`)

Points are **expert-assigned, not learned or calibrated**. Heuristic score = sum of points, capped at 100.

| Indicator | Severity | Points |
|:--|:--:|:--:|
| Mixed-alphabet (homoglyph) domain, e.g. Cyrillic `а` in `pаypal` | high | 30 |
| Brand name outside its official registered domain | high | 30 |
| Typosquat of a brand domain (`paypa1`, `arnazon`, `mircosoft`) | high | 30 |
| IP address as host (incl. decimal/hex forms) | high | 25 |
| `@` in address (real host is after it) | high | 25 |
| Internationalised (punycode) domain | medium | 15 |
| Link shortener | medium | 15 |
| Direct link to executable (`.exe`, `.apk`, …) | medium | 15 |
| Another URL embedded in path/query (redirect) | medium | 12 |
| ≥2 credential words (`login`, `verify`, …) / 1 word | medium / low | 12 / 5 |
| Non-standard port | medium | 10 |
| ≥4 subdomain levels | low | 8 |
| TLD often abused (`.xyz`, `.top`, `.tk`, …; configurable) | low | 8 |
| ≥3 hyphens in domain name | low | 6 |
| Plain HTTP (only judged if the user typed the scheme) | low | 5 |
| URL longer than 100 characters | low | 5 |

Official brand domains (`reference_data.py`) are compared against the **registered domain**, so
`paypal.com.evil.xyz` is not trusted. This list is not threat intelligence: it says what legitimate
brands look like and contains no known-bad URLs. A brand whose real domain is missing from the list
will be flagged, so add domains before relying on a brand's check.

---

## Risk scoring

`phishshield/scoring/risk_engine.py`:

```
model      = 100 × P(phishing)                  (if the URL model is loaded)
heuristic  = Σ points of fired rules, max 100
external   = strongest threat-intel finding      (only if THREAT_INTEL_API_URL is set and it matched;
                                                 see Threat-intelligence integration for the policy)

weighted   = Σ weightᵢ × scoreᵢ / Σ weightᵢ      over available sources
             default weights: model 0.6, heuristic 0.4, external 0.5

adjustments (each shown in the UI/API when applied):
  • any high-severity rule fired            → score ≥ 50  (Suspicious)
  • external "malicious", confidence ≥ 0.8  → score ≥ 80
  • official brand domain and no medium/high rule fired → score ≤ 20

bands: 0–20 Safe · 21–40 Low Risk · 41–60 Suspicious · 61–80 High Risk · 81–100 Critical
```

If the model file is missing, the weights are renormalised and the score uses rules only. The UI
says so explicitly. The result also reports whether the model and the rules **agree**, or whether
only one of them flags the URL.

In the message analyser, each link's URL score feeds the existing fusion engine. A link scoring
above 60 sets a floor on the message score, and it overrides a "legitimate notification" match,
because a real-looking bank alert with a phishing link is a common attack.

---

## Explanations

Every URL result (UI and API) contains these sections:

| Section | Contents |
|:--|:--|
| `summary` | One paragraph: band, model probability, strongest rule, model/rule disagreement |
| `model_evidence` | Probability and the top features pushing **toward phishing** / **toward legitimate**, with their raw values and log-odds contributions |
| `heuristic_evidence` | Every fired rule (title, detail, severity, points), the checks that passed, official-domain status |
| `external_evidence` | Threat-intel findings and lookup status (`available`, `checked`, `match`, `records`, `message`, `error`) |
| `verdict` (top level) | `classification` (PHISHING / SUSPICIOUS / LOW_RISK), `risk_score`, `severity`, `ml_probability`, `threat_intelligence` summary, and `reasons` tagged `threat_intelligence` / `ml` / `heuristic` / `score_rule` |
| `score_breakdown` | Each component's score, weight and points, and every adjustment with its reason |
| `recommendations` | What the user should do |
| `limitations` | What this analysis could not check, and parser notes (e.g. "no scheme given, http assumed") |

For logistic regression, `logit = intercept + Σ coefᵢ · (xᵢ − meanᵢ)/scaleᵢ`, so each term is that
feature's **exact** contribution relative to the average training URL. A test checks that the terms
add back up to the model's logit.

---

## Model performance (measured)

All numbers below come from `models/url_model_metrics.json` and `spam_model_metrics.json` and were
produced by the training scripts in this repository. Re-running the scripts regenerates them.

### URL model

Dataset: *Web page phishing detection* (Hannousse & Yahiouche, 2021), 11,430 URLs, collected May 2020.
After cleaning there are 11,413 URLs (5,698 phishing / 5,715 legitimate) across 7,260 registered domains.
The test set is 20% of the **registered domains**, held out completely, so no domain appears in
both training and test.

| Metric (held-out test, n = 2,704, threshold 0.5) | Value |
|:--|:--:|
| Accuracy | 78.9% |
| Precision (phishing) | 88.1% |
| Recall (phishing) | 75.2% |
| F1 | 0.812 |
| ROC-AUC | 0.877 |
| False-positive rate | 15.6% |
| 5-fold grouped CV ROC-AUC (training set) | 0.842 ± 0.030 |

For comparison, a gradient-boosting model on the same features and split reaches ROC-AUC 0.892 and
accuracy 81.4%. It is not used, because its explanations would be approximations. These figures are
**modest by design**: the model only sees the URL text. Many published URL-detection results are
above 99%, but those often come from datasets where legitimate URLs are all bare homepages. In the
UCI PhiUSIIL dataset, for example, 100% of legitimate URLs are `https://www.<domain>` with no path,
so any path predicts "phishing". That dataset was checked and rejected for this reason.

### SMS spam model (messages)

SMS Spam Collection, 5,157 unique messages after cleaning, 80/20 stratified split made before
upsampling. Test (n = 1,032): **accuracy 96.9%, spam precision 87.5%, recall 87.5%, F1 0.875**.

The 96.94% previously in this README came from the leaky split. The corrected accuracy happens to be
similar, but F1 is the more informative number because only ~12% of messages are spam.

### Illustrative outputs (not an accuracy claim)

| URL | Score | Model P(phish) | Rules |
|:--|:--:|:--:|:--:|
| `https://www.google.com` | 5 Safe | 0.08 | 0 |
| `https://en.wikipedia.org/wiki/Phishing` | 14 Safe | 0.24 | 0 |
| `https://stackoverflow.com/questions/12345/how-to-parse-url` | 26 Low Risk | 0.43 | 0 |
| `https://www.amazon.in/gp/your-account/order-history?...` | 20 Safe (official-domain cap) | **0.81** | 5 |
| `http://google.com.evil.xyz/login` | 78 High Risk | 0.98 | 48 |
| `http://paypa1.com/signin/verify` | 77 High Risk | 0.98 | 47 |
| `https://xn--pypal-4ve.com/` | 58 Suspicious | 0.77 | 30 |

The Amazon row shows a real model weakness: legitimate account pages contain words like "account".
The official-domain rule corrects it, which is why the two evidence sources are combined.

---

## Message analysis

These modules are unchanged in behaviour except where noted under [What changed](#what-changed-in-21):

| Module | What it does | Evidence type |
|:--|:--|:--|
| 0 Adversarial normalisation | Removes zero-width characters, maps Cyrillic homoglyphs, collapses `V e r i f y`, decodes leet speak | rules |
| 1 Language | Detects the language with `langdetect`; translates to English via Google Translate when enabled and reachable | — |
| 2 Legitimate notification | Regex patterns for bank alerts, OTP delivery, delivery updates | rules |
| 3 Brand mentions | 25 brand keywords in the text | rules |
| 4 URL intelligence | **Now uses the URL engine above** | url analysis |
| 5 Social engineering | Urgency / fear / authority / reward / curiosity / trust scores | zero-shot model if cached, else rules |
| 6 Intent | 17 scam categories + 4 legitimate ones | zero-shot model if cached, else rules |
| 7 Highlighting | Colour-coded suspicious words | rules |
| 8 Attack flow | Stage sequence derived from 5–7 | rules |
| 9 Risk fusion | Weighted sum + floor rules (+ URL floor, new) | — |
| 10–11 Evidence, recommendations | Tagged evidence list, advice | — |
| 12 Robustness test | Re-scores leet / homoglyph / spacing variants | — |
| 13 Feedback | SQLite store of 👍/👎; shown as *user agreement*, not accuracy | — |

**What "multilingual" means here, precisely:**
- Language detection works for native scripts. For example, a Devanagari Hindi message is detected as `hi`.
- **Romanised code-mixed text** (e.g. Tamil written in Latin letters) is usually detected as English.
  The 2.0 README example claiming Tamil detection for such text does not reproduce.
- Translation uses an unofficial Google Translate endpoint through `deep-translator`. It needs
  internet access and can be rate-limited; during testing it returned "too many requests". When it
  fails, the original text is analysed and the UI shows a note. Set `PHISHSHIELD_ENABLE_TRANSLATION=false`
  to stay fully offline.
- Without translation, the English keyword rules and the SMS spam model see little in non-English
  text. In that case the URL engine is the most informative component.

---

## Setup

Requires Python 3.10+ (developed and tested with Python 3.14, scikit-learn 1.9).

```bash
git clone <your repo url>
cd PHISHSHIELD-X-Explainable-Multilingual-AI-for-Scam-and-Phishing-Detection-main

python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt           # add -r requirements-dev.txt for tests

python app.py                             # → http://127.0.0.1:5000
```

The trained URL model (`models/url_model.joblib`, 4 KB) is included, so the app works immediately.
If it fails to load (for example with a very different scikit-learn version), the app logs why and
runs with rule-based URL indicators only. Retrain to fix it:

```bash
python scripts/download_url_dataset.py    # downloads 3.6 MB from Mendeley Data, verifies SHA-256
python train_url_model.py                 # ~10 s; writes models/url_model.joblib + _metrics.json
python train_model.py                     # optional: retrain the SMS spam model
```

`train_url_model.py` accepts any CSV with a URL column and a binary label column:
`--data FILE --url-col URL --label-col label --positive-label 1 --dataset-name "..."`.

Optional zero-shot model (~1.6 GB download), used for social-engineering and intent scores:

```bash
pip install -r requirements-optional.txt
python -c "from transformers import pipeline; pipeline('zero-shot-classification', model='facebook/bart-large-mnli')"
```

Use `app.py` with Flask's development server for local use only. To serve it to others, use a WSGI
server, e.g. `waitress-serve --port=5000 app:app` (Windows) or `gunicorn app:app`.

---

## Configuration

All settings are optional environment variables. Invalid values stop startup with a clear message.

| Variable | Default | Purpose |
|:--|:--|:--|
| `PHISHSHIELD_URL_MODEL_PATH` | `models/url_model.joblib` | URL model artifact |
| `PHISHSHIELD_SPAM_MODEL_PATH` | `spam_pipeline.joblib` | SMS spam model |
| `PHISHSHIELD_FEEDBACK_DB` | `feedback.db` | SQLite feedback database |
| `PHISHSHIELD_ENABLE_TRANSLATION` | `true` | Google Translate for non-English messages (network) |
| `PHISHSHIELD_ENABLE_ZERO_SHOT` | `true` | Load the zero-shot model if it is cached locally |
| `PHISHSHIELD_ZERO_SHOT_TIMEOUT` | `30` | Seconds to wait for it at startup |
| `PHISHSHIELD_WEIGHT_MODEL` | `0.6` | URL score weight of the model |
| `PHISHSHIELD_WEIGHT_HEURISTIC` | `0.4` | URL score weight of the rules |
| `PHISHSHIELD_WEIGHT_EXTERNAL` | `0.5` | URL score weight of threat intel (when configured) |
| `PHISHSHIELD_MAX_MESSAGE_CHARS` | `10000` | Message length limit |
| `PHISHSHIELD_MAX_URL_LENGTH` | `2048` | URL length limit |
| `PHISHSHIELD_HOST` / `PHISHSHIELD_PORT` | `127.0.0.1` / `5000` | Bind address |
| `FLASK_DEBUG` | `false` | Flask debug mode. Never enable it on a reachable host |
| `THREAT_INTEL_API_URL` / `_API_KEY` / `_API_TIMEOUT` / `_CHECK_HOST` | empty / empty / `5` / `true` | Threat-intel service; see [integration](#threat-intelligence-integration) |

Settings can also go in a `.env` file in the project root (see `.env.example`). Real environment variables take precedence.

```powershell
# PowerShell
$env:PHISHSHIELD_ENABLE_TRANSLATION = "false"; python app.py
```
```bash
# bash
PHISHSHIELD_ENABLE_TRANSLATION=false python app.py
```

---

## HTTP API

```bash
curl -X POST http://127.0.0.1:5000/api/analyze-url \
     -H "Content-Type: application/json" -d '{"url": "http://paypa1.com/signin"}'
```
Returns `{status, url, parsed, score, risk, verdict, explanation}`, where `explanation` has the sections
described in [Explanations](#explanations). Invalid URLs return HTTP 400 with a message.

| Endpoint | Body | Returns |
|:--|:--|:--|
| `POST /api/analyze-url` (alias `POST /api/analyze`) | `{"url": "..."}` | URL risk assessment: `score`, `risk`, `verdict`, `explanation` |
| `GET /api/threat-intel/latest?limit=&page=&analyze=` | — | Newest URLs from the threat-intel service (fetched server-side); `analyze=true` scores each one |
| `POST /api/analyze-message` | `{"message": "..."}` | Message score, evidence (with `source`), URL results, language, … |
| `GET /api/health` | — | Which components are loaded / enabled, model test metrics |
| `POST /feedback` | `{analysis_id, message, score, risk_label, attack_type, language, is_correct}` | Updated feedback stats |

---

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The suite (164 tests) runs offline. Threat-intel tests use a local stub server, not the real service. `tests/conftest.py` disables translation and the zero-shot model.
It covers URL parsing edge cases, feature extraction, every heuristic rule, typosquat true and false
positives, the risk engine's weights and adjustments, exact reconstruction of model explanations,
model-loading failures, the threat-intel interface with a test double, provider-failure handling,
config validation, the training script (on a tiny synthetic CSV, mechanics only), Flask pages and
API endpoints, and regression tests for each bug listed above.

---

## Threat-intelligence integration

PhishShield X consumes live threat intelligence from a **separate, independently runnable
service** over REST. The two projects share no code and no database.

| | Project | Responsibility | Default address |
|:--|:--|:--|:--|
| **Project 1** | Real-Time Phishing URL Collection & Threat Intelligence API (FastAPI, `phishing-threat-intel-api/`) | Collect → validate → normalise → store → serve | `http://127.0.0.1:8000` |
| **Project 2** | PHISHSHIELD-X: Explainable Phishing Detection and Risk Scoring (this repository, Flask) | Receive → analyse → detect → combine threat intel → score → explain | `http://127.0.0.1:5000` |

```
 Project 1: threat-intel API ── collects OpenPhish, PhishStats, PhishTank, URLhaus feeds
        │
        │  REST / JSON  (GET /api/urls/lookup, /api/urls?hostname=, /api/urls/latest, /api/health)
        ▼
 Project 2 backend: phishshield/threat_intel/threat_intel_client.py   HTTP, validation, normalisation
        ▼
 phishshield/threat_intel/api_provider.py   records → ThreatIndicator (documented evidence policy)
        ▼
 URL analysis (parser) + ML detection (URL model) + heuristics   ← PhishShield's own detection
        ▼
 scoring/risk_engine.py   threat intel = one weighted component + one documented floor rule
        ▼
 explain/url_explainer.py   threat-intel / ML / rule evidence kept separate; verdict + reasons
        ▼
 Dashboard (templates/index.html)  ←  Browser talks only to Project 2
```

**The browser never calls Project 1.** All requests go Browser → Project 2 backend → Project 1, so
the API key and the service address stay on the server.

### What is called

| PhishShield action | Project 1 request | Used for |
|:--|:--|:--|
| Analyse a URL | `GET /api/urls/lookup?url=<url>` | Exact match. The service normalises the URL itself. |
| … if no exact match | `GET /api/urls?hostname=<host>&limit=5` | Host-level match: other reported URLs on the same host (`THREAT_INTEL_CHECK_HOST`) |
| Threat Feed tab | `GET /api/urls/latest?limit=&page=` | Newest collected URLs, each scored by PhishShield |
| `GET /api/health` | `GET /api/health` | Reports whether Project 1 is reachable |

Response contract consumed (Project 1's actual format): `{"success": true, "data": …}`, with
`count` and `pagination` on lists, and `{"success": false, "error": {"code", "message"}}` on errors.
URL records contain `id, url, hostname, domain, sources[], threat_type, threat_types[], confidence,
status, tags[], first_seen, last_seen, sightings[]`.

### How threat intelligence affects the score

Threat intelligence is an **input** to PhishShield's scoring. It does not replace the model or
the rules. Defined in `phishshield/threat_intel/api_provider.py`:

| Finding | Verdict | Confidence used for scoring |
|:--|:--|:--|
| Exact URL listed | `malicious` | Highest confidence a feed published. None of the current feeds publishes one, so a **policy value** is used instead: **0.85** for 1 feed, **0.95** for 2+ feeds (independent corroboration). |
| …last seen in a feed > 30 days ago | `malicious` | × 0.75. Phishing pages are short-lived and compromised sites get cleaned up. |
| Only other URLs on the same host listed | `suspicious` | 0.60 (policy value). Weaker evidence. |
| Not listed | none | Nothing is added. Absence from the feeds never lowers the score. |

The risk engine then applies its existing, unchanged rules:

```
external component = 100 × confidence (malicious) or 60 × confidence (suspicious)
weighted score     = Σ weightᵢ × scoreᵢ / Σ weightᵢ   (model 0.6, rules 0.4, external 0.5 → 40% / 27% / 33%)
floor rule         = external "malicious" with confidence ≥ 0.8 → final score ≥ 80
```

So an exact listing by one feed puts a URL at **≥ 80 (High Risk)** even when the model and rules miss it.
Each indicator carries `confidence_basis`, which states whether the number came from a feed or from
the policy above. The UI prints it, so a policy value is never presented as a feed's confidence.

### Fallback when Project 1 is unavailable

If Project 1 is down, slow (longer than `THREAT_INTEL_API_TIMEOUT`), rate-limiting, rejecting the
key or returning malformed data, the analysis **still runs** with the model and rules only.

- The result says so: `verdict.threat_intelligence.status = "unavailable"`, and the summary,
  reasons, limitations and UI card show **"Live threat intelligence unavailable"**.
- The score is the same as it would be with no threat intelligence configured. No data is
  pretended.
- `GET /api/threat-intel/latest` returns HTTP 503 with `"available": false`.

URLs that Project 1 cannot store (private IPs, `localhost`, unknown TLDs) are reported as
*not checked*, not as errors.

### Configuration

| Variable | Default | Purpose |
|:--|:--|:--|
| `THREAT_INTEL_API_URL` | *(empty → disabled)* | Base URL of Project 1, e.g. `http://127.0.0.1:8000` |
| `THREAT_INTEL_API_KEY` | *(empty)* | Sent as `X-API-Key`. Needed only if Project 1 sets `READ_API_KEYS`. Server-side only. |
| `THREAT_INTEL_API_TIMEOUT` | `5` | Seconds per request before falling back to model + rules |
| `THREAT_INTEL_CHECK_HOST` | `true` | Also run the host-level check (one extra request when the URL is not listed) |

Put them in a `.env` file (copy `.env.example`; `.env` is git-ignored) or set them in the environment.

### Running both projects locally

```bash
# Terminal 1: Project 1 (threat-intel API), port 8000
cd phishing-threat-intel-api
.venv\Scripts\activate
python -m threatintel init-db          # first time (or `alembic upgrade head` for PostgreSQL)
python -m threatintel collect          # fetch real feeds once
python -m threatintel serve            # http://127.0.0.1:8000   (docs: /docs)

# Terminal 2: Project 2 (PhishShield X), port 5000
cd PHISHSHIELD-X-Explainable-Multilingual-AI-for-Scam-and-Phishing-Detection-main
.venv\Scripts\activate
copy .env.example .env                 # sets THREAT_INTEL_API_URL=http://127.0.0.1:8000
python app.py                          # http://127.0.0.1:5000
```

Either project runs on its own. Project 2 without Project 1 behaves as described under *Fallback*.

### Testing the connection

```bash
curl http://127.0.0.1:5000/api/health
#  "threat_intel": {"configured": true, "provider": "threat-intel-api"},
#  "threat_intel_api": {"reachable": true, "status": "ok", "database": "ok"}

curl -X POST http://127.0.0.1:5000/api/analyze -H "Content-Type: application/json" \
     -d '{"url": "<a URL from http://127.0.0.1:8000/api/urls/latest>"}'

curl "http://127.0.0.1:5000/api/threat-intel/latest?limit=5&analyze=true"
```

In the UI, the **URL** tab shows a *Threat Intelligence* card (MATCH FOUND / No match /
unavailable) and a *Why this score* list. The **Threat Feed** tab lists the newest collected URLs,
shown defanged (`hxxps://example[.]com`) so they cannot be clicked.

### Example (real run, 7 Oct 2026)

A URL that Project 1 had collected from OpenPhish (shown defanged here:
`hxxps://jnctextiles[.]com/personas[.]php`). Project 1's lookup returned (abridged):

```json
{"success": true, "data": {"found": true, "normalized_url": "https://jnctextiles.com/personas.php",
  "record": {"id": 1, "url": "https://jnctextiles.com/personas.php", "sources": ["openphish"],
             "threat_type": "phishing", "confidence": null, "status": null,
             "first_seen": "2026-10-07T13:41:59.504537Z", "last_seen": "2026-10-07T13:41:59.504537Z"}}}
```

PhishShield's `POST /api/analyze` result (`verdict` excerpt):

```json
{
  "classification": "PHISHING", "risk_score": 80, "severity": "HIGH RISK",
  "ml_probability": 0.191, "heuristic_score": 0,
  "threat_intelligence": {
    "status": "match", "match": true, "match_type": "url", "sources": ["openphish"],
    "threat_types": ["phishing"], "confidence": 0.85,
    "confidence_basis": "PhishShield policy value for a URL listed by 1 feed (1 feed -> 0.85); the feeds do not publish a confidence."
  },
  "reasons": [
    {"category": "threat_intelligence", "effect": "raises", "text": "URL matched a known threat-intelligence record. Listed by openphish as phishing; last seen in a feed today."},
    {"category": "ml", "effect": "lowers", "text": "URL model estimates only a 19% phishing probability."},
    {"category": "score_rule", "effect": "raises", "text": "External source 'threat-intel-api' reports this as malicious (confidence 85%)."}
  ]
}
```

In this case the URL model alone (19%) and the rules (0 points) would have rated the URL Low Risk.
The threat-intelligence match is what flagged it, and the explanation says exactly that.

### Tests

`tests/test_threat_intel_integration.py` (42 tests) runs the real HTTP client against a local stub
server (`tests/threat_intel_stub.py`) that speaks Project 1's JSON contract with synthetic
`example.*` data. The tests cover:

- a successful response, plus timeout, connection refused, 401/403/429/5xx, malformed or non-JSON
  bodies, redirects and empty results
- URL found, host-only match and URL not found
- the evidence policy (single feed, multiple feeds, published confidence, stale listings)
- scoring with and without threat intelligence, and the fallback
- the Flask routes and health check

The suite never needs Project 1 to be running. `tests/conftest.py` clears `THREAT_INTEL_API_URL`,
so a local `.env` cannot make tests hit a real service.

### Adding another source

Subclass `ThreatIntelProvider` (`phishshield/threat_intel/base.py`) and return `ThreatIndicator`
objects with an honest `confidence_basis`. Then pass the instance to
`URLAnalysisService.from_settings(settings, threat_intel=...)` in `app.py`.

---

## Limitations

- **URL text only.** Page content, DNS, WHOIS / domain age, certificates and redirects are not inspected,
  and the link is never opened. Phishing on compromised legitimate sites, or on clean-looking new
  domains, can score low.
- **Dated training data.** The URL dataset is from 2020, and test accuracy on today's URLs may be lower.
  The model has a 15.6% false-positive rate on the held-out set and leans toward flagging long or
  account-related legitimate URLs.
- **Hand-set rule points.** They are not calibrated, and the brand / official-domain list is short and
  must be maintained.
- **Hosted content on official domains** (e.g. `sites.google.com`) gets the official-domain cap
  unless a medium or high rule fires.
- **Message analysis is English-centric.** Its rules and spam model are English. See the multilingual
  notes above.
- **Threat-intel coverage** is limited to the feeds Project 1 collects (and their update frequency).
  Not being listed does not mean a URL is safe. The match confidences are documented policy values,
  because the feeds publish none.
- The risk score is a decision aid, **not proof** that a site is malicious or safe.

---

## Data sources and licences

- **URL dataset:** Hannousse, A. & Yahiouche, S. (2021). *Web page phishing detection* (v3), Mendeley Data,
  https://doi.org/10.17632/c2gw7fy2j4.3, CC BY 4.0. Associated paper: *Towards benchmark datasets for machine
  learning based website phishing detection: An experimental study*, Engineering Applications of
  Artificial Intelligence 104 (2021) 104347. Modification: only the `url` and `status` columns are used.
  The dataset is downloaded by the user and not redistributed here.
- **SMS dataset (`emails.csv`):** SMS Spam Collection (Almeida & Gómez Hidalgo, UCI Machine Learning Repository).
- **Public Suffix List:** snapshot bundled with `tldextract`.

## Disclaimer

PhishShield X is a research and educational project. It helps identify potentially suspicious
messages and links but is **not a substitute for professional security or legal advice**. Always
verify suspicious communications through official channels. In India, report cyber fraud at
cybercrime.gov.in or call **1930**. Report threats of violence to the police (**112** / **100**).

## License

[MIT](LICENSE)
