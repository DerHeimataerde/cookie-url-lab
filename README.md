# Local Tracker Lab

A localhost-only research sandbox for studying whether values seen in URLs are likely reused, transformed, or encoded into cookie values.

The lab intentionally includes both:
- scenarios that *should* be detectable by reversible transforms (`identity`, `base64`, token splitting), and
- scenarios that should be hard or impossible to infer from client-visible data alone (server-side lookup and random noise).

---

## Goals

This project helps you answer questions like:
- “Does query parameter `xid` appear to become cookie `tid_plain` directly?”
- “Is a cookie likely derived from a URL token after a common transform?”
- “Which mappings are stable across repeated runs versus one-off coincidences?”

It is built for synthetic local experimentation, not production traffic analysis.

---

## Demo


https://github.com/user-attachments/assets/1c347d46-9b10-4c48-9f98-919bd4765a9f


---

## Project structure

- `server.py`  
	Runs a local HTTP server (`127.0.0.1:8765`) with synthetic redirect + tracker endpoints.

- `crawler.py`  
	Visits predefined scenarios repeatedly, follows redirects, and records per-hop events (URL, cookies sent, cookies set, status, redirect target).

- `detector.py`  
	Scores URL-token ↔ cookie-value relationships using candidate transforms and similarity heuristics; outputs ranked grouped findings.

- `reverse_engineer_toy.py`  
	Simple helper to summarize specific URL parameter / cookie pairs in the synthetic dataset.

- `dashboard.py`  
	Local Flask dashboard to start/stop the synthetic server, run the full pipeline, and inspect logs/results.

- `test_data_generator.py`  
	Defines ad-platform tracking scenarios (Meta, Google, TikTok, Microsoft/Amazon) used by both `server.py` and `crawler.py` to simulate realistic ad-click redirect and cookie-setting patterns.

- `capture.json`  
	Raw captured event log from the crawler.

- `findings.json`  
	Ranked detector output.

---

## Environment and setup (Windows / PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

Requirements are intentionally minimal:
- `requests>=2.31.0`
- `Flask>=3.0.0`

---

## Local dashboard (run everything from one UI)

If you want one local interface for the whole workflow:

```powershell
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py dashboard.py
```

Open:

```text
http://127.0.0.1:8890
```

From the dashboard you can:
- Start/stop the synthetic tracker server (`server.py`).
- Run crawler + detector + reverse-engineer helper in one click.
- Tune runs, threshold, and output file names.
- View pipeline logs, server logs, and top ranked findings.

Notes:
- The pipeline run auto-starts the tracker server if it is not already running.
- Default outputs are still `capture.json` and `findings.json`.
- The UI polls state every 2 seconds to show progress live.

---

## Run workflow

### 1) Start the synthetic server

```powershell
py server.py
```

Expected console line:

```text
Serving on http://127.0.0.1:8765
```

### 2) Capture traffic-like events (separate shell)

```powershell
.venv\Scripts\Activate.ps1
py crawler.py --output capture.json --runs 3
```

What this does:
- Executes each scenario path multiple times.
- Follows redirect chains.
- Stores one event for each response in the chain.

### 3) Detect candidate mappings

```powershell
py detector.py capture.json --output findings.json
```

Optional threshold tuning:

```powershell
py detector.py capture.json --threshold 1.10 --output findings.json
```

### 4) Inspect a specific synthetic pair (optional helper)

```powershella
py reverse_engineer_toy.py capture.json tid_b64 xid
```

---

## Synthetic endpoint behavior

The server exposes two conceptual layers:

1. ` /site/* ` endpoints (simulate pages that redirect to a tracker).
2. ` /tracker/* ` endpoints (set cookies under different mapping strategies).

Scenarios:

- **Plain**
	- Request shape: `/site/plain?cid=user-123`
	- Redirect carries `xid=user-123`
	- Tracker sets `tid_plain=user-123`
	- Expected detector result: strong `identity` mapping from `xid` to `tid_plain`

- **Base64**
	- Redirect carries `xid=<base64(cid)>`
	- Tracker decodes and sets `tid_b64=<decoded cid>`
	- Expected detector result: strong `b64` mapping from `xid` to `tid_b64`

- **Split token**
	- Redirect carries `blob=v1.<base64(cid)>.sig`
	- Tracker extracts middle token, decodes, sets `tid_split=id::<decoded cid>`
	- Expected detector result: strong `split+b64` mapping from `blob` to `tid_split`

- **Lookup**
	- Redirect carries opaque `tok=<random token>`
	- Tracker resolves token server-side using an in-memory DB and sets `tid_lookup=L::<resolved cid>`
	- Expected detector result: weak/inconsistent or absent high-confidence reversible mapping

- **Random noise**
	- Redirect carries random parameter and sets unrelated random cookie
	- Expected detector result: no stable high-confidence mapping

- **Meta (Facebook click ID)**
	- Request shape: `/site/meta?fbclid=<id>`
	- Redirect carries `event_id=fb.1.<base64(id)>.sig`
	- Tracker extracts middle segment, decodes, sets `_fbc=<id>`
	- Expected detector result: strong `split+b64` mapping from `event_id` to `_fbc`

- **Google Search (click ID)**
	- Request shape: `/site/search?gclid=<id>`
	- Redirect carries `adid=gcl::<hex(id)>::ad`
	- Tracker decodes and sets `_gcl_au=<id>`
	- Expected detector result: strong hex-split mapping from `adid` to `_gcl_au`

- **TikTok (click ID)**
	- Request shape: `/site/video?ttclid=<id>`
	- Redirect carries `click_id=tt.<base64(id)>~end`
	- Tracker extracts and decodes, sets `_ttp=<id>`
	- Expected detector result: strong `split+b64` mapping from `click_id` to `_ttp`

- **Microsoft / Amazon (commerce click ID)**
	- Request shape: `/site/commerce?msclkid=<id>`
	- Redirect carries `aid=ms.<base64(id)>.trail`
	- Tracker extracts middle segment, decodes, sets `ubid-main=<id>`
	- Expected detector result: strong `split+b64` mapping from `aid` to `ubid-main`

All ad scenarios are defined in `test_data_generator.py` and dynamically registered into both `server.py` routing and the `crawler.py` scenario list.

---

## Capture format (`capture.json`)

Each event written by `crawler.py` contains:

- `ts`: Unix timestamp
- `request_url`: fully qualified URL requested for that hop
- `status_code`: HTTP status for the hop
- `cookies_sent`: parsed Cookie header sent on that request
- `set_cookies`: cookies present on that response object
- `redirect_to`: next request URL in chain (or `null` at chain end)

This event-level granularity allows you to reason about when state appears and how it propagates through redirects.

---

## Detector methodology (`detector.py`)

For each event that sets cookies:

1. Extract URL tokens from:
	 - query params,
	 - path segments,
	 - fragment (if present).
2. Generate candidate transform outputs for each token, including:
	 - `identity`, `urldecode`, `b64`, `hex`,
	 - split-based forms (`split:*`, `split+b64:*`),
	 - prefix/suffix stripping variants.
3. Compare transformed token to cookie value with a composite similarity score.
4. Keep matches above threshold (default `0.95`).
5. Group findings by `(url_component, param_or_index, cookie_name, transform)` and rank by count + average score.

### Similarity signals used

- character-set overlap (Jaccard-like)
- length similarity
- entropy similarity
- shared prefix bonus
- exact-equality bonus
- substring containment bonus
- short SHA-256 prefix hint bonus (limited heuristic)

This is intentionally heuristic ranking, not formal proof of causality.

---

## Interpreting `findings.json`

Each ranked item includes:
- `mapping`: grouped mapping signature
- `count`: number of supporting events
- `avg_score`: average confidence score across grouped events
- `examples`: sample underlying event-level matches

Interpretation guidance:
- Prefer mappings with both **high count** and **high average score**.
- One-off high scores can be accidental.
- Reversible transform scenarios should persist across runs.
- Lookup/random scenarios should generally not produce durable top-ranked reversible matches.

---

## Expected baseline outcomes

Under normal runs (`--runs 3`, default threshold):

- likely strong:
	- `xid -> tid_plain` (`identity`)
	- `xid -> tid_b64` (`b64`)
	- `blob -> tid_split` (`split+b64` + wrapper-related similarity)

- likely weak/unstable:
	- `tok -> tid_lookup` (server-side lookup is opaque client-side)
	- random-noise relationships

---

## Useful experiments

- Increase `--runs` to improve repeatability and reduce chance findings.
- Raise `--threshold` to suppress fuzzy matches and keep only stronger candidates.
- Lower `--threshold` to explore borderline candidates (expect more noise).
- Modify scenario values in `crawler.py` to test edge-case token formats.

---

## Troubleshooting

- **Connection errors from crawler**
	- Ensure `server.py` is running first and listening on `127.0.0.1:8765`.

- **No findings in output**
	- Lower threshold (for example `--threshold 0.75`) and/or increase run count.

- **Unexpected weak scores for known mappings**
	- Verify you are using fresh `capture.json` from current server behavior.

- **PowerShell execution policy blocks activation**
	- Use your local policy workflow, or run tools with global `py` if your environment is already configured.

---

## Future work: AI-assisted mapping

The current detector is rule/heuristic-based. A next step is to add an AI layer that learns non-obvious mapping patterns while keeping the existing heuristic engine as a transparent baseline.

### 1) Problem framing

Treat mapping as a ranking or classification problem over candidate pairs:
- Input pair: `(url_token, cookie_value, context_features)`
- Output: probability that cookie value is derived from the URL token

This can be approached in two ways:
- **Pair classifier**: predicts yes/no for each pair.
- **Learning-to-rank**: orders candidate URL tokens per cookie by likelihood.

### 2) Candidate features

Build features from each event and from repeated observations:

- **String/transform features**
	- exact match flags, substring relations
	- decode success flags (b64/hex/url)
	- edit distance, length ratio, prefix/suffix overlap
	- character class composition (alnum, symbols, entropy)

- **Behavioral features**
	- co-occurrence frequency across runs
	- temporal ordering in redirect chains
	- stability of mapping over time

- **Structural features**
	- source location (`query`, `path`, `fragment`)
	- parameter name and cookie name patterns
	- endpoint family (`plain`, `base64`, `lookup`, etc.)

### 3) Model options (from simple to advanced)

- Logistic regression / gradient-boosted trees on engineered features (recommended starting point).
- Siamese or contrastive text-embedding models for token/cookie similarity in harder transform cases.
- Sequence models over full redirect chains to capture multi-hop dependencies.

For this lab, tree-based models are usually the most practical first step because they are fast, interpretable, and work well with mixed numeric/categorical features.

### 4) Training data strategy

Use the synthetic server to generate labeled data at scale:
- Positive labels: known mappings from reversible scenarios (`plain`, `base64`, `split`).
- Hard negatives: lookup/random pairs and shuffled pairings within the same run.
- Stress data: varied token lengths, wrappers, delimiters, and noise rates.

Then split by run/session to avoid leakage (train and test should not share near-duplicate events).

### 5) Evaluation and calibration

Recommended metrics:
- Precision/recall/F1 for pair classification.
- Top-k recall and MRR/NDCG for ranking quality.
- Calibration curves so confidence scores are meaningful.

Also measure robustness under threshold shifts and distribution shifts (for example, introducing new token wrapper formats).

### 6) Human-in-the-loop workflow

A practical future pipeline:
1. Existing heuristic detector generates candidates.
2. AI model rescoring stage refines ranking.
3. Analyst review confirms high-confidence mappings.
4. Confirmed mappings feed back into training data.

This keeps explainability while improving recall on harder patterns.

### 7) Guardrails

- Keep deterministic rules as a baseline for auditability.
- Store feature-attribution outputs (for example, SHAP values) for model decisions.
- Avoid treating model score as proof of causality; keep explicit confidence language.
- Restrict usage to authorized, synthetic or consented datasets.

---

## Scope and ethics

- This repository is for local synthetic lab research.
- Do not use this workflow to profile real users or analyze third-party systems without explicit authorization.
- The helper reverse-engineering script is intentionally limited and not intended for live-tracker deobfuscation.
