# Client Intelligence

A small Flask app that, given a competitor's domain, runs a 3-phase AI pipeline to discover and extract a verified list of their public clients (case studies, references, testimonials, logo walls).

> Production deployment: https://web-production-a23e.up.railway.app
> Repo: https://github.com/donsim1109/client-intelligence

---

## How it works

Single file (`server.py`), Flask + SQLite (or PostgreSQL on Railway via `DATABASE_URL`). The frontend (`INDEX_HTML`) is served inline from the same file — `index.html` on disk is dead code and out of sync.

Three-phase pipeline per scrape:

| Phase | What it does | Tool | Approx tokens |
|---|---|---|---|
| 1. Discovery | Claude searches the web to find every page on the target domain that mentions clients/cases/references/partners | `web_search_20250305` | ~10–15k input |
| 2. Fetch | Server downloads HTML for each discovered page (max 15 pages, 8k chars each) | `requests` + `BeautifulSoup` | 0 (no LLM) |
| 3. Analysis | Claude reads the concatenated page texts and returns a structured JSON of clients + technology partners | Plain message | ~20–30k input |

Result is persisted in the `repos` table keyed by `(email, domain)`. Token usage per call is logged in `usage_log`.

Model: `claude-sonnet-4-5` (overridable via `ANTHROPIC_MODEL`). Note: the literal default in `server.py` is still the deprecated `claude-sonnet-4-20250514` — Railway should set `ANTHROPIC_MODEL=claude-sonnet-4-5` until that is fixed in code.

---

## Quick start (local)

```bash
pip install flask==3.0.3 flask-cors==4.0.1 requests==2.31.0 beautifulsoup4==4.12.3 "lxml>=5.3.0" "anthropic>=0.42.0"

# Linux / macOS
ANTHROPIC_API_KEY=sk-ant-... \
SECRET_KEY=any-32-char-string \
PORT=5050 \
python server.py
```

```powershell
# Windows PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
$env:SECRET_KEY        = "any-32-char-string"
$env:PORT              = "5050"
python server.py
```

Then open http://127.0.0.1:5050/, sign up, and scrape.

> If you skip `psycopg2-binary` (the only requirement that fails to wheel-build on Python 3.14) the app falls back to SQLite at `data/app.db` automatically.

---

## Configuration

| Env var | Purpose | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | Builtin server-wide key. **Without this, every scrape fails silently with "No Anthropic API key set".** | empty |
| `ANTHROPIC_MODEL` | Claude model id | `claude-sonnet-4-5` |
| `ANTHROPIC_TIMEOUT` | SDK timeout (seconds) | `180` |
| `ANTHROPIC_MAX_RETRIES` | SDK retries | `4` |
| `SECRET_KEY` | Flask session signing | `dev-secret-change-on-railway` (do not ship this) |
| `DATABASE_URL` | Postgres URL. If empty → SQLite at `data/app.db` | empty |
| `PORT` | HTTP port | `5050` |

Per-user override: any logged-in user can paste their own `sk-ant-...` key under **Settings → Custom Anthropic API key**. That key takes precedence over the builtin one for that user only.

---

## Anthropic rate limits — the gotcha you'll hit first

Phase 3 packs up to 15 pages × 8000 chars (~25–35k tokens) into a single request, and Phase 1 typically adds another ~10–15k tokens within the same minute window. **On a fresh Anthropic Tier 1 account (30 000 input tokens/min) a single scrape of a content-rich site is enough to trigger HTTP 429**:

```
Claude API 429: rate_limit_error
This request would exceed your organization's rate limit
of 30,000 input tokens per minute (model: claude-sonnet-4-5...)
```

This is **not** a bug — it is the API rejecting the call. Options, in order of preference:

### 1. Upgrade your Anthropic tier (recommended)

Console → Settings → Limits. Tier 2 raises the limit to 450 000 input tokens/min, which makes this problem disappear forever. Activation is automatic once you have purchase history with Anthropic.

### 2. Retry with a smaller target

Sites with few reference pages (1-page landings, small agencies) stay well under 30k. Wait ~60 s between scrapes if you hit the limit; the window is rolling.

### 3. Stagger Phase 1 and Phase 3 in code (no quality loss)

Add a `time.sleep(45)` between the discovery call and the analysis call so they fall in different per-minute windows. Costs +45s of latency. Patch in `run_scrape_events`:

```python
# After Phase 2's "for page_info in unique_pages[:15]:" loop completes
import time; time.sleep(45)   # avoid Tier 1 rate limit
yield log("Phase 3: AI analysing content to extract verified clients...")
```

### 4. Reduce payload (last resort — measurable quality loss)

Two knobs, both in `run_scrape_events`:

- `unique_pages[:15]` → `[:8]` — small loss. Phase 1 already ranks pages by relevance, so the top 8 carry most clients. Agencies with rich portfolios will lose minor case studies.
- `max_chars=8000` → `max_chars=4000` — **real loss.** `page_text` slices by HTML order, and logo walls / reference lists / testimonials often sit below the fold. Truncating halves the chance of seeing them.

**Recommended conservative patch:** `[:15] → [:10]`, leave `max_chars=8000`. Cuts Phase 3 by ~33% with negligible quality impact.

---

## Local validation checklist (manual smoke test)

```bash
# 1) API key works
python -c "import anthropic; print(anthropic.Anthropic(api_key='$ANTHROPIC_API_KEY').messages.create(model='claude-sonnet-4-5', max_tokens=16, messages=[{'role':'user','content':'say OK'}]).content[0].text)"

# 2) server boots
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5050/api/me   # → 401 (not logged in, server up)

# 3) signup + auth
curl -s -c /tmp/c.txt -X POST http://127.0.0.1:5050/api/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@local.dev","password":"testpass123"}'

# 4) settings reports builtin key
curl -s -b /tmp/c.txt http://127.0.0.1:5050/api/settings
# → {"ai_enabled":true,"has_builtin_key":true,"has_user_key":false}

# 5) scrape end-to-end (small site recommended on Tier 1)
curl -s -b /tmp/c.txt -X POST http://127.0.0.1:5050/api/scrape \
  -H 'Content-Type: application/json' -d '{"url":"optiweb.com"}' --no-buffer

# 6) usage tracking
curl -s -b /tmp/c.txt http://127.0.0.1:5050/api/usage
```

A successful scrape on `optiweb.com` returns ~7 clients + 2 technology partners and consumes ~40k input + ~2k output tokens across 2 Claude calls.

---

## Known issues (worth fixing before more users hit them)

These were found while reviewing the repo. None block today's flow once `ANTHROPIC_API_KEY` is set, but they will bite at scale.

1. **Default model in `server.py:391`** is `claude-sonnet-4-20250514`, deprecated by Anthropic on 2026-04-14 and shutting down on 2026-06-15. Either change the default to `claude-sonnet-4-5` or set `ANTHROPIC_MODEL` on Railway.
2. **`/api/scrape` no pre-flight check.** When neither builtin nor user key is set, the request silently runs and returns an empty result with an error in the body. Should reject upfront with a clear "configure Anthropic key" message.
3. **`/api/settings` returns `ai_enabled: true` unconditionally** even when no key exists. The "AI ON" badge in the UI lies in that case.
4. **`Procfile` timeout vs SDK timeout.** Gunicorn `--timeout 300` is fine, but the SDK is set to 180 s; for very large sites the analysis call can approach that. Worth aligning.
5. **`index.html` is dead code.** Frontend is served from the `INDEX_HTML` string in `server.py`. Delete the file, or wire it up — pick one.
6. **Frontend hides logs on error.** When the result includes both `error` and `logs`, the UI only shows `error`. Always render logs on failure for diagnostics.
7. **No prompt caching on the discovery prompt or page contents.** The analysis system prompt has `cache_control` (good), but Phase 1 and Phase 3 user content do not. Adding caching to the static portions would cut ~50% of input cost on repeat scrapes within 5 min.
8. **Cosmetic:** UI says "Case Studys" instead of "Case Studies" in the company header pills.

---

## Deployment notes (Railway)

The single thing that breaks the production deployment today: **`ANTHROPIC_API_KEY` is not set in Railway → Variables.** Add it and redeploy. Also worth setting:

```
ANTHROPIC_API_KEY = sk-ant-...
ANTHROPIC_MODEL   = claude-sonnet-4-5
SECRET_KEY        = <32+ random chars>
```

The Procfile already runs gunicorn with 2 workers and 300 s timeout; no other infra changes needed.

---

## File map

```
server.py            # everything: routes, DB, scraper, AI pipeline, frontend
Procfile             # gunicorn config for Railway
railway.json         # Railway build/deploy config
requirements.txt     # Python deps (psycopg2-binary fails on Python 3.14, optional)
data/app.db          # SQLite DB (created on first boot when DATABASE_URL unset)
index.html           # dead code — UI is served inline from server.py
REPLY_TO_SIMON.md    # diagnosis email draft (the original "why doesn't it work" reply)
```
