"""
Client Intelligence - Complete server
Three-phase AI pipeline:
  1. Web search to discover ALL client/reference pages
  2. Fetch full HTML of each page
  3. Claude reads everything and returns structured client database
"""
import re, json, time, hashlib, secrets, os, sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-on-railway")
app.permanent_session_lifetime = timedelta(days=30)

_is_https = bool(os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("RENDER"))
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SECURE"]   = _is_https
app.config["SESSION_COOKIE_SAMESITE"] = "None" if _is_https else "Lax"

CORS(app, supports_credentials=True, origins="*")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2, psycopg2.extras
    print("[DB] PostgreSQL")
else:
    SQLITE_PATH = os.path.join(DATA_DIR, "app.db")
    print("[DB] SQLite:", SQLITE_PATH)

@contextmanager
def get_db():
    if USE_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        try:
            yield conn; conn.commit()
        except:
            conn.rollback(); raise
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn; conn.commit()
        except:
            conn.rollback(); raise
        finally:
            conn.close()

PH = "%s" if USE_POSTGRES else "?"

def init_db():
    with get_db() as db:
        c = db.cursor()
        if USE_POSTGRES:
            c.execute("""CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW())""")
            c.execute("""CREATE TABLE IF NOT EXISTS repos (
                email TEXT NOT NULL, company_key TEXT NOT NULL,
                data JSONB NOT NULL, updated_at TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY (email, company_key))""")
            c.execute("""CREATE TABLE IF NOT EXISTS settings (
                email TEXT NOT NULL, name TEXT NOT NULL,
                value TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (email, name))""")
        else:
            c.execute("""CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now')))""")
            c.execute("""CREATE TABLE IF NOT EXISTS repos (
                email TEXT NOT NULL, company_key TEXT NOT NULL,
                data TEXT NOT NULL, updated_at TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (email, company_key))""")
            c.execute("""CREATE TABLE IF NOT EXISTS settings (
                email TEXT NOT NULL, name TEXT NOT NULL,
                value TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (email, name))""")

init_db()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# DB helpers
def db_get_user(email):
    try:
        with get_db() as db:
            c = db.cursor()
            c.execute(f"SELECT email,password_hash FROM users WHERE email={PH}", (email,))
            row = c.fetchone()
            return dict(row) if row else None
    except: return None

def db_create_user(email, pw):
    with get_db() as db:
        c = db.cursor()
        c.execute(f"INSERT INTO users(email,password_hash) VALUES({PH},{PH})", (email, hash_pw(pw)))

def db_get_repo(email):
    try:
        with get_db() as db:
            c = db.cursor()
            c.execute(f"SELECT company_key,data FROM repos WHERE email={PH}", (email,))
            rows = c.fetchall()
            result = {}
            for row in rows:
                k = row[0] if USE_POSTGRES else row["company_key"]
                v = row[1] if USE_POSTGRES else row["data"]
                result[k] = v if isinstance(v, dict) else json.loads(v)
            return result
    except: return {}

def db_save_entry(email, key, data):
    payload = json.dumps(data, ensure_ascii=False)
    with get_db() as db:
        c = db.cursor()
        if USE_POSTGRES:
            c.execute("""INSERT INTO repos(email,company_key,data,updated_at)
                VALUES(%s,%s,%s::jsonb,NOW())
                ON CONFLICT(email,company_key) DO UPDATE
                SET data=EXCLUDED.data,updated_at=NOW()""", (email, key, payload))
        else:
            c.execute("""INSERT INTO repos(email,company_key,data,updated_at)
                VALUES(?,?,?,datetime('now'))
                ON CONFLICT(email,company_key) DO UPDATE
                SET data=excluded.data,updated_at=datetime('now')""", (email, key, payload))

def db_delete_entry(email, key):
    with get_db() as db:
        c = db.cursor()
        c.execute(f"DELETE FROM repos WHERE email={PH} AND company_key={PH}", (email, key))

def db_get_setting(email, name):
    try:
        with get_db() as db:
            c = db.cursor()
            c.execute(f"SELECT value FROM settings WHERE email={PH} AND name={PH}", (email, name))
            row = c.fetchone()
            return (row[0] if USE_POSTGRES else row["value"]) if row else None
    except: return None

def db_save_setting(email, name, value):
    with get_db() as db:
        c = db.cursor()
        if USE_POSTGRES:
            c.execute("""INSERT INTO settings(email,name,value) VALUES(%s,%s,%s)
                ON CONFLICT(email,name) DO UPDATE SET value=EXCLUDED.value""", (email, name, value))
        else:
            c.execute("""INSERT INTO settings(email,name,value) VALUES(?,?,?)
                ON CONFLICT(email,name) DO UPDATE SET value=excluded.value""", (email, name, value))

# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    d = request.json or {}
    email = (d.get("email") or "").strip().lower()
    pw    = d.get("password") or ""
    if not email or not pw:
        return jsonify(error="Email and password required"), 400
    if len(pw) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400
    if db_get_user(email):
        return jsonify(error="An account with this email already exists"), 400
    try:
        db_create_user(email, pw)
    except Exception as e:
        return jsonify(error=f"Could not create account: {e}"), 500
    session.permanent = True
    session["email"] = email
    return jsonify(ok=True, email=email)

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    email = (d.get("email") or "").strip().lower()
    pw    = d.get("password") or ""
    user  = db_get_user(email)
    if not user:
        return jsonify(error="No account found with this email"), 401
    if user["password_hash"] != hash_pw(pw):
        return jsonify(error="Incorrect password"), 401
    session.permanent = True
    session["email"] = email
    return jsonify(ok=True, email=email)

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify(ok=True)

@app.route("/api/me")
def me():
    email = session.get("email")
    if not email:
        return jsonify(error="Not logged in"), 401
    return jsonify(email=email)

# ---------------------------------------------------------------------------
# Repo routes
# ---------------------------------------------------------------------------
@app.route("/api/repo")
def get_repo():
    email = session.get("email")
    if not email:
        return jsonify(error="Not logged in"), 401
    return jsonify(db_get_repo(email))

@app.route("/api/repo/<key>", methods=["DELETE"])
def delete_entry(key):
    email = session.get("email")
    if not email:
        return jsonify(error="Not logged in"), 401
    db_delete_entry(email, key)
    return jsonify(ok=True)

# ---------------------------------------------------------------------------
# Settings routes
# ---------------------------------------------------------------------------
@app.route("/api/settings")
def get_settings():
    email = session.get("email")
    if not email:
        return jsonify(error="Not logged in"), 401
    user_key = db_get_setting(email, "anthropic_key") or ""
    return jsonify(ai_enabled=True, has_user_key=bool(user_key))

@app.route("/api/settings/apikey", methods=["POST"])
def save_apikey():
    email = session.get("email")
    if not email:
        return jsonify(error="Not logged in"), 401
    d = request.json or {}
    key = (d.get("key") or "").strip()
    if key and not key.startswith("sk-ant-"):
        return jsonify(error="Key should start with sk-ant-"), 400
    db_save_setting(email, "anthropic_key", key)
    return jsonify(ok=True, ai_enabled=True)

# ---------------------------------------------------------------------------
# Scraper helpers
# ---------------------------------------------------------------------------
FETCH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,sl;q=0.8,de;q=0.7",
}
FETCH_TIMEOUT = 15
HEAD_TIMEOUT  = 6

TLD_LANG = {
    "si":"slovenian","de":"german","at":"german","ch":"german","fr":"french",
    "es":"spanish","it":"italian","nl":"dutch","pl":"polish","cz":"czech",
    "sk":"slovak","hr":"croatian","rs":"serbian","hu":"hungarian",
    "ro":"romanian","pt":"portuguese","ru":"russian","br":"portuguese",
}
TLD_COUNTRY = {
    "si":"Slovenia","de":"Germany","at":"Austria","ch":"Switzerland",
    "fr":"France","es":"Spain","it":"Italy","nl":"Netherlands","pl":"Poland",
    "cz":"Czech Republic","sk":"Slovakia","hr":"Croatia","rs":"Serbia",
    "hu":"Hungary","ro":"Romania","pt":"Portugal","ru":"Russia",
    "uk":"United Kingdom","be":"Belgium","se":"Sweden","no":"Norway",
    "dk":"Denmark","fi":"Finland",
}

def fetch_url(url):
    r = requests.get(url, headers=FETCH_HEADERS, timeout=FETCH_TIMEOUT, allow_redirects=True)
    r.raise_for_status()
    return r.text, r.url

def page_text(html, max_chars=8000):
    """Strip boilerplate, return clean readable text."""
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script","style","nav","footer","head","noscript","svg","iframe"]):
        tag.decompose()
    # Keep structured text — tables, headings, paragraphs
    text = soup.get_text(separator="\n", strip=True)
    # Collapse blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text[:max_chars]

def dedupe(clients):
    seen, out = {}, []
    for c in clients:
        k = (c.get("name") or "").lower().strip()
        if k and k not in seen:
            seen[k] = True; out.append(c)
    return out

# ---------------------------------------------------------------------------
# AI pipeline
# ---------------------------------------------------------------------------
ANTHROPIC_API = "https://api.anthropic.com/v1/messages"
BUILTIN_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")

def get_api_key(user_key=None):
    return user_key or BUILTIN_KEY or ""

def claude(prompt, api_key, max_tokens=8000, use_search=False):
    """Call Claude, return text. Raises on failure."""
    body = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    if use_search:
        body["tools"] = [{"type": "web_search_20250305", "name": "web_search"}]
        headers["anthropic-beta"] = "web-search-2025-03-05"
    r = requests.post(ANTHROPIC_API, headers=headers, json=body, timeout=180)
    if not r.ok:
        err_body = r.text[:300]
        raise RuntimeError(f"Claude API {r.status_code}: {err_body}")
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"].get("message", "Claude API error"))
    return "".join(b.get("text","") for b in data.get("content",[]) if b.get("type")=="text")

def parse_json(text):
    """Extract first JSON object from text."""
    text = re.sub(r"```json|```", "", text).strip()
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        raise ValueError("No JSON found in response")
    return json.loads(m.group())

# ---------------------------------------------------------------------------
# Main scrape pipeline
# ---------------------------------------------------------------------------
def run_scrape(input_url, logs, user_api_key=None):
    """
    Three-phase intelligence pipeline:
    1. AI web search discovers ALL client/reference pages
    2. Fetch full HTML content of each page
    3. AI analyses all content, returns structured client database
    """
    url = input_url.strip()
    if not re.match(r"^https?://", url):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lstrip("www.")
    tld    = domain.split(".")[-1].lower()
    lang   = TLD_LANG.get(tld, "english")
    country = TLD_COUNTRY.get(tld, "")

    api_key = get_api_key(user_api_key)
    if not api_key:
        return _build_result(domain, domain.split(".")[0].title(), "", lang, country, [], [],
                             error="No Anthropic API key set. Add ANTHROPIC_API_KEY on Railway.")

    logs.append(f"Target: {url}")
    logs.append(f"Domain: {domain} | Language: {lang}")

    # ── Phase 1: AI web search to discover all pages ────────────────────────
    logs.append("Phase 1: AI searching for all client/reference pages...")

    discovery_prompt = f"""Research the company at {url}

Find EVERY page on {domain} that contains client names, case studies, references, testimonials, portfolio projects, or technology partners.

Search strategies:
1. Their main reference/clients/portfolio page (try: {domain}/reference, /clients, /case-studies, /portfolio, /references, /stranke, /klienti, /referenzen, /referencje)
2. Individual case study sub-pages
3. Blog posts that describe client projects  
4. Job postings (these often list real client names as examples of work)
5. Technologies/partners page
6. Any industry-specific reference sub-sections
7. Homepage (logos carousel, testimonials section)

Search in {lang} AND English. Be thorough — check multiple search queries.

Return ONLY valid JSON:
{{
  "company_name": "Official company name",
  "company_description": "One sentence what they do",
  "pages": [
    {{"url": "https://...", "type": "one of: homepage|case_studies_index|case_study|reference_list|testimonials|blog_post|job_listing|partners", "description": "what client info it contains"}}
  ]
}}"""

    comp_name = domain.split(".")[0].replace("-"," ").title()
    comp_desc = ""
    pages_to_fetch = []

    try:
        disc_text = claude(discovery_prompt, api_key, max_tokens=4000, use_search=True)
        disc = parse_json(disc_text)
        comp_name = disc.get("company_name", comp_name)
        comp_desc = disc.get("company_description", "")
        pages_to_fetch = disc.get("pages", [])
        logs.append(f"  Found {len(pages_to_fetch)} pages to analyse:")
        for p in pages_to_fetch:
            logs.append(f"    [{p.get('type','?')}] {p.get('url','')} — {p.get('description','')}")
    except RuntimeError as e:
        err = str(e)
        logs.append(f"  Discovery failed: {err}")
        if "400" in err:
            logs.append("  Hint: web search tool may need anthropic-beta header — check server logs")
        logs.append("  Falling back: fetching input URL directly")
        pages_to_fetch = [{"url": url, "type": "homepage", "description": "direct input"}]
    except Exception as e:
        logs.append(f"  Discovery failed: {e}. Falling back to input URL.")
        pages_to_fetch = [{"url": url, "type": "homepage", "description": "direct input"}]

    # Deduplicate URLs, keep input URL as fallback
    seen_urls = set()
    unique_pages = []
    for p in pages_to_fetch:
        u = p.get("url","")
        if u and u not in seen_urls:
            seen_urls.add(u)
            unique_pages.append(p)
    if not unique_pages:
        unique_pages = [{"url": url, "type": "homepage", "description": "direct input"}]

    # ── Phase 2: Fetch HTML content ──────────────────────────────────────────
    logs.append(f"Phase 2: Fetching content from {len(unique_pages)} page(s)...")

    page_contents = []
    scraped_urls  = []

    for page_info in unique_pages[:15]:
        page_url = page_info.get("url","")
        if not page_url or not page_url.startswith("http"):
            continue
        try:
            html, final_url = fetch_url(page_url)
            text = page_text(html, max_chars=8000)
            page_contents.append({
                "url":  final_url,
                "type": page_info.get("type","unknown"),
                "desc": page_info.get("description",""),
                "text": text,
            })
            scraped_urls.append(final_url)
            logs.append(f"  OK: {final_url} ({len(text)} chars)")
            time.sleep(0.5)
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else 0
            logs.append(f"  HTTP {code}: {page_url}")
        except Exception as e:
            logs.append(f"  Failed: {page_url} — {e}")

    if not page_contents:
        logs.append("Could not fetch any pages.")
        return _build_result(domain, comp_name, comp_desc, lang, country, [], scraped_urls)

    # ── Phase 3: AI analyses all content ─────────────────────────────────────
    logs.append("Phase 3: AI analysing content to extract verified clients...")

    # Build the full content block
    all_content = ""
    for i, p in enumerate(page_contents):
        all_content += f"\n\n{'='*60}\nPAGE {i+1} | {p['url']} | type: {p['type']}\n{'='*60}\n{p['text']}"

    analysis_prompt = f"""You are a senior business intelligence analyst building a verified client database for a sales team.

COMPANY: {comp_name} ({domain})
This company sells products/services. We want to know WHO their clients are.

SCRAPED CONTENT FROM {len(page_contents)} PAGES:
{all_content[:35000]}

YOUR TASK:
Extract every real client/customer this company has publicly worked with. Be thorough and precise.

WHAT TO EXTRACT AS CLIENTS:
- Companies explicitly named as clients, customers, or project recipients
- Names extracted from case study titles: "We built X for Acme Corp" → client is "Acme Corp"
- Names from reference lists (even just a company name in a list = valid client)
- Names from logo walls (alt text naming real companies)
- Names mentioned in testimonial quotes
- Names from job postings as "clients we work with" or project examples

WHAT TO MARK AS technology_partner (NOT clients):
- Software vendors they resell or are certified for (Pimcore, Shopware, SAP, Salesforce, etc.)
- Platforms they partner with (Google, Meta, HubSpot, etc.)
- Hardware suppliers they integrate with

WHAT TO EXCLUDE COMPLETELY (not clients, not partners):
- Navigation/menu items
- Service/product names
- The company's own name and subsidiaries
- Generic words, slogans, contact info
- Certifications and awards

EXTRACTION RULES:
1. From case study headlines: extract ONLY the client company name
   "Za Žak smo povečali prihodek za 80%" → name: "Žak"
   "How Intersport expanded to 4 markets" → name: "Intersport"
   "Custom PIM for SIP Mehanizacija" → name: "SIP Mehanizacija"
2. Normalise names: fix capitalisation, remove trailing punctuation
3. Deduplicate: same company in logo + case study = ONE entry
4. For each client, write a specific evidence note (what project/relationship)

Return ONLY valid JSON, absolutely no markdown or explanation:
{{
  "clients": [
    {{
      "name": "Exact Company Name",
      "industry": "their industry sector",
      "country": "country (guess from context/language/domain)",
      "source_type": "case_study|reference_list|logo|testimonial|blog|job_listing",
      "evidence": "One specific sentence about the project or relationship",
      "confidence": 95
    }}
  ],
  "technology_partners": [
    {{
      "name": "Partner Name",
      "role": "What the partnership is"
    }}
  ],
  "summary": "Found X clients across Y pages. [Key industries and notes]"
}}"""

    try:
        analysis_text = claude(analysis_prompt, api_key, max_tokens=8000)
        result = parse_json(analysis_text)

        raw_clients  = result.get("clients", [])
        tech_partners = result.get("technology_partners", [])
        summary      = result.get("summary", "")

        # Build final client list
        clients = []
        for c in raw_clients:
            if not c.get("name","").strip():
                continue
            clients.append({
                "name":       c.get("name","").strip(),
                "industry":   c.get("industry",""),
                "country":    c.get("country",""),
                "source":     c.get("source_type","reference_list"),
                "ai_note":    c.get("evidence",""),
                "confidence": c.get("confidence", 80),
            })

        for p in tech_partners:
            if not p.get("name","").strip():
                continue
            clients.append({
                "name":       p.get("name","").strip(),
                "industry":   "Technology vendor",
                "country":    "",
                "source":     "technology_partner",
                "ai_note":    p.get("role",""),
                "confidence": 99,
            })

        clients = dedupe(clients)
        real_count = len([c for c in clients if c["source"] != "technology_partner"])
        partner_count = len([c for c in clients if c["source"] == "technology_partner"])
        logs.append(f"  Extracted {real_count} clients + {partner_count} technology partners")
        if summary:
            logs.append(f"  {summary}")

        return _build_result(domain, comp_name, comp_desc, lang, country, clients, scraped_urls)

    except Exception as e:
        logs.append(f"AI analysis failed: {e}")
        return _build_result(domain, comp_name, comp_desc, lang, country, [], scraped_urls,
                             error=str(e))


def _build_result(domain, comp_name, comp_desc, lang, country, clients, scraped_urls, error=None):
    key = re.sub(r"[^a-z0-9.-]", "", domain)
    r = {
        "key":                key,
        "company_name":       comp_name,
        "company_domain":     domain,
        "company_description": comp_desc,
        "detected_language":  lang,
        "detected_country":   country,
        "clients":            clients,
        "sources_checked":    scraped_urls,
        "scraped_at":         datetime.now().isoformat(),
        "ai_cleaned":         True,
    }
    if error:
        r["error"] = error
    return r


# ---------------------------------------------------------------------------
# Scrape API route
# ---------------------------------------------------------------------------
@app.route("/api/scrape", methods=["POST"])
def scrape_endpoint():
    email = session.get("email")
    if not email:
        return jsonify(error="Not logged in"), 401
    d = request.json or {}
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify(error="URL required"), 400

    logs = []
    try:
        user_key = db_get_setting(email, "anthropic_key") or ""
        result   = run_scrape(url, logs, user_api_key=user_key)
        db_save_entry(email, result["key"], result)
        return jsonify(result=result, logs=logs)
    except requests.exceptions.ConnectionError:
        msg = f"Could not connect to {url} — site may be unreachable or blocking this server."
        return jsonify(error=msg, logs=logs), 422
    except requests.exceptions.Timeout:
        msg = f"Timed out connecting to {url}."
        return jsonify(error=msg, logs=logs), 422
    except Exception as e:
        logs.append(f"Unexpected error: {e}")
        return jsonify(error=str(e), logs=logs), 500


# ---------------------------------------------------------------------------
# Error handlers (always return JSON for API routes)
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    return INDEX_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify(error="Method not allowed"), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify(error=f"Internal server error: {e}"), 500


# ---------------------------------------------------------------------------
# Frontend (served as string to avoid path issues on Railway)
# ---------------------------------------------------------------------------
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Client Intelligence</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg0:#0e0e0f;--bg1:#141416;--bg2:#1a1a1d;--bg3:#222226;--bg4:#2a2a2f;
  --border:#2e2e34;--border2:#3a3a42;
  --text0:#f0f0f0;--text1:#b8b8c0;--text2:#72727a;--text3:#484850;
  --accent:#c8f135;
  --blue:#4a9eff;--green:#3dd68c;--orange:#ff8c42;--purple:#b06aff;
  --yellow:#ffd166;--red:#ff5c5c;
  --blue-bg:rgba(74,158,255,.12);--blue-fg:#4a9eff;
  --green-bg:rgba(61,214,140,.12);--green-fg:#3dd68c;
  --orange-bg:rgba(255,140,66,.12);--orange-fg:#ff8c42;
  --purple-bg:rgba(176,106,255,.12);--purple-fg:#c48aff;
  --gray-bg:rgba(114,114,122,.12);--gray-fg:#b8b8c0;
  --mono:'IBM Plex Mono',monospace;
  --sans:'IBM Plex Sans',sans-serif;
}
html,body{height:100%;overflow:hidden}
body{font-family:var(--sans);background:var(--bg0);color:var(--text0);font-size:13px;line-height:1.5}

/* Auth */
#auth{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--bg0);z-index:1000}
.auth-wrap{width:360px}
.auth-logo{text-align:center;margin-bottom:28px}
.auth-icon{display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;background:var(--accent);border-radius:9px;margin-bottom:12px}
.auth-icon svg{width:18px;height:18px;color:#000}
.auth-h1{font-size:21px;font-weight:600;letter-spacing:-.3px}
.auth-sub{color:var(--text2);font-size:12px;margin-top:4px;font-family:var(--mono)}
.auth-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:26px}
.auth-card h2{font-size:15px;font-weight:600;margin-bottom:18px}
.auth-err,.auth-info{padding:8px 12px;border-radius:7px;font-size:12px;margin-bottom:12px;display:none}
.auth-err{background:rgba(255,92,92,.1);border:1px solid rgba(255,92,92,.25);color:#ff8a8a}
.auth-info{background:rgba(74,158,255,.1);border:1px solid rgba(74,158,255,.25);color:#7ab8ff}
.field{margin-bottom:13px}
.field label{display:block;font-size:11px;font-weight:500;color:var(--text2);margin-bottom:5px;text-transform:uppercase;letter-spacing:.6px;font-family:var(--mono)}
.field input{width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:7px;padding:9px 12px;font-size:13px;color:var(--text0);font-family:var(--sans);outline:none;transition:border-color .15s}
.field input:focus{border-color:var(--accent)}
.btn-primary{width:100%;background:var(--accent);color:#0e0e0f;border:none;border-radius:7px;padding:10px;font-size:13px;font-weight:600;cursor:pointer;margin-top:4px;font-family:var(--sans);display:flex;align-items:center;justify-content:center;gap:7px}
.btn-primary:disabled{opacity:.5;cursor:not-allowed}
.auth-links{border-top:1px solid var(--border);margin-top:18px;padding-top:16px;display:flex;flex-direction:column;gap:8px;align-items:center}
.auth-links button{background:none;border:none;cursor:pointer;font-size:12px;color:var(--text2);font-family:var(--sans)}
.auth-links button span{color:var(--accent)}
.auth-foot{text-align:center;margin-top:12px;font-size:11px;color:var(--text3);font-family:var(--mono)}

/* App shell */
#app{display:none;height:100vh;flex-direction:column}
#app.on{display:flex}

/* Topbar */
.topbar{height:48px;background:var(--bg1);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 16px;gap:12px;flex-shrink:0}
.topbar-brand{font-weight:600;font-size:13px;display:flex;align-items:center;gap:8px}
.topbar-icon{width:26px;height:26px;background:var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.topbar-icon svg{width:13px;height:13px;color:#000}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:8px;position:relative}
.ai-badge{background:var(--green-bg);border:1px solid rgba(61,214,140,.3);color:var(--green);font-family:var(--mono);font-size:10px;font-weight:500;padding:3px 9px;border-radius:20px}
.avatar-btn{display:flex;align-items:center;gap:7px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:5px 10px;cursor:pointer;font-size:12px;color:var(--text1)}
.avatar{width:22px;height:22px;border-radius:50%;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#000;flex-shrink:0}
.dropdown{position:absolute;right:0;top:calc(100% + 6px);background:var(--bg3);border:1px solid var(--border2);border-radius:9px;padding:10px;min-width:200px;z-index:100;display:none}
.dropdown.open{display:block}
.dropdown-info{font-size:11px;color:var(--text2);padding-bottom:8px;margin-bottom:8px;border-bottom:1px solid var(--border);font-family:var(--mono)}
.dropdown-info strong{display:block;color:var(--text1);font-weight:500;margin-bottom:2px}
.dropdown button{width:100%;text-align:left;background:none;border:none;cursor:pointer;font-size:12px;color:#ff8a8a;padding:3px 0;font-family:var(--sans)}

/* Filter bar */
.filterbar{height:44px;background:var(--bg1);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;padding:0 16px;flex-shrink:0;overflow-x:auto}
.filterbar::-webkit-scrollbar{display:none}
.chip{padding:5px 12px;border-radius:20px;font-size:11px;font-weight:500;cursor:pointer;border:1px solid var(--border2);color:var(--text2);background:transparent;white-space:nowrap;font-family:var(--sans)}
.chip.on{background:var(--bg4);color:var(--text0);border-color:var(--border2)}

/* Layout */
.layout{display:flex;flex:1;overflow:hidden}

/* Sidebar */
.sidebar{width:272px;flex-shrink:0;background:var(--bg1);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.sidebar-hdr{padding:11px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.sidebar-hdr-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--text2);font-family:var(--mono)}
.sidebar-count{font-size:11px;color:var(--accent);font-family:var(--mono);font-weight:600}
.sidebar-search{padding:9px 12px;border-bottom:1px solid var(--border);flex-shrink:0}
.sidebar-search-wrap{position:relative}
.sidebar-search-icon{position:absolute;left:9px;top:50%;transform:translateY(-50%);color:var(--text3);pointer-events:none}
.sidebar-search input{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:7px 10px 7px 28px;font-size:12px;color:var(--text0);outline:none;font-family:var(--sans)}
.sidebar-list{flex:1;overflow-y:auto}
.sidebar-list::-webkit-scrollbar{width:3px}
.sidebar-list::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.agency-row{display:flex;align-items:center;gap:9px;padding:10px 16px;cursor:pointer;border-left:2px solid transparent}
.agency-row:hover{background:var(--bg2)}
.agency-row.on{background:var(--bg2);border-left-color:var(--accent)}
.agency-logo{width:30px;height:30px;border-radius:7px;background:var(--bg4);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0}
.agency-info{flex:1;min-width:0}
.agency-name{font-size:13px;font-weight:500;color:var(--text1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.agency-row.on .agency-name{color:var(--text0)}
.agency-type{font-size:11px;color:var(--text3);margin-top:1px}
.agency-num{font-size:12px;color:var(--text2);font-family:var(--mono);flex-shrink:0}
.agency-row.on .agency-num{color:var(--accent)}
.sidebar-empty{padding:28px 16px;text-align:center;color:var(--text3);font-size:12px;line-height:1.6}

/* Detail panel */
.detail{flex:1;overflow-y:auto;background:var(--bg0);display:flex;flex-direction:column}
.detail::-webkit-scrollbar{width:4px}
.detail::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.detail-empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;color:var(--text3)}
.detail-empty-icon{font-size:34px;opacity:.3}
.detail-empty p{font-size:13px;font-family:var(--mono)}
.detail-hdr{padding:22px 26px 18px;border-bottom:1px solid var(--border);flex-shrink:0}
.detail-title-row{display:flex;align-items:center;gap:13px;margin-bottom:13px}
.detail-logo-box{width:42px;height:42px;border-radius:10px;background:var(--bg3);border:1px solid var(--border2);display:flex;align-items:center;justify-content:center;font-size:17px;font-weight:700;flex-shrink:0}
.detail-name{font-size:20px;font-weight:600;letter-spacing:-.3px}
.detail-domain{font-size:12px;color:var(--text2);font-family:var(--mono);margin-top:2px}
.detail-badges{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:14px}
.src-badge{padding:3px 9px;border-radius:5px;font-size:11px;font-weight:600;font-family:var(--mono)}
.stats-row{display:flex;gap:26px}
.stat{display:flex;flex-direction:column;gap:2px}
.stat-num{font-size:24px;font-weight:600;color:var(--accent);font-family:var(--mono);line-height:1}
.stat-label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px}

/* Table */
.table-area{padding:0 26px 26px;flex:1}
.table-toolbar{display:flex;align-items:center;gap:9px;padding:14px 0 11px;border-bottom:1px solid var(--border);margin-bottom:0}
.table-search-wrap{position:relative;display:flex;align-items:center}
.table-search-wrap svg{position:absolute;left:9px;color:var(--text3);pointer-events:none}
.table-search{background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:7px 10px 7px 28px;font-size:12px;color:var(--text0);outline:none;font-family:var(--sans);width:220px}
.table-count{font-size:11px;color:var(--text2);font-family:var(--mono);margin-left:auto}
.remove-btn{background:none;border:1px solid var(--border);border-radius:6px;padding:5px 10px;color:var(--text3);font-size:11px;cursor:pointer;font-family:var(--mono)}
.remove-btn:hover{color:var(--red);border-color:rgba(255,92,92,.4)}
table{width:100%;border-collapse:collapse}
thead tr{border-bottom:1px solid var(--border)}
thead th{padding:9px 10px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.7px;color:var(--text3);text-align:left;font-family:var(--mono);white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
tbody tr:hover{background:var(--bg2)}
tbody tr:last-child{border-bottom:none}
td{padding:11px 10px;vertical-align:top;font-size:13px}
.td-num{color:var(--text3);font-family:var(--mono);font-size:11px;white-space:nowrap;width:28px}
.td-name{font-weight:600;color:var(--text0);min-width:120px}
.td-ind{color:var(--text1);min-width:100px}
.td-ctr{color:var(--text2);font-size:12px;white-space:nowrap}
.td-src{}
.td-note{color:var(--text2);font-size:12px;line-height:1.4;min-width:160px}
.src-tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;font-family:var(--mono);white-space:nowrap}
.s-case{background:var(--blue-bg);color:var(--blue-fg)}
.s-ref{background:var(--green-bg);color:var(--green-fg)}
.s-logo{background:var(--orange-bg);color:var(--orange-fg)}
.s-testi{background:var(--purple-bg);color:var(--purple-fg)}
.s-blog{background:var(--green-bg);color:var(--green-fg)}
.s-job{background:var(--purple-bg);color:var(--purple-fg)}
.s-partner{background:rgba(255,255,255,.06);color:var(--text2)}
.s-other{background:var(--gray-bg);color:var(--gray-fg)}
.section-divider td{padding:7px 10px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.7px;color:var(--text2);background:var(--bg2);border-top:1px solid var(--border);font-family:var(--mono)}
.empty-table{text-align:center;padding:40px;color:var(--text3);font-family:var(--mono);font-size:12px}

/* Scrape bar */
.scrape-bar{border-top:1px solid var(--border);background:var(--bg1);padding:12px 26px;flex-shrink:0}
.scrape-row{display:flex;gap:8px}
.scrape-input{flex:1;background:var(--bg3);border:1px solid var(--border2);border-radius:7px;padding:9px 13px;font-size:13px;color:var(--text0);font-family:var(--mono);outline:none}
.scrape-input:focus{border-color:var(--accent)}
.scrape-input::placeholder{color:var(--text3)}
.scrape-btn{background:var(--accent);color:#000;border:none;border-radius:7px;padding:9px 18px;font-size:13px;font-weight:600;cursor:pointer;font-family:var(--sans);display:flex;align-items:center;gap:7px;white-space:nowrap}
.scrape-btn:disabled{opacity:.5;cursor:not-allowed}
.scrape-status{display:none;align-items:center;gap:8px;font-size:11px;color:var(--text2);font-family:var(--mono);margin-top:7px}
.scrape-status.on{display:flex}
.scrape-hint{font-size:11px;color:var(--text3);font-family:var(--mono);margin-top:5px}
.scrape-err{font-size:11px;color:#ff8a8a;font-family:var(--mono);margin-top:5px;display:none}
.scrape-err.on{display:block}
.log-toggle{background:none;border:1px solid var(--border);border-radius:5px;padding:2px 7px;cursor:pointer;color:var(--text3);font-size:10px;font-family:var(--mono);margin-left:auto}
.log-box{background:var(--bg0);border:1px solid var(--border);border-radius:7px;padding:8px 12px;max-height:120px;overflow-y:auto;font-family:var(--mono);font-size:10px;color:var(--text2);line-height:1.7;margin-top:6px;display:none}
.log-box.on{display:block}

/* Settings modal */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:500;align-items:center;justify-content:center;display:none}
.modal-bg.on{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border2);border-radius:14px;width:440px;max-width:95vw;padding:26px}
.modal-title{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.modal-title h2{font-size:15px;font-weight:600}
.modal-close{background:none;border:none;cursor:pointer;color:var(--text2);font-size:20px;line-height:1}
.modal-section{margin-bottom:18px;padding:13px;background:var(--bg3);border-radius:9px;border:1px solid var(--border)}
.modal-section-title{font-size:12px;font-weight:600;color:var(--text1);margin-bottom:6px;display:flex;align-items:center;gap:8px}
.modal-section-desc{font-size:12px;color:var(--text2);line-height:1.6}
.key-row{display:flex;gap:8px;margin-top:12px}
.key-row input{flex:1;background:var(--bg3);border:1px solid var(--border2);border-radius:7px;padding:8px 12px;font-size:12px;color:var(--text0);font-family:var(--mono);outline:none}
.key-row input:focus{border-color:var(--accent)}
.key-save-btn{background:var(--accent);color:#000;border:none;border-radius:7px;padding:8px 14px;font-size:12px;font-weight:600;cursor:pointer;font-family:var(--sans);white-space:nowrap}
.key-msg{font-size:11px;margin-top:6px;font-family:var(--mono)}
.modal-hint{font-size:11px;color:var(--text3);line-height:1.7;font-family:var(--mono)}

/* Spinner */
.spin{display:inline-block;width:12px;height:12px;border-radius:50%;border:2px solid rgba(255,255,255,.15);border-top-color:var(--text1);animation:spin .7s linear infinite;flex-shrink:0}
.spin-dark{border-color:rgba(0,0,0,.2);border-top-color:#000}
@keyframes spin{to{transform:rotate(360deg)}}

@media(max-width:600px){
  .sidebar{width:220px}
  .detail-hdr,.table-area{padding-left:16px;padding-right:16px}
}
</style>
</head>
<body>

<!-- AUTH -->
<div id="auth">
  <div class="auth-wrap">
    <div class="auth-logo">
      <div class="auth-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg></div>
      <div class="auth-h1">Client Intelligence</div>
      <div class="auth-sub">// competitor client discovery</div>
    </div>
    <div class="auth-card">
      <h2 id="authTitle">Sign in</h2>
      <div class="auth-err" id="authErr"></div>
      <div class="auth-info" id="authInfo"></div>
      <div class="field"><label>Email</label><input type="email" id="authEmail" placeholder="you@company.com" autocomplete="email"></div>
      <div class="field" id="pwField"><label>Password</label><input type="password" id="authPw" placeholder="Min 8 characters"></div>
      <div class="field" id="pw2Field" style="display:none"><label>Confirm password</label><input type="password" id="authPw2" placeholder="Repeat password"></div>
      <button class="btn-primary" id="authBtn" onclick="doAuth()">Sign in</button>
      <div class="auth-links" id="authLinks1">
        <button onclick="setMode('signup')">No account? <span>Create one</span></button>
        <button onclick="setMode('reset')">Forgot password?</button>
      </div>
      <div class="auth-links" id="authLinks2" style="display:none">
        <button onclick="setMode('login')">Back to sign in</button>
      </div>
    </div>
    <div class="auth-foot">passwords hashed with SHA-256</div>
  </div>
</div>

<!-- APP -->
<div id="app">
  <!-- topbar -->
  <nav class="topbar">
    <div class="topbar-brand">
      <div class="topbar-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg></div>
      Client Intel
    </div>
    <div style="font-size:11px;color:var(--text3);font-family:var(--mono)">// competitor intelligence</div>
    <div class="topbar-right">
      <span class="ai-badge">AI ON</span>
      <button onclick="showSettings()" style="background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:5px 10px;cursor:pointer;font-size:11px;color:var(--text2);font-family:var(--mono)">Settings</button>
      <button class="avatar-btn" onclick="toggleDrop()">
        <span class="avatar" id="avLetter">?</span>
        <span id="avEmail" style="max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono)"></span>
      </button>
      <div class="dropdown" id="dropdown">
        <div class="dropdown-info"><strong id="dropEmail"></strong><span id="dropStats"></span></div>
        <button onclick="doLogout()">Sign out</button>
      </div>
    </div>
  </nav>

  <!-- filter chips -->
  <div class="filterbar" id="filterbar">
    <button class="chip on" data-f="all" onclick="setFilter('all',this)">All</button>
  </div>

  <!-- main -->
  <div class="layout">
    <!-- sidebar -->
    <aside class="sidebar">
      <div class="sidebar-hdr">
        <span class="sidebar-hdr-label">Companies</span>
        <span class="sidebar-count" id="sideCount">0</span>
      </div>
      <div class="sidebar-search">
        <div class="sidebar-search-wrap">
          <svg class="sidebar-search-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <input type="text" id="sideQ" placeholder="Search..." oninput="renderSidebar()">
        </div>
      </div>
      <div class="sidebar-list" id="sideList">
        <div class="sidebar-empty">No companies yet.<br>Paste a URL below to start.</div>
      </div>
    </aside>

    <!-- detail -->
    <main class="detail" id="detail">
      <div class="detail-empty" id="detailEmpty">
        <div class="detail-empty-icon">&#128269;</div>
        <p>Select a company or scrape a new one</p>
      </div>
      <div id="detailContent" style="display:none">
        <div class="detail-hdr">
          <div class="detail-title-row">
            <div class="detail-logo-box" id="dLogo"></div>
            <div>
              <div class="detail-name" id="dName"></div>
              <div class="detail-domain"><a id="dDomain" href="#" target="_blank" style="color:var(--text2);text-decoration:none;font-family:var(--mono);font-size:12px"></a></div>
            </div>
          </div>
          <div class="detail-badges" id="dBadges"></div>
          <div class="stats-row">
            <div class="stat"><span class="stat-num" id="dCount">0</span><span class="stat-label">Clients</span></div>
            <div class="stat"><span class="stat-num" id="dIndustries">0</span><span class="stat-label">Industries</span></div>
            <div class="stat" id="dCountryStat"><span class="stat-num" id="dCountries">0</span><span class="stat-label">Countries</span></div>
          </div>
        </div>
        <div class="table-area">
          <div class="table-toolbar">
            <div class="table-search-wrap">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
              <input class="table-search" type="text" id="tableQ" placeholder="Filter clients..." oninput="renderTable()">
            </div>
            <span class="table-count" id="tableCount"></span>
            <button class="remove-btn" onclick="deleteCompany()">Remove</button>
          </div>
          <table>
            <thead><tr>
              <th class="td-num">#</th>
              <th style="min-width:130px">Company</th>
              <th style="min-width:110px">Industry</th>
              <th style="min-width:80px">Country</th>
              <th style="min-width:90px">Source</th>
              <th>Evidence / project</th>
            </tr></thead>
            <tbody id="clientTbody"></tbody>
          </table>
        </div>
      </div>
    </main>
  </div>

  <!-- scrape bar -->
  <div class="scrape-bar">
    <div class="scrape-row">
      <input class="scrape-input" type="text" id="scrapeInput"
        placeholder="https://www.optiweb.com  or  metronik.si  or  any company URL"
        onkeydown="if(event.key==='Enter'&&!S.loading)doScrape()">
      <button class="scrape-btn" id="scrapeBtn" onclick="doScrape()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        Scrape
      </button>
    </div>
    <div class="scrape-status" id="scrapeStatus">
      <span class="spin"></span>
      <span id="statusMsg">Working...</span>
      <button class="log-toggle" onclick="toggleLog()">logs</button>
    </div>
    <div class="scrape-err" id="scrapeErr"></div>
    <div class="log-box" id="logBox"></div>
    <div class="scrape-hint">AI searches web + fetches pages + extracts verified clients &mdash; 3-phase pipeline</div>
  </div>
</div>

<!-- Settings modal -->
<div class="modal-bg" id="settingsModal">
  <div class="modal">
    <div class="modal-title">
      <h2>Settings</h2>
      <button class="modal-close" onclick="hideSettings()">&times;</button>
    </div>
    <div class="modal-section">
      <div class="modal-section-title"><span style="color:var(--green)">&#9679;</span> AI Pipeline &mdash; Active</div>
      <div class="modal-section-desc">
        3-phase intelligence: web search discovers all client pages &rarr; full HTML fetched &rarr;
        Claude extracts verified clients with industry, country, source type and evidence note.
        Technology partners are automatically separated from real clients.
      </div>
    </div>
    <div class="modal-section">
      <div class="modal-section-title">Custom Anthropic API key (optional)</div>
      <div class="modal-section-desc">Add your own key to use your quota instead of the built-in key.</div>
      <div class="key-row">
        <input type="password" id="keyInput" placeholder="sk-ant-...  (leave blank to use built-in)">
        <button class="key-save-btn" onclick="saveKey()">Save</button>
      </div>
      <div class="key-msg" id="keyMsg"></div>
    </div>
    <div class="modal-hint">
      Built-in key is always active &mdash; no setup needed.<br>
      Get your own key at console.anthropic.com &rarr; API Keys.
    </div>
  </div>
</div>

<script>
// ── State ────────────────────────────────────────────────────────────────────
const S = { user:null, repo:{}, selected:null, filter:"all", loading:false, showLog:false };

const SRC_LABEL = {
  case_study:"Case Study", reference_list:"Reference", reference:"Reference",
  logo:"Logo", testimonial:"Testimonial", blog:"Blog", job_listing:"Job Listing",
  technology_partner:"Tech Partner",
};
const SRC_CLASS = {
  case_study:"s-case", reference_list:"s-ref", reference:"s-ref",
  logo:"s-logo", testimonial:"s-testi", blog:"s-blog", job_listing:"s-job",
  technology_partner:"s-partner",
};
const TYPE_COLORS = {
  "Performance Marketing":"#ff8c42","System Integrator":"#4a9eff",
  "AI Agency":"#b06aff","Webflow Agency":"#3dd68c","Design Agency":"#ffd166",
  "Dev Agency":"#c8f135","Digital Agency":"#4a9eff",
};

// ── API ──────────────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const opts = { method, credentials:"include", headers:{"Content-Type":"application/json"} };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  const ct = r.headers.get("content-type") || "";
  if (!ct.includes("application/json")) {
    const t = await r.text();
    throw new Error("Server error (" + r.status + "): " + t.slice(0,120));
  }
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || "Request failed");
  return data;
}

// ── Boot ─────────────────────────────────────────────────────────────────────
async function init() {
  try {
    const me = await api("GET","/api/me");
    S.repo = await api("GET","/api/repo");
    loginDone(me.email);
  } catch { showAuth(); }
}

function showAuth() {
  document.getElementById("auth").style.display = "flex";
  document.getElementById("app").classList.remove("on");
}

function loginDone(email) {
  S.user = email;
  document.getElementById("auth").style.display = "none";
  document.getElementById("app").classList.add("on");
  document.getElementById("avLetter").textContent = email[0].toUpperCase();
  document.getElementById("avEmail").textContent = email;
  document.getElementById("dropEmail").textContent = email;
  renderAll();
}

// ── Auth ──────────────────────────────────────────────────────────────────────
let authMode = "login";
function setMode(m) {
  authMode = m;
  document.getElementById("authErr").style.display="none";
  document.getElementById("authInfo").style.display="none";
  const T={login:"Sign in",signup:"Create account",reset:"Reset password"};
  const B={login:"Sign in",signup:"Create account",reset:"Send reset link"};
  document.getElementById("authTitle").textContent = T[m];
  document.getElementById("authBtn").textContent   = B[m];
  document.getElementById("pwField").style.display  = m==="reset"?"none":"";
  document.getElementById("pw2Field").style.display = m==="signup"?"":"none";
  document.getElementById("authLinks1").style.display = m==="login"?"":"none";
  document.getElementById("authLinks2").style.display = m!=="login"?"":"none";
}

["authEmail","authPw","authPw2"].forEach(id =>
  document.getElementById(id).addEventListener("keydown", e => { if(e.key==="Enter") doAuth(); })
);

async function doAuth() {
  const email = document.getElementById("authEmail").value.trim().toLowerCase();
  const pw    = document.getElementById("authPw").value;
  const pw2   = document.getElementById("authPw2").value;
  const errEl = document.getElementById("authErr");
  const infEl = document.getElementById("authInfo");
  errEl.style.display = infEl.style.display = "none";
  const btn = document.getElementById("authBtn");
  btn.disabled = true;
  btn.innerHTML = "<span class='spin spin-dark'></span> Please wait...";
  try {
    if (authMode === "login") {
      await api("POST","/api/login",{email,password:pw});
      S.repo = await api("GET","/api/repo");
      loginDone(email);
    } else if (authMode === "signup") {
      if (pw.length < 8) throw new Error("Password must be at least 8 characters");
      if (pw !== pw2) throw new Error("Passwords do not match");
      await api("POST","/api/signup",{email,password:pw});
      S.repo = {};
      loginDone(email);
    } else {
      infEl.textContent = "If an account exists, a reset link would be sent. (Requires backend SMTP.)";
      infEl.style.display = "block";
    }
  } catch(e) {
    errEl.textContent = e.message;
    errEl.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = {login:"Sign in",signup:"Create account",reset:"Send reset link"}[authMode];
  }
}

async function doLogout() {
  await api("POST","/api/logout").catch(()=>{});
  S.user=null; S.repo={}; S.selected=null;
  document.getElementById("dropdown").classList.remove("open");
  showAuth();
}

function toggleDrop() { document.getElementById("dropdown").classList.toggle("open"); }
document.addEventListener("click", e => {
  if (!e.target.closest(".topbar-right")) document.getElementById("dropdown").classList.remove("open");
});

// ── Scrape ────────────────────────────────────────────────────────────────────
async function doScrape() {
  const url = document.getElementById("scrapeInput").value.trim();
  if (!url || S.loading) return;
  S.loading = true;
  const btn   = document.getElementById("scrapeBtn");
  const stat  = document.getElementById("scrapeStatus");
  const errEl = document.getElementById("scrapeErr");
  const logBox= document.getElementById("logBox");
  btn.disabled = true;
  btn.innerHTML = "<span class='spin spin-dark'></span> Scraping...";
  stat.classList.add("on");
  errEl.classList.remove("on");
  logBox.innerHTML = "";
  document.getElementById("statusMsg").textContent = "Phase 1: Searching for client pages...";
  try {
    const r = await api("POST","/api/scrape",{url});
    (r.logs||[]).forEach(l => {
      document.getElementById("statusMsg").textContent = l.slice(0,80);
      const d = document.createElement("div"); d.textContent = l;
      logBox.appendChild(d); logBox.scrollTop = logBox.scrollHeight;
    });
    S.repo = await api("GET","/api/repo");
    renderAll();
    if (r.result?.key) selectCompany(r.result.key);
    document.getElementById("scrapeInput").value = "";
    if (r.result?.error) {
      errEl.textContent = r.result.error;
      errEl.classList.add("on");
    }
  } catch(e) {
    errEl.textContent = e.message;
    errEl.classList.add("on");
  } finally {
    S.loading = false;
    btn.disabled = false;
    btn.innerHTML = "<svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.5'><circle cx='11' cy='11' r='8'/><path d='m21 21-4.35-4.35'/></svg> Scrape";
    stat.classList.remove("on");
  }
}

function toggleLog() {
  S.showLog = !S.showLog;
  document.getElementById("logBox").classList.toggle("on", S.showLog);
}

async function deleteCompany() {
  if (!S.selected || !confirm("Remove this company?")) return;
  await api("DELETE","/api/repo/"+S.selected);
  delete S.repo[S.selected];
  S.selected = null;
  document.getElementById("detailContent").style.display = "none";
  document.getElementById("detailEmpty").style.display   = "flex";
  renderAll();
}

// ── Settings ──────────────────────────────────────────────────────────────────
function showSettings() { document.getElementById("settingsModal").classList.add("on"); }
function hideSettings() { document.getElementById("settingsModal").classList.remove("on"); }
document.getElementById("settingsModal").addEventListener("click", function(e){ if(e.target===this) hideSettings(); });

async function saveKey() {
  const key = document.getElementById("keyInput").value.trim();
  const msg = document.getElementById("keyMsg");
  try {
    await api("POST","/api/settings/apikey",{key});
    msg.style.color = "var(--green)";
    msg.textContent = key ? "Key saved. Your quota will be used." : "Key cleared. Built-in key active.";
  } catch(e) {
    msg.style.color = "var(--red)";
    msg.textContent = e.message;
  }
}

// ── Render ────────────────────────────────────────────────────────────────────
function renderAll() {
  buildFilterBar();
  renderSidebar();
  updateDropStats();
  if (S.selected && S.repo[S.selected]) renderDetail(S.selected);
}

function getTypeColor(c) {
  if (c.detected_language === "slovenian") return "#c8f135";
  if (c.detected_language === "german")    return "#4a9eff";
  if (c.detected_language === "croatian")  return "#3dd68c";
  return "#b8b8c0";
}

function buildFilterBar() {
  const types = new Set(["all"]);
  Object.values(S.repo).forEach(c => { if(c.agency_type) types.add(c.agency_type); });
  const bar = document.getElementById("filterbar");
  bar.innerHTML = "";
  types.forEach(t => {
    const b = document.createElement("button");
    b.className = "chip" + (S.filter===t?" on":"");
    b.dataset.f = t;
    b.textContent = t==="all" ? "All" : t;
    b.onclick = () => setFilter(t,b);
    bar.appendChild(b);
  });
}

function setFilter(f, el) {
  S.filter = f;
  document.querySelectorAll(".chip").forEach(c=>c.classList.remove("on"));
  el.classList.add("on");
  renderSidebar();
}

function renderSidebar() {
  const companies = Object.values(S.repo);
  const q = (document.getElementById("sideQ").value||"").toLowerCase();
  const filtered = companies.filter(c => {
    if (S.filter!=="all" && c.agency_type!==S.filter) return false;
    if (q && !c.company_name.toLowerCase().includes(q) &&
        !(c.clients||[]).some(cl=>cl.name.toLowerCase().includes(q))) return false;
    return true;
  }).sort((a,b)=>(b.clients||[]).filter(c=>c.source!=="technology_partner").length -
                 (a.clients||[]).filter(c=>c.source!=="technology_partner").length);

  document.getElementById("sideCount").textContent = filtered.length;
  const list = document.getElementById("sideList");
  if (!filtered.length) {
    list.innerHTML = "<div class='sidebar-empty'>No companies yet.<br>Paste a URL below to start.</div>";
    return;
  }
  const color = c => getTypeColor(c);
  list.innerHTML = filtered.map(c => {
    const n = (c.clients||[]).filter(cl=>cl.source!=="technology_partner").length;
    const col = color(c);
    return `<div class="agency-row${S.selected===c.key?" on":""}" onclick="selectCompany('${esc(c.key)}')">
      <div class="agency-logo" style="color:${col};background:${col}18;border:1px solid ${col}25">${(c.company_name||"?")[0].toUpperCase()}</div>
      <div class="agency-info">
        <div class="agency-name">${esc(c.company_name)}</div>
        <div class="agency-type">${esc(c.detected_country||c.detected_language||"")}</div>
      </div>
      <div class="agency-num">${n}</div>
    </div>`;
  }).join("");
}

function selectCompany(key) {
  S.selected = key;
  renderSidebar();
  renderDetail(key);
}

function renderDetail(key) {
  const c = S.repo[key];
  if (!c) return;
  document.getElementById("detailEmpty").style.display    = "none";
  document.getElementById("detailContent").style.display = "block";

  const col = getTypeColor(c);
  const logoEl = document.getElementById("dLogo");
  logoEl.textContent = (c.company_name||"?")[0].toUpperCase();
  logoEl.style.cssText = `width:42px;height:42px;border-radius:10px;background:${col}18;border:1px solid ${col}30;display:flex;align-items:center;justify-content:center;font-size:17px;font-weight:700;flex-shrink:0;color:${col}`;

  document.getElementById("dName").textContent = c.company_name;
  const domEl = document.getElementById("dDomain");
  domEl.textContent = c.company_domain;
  domEl.href = "https://"+c.company_domain;

  // Source breakdown badges
  const srcMap = {};
  (c.clients||[]).forEach(cl => {
    const s = cl.source||"reference";
    const label = cl.source==="technology_partner" ? "Tech Partner" :
                  cl.source==="case_study"  ? "Case Study" :
                  cl.source==="reference_list"||cl.source==="reference" ? "Reference" :
                  cl.source==="logo" ? "Logo" :
                  cl.source==="testimonial" ? "Testimonial" :
                  cl.source==="blog" ? "Blog" :
                  cl.source==="job_listing" ? "Job Listing" : s;
    const cls   = cl.source==="technology_partner" ? "s-partner" :
                  cl.source==="case_study" ? "s-case" :
                  cl.source==="reference_list"||cl.source==="reference" ? "s-ref" :
                  cl.source==="logo" ? "s-logo" : "s-other";
    if (!srcMap[label]) srcMap[label] = {count:0, cls};
    srcMap[label].count++;
  });
  document.getElementById("dBadges").innerHTML =
    Object.entries(srcMap).sort((a,b)=>b[1].count-a[1].count)
      .map(([l,v])=>`<span class="src-badge ${v.cls}">${v.count} ${l}${v.count>1?"s":""}</span>`).join("");

  const clients = c.clients||[];
  const realClients = clients.filter(cl=>cl.source!=="technology_partner");
  document.getElementById("dCount").textContent = realClients.length;
  const industries = new Set(realClients.map(cl=>cl.industry).filter(Boolean));
  document.getElementById("dIndustries").textContent = industries.size;
  const countries  = new Set(realClients.map(cl=>cl.country).filter(Boolean));
  const cstat = document.getElementById("dCountryStat");
  cstat.style.display = countries.size>0?"":"none";
  document.getElementById("dCountries").textContent = countries.size;

  document.getElementById("tableQ").value = "";
  renderTable();
}

function srcTag(src) {
  const label = SRC_LABEL[src] || src || "Reference";
  const cls   = SRC_CLASS[src]  || "s-other";
  return `<span class="src-tag ${cls}">${esc(label)}</span>`;
}

function renderTable() {
  const c = S.repo[S.selected];
  if (!c) return;
  const q = (document.getElementById("tableQ").value||"").toLowerCase();
  const all = (c.clients||[]).filter(cl =>
    !q || cl.name.toLowerCase().includes(q) ||
    (cl.industry||"").toLowerCase().includes(q) ||
    (cl.country||"").toLowerCase().includes(q) ||
    (cl.ai_note||"").toLowerCase().includes(q)
  );
  const real     = all.filter(cl => cl.source !== "technology_partner");
  const partners = all.filter(cl => cl.source === "technology_partner");
  const total    = (c.clients||[]).filter(cl=>cl.source!=="technology_partner").length;
  document.getElementById("tableCount").textContent =
    q ? `${real.length} of ${total} clients` : `${total} clients`;

  const tbody = document.getElementById("clientTbody");
  if (!all.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-table">No clients found${q?` matching "${q}"`:""}.</td></tr>`;
    return;
  }

  const makeRow = (cl, i) => `
    <tr>
      <td class="td-num">${i+1}</td>
      <td class="td-name">${esc(cl.name)}</td>
      <td class="td-ind">${esc(cl.industry||"")}</td>
      <td class="td-ctr">${esc(cl.country||"")}</td>
      <td class="td-src">${srcTag(cl.source)}</td>
      <td class="td-note">${esc((cl.ai_note||"").slice(0,100))}${(cl.ai_note||"").length>100?"...":""}</td>
    </tr>`;

  let html = real.map((cl,i) => makeRow(cl,i+1)).join("");
  if (partners.length) {
    html += `<tr class="section-divider"><td colspan="6">Technology partners</td></tr>`;
    html += partners.map((cl,i) => makeRow(cl,i+1)).join("");
  }
  tbody.innerHTML = html;
}

function updateDropStats() {
  const n = Object.keys(S.repo).length;
  const t = new Set(Object.values(S.repo)
    .flatMap(r=>(r.clients||[])
      .filter(c=>c.source!=="technology_partner")
      .map(c=>c.name.toLowerCase()))).size;
  document.getElementById("dropStats").textContent = `${n} companies, ${t} clients`;
}

function esc(s) {
  return (s||"").toString()
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

init();
</script>
</body>
</html>
"""

@app.route("/")
@app.route("/<path:path>")
def frontend(path=""):
    if path and path.startswith("api/"):
        return jsonify(error="Not found"), 404
    return INDEX_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  Client Intelligence running at http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
