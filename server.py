import re
import json
import time
import hashlib
import secrets
import os
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse

from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__, template_folder=TEMPLATES_DIR)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=30)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
CORS(app, supports_credentials=True)

# ---- storage ------------------------------------------------------------------

def users_file():
    return os.path.join(DATA_DIR, "users.json")

def repo_file(email):
    h = hashlib.md5(email.encode()).hexdigest()
    return os.path.join(DATA_DIR, f"repo_{h}.json")

def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ---- auth routes --------------------------------------------------------------

@app.route("/api/signup", methods=["POST"])
def signup():
    d = request.json or {}
    email = (d.get("email") or "").strip().lower()
    pw = d.get("password") or ""
    if not email or not pw:
        return jsonify(error="Email and password required"), 400
    if len(pw) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400
    users = load_json(users_file(), {})
    if email in users:
        return jsonify(error="An account with this email already exists"), 400
    users[email] = {"email": email, "ph": hash_pw(pw), "created": datetime.now().isoformat()}
    save_json(users_file(), users)
    session.permanent = True
    session["email"] = email
    return jsonify(ok=True, email=email)

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    email = (d.get("email") or "").strip().lower()
    pw = d.get("password") or ""
    users = load_json(users_file(), {})
    user = users.get(email)
    if not user:
        return jsonify(error="No account found with this email"), 401
    if user["ph"] != hash_pw(pw):
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

# ---- repo routes --------------------------------------------------------------

@app.route("/api/repo")
def get_repo():
    email = session.get("email")
    if not email:
        return jsonify(error="Not logged in"), 401
    return jsonify(load_json(repo_file(email), {}))

@app.route("/api/repo/<key>", methods=["DELETE"])
def delete_entry(key):
    email = session.get("email")
    if not email:
        return jsonify(error="Not logged in"), 401
    repo = load_json(repo_file(email), {})
    repo.pop(key, None)
    save_json(repo_file(email), repo)
    return jsonify(ok=True)

# ---- scraper ------------------------------------------------------------------

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,sl;q=0.8,de;q=0.7",
}

CLIENT_PATH_RE = re.compile(
    r"/(clients?|customers?|references?|testimonials?|portfolio|partners?|"
    r"case-studies?|our-clients?|referencje|werk|realisations?|projets?|"
    r"projekte?|realizacje|arbeiten|reference|stranke|nase-stranke|"
    r"partnerji|klienti|referenzen|kunden|clientes?|referencias?|"
    r"proyectos?|clienti|referenze|progetti|klijenti|partneri|"
    r"klanten|referenties|opdrachtgevers|projecten|klienci|"
    r"referencie|zakaznici|projekty|work|our-work|selected-work)(/|$)",
    re.IGNORECASE,
)

CASE_STUDY_RE = re.compile(
    r"/(case-studies?|portfolio|werk|projets?|projekte?|trabajo|lavori|"
    r"realizacje|reference|references?|client|clients?|customers?|work|projects?|case)"
    r"/([^/?#]{2,})",
    re.IGNORECASE,
)

SKIP = {
    "home","about","contact","services","blog","news","products","pricing",
    "login","signup","privacy","terms","faq","search","menu","loading",
    "read more","learn more","see more","view all","next","previous","back",
    "more","all","featured","selected","development","design","migration",
    "redesign","maintenance","seo","optimization","integration","localization",
    "webflow","case study","case studies","portfolio","our work","showing",
    "out of","projects","clear all","filter","app development","trusted by",
    "load more","get started","schedule","contact us","about us","our team",
    "wordpress","shopify","squarespace","wix","drupal",
}

CLIENT_KW = [
    "our clients","our customers","clients","references","testimonials",
    "case studies","partners","who we work","trusted by","our portfolio",
    "our work","selected work","featured clients","client work",
    "nase stranke","nasi klienti","reference","stranke","partnerji",
    "unsere kunden","referenzen","kunden","projekte",
    "nos clients","references","temoignages",
    "nuestros clientes","clientes","referencias",
    "i nostri clienti","clienti","referenze",
    "nasi klijenti","klijenti",
    "onze klanten","klanten","referenties",
    "nasi klienci","klienci","referencje",
    "nasi klienti","zakaznici","referencie",
]

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

def clean(text):
    return re.sub(r"\s+", " ", (text or "")).strip().strip("-*>|#").strip()

def is_name(text):
    t = (text or "").strip()
    if not t or len(t) < 2 or len(t) > 100: return False
    if re.match(r"^(https?:|www\.|tel:|email:|@|[0-9]{4,})", t): return False
    if t.lower() in SKIP: return False
    if re.match(r"^(development|design|migration|redesign|seo|maintenance|"
                r"optimization|integration|localization|app development|webflow|"
                r"wordpress|shopify|squarespace|wix)$", t, re.I): return False
    if not re.search(r"[a-zA-Z\u00c0-\u024f]", t): return False
    return True

def slug_to_name(slug):
    return " ".join(w.capitalize() for w in re.split(r"[-_]", slug))

def fetch_page(url):
    r = requests.get(url, headers=HEADERS, timeout=15, allow_redirects=True)
    r.raise_for_status()
    return BeautifulSoup(r.text, "lxml"), r.url

def from_tables(soup):
    out = []
    for table in soup.find_all("table"):
        rows = table.find_all("tr")
        if len(rows) < 2: continue
        hdrs = [c.get_text(strip=True).lower() for c in rows[0].find_all(["th","td"])]
        name_re = re.compile(r"naziv|name|company|podjetje|firma|klient|client|stranka|organization|empresa|azienda", re.I)
        ni = next((i for i,h in enumerate(hdrs) if name_re.search(h)), 0)
        ii = next((i for i,h in enumerate(hdrs) if re.search(r"dejavnost|industry|sector|branch", h)), -1)
        ci = next((i for i,h in enumerate(hdrs) if re.search(r"drzava|country|land|pays|paese", h)), -1)
        xi = next((i for i,h in enumerate(hdrs) if re.search(r"mesto|city|stadt|ciudad|ville", h)), -1)
        for row in rows[1:]:
            cells = row.find_all(["td","th"])
            if len(cells) <= ni: continue
            name = clean(cells[ni].get_text())
            if not is_name(name): continue
            e = {"name": name, "source": "table"}
            if ii >= 0 and len(cells) > ii:
                v = clean(cells[ii].get_text())
                if v: e["industry"] = v
            if ci >= 0 and len(cells) > ci:
                v = clean(cells[ci].get_text())
                if v: e["country"] = v
            if xi >= 0 and len(cells) > xi:
                v = clean(cells[xi].get_text())
                if v: e["city"] = v
            out.append(e)
    return out

def from_case_links(soup, base):
    out, seen = [], set()
    for a in soup.find_all("a", href=True):
        abs_url = urljoin(base, a["href"])
        m = CASE_STUDY_RE.search(urlparse(abs_url).path)
        if not m: continue
        slug = m.group(2)
        if not slug or slug.lower() in ("page","") or re.match(r"^\d+$", slug): continue
        h = a.find(["h1","h2","h3","h4","h5","strong"])
        txt = clean(h.get_text() if h else a.get_text())
        txt = re.sub(r"\b(DEVELOPMENT|DESIGN|MIGRATION|REDESIGN|SEO|MAINTENANCE|"
                     r"OPTIMIZATION|INTEGRATION|LOCALIZATION|APP DEVELOPMENT|WEBFLOW INTEGRATION)\b", "", txt).strip()
        txt = re.sub(r"\s+", " ", txt).strip()
        name = txt if (txt and is_name(txt)) else slug_to_name(slug)
        if is_name(name) and name.lower() not in seen:
            seen.add(name.lower())
            out.append({"name": name, "source": "case study link"})
    return out

def from_headings(soup, url):
    out, seen = [], set()
    path = urlparse(url).path
    if not CLIENT_PATH_RE.search(path): return out
    skip_re = re.compile(r"^(all |our |featured |selected |recent |trusted |client |"
                         r"case |portfolio |project |reference |partner |customer |"
                         r"webflow |more |load |see |view )", re.I)
    for tag in ["h2","h3"]:
        for h in soup.find_all(tag):
            name = clean(h.get_text())
            if not is_name(name): continue
            if skip_re.match(name): continue
            if name.lower() not in seen:
                seen.add(name.lower())
                out.append({"name": name, "source": "heading"})
    return out

def from_sections(soup):
    out, seen = [], set()
    def add(name, src):
        name = clean(name)
        if is_name(name) and name.lower() not in seen:
            seen.add(name.lower()); out.append({"name": name, "source": src})
    for el in soup.find_all(["h1","h2","h3","h4","h5","h6","p"]):
        txt = el.get_text(strip=True).lower()
        if len(txt) > 120: continue
        if not any(kw in txt for kw in CLIENT_KW): continue
        container = el.find_parent(["section","article","div"]) or el.parent
        if not container: continue
        for li in container.find_all("li"): add(li.get_text(), "list")
        for card in container.find_all(class_=re.compile(r"client|customer|partner|reference|brand|testimonial", re.I)):
            h = card.find(["h2","h3","h4","h5","strong","b"])
            add((h or card).get_text().split("\n")[0], "card")
    gc = re.compile(r"client|customer|partner|reference|logo|brand|testimonial|stranke|klienti|referenzen|clientes|clienti|klanten|klienci", re.I)
    for container in soup.find_all(class_=gc):
        for el in container.find_all(["li","h3","h4","h5","strong"]):
            add(el.get_text(), "grid")
    return out

def from_logos(soup):
    out, seen = [], set()
    for img in soup.find_all("img"):
        src = img.get("src","") or ""
        alt = (img.get("alt","") or "").strip()
        title = (img.get("title","") or "").strip()
        ctx = " ".join([src, str(img.get("class","") or "")])
        if not re.search(r"logo|client|partner|reference|brand|customer|sponsor", ctx, re.I): continue
        def try_add(n, s):
            n = clean(n)
            if is_name(n) and 2 < len(n) < 80 and n.lower() not in seen:
                seen.add(n.lower()); out.append({"name": n, "source": s})
        if alt: try_add(alt, "logo alt")
        elif title: try_add(title, "logo title")
        else:
            fname = src.split("/")[-1].split("?")[0]
            fname = re.sub(r"\.(png|jpg|jpeg|svg|webp|gif|avif)$","",fname,flags=re.I)
            fname = re.sub(r"[-_]"," ", re.sub(r"logo|client|partner|\d{2,}|thumb|og\d?","",fname,flags=re.I)).strip()
            if fname: try_add(fname.title(), "logo filename")
    return out

def from_jsonld(soup):
    out = []
    for s in soup.find_all("script", type="application/ld+json"):
        try:
            items = json.loads(s.string or "")
            if not isinstance(items, list): items = [items]
            for item in items:
                if item.get("@type") == "ItemList":
                    for el in item.get("itemListElement",[]):
                        name = el.get("name") or (el.get("item") or {}).get("name")
                        if name and is_name(name):
                            out.append({"name": clean(name), "source": "json-ld"})
        except Exception:
            pass
    return out

def pagination_urls(base, soup):
    urls = set()
    from urllib.parse import parse_qs, urlencode
    parsed = urlparse(base)
    for a in soup.find_all("a", href=True):
        txt = a.get_text(strip=True).lower()
        href = a["href"]
        if re.search(r"next", txt) or re.search(r"[?&](\w+_)?page=\d", href):
            try:
                candidate = urljoin(base, href)
                if candidate != base: urls.add(candidate)
            except Exception:
                pass
    params = dict(parse_qs(parsed.query))
    for p in range(2, 8):
        params["page"] = [str(p)]
        flat = "&".join(f"{k}={v[0]}" for k,v in params.items())
        urls.add(parsed._replace(query=flat).geturl())
    return [u for u in urls if u != base][:8]

def discover_urls(base, soup):
    origin = urlparse(base).netloc
    found = []
    for a in soup.find_all("a", href=True):
        abs_url = urljoin(base, a["href"])
        if urlparse(abs_url).netloc != origin: continue
        if CLIENT_PATH_RE.search(urlparse(abs_url).path):
            found.append(abs_url)
    return list(dict.fromkeys(found))[:8]

def probe_paths(origin):
    paths = ["clients","customers","references","reference","testimonials","portfolio",
             "partners","case-studies","werk","projets","projekte","stranke","klienti",
             "referenzen","kunden","clientes","clienti","klanten","klienci"]
    found = []
    for p in paths:
        url = f"{origin}/{p}/"
        try:
            r = requests.head(url, headers=HEADERS, timeout=5, allow_redirects=True)
            if r.status_code < 400: found.append(url)
        except Exception:
            pass
    return found[:5]

def dedupe(clients):
    seen, out = {}, []
    for c in clients:
        k = (c["name"] or "").lower().strip()
        if k and k not in seen:
            seen[k] = True; out.append(c)
    return out

def scrape_one(url, logs):
    logs.append(f"Fetching: {url}")
    soup, final = fetch_page(url)
    results = (
        from_tables(soup) +
        from_case_links(soup, final) +
        from_headings(soup, final) +
        from_sections(soup) +
        from_jsonld(soup) +
        from_logos(soup)
    )
    t = len(from_tables(soup))
    cs = len(from_case_links(soup, final))
    h = len(from_headings(soup, final))
    sec = len(from_sections(soup))
    lg = len(from_logos(soup))
    logs.append(f"  -> tables:{t} case-links:{cs} headings:{h} sections:{sec} logos:{lg}")
    return results, soup, final

def run_scrape(input_url, logs):
    url = input_url.strip()
    if not re.match(r"^https?://", url): url = "https://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lstrip("www.")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    tld = domain.split(".")[-1].lower()
    lang = TLD_LANG.get(tld, "english")
    country = TLD_COUNTRY.get(tld, "")

    logs.append(f"Target: {url}")
    logs.append(f"Domain: {domain} | Language: {lang}")

    is_client = bool(CLIENT_PATH_RE.search(parsed.path))
    all_clients, scraped, home_soup = [], [], None

    if is_client:
        client_urls = [url]
        logs.append("Direct client/reference page detected")
    else:
        logs.append("Fetching homepage to find client pages...")
        try:
            hp_clients, home_soup, _ = scrape_one(url, logs)
            all_clients.extend(hp_clients)
            client_urls = discover_urls(url, home_soup)
            logs.append(f"Found {len(client_urls)} client page link(s)")
        except Exception as e:
            logs.append(f"Homepage failed: {e}")
            home_soup, client_urls = None, []
        if not client_urls:
            logs.append("Probing common paths...")
            client_urls = probe_paths(origin)

    for cu in client_urls:
        if cu in scraped: continue
        try:
            clients, soup, final = scrape_one(cu, logs)
            all_clients.extend(clients)
            scraped.append(cu)
            time.sleep(0.3)
            for pu in pagination_urls(cu, soup):
                if pu in scraped: continue
                try:
                    pg, _, _ = scrape_one(pu, logs)
                    if pg:
                        all_clients.extend(pg)
                        scraped.append(pu)
                        time.sleep(0.3)
                except Exception as e:
                    logs.append(f"  Pagination failed: {e}")
        except Exception as e:
            logs.append(f"  Failed {cu}: {e}")

    deduped = dedupe(all_clients)
    logs.append(f"Done: {len(deduped)} unique clients from {len(scraped)} page(s)")

    comp_name, comp_desc = "", ""
    if home_soup:
        og_title = home_soup.find("meta", property="og:title")
        title_tag = home_soup.find("title")
        og_desc = home_soup.find("meta", property="og:description")
        meta_desc = home_soup.find("meta", attrs={"name":"description"})
        raw_name = (og_title or {}).get("content","") or (title_tag.get_text() if title_tag else "")
        comp_name = re.split(r"[|\-\u2013\u2014]", raw_name)[0].strip()[:80]
        comp_desc = ((og_desc or {}).get("content","") or (meta_desc or {}).get("content",""))[:200]

    if not comp_name:
        comp_name = domain.split(".")[0].replace("-"," ").title()

    key = re.sub(r"[^a-z0-9.-]", "", domain)
    return {
        "key": key,
        "company_name": comp_name,
        "company_domain": domain,
        "company_description": comp_desc,
        "detected_language": lang,
        "detected_country": country,
        "clients": deduped,
        "sources_checked": scraped,
        "scraped_at": datetime.now().isoformat(),
    }

# ---- scrape API ---------------------------------------------------------------

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
        result = run_scrape(url, logs)
        repo = load_json(repo_file(email), {})
        repo[result["key"]] = result
        save_json(repo_file(email), repo)
        return jsonify(result=result, logs=logs)
    except Exception as e:
        logs.append(f"Error: {e}")
        return jsonify(error=str(e), logs=logs), 500

# ---- global error handlers ---------------------------------------------------

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
    return jsonify(error="Internal server error: " + str(e)), 500

# ---- frontend -----------------------------------------------------------------

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Client Intelligence</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg0:#0e0e0f;
  --bg1:#141416;
  --bg2:#1a1a1d;
  --bg3:#222226;
  --bg4:#2a2a2f;
  --border:#2e2e34;
  --border2:#3a3a42;
  --text0:#f0f0f0;
  --text1:#b8b8c0;
  --text2:#72727a;
  --text3:#484850;
  --accent:#c8f135;
  --blue:#4a9eff;
  --green:#3dd68c;
  --orange:#ff8c42;
  --purple:#b06aff;
  --yellow:#ffd166;
  --red:#ff5c5c;
  --mono:'IBM Plex Mono',monospace;
  --sans:'IBM Plex Sans',sans-serif;
}
html,body{height:100%;overflow:hidden}
body{font-family:var(--sans);background:var(--bg0);color:var(--text0);font-size:13px;line-height:1.5}

/* ---- auth ----------------------------------------------------------------- */
#authScreen{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--bg0);z-index:1000}
.auth-wrap{width:360px}
.auth-logo{text-align:center;margin-bottom:28px}
.auth-logo-mark{display:inline-flex;align-items:center;gap:10px;margin-bottom:12px}
.auth-logo-icon{width:36px;height:36px;background:var(--accent);border-radius:8px;display:flex;align-items:center;justify-content:center}
.auth-logo-icon svg{width:18px;height:18px;color:#000}
.auth-title{font-size:20px;font-weight:600;letter-spacing:-.3px}
.auth-sub{color:var(--text2);font-size:12px;margin-top:4px;font-family:var(--mono)}
.auth-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:28px}
.auth-card h2{font-size:15px;font-weight:600;margin-bottom:20px}
.auth-alert{padding:9px 12px;border-radius:7px;font-size:12px;margin-bottom:14px;display:none}
.auth-alert.error{background:rgba(255,92,92,.12);border:1px solid rgba(255,92,92,.3);color:#ff8a8a}
.auth-alert.info{background:rgba(74,158,255,.1);border:1px solid rgba(74,158,255,.25);color:#7ab8ff}
.field{margin-bottom:14px}
.field label{display:block;font-size:11px;font-weight:500;color:var(--text2);margin-bottom:6px;text-transform:uppercase;letter-spacing:.6px;font-family:var(--mono)}
.field input{width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:7px;padding:9px 12px;font-size:13px;color:var(--text0);font-family:var(--sans);outline:none;transition:border-color .15s}
.field input:focus{border-color:var(--accent)}
.btn-auth{width:100%;background:var(--accent);color:#0e0e0f;border:none;border-radius:7px;padding:10px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s;margin-top:4px;font-family:var(--sans)}
.btn-auth:hover{opacity:.9}
.btn-auth:disabled{opacity:.5;cursor:not-allowed}
.auth-links{border-top:1px solid var(--border);margin-top:20px;padding-top:16px;display:flex;flex-direction:column;gap:8px;align-items:center}
.auth-links button{background:none;border:none;cursor:pointer;font-size:12px;color:var(--text2);font-family:var(--sans)}
.auth-links button span{color:var(--accent)}
.auth-foot{text-align:center;margin-top:14px;font-size:11px;color:var(--text3);font-family:var(--mono)}

/* ---- app shell ------------------------------------------------------------ */
#appScreen{display:none;height:100vh;flex-direction:column}
#appScreen.visible{display:flex}

/* topbar */
.topbar{height:48px;background:var(--bg1);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 16px;gap:12px;flex-shrink:0}
.topbar-brand{display:flex;align-items:center;gap:8px;font-weight:600;font-size:13px;margin-right:4px}
.topbar-icon{width:26px;height:26px;background:var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.topbar-icon svg{width:13px;height:13px;color:#000}
.topbar-divider{width:1px;height:20px;background:var(--border);flex-shrink:0}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:8px;position:relative}
.avatar-btn{display:flex;align-items:center;gap:7px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:5px 10px;cursor:pointer;font-size:12px;color:var(--text1)}
.avatar{width:22px;height:22px;border-radius:50%;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#000;flex-shrink:0}
.dropdown{position:absolute;right:0;top:calc(100% + 6px);background:var(--bg3);border:1px solid var(--border2);border-radius:9px;padding:10px;min-width:200px;z-index:100;display:none}
.dropdown.open{display:block}
.dropdown-email{font-size:11px;color:var(--text2);padding-bottom:8px;margin-bottom:8px;border-bottom:1px solid var(--border);font-family:var(--mono)}
.dropdown-email strong{display:block;color:var(--text1);font-weight:500;margin-bottom:2px}
.dropdown button{width:100%;text-align:left;background:none;border:none;cursor:pointer;font-size:12px;color:#ff8a8a;padding:3px 0;font-family:var(--sans)}

/* filter bar */
.filterbar{height:44px;background:var(--bg1);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;padding:0 16px;flex-shrink:0;overflow-x:auto}
.filterbar::-webkit-scrollbar{display:none}
.filter-chip{padding:5px 12px;border-radius:20px;font-size:11px;font-weight:500;cursor:pointer;border:1px solid var(--border2);color:var(--text2);background:transparent;white-space:nowrap;transition:all .15s;font-family:var(--sans)}
.filter-chip:hover{border-color:var(--border2);color:var(--text1);background:var(--bg3)}
.filter-chip.active{background:var(--bg4);color:var(--text0);border-color:var(--border2)}

/* main layout */
.layout{display:flex;flex:1;overflow:hidden}

/* sidebar */
.sidebar{width:280px;flex-shrink:0;background:var(--bg1);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.sidebar-header{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.sidebar-header-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--text2);font-family:var(--mono)}
.sidebar-count{font-size:11px;color:var(--accent);font-family:var(--mono);font-weight:600}
.sidebar-search{padding:10px 12px;border-bottom:1px solid var(--border);flex-shrink:0}
.sidebar-search input{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:7px 10px 7px 30px;font-size:12px;color:var(--text0);outline:none;font-family:var(--sans)}
.sidebar-search input:focus{border-color:var(--border2)}
.search-wrap{position:relative}
.search-icon{position:absolute;left:9px;top:50%;transform:translateY(-50%);color:var(--text3);pointer-events:none}
.sidebar-list{flex:1;overflow-y:auto}
.sidebar-list::-webkit-scrollbar{width:3px}
.sidebar-list::-webkit-scrollbar-track{background:transparent}
.sidebar-list::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.agency-item{display:flex;align-items:center;gap:10px;padding:11px 16px;cursor:pointer;border-left:2px solid transparent;transition:all .1s}
.agency-item:hover{background:var(--bg2)}
.agency-item.active{background:var(--bg2);border-left-color:var(--accent)}
.agency-logo{width:32px;height:32px;border-radius:8px;background:var(--bg4);display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0;font-weight:700;color:var(--text1)}
.agency-info{flex:1;min-width:0}
.agency-name{font-size:13px;font-weight:500;color:var(--text1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.agency-item.active .agency-name{color:var(--text0)}
.agency-type{font-size:11px;color:var(--text3);margin-top:1px}
.agency-num{font-size:12px;color:var(--text2);font-family:var(--mono);flex-shrink:0}
.agency-item.active .agency-num{color:var(--accent)}
.sidebar-empty{padding:32px 16px;text-align:center;color:var(--text3);font-size:12px}

/* detail panel */
.detail{flex:1;overflow-y:auto;background:var(--bg0);display:flex;flex-direction:column}
.detail::-webkit-scrollbar{width:4px}
.detail::-webkit-scrollbar-track{background:transparent}
.detail::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.detail-empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;color:var(--text3)}
.detail-empty-icon{font-size:36px;opacity:.3}
.detail-empty p{font-size:13px;font-family:var(--mono)}

/* detail header */
.detail-header{padding:24px 28px 20px;border-bottom:1px solid var(--border);flex-shrink:0}
.detail-title-row{display:flex;align-items:center;gap:14px;margin-bottom:14px}
.detail-logo{width:44px;height:44px;border-radius:10px;background:var(--bg3);border:1px solid var(--border2);display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;color:var(--text1);flex-shrink:0}
.detail-name{font-size:22px;font-weight:600;letter-spacing:-.4px}
.detail-domain{font-size:12px;color:var(--text2);font-family:var(--mono);margin-top:2px}
.detail-badges{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.source-badge{padding:4px 10px;border-radius:5px;font-size:11px;font-weight:600;font-family:var(--mono);cursor:default}
.sb-case{background:rgba(61,214,140,.12);color:#3dd68c;border:1px solid rgba(61,214,140,.25)}
.sb-testimonial{background:rgba(74,158,255,.12);color:#4a9eff;border:1px solid rgba(74,158,255,.25)}
.sb-logo{background:rgba(255,140,66,.12);color:#ff8c42;border:1px solid rgba(255,140,66,.25)}
.sb-table{background:rgba(176,106,255,.12);color:#c48aff;border:1px solid rgba(176,106,255,.25)}
.sb-heading{background:rgba(200,241,53,.1);color:var(--accent);border:1px solid rgba(200,241,53,.2)}
.sb-list{background:rgba(114,114,122,.12);color:var(--text1);border:1px solid var(--border)}
.detail-stats{display:flex;gap:28px}
.stat-item{display:flex;flex-direction:column;gap:2px}
.stat-num{font-size:26px;font-weight:600;color:var(--accent);font-family:var(--mono);line-height:1}
.stat-label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px}

/* client table */
.table-wrap{padding:0 28px 28px;flex:1}
.table-toolbar{display:flex;align-items:center;gap:10px;padding:16px 0 12px;border-bottom:1px solid var(--border);margin-bottom:0}
.table-search{flex:1;background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:7px 10px 7px 30px;font-size:12px;color:var(--text0);outline:none;font-family:var(--sans);max-width:260px}
.table-search:focus{border-color:var(--border2)}
.table-search-wrap{position:relative;display:flex;align-items:center}
.table-search-wrap svg{position:absolute;left:9px;color:var(--text3);pointer-events:none}
.table-count{font-size:11px;color:var(--text2);font-family:var(--mono);margin-left:auto}
table{width:100%;border-collapse:collapse}
thead tr{border-bottom:1px solid var(--border)}
thead th{padding:10px 12px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.7px;color:var(--text3);text-align:left;font-family:var(--mono);white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s;cursor:default}
tbody tr:hover{background:var(--bg2)}
tbody tr:last-child{border-bottom:none}
td{padding:13px 12px;font-size:13px;vertical-align:middle}
.td-company{font-weight:600;color:var(--text0)}
.td-industry{color:var(--text1)}
.td-source-tag{display:inline-flex;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;font-family:var(--mono)}
.td-country{color:var(--text2);font-family:var(--mono);font-size:11px}
.td-date{color:var(--text2);font-family:var(--mono);font-size:11px}
.td-link a{color:var(--text3);font-size:11px;font-family:var(--mono);text-decoration:none;background:var(--bg3);border:1px solid var(--border);padding:3px 8px;border-radius:5px;transition:all .15s;display:inline-flex;align-items:center;gap:4px}
.td-link a:hover{color:var(--text1);border-color:var(--border2)}
.empty-table{text-align:center;padding:48px 0;color:var(--text3);font-family:var(--mono);font-size:12px}

/* scrape bar */
.scrape-panel{border-top:1px solid var(--border);background:var(--bg1);padding:12px 28px;flex-shrink:0}
.scrape-row{display:flex;gap:8px;align-items:center}
.scrape-input{flex:1;background:var(--bg3);border:1px solid var(--border2);border-radius:7px;padding:9px 14px;font-size:13px;color:var(--text0);font-family:var(--mono);outline:none;transition:border-color .15s}
.scrape-input:focus{border-color:var(--accent)}
.scrape-input::placeholder{color:var(--text3)}
.btn-scrape{background:var(--accent);color:#000;border:none;border-radius:7px;padding:9px 18px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap;font-family:var(--sans);transition:opacity .15s;display:flex;align-items:center;gap:7px}
.btn-scrape:disabled{opacity:.5;cursor:not-allowed}
.btn-scrape:hover:not(:disabled){opacity:.88}
.scrape-hint{font-size:11px;color:var(--text3);font-family:var(--mono);margin-top:6px}
.scrape-progress{display:none;align-items:center;gap:8px;font-size:11px;color:var(--text2);font-family:var(--mono);margin-top:8px}
.scrape-progress.visible{display:flex}
.scrape-error{font-size:11px;color:#ff8a8a;font-family:var(--mono);margin-top:6px;display:none}
.scrape-error.visible{display:block}

/* spinner */
.spin{display:inline-block;width:12px;height:12px;border-radius:50%;border:2px solid rgba(0,0,0,.2);border-top-color:#000;animation:spin .7s linear infinite;flex-shrink:0}
.spin-light{border-color:rgba(255,255,255,.15);border-top-color:var(--text1)}
@keyframes spin{to{transform:rotate(360deg)}}

/* log */
.log-box{background:var(--bg0);border:1px solid var(--border);border-radius:7px;padding:8px 12px;max-height:100px;overflow-y:auto;font-family:var(--mono);font-size:10px;color:var(--text2);line-height:1.7;margin-top:8px;display:none}
.log-box.visible{display:block}

/* alerts */
.alert{padding:8px 12px;border-radius:7px;font-size:12px;margin-top:8px;display:none;font-family:var(--mono)}
.alert.visible{display:block}
.alert.error{background:rgba(255,92,92,.1);border:1px solid rgba(255,92,92,.2);color:#ff8a8a}
</style>
</head>
<body>

<!-- AUTH -->
<div id="authScreen">
  <div class="auth-wrap">
    <div class="auth-logo">
      <div class="auth-logo-mark">
        <div class="auth-logo-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        </div>
        <span class="auth-title">Client Intel</span>
      </div>
      <div class="auth-sub">// competitor client discovery</div>
    </div>
    <div class="auth-card">
      <h2 id="authTitle">Sign in</h2>
      <div class="auth-alert error" id="authErr"></div>
      <div class="auth-alert info" id="authInfo"></div>
      <div class="field">
        <label>Email</label>
        <input type="email" id="authEmail" placeholder="you@company.com" autocomplete="email">
      </div>
      <div class="field" id="pwField">
        <label>Password</label>
        <input type="password" id="authPw" placeholder="Min. 8 characters" autocomplete="current-password">
      </div>
      <div class="field" id="pw2Field" style="display:none">
        <label>Confirm password</label>
        <input type="password" id="authPw2" placeholder="Repeat password">
      </div>
      <button class="btn-auth" id="authBtn" onclick="handleAuth()">Sign in</button>
      <div class="auth-links" id="authLinks1">
        <button onclick="setMode('signup')">No account? <span>Create one</span></button>
        <button onclick="setMode('reset')">Forgot password?</button>
      </div>
      <div class="auth-links" id="authLinks2" style="display:none">
        <button onclick="setMode('login')">Back to sign in</button>
      </div>
    </div>
    <div class="auth-foot">passwords hashed with SHA-256 // data stored on server</div>
  </div>
</div>

<!-- APP -->
<div id="appScreen">

  <!-- topbar -->
  <nav class="topbar">
    <div class="topbar-brand">
      <div class="topbar-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      </div>
      Client Intel
    </div>
    <div class="topbar-divider"></div>
    <span style="font-size:11px;color:var(--text3);font-family:var(--mono)">competitor client discovery</span>
    <div class="topbar-right">
      <button class="avatar-btn" onclick="toggleDrop()">
        <span class="avatar" id="avLetter">?</span>
        <span id="avEmail" style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono)"></span>
      </button>
      <div class="dropdown" id="dropdown">
        <div class="dropdown-email">
          <strong id="dropEmail"></strong>
          <span id="dropStats"></span>
        </div>
        <button onclick="doLogout()">Sign out</button>
      </div>
    </div>
  </nav>

  <!-- filter bar -->
  <div class="filterbar" id="filterbar">
    <button class="filter-chip active" data-type="all" onclick="setFilter('all',this)">All agencies</button>
  </div>

  <!-- main -->
  <div class="layout">

    <!-- sidebar -->
    <aside class="sidebar">
      <div class="sidebar-header">
        <span class="sidebar-header-label">Agencies</span>
        <span class="sidebar-count" id="sideCount">0</span>
      </div>
      <div class="sidebar-search">
        <div class="search-wrap">
          <svg class="search-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <input type="text" id="sideSearch" placeholder="Search agencies..." oninput="renderSidebar()">
        </div>
      </div>
      <div class="sidebar-list" id="sideList">
        <div class="sidebar-empty">No agencies yet.<br>Scrape one below.</div>
      </div>
    </aside>

    <!-- detail -->
    <main class="detail" id="detail">
      <div class="detail-empty" id="detailEmpty">
        <div class="detail-empty-icon">&#128269;</div>
        <p>Select an agency to view clients</p>
      </div>
      <div id="detailContent" style="display:none;flex-direction:column;flex:1">

        <!-- header -->
        <div class="detail-header">
          <div class="detail-title-row">
            <div class="detail-logo" id="dLogo"></div>
            <div>
              <div class="detail-name" id="dName"></div>
              <div class="detail-domain"><a id="dDomain" href="#" target="_blank" style="color:var(--text2);text-decoration:none"></a></div>
            </div>
          </div>
          <div class="detail-badges" id="dBadges"></div>
          <div class="detail-stats">
            <div class="stat-item">
              <span class="stat-num" id="dCount">0</span>
              <span class="stat-label">Indexed clients</span>
            </div>
            <div class="stat-item">
              <span class="stat-num" id="dIndustries">0</span>
              <span class="stat-label">Industries</span>
            </div>
            <div class="stat-item" id="dCountryStat" style="display:none">
              <span class="stat-num" id="dCountries">0</span>
              <span class="stat-label">Countries</span>
            </div>
          </div>
        </div>

        <!-- table -->
        <div class="table-wrap">
          <div class="table-toolbar">
            <div class="table-search-wrap">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
              <input class="table-search" type="text" id="tableSearch" placeholder="Filter clients..." oninput="renderTable()">
            </div>
            <span class="table-count" id="tableCount"></span>
            <button onclick="deleteCompany()" style="background:none;border:1px solid var(--border);border-radius:6px;padding:5px 10px;color:var(--text3);font-size:11px;cursor:pointer;font-family:var(--mono)">Remove</button>
          </div>
          <table>
            <thead>
              <tr>
                <th style="width:36px">#</th>
                <th>Company</th>
                <th>Industry</th>
                <th>Country</th>
                <th>Source</th>
                <th>Indexed</th>
                <th></th>
              </tr>
            </thead>
            <tbody id="clientTbody"></tbody>
          </table>
        </div>

      </div>
    </main>

  </div>

  <!-- scrape bar -->
  <div class="scrape-panel">
    <div class="scrape-row">
      <input class="scrape-input" type="text" id="scrapeInput"
        placeholder="https://www.flowout.com/portfolio  or  imagine.si  or  any company URL"
        onkeydown="if(event.key==='Enter')doScrape()">
      <button class="btn-scrape" id="scrapeBtn" onclick="doScrape()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        Scrape
      </button>
    </div>
    <div class="scrape-progress" id="scrapeProgress">
      <span class="spin spin-light"></span>
      <span id="progressMsg">Scraping...</span>
      <button onclick="toggleLog()" style="background:none;border:none;cursor:pointer;color:var(--text3);font-size:10px;margin-left:auto">logs</button>
    </div>
    <div class="alert error" id="scrapeErr"></div>
    <div class="log-box" id="logBox"></div>
    <div class="scrape-hint">Direct URL works best &mdash; e.g. company.com/clients/ &bull; Zero AI tokens</div>
  </div>

</div>

<script>
// ---- state ------------------------------------------------------------------
let S = { user: null, repo: {}, selected: null, filter: 'all', showLog: false };

const SOURCE_CLASS = {
  'table':           'sb-table',
  'heading':         'sb-heading',
  'case study link': 'sb-case',
  'list':            'sb-list',
  'card':            'sb-list',
  'grid':            'sb-list',
  'logo alt':        'sb-logo',
  'logo title':      'sb-logo',
  'logo filename':   'sb-logo',
  'json-ld':         'sb-list',
};

const TYPE_COLORS = {
  'Performance Marketing': '#ff8c42',
  'System Integrator':     '#4a9eff',
  'AI Agency':             '#b06aff',
  'Webflow Agency':        '#3dd68c',
  'Design Agency':         '#ffd166',
  'Content Agency':        '#ff5c8a',
  'Dev Agency':            '#c8f135',
};

// ---- api --------------------------------------------------------------------
async function api(method, path, body) {
  const opts = { method, credentials: 'include', headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  const ct = r.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    const t = await r.text();
    throw new Error('Server error (' + r.status + '): ' + t.slice(0, 120));
  }
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ---- boot -------------------------------------------------------------------
async function init() {
  try {
    const me = await api('GET', '/api/me');
    await loginSuccess(me.email, true);
  } catch { showAuth(); }
}

function showAuth() {
  document.getElementById('authScreen').style.display = 'flex';
  document.getElementById('appScreen').classList.remove('visible');
}

async function loginSuccess(email, load) {
  S.user = email;
  document.getElementById('authScreen').style.display = 'none';
  document.getElementById('appScreen').classList.add('visible');
  document.getElementById('avLetter').textContent = email[0].toUpperCase();
  document.getElementById('avEmail').textContent = email;
  document.getElementById('dropEmail').textContent = email;
  if (load) {
    try { S.repo = await api('GET', '/api/repo'); } catch { S.repo = {}; }
  }
  renderAll();
}

// ---- auth -------------------------------------------------------------------
let authMode = 'login';
function setMode(m) {
  authMode = m;
  document.getElementById('authErr').style.display = 'none';
  document.getElementById('authInfo').style.display = 'none';
  const titles = { login:'Sign in', signup:'Create account', reset:'Reset password' };
  const btns   = { login:'Sign in', signup:'Create account', reset:'Send reset link' };
  document.getElementById('authTitle').textContent  = titles[m];
  document.getElementById('authBtn').textContent    = btns[m];
  document.getElementById('pwField').style.display  = m === 'reset'  ? 'none' : '';
  document.getElementById('pw2Field').style.display = m === 'signup' ? ''     : 'none';
  document.getElementById('authLinks1').style.display = m === 'login' ? '' : 'none';
  document.getElementById('authLinks2').style.display = m !== 'login' ? '' : 'none';
}
document.getElementById('authEmail').addEventListener('keydown', e => { if (e.key === 'Enter') handleAuth(); });
document.getElementById('authPw').addEventListener('keydown',   e => { if (e.key === 'Enter') handleAuth(); });

async function handleAuth() {
  const email = document.getElementById('authEmail').value.trim().toLowerCase();
  const pw    = document.getElementById('authPw').value;
  const pw2   = document.getElementById('authPw2').value;
  const err   = document.getElementById('authErr');
  const info  = document.getElementById('authInfo');
  err.style.display = info.style.display = 'none';
  const btn = document.getElementById('authBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Please wait...';
  try {
    if (authMode === 'login') {
      const r = await api('POST', '/api/login', { email, password: pw });
      S.repo = await api('GET', '/api/repo');
      await loginSuccess(r.email, false);
    } else if (authMode === 'signup') {
      if (pw.length < 8) throw new Error('Password must be at least 8 characters');
      if (pw !== pw2) throw new Error('Passwords do not match');
      const r = await api('POST', '/api/signup', { email, password: pw });
      S.repo = {};
      await loginSuccess(r.email, false);
    } else {
      info.textContent = 'If an account exists, a reset link would be sent.';
      info.style.display = 'block';
    }
  } catch(e) {
    err.textContent = e.message;
    err.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = { login:'Sign in', signup:'Create account', reset:'Send reset link' }[authMode];
  }
}

async function doLogout() {
  await api('POST', '/api/logout').catch(() => {});
  S.user = null; S.repo = {}; S.selected = null;
  document.getElementById('dropdown').classList.remove('open');
  showAuth();
}

function toggleDrop() { document.getElementById('dropdown').classList.toggle('open'); }
document.addEventListener('click', e => { if (!e.target.closest('.topbar-right')) document.getElementById('dropdown').classList.remove('open'); });

// ---- scrape -----------------------------------------------------------------
async function doScrape() {
  const url = document.getElementById('scrapeInput').value.trim();
  if (!url) return;
  const btn = document.getElementById('scrapeBtn');
  const prog = document.getElementById('scrapeProgress');
  const errEl = document.getElementById('scrapeErr');
  const logBox = document.getElementById('logBox');

  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Scraping...';
  prog.classList.add('visible');
  errEl.classList.remove('visible');
  logBox.innerHTML = '';
  document.getElementById('progressMsg').textContent = 'Fetching page...';

  try {
    const r = await api('POST', '/api/scrape', { url });
    (r.logs || []).forEach(l => {
      const d = document.createElement('div');
      d.textContent = l;
      logBox.appendChild(d);
      logBox.scrollTop = logBox.scrollHeight;
      document.getElementById('progressMsg').textContent = l.slice(0, 80);
    });
    S.repo = await api('GET', '/api/repo');
    renderAll();
    if (r.result?.key) selectCompany(r.result.key);
    document.getElementById('scrapeInput').value = '';
  } catch(e) {
    errEl.textContent = e.message;
    errEl.classList.add('visible');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg> Scrape';
    prog.classList.remove('visible');
  }
}

function toggleLog() {
  S.showLog = !S.showLog;
  document.getElementById('logBox').classList.toggle('visible', S.showLog);
}

// ---- delete -----------------------------------------------------------------
async function deleteCompany() {
  if (!S.selected) return;
  if (!confirm('Remove this company from your repository?')) return;
  await api('DELETE', '/api/repo/' + S.selected);
  delete S.repo[S.selected];
  S.selected = null;
  renderAll();
  document.getElementById('detailContent').style.display = 'none';
  document.getElementById('detailEmpty').style.display = 'flex';
}

// ---- filters ----------------------------------------------------------------
function setFilter(type, el) {
  S.filter = type;
  document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  renderSidebar();
}

function buildFilters() {
  const types = new Set(['all']);
  Object.values(S.repo).forEach(c => { if (c.agency_type) types.add(c.agency_type); });
  const bar = document.getElementById('filterbar');
  bar.innerHTML = '';
  types.forEach(t => {
    const btn = document.createElement('button');
    btn.className = 'filter-chip' + (S.filter === t ? ' active' : '');
    btn.dataset.type = t;
    btn.textContent = t === 'all' ? 'All agencies' : t;
    btn.onclick = () => setFilter(t, btn);
    bar.appendChild(btn);
  });
}

// ---- render -----------------------------------------------------------------
function renderAll() {
  buildFilters();
  renderSidebar();
  updateDropStats();
  if (S.selected && S.repo[S.selected]) renderDetail(S.selected);
}

function getTypeColor(type) {
  return TYPE_COLORS[type] || 'var(--text2)';
}

function companyInitial(name) {
  return (name || '?')[0].toUpperCase();
}

function renderSidebar() {
  const companies = Object.values(S.repo);
  const q = (document.getElementById('sideSearch').value || '').toLowerCase();
  const filtered = companies.filter(c => {
    if (S.filter !== 'all' && c.agency_type !== S.filter) return false;
    if (q && !c.company_name.toLowerCase().includes(q) &&
        !(c.clients||[]).some(cl => cl.name.toLowerCase().includes(q))) return false;
    return true;
  }).sort((a,b) => (b.clients||[]).length - (a.clients||[]).length);

  document.getElementById('sideCount').textContent = filtered.length;

  const list = document.getElementById('sideList');
  if (filtered.length === 0) {
    list.innerHTML = '<div class="sidebar-empty">No agencies yet.<br>Scrape one below.</div>';
    return;
  }

  list.innerHTML = filtered.map(c => {
    const color = getTypeColor(c.agency_type);
    const n = (c.clients||[]).length;
    return `<div class="agency-item${S.selected === c.key ? ' active' : ''}" onclick="selectCompany('${esc(c.key)}')">
      <div class="agency-logo" style="color:${color};background:${color}18;border:1px solid ${color}30">${companyInitial(c.company_name)}</div>
      <div class="agency-info">
        <div class="agency-name">${esc(c.company_name)}</div>
        <div class="agency-type" style="color:${color}">${esc(c.agency_type || c.detected_language || 'Agency')}</div>
      </div>
      <div class="agency-num">${n}</div>
    </div>`;
  }).join('');
}

function selectCompany(key) {
  S.selected = key;
  renderSidebar();
  renderDetail(key);
}

function renderDetail(key) {
  const c = S.repo[key];
  if (!c) return;

  document.getElementById('detailEmpty').style.display = 'none';
  const dc = document.getElementById('detailContent');
  dc.style.display = 'flex';

  const color = getTypeColor(c.agency_type);
  document.getElementById('dLogo').textContent = companyInitial(c.company_name);
  document.getElementById('dLogo').style.cssText = `color:${color};background:${color}18;border:1px solid ${color}30;width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;flex-shrink:0`;
  document.getElementById('dName').textContent = c.company_name;
  const domEl = document.getElementById('dDomain');
  domEl.textContent = c.company_domain;
  domEl.href = 'https://' + c.company_domain;

  // Source breakdown badges
  const srcMap = {};
  (c.clients||[]).forEach(cl => {
    const s = cl.source || 'unknown';
    const key2 = s.includes('case') ? 'Case Study' : s.includes('table') ? 'Table' :
                 s.includes('logo') ? 'Logo' : s.includes('heading') ? 'Heading' :
                 s.includes('list') || s.includes('card') || s.includes('grid') ? 'List/Section' : 'Other';
    srcMap[key2] = (srcMap[key2]||0) + 1;
  });
  const badgeClass = { 'Case Study':'sb-case','Table':'sb-table','Logo':'sb-logo','Heading':'sb-heading','List/Section':'sb-list','Other':'sb-list' };
  document.getElementById('dBadges').innerHTML =
    Object.entries(srcMap).sort((a,b)=>b[1]-a[1])
      .map(([k,v]) => `<span class="source-badge ${badgeClass[k]||'sb-list'}">${v} ${k}${v>1&&k!=='Other'?'s':''}</span>`).join('');

  // Stats
  const clients = c.clients || [];
  document.getElementById('dCount').textContent = clients.length;
  const industries = new Set(clients.map(cl => cl.industry).filter(Boolean));
  document.getElementById('dIndustries').textContent = industries.size;
  const countries = new Set(clients.map(cl => cl.country).filter(Boolean));
  if (countries.size > 0) {
    document.getElementById('dCountryStat').style.display = '';
    document.getElementById('dCountries').textContent = countries.size;
  } else {
    document.getElementById('dCountryStat').style.display = 'none';
  }

  document.getElementById('tableSearch').value = '';
  renderTable();
}

function renderTable() {
  const c = S.repo[S.selected];
  if (!c) return;
  const q = (document.getElementById('tableSearch').value || '').toLowerCase();
  const clients = (c.clients||[]).filter(cl =>
    !q || cl.name.toLowerCase().includes(q) ||
    (cl.industry||'').toLowerCase().includes(q) ||
    (cl.country||'').toLowerCase().includes(q)
  );

  document.getElementById('tableCount').textContent = clients.length + ' clients';

  const tbody = document.getElementById('clientTbody');
  if (clients.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-table">No clients found${q ? ' matching "'+q+'"' : ''}.</td></tr>`;
    return;
  }

  const scraped = c.scraped_at ? new Date(c.scraped_at) : null;
  tbody.innerHTML = clients.map((cl, i) => {
    const src = cl.source || '';
    const srcKey = src.includes('case') ? 'Case Study' : src.includes('table') ? 'Table' :
                   src.includes('logo') ? 'Logo' : src.includes('heading') ? 'Heading' :
                   src.includes('list')||src.includes('card')||src.includes('grid') ? 'Section' : src;
    const cls = SOURCE_CLASS[src] || 'sb-list';
    const dateStr = scraped ? scraped.toLocaleDateString('en-US', {month:'short',year:'numeric'}) : '';
    const sourceUrl = (c.sources_checked||[])[0];
    return `<tr>
      <td style="color:var(--text3);font-family:var(--mono);font-size:11px">${i+1}</td>
      <td class="td-company">${esc(cl.name)}</td>
      <td class="td-industry">${esc(cl.industry||'')}</td>
      <td class="td-country">${esc(cl.country||'')}</td>
      <td><span class="td-source-tag ${cls}">${esc(srcKey)}</span></td>
      <td class="td-date">${dateStr}</td>
      <td class="td-link">${sourceUrl ? `<a href="${esc(sourceUrl)}" target="_blank">Source &nearr;</a>` : ''}</td>
    </tr>`;
  }).join('');
}

function updateDropStats() {
  const n = Object.keys(S.repo).length;
  const c = new Set(Object.values(S.repo).flatMap(r => (r.clients||[]).map(x=>x.name.toLowerCase()))).size;
  document.getElementById('dropStats').textContent = n + ' companies, ' + c + ' clients';
}

function esc(s) {
  return (s||'').toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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

# ---- run ----------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  Client Intelligence running at http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
