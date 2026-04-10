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
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #ffffff; --bg2: #f5f5f4; --bg3: #efefed;
    --text: #1a1a18; --text2: #6b6b66; --text3: #9b9b96;
    --border: rgba(0,0,0,0.10); --border2: rgba(0,0,0,0.18);
    --blue: #1a6dc2; --blue-bg: #e8f0fb; --blue-text: #0e4a8a;
    --green-bg: #e8f5ee; --green-text: #1a6640;
    --amber-bg: #fef3e2; --amber-text: #92520a;
    --red-bg: #fdeaea; --red-text: #a32020;
    --radius: 8px; --radius-lg: 12px;
    --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.04);
  }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg2); color: var(--text); font-size: 14px; line-height: 1.5; min-height: 100vh; }
  a { color: var(--blue); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Layout */
  .app { display: none; }
  .app.visible { display: block; }
  .page { display: none; }
  .page.active { display: block; }

  /* Auth */
  .auth-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 2rem; }
  .auth-card { width: 100%; max-width: 380px; }
  .auth-logo { text-align: center; margin-bottom: 2rem; }
  .auth-logo-icon { display: inline-flex; align-items: center; justify-content: center; width: 48px; height: 48px; background: var(--bg); border: 1px solid var(--border2); border-radius: var(--radius-lg); font-size: 22px; margin-bottom: 14px; }
  .auth-logo h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }
  .auth-logo p { color: var(--text2); font-size: 13px; }
  .auth-box { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 1.75rem; box-shadow: var(--shadow); }
  .auth-box h2 { font-size: 16px; font-weight: 600; margin-bottom: 1.25rem; }
  .auth-footer { text-align: center; margin-top: 1rem; font-size: 12px; color: var(--text3); }
  .auth-links { border-top: 1px solid var(--border); margin-top: 1.25rem; padding-top: 1.25rem; display: flex; flex-direction: column; gap: 8px; align-items: center; }
  .auth-links button { background: none; border: none; cursor: pointer; font-size: 13px; color: var(--text2); }
  .auth-links button span { color: var(--text); font-weight: 500; }

  /* Form elements */
  .field { margin-bottom: 14px; }
  .field label { display: block; font-size: 12px; font-weight: 500; color: var(--text2); margin-bottom: 5px; }
  input[type=text], input[type=email], input[type=password], input[type=url], select, textarea {
    width: 100%; padding: 9px 12px; border: 1px solid var(--border2); border-radius: var(--radius);
    font-size: 14px; background: var(--bg); color: var(--text); outline: none; transition: border-color 0.15s;
  }
  input:focus, select:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(26,109,194,0.1); }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 7px; padding: 9px 18px; border-radius: var(--radius); font-size: 14px; font-weight: 500; cursor: pointer; border: 1px solid; transition: all 0.15s; white-space: nowrap; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-primary { background: var(--text); border-color: var(--text); color: #fff; }
  .btn-primary:hover:not(:disabled) { background: #333; }
  .btn-default { background: var(--bg); border-color: var(--border2); color: var(--text); }
  .btn-default:hover:not(:disabled) { background: var(--bg2); }
  .btn-ghost { background: transparent; border-color: transparent; color: var(--text2); }
  .btn-ghost:hover:not(:disabled) { background: var(--bg2); }
  .btn-danger { background: transparent; border-color: var(--border); color: var(--red-text); }
  .btn-danger:hover:not(:disabled) { background: var(--red-bg); }
  .btn-full { width: 100%; }

  /* Alerts */
  .alert { padding: 9px 13px; border-radius: var(--radius); font-size: 13px; margin-bottom: 14px; }
  .alert-error { background: var(--red-bg); color: var(--red-text); }
  .alert-info { background: var(--blue-bg); color: var(--blue-text); }
  .alert-warn { background: var(--amber-bg); color: var(--amber-text); }
  .alert-success { background: var(--green-bg); color: var(--green-text); }

  /* Topbar */
  .topbar { background: var(--bg); border-bottom: 1px solid var(--border); padding: 0 1.5rem; height: 56px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; }
  .topbar-brand { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 15px; }
  .topbar-brand-icon { width: 28px; height: 28px; background: var(--text); color: #fff; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 14px; }
  .topbar-right { display: flex; align-items: center; gap: 8px; position: relative; }
  .avatar-btn { display: flex; align-items: center; gap: 8px; padding: 5px 10px; background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius); cursor: pointer; font-size: 13px; }
  .avatar { width: 24px; height: 24px; border-radius: 50%; background: var(--blue-bg); color: var(--blue-text); display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 600; flex-shrink: 0; }
  .dropdown { position: absolute; right: 0; top: calc(100% + 6px); background: var(--bg); border: 1px solid var(--border2); border-radius: var(--radius-lg); padding: 0.75rem; min-width: 200px; box-shadow: var(--shadow); z-index: 200; display: none; }
  .dropdown.open { display: block; }
  .dropdown-email { font-size: 12px; color: var(--text2); padding-bottom: 8px; margin-bottom: 8px; border-bottom: 1px solid var(--border); }
  .dropdown-email strong { display: block; color: var(--text); font-weight: 500; margin-bottom: 2px; }
  .dropdown button { width: 100%; text-align: left; background: none; border: none; cursor: pointer; font-size: 13px; color: var(--red-text); padding: 4px 0; }

  /* Tabs */
  .tabs { display: flex; gap: 6px; padding: 1.25rem 1.5rem 0; flex-wrap: wrap; }
  .tab { padding: 7px 15px; border-radius: var(--radius); cursor: pointer; font-size: 13px; background: transparent; border: 1px solid var(--border); color: var(--text2); font-weight: 500; }
  .tab.active { background: var(--bg); border-color: var(--border2); color: var(--text); box-shadow: var(--shadow); }
  .tab:hover:not(.active) { background: var(--bg); }

  /* Main content */
  .main { max-width: 860px; margin: 0 auto; padding: 1.5rem; }

  /* Scrape bar */
  .scrape-bar { display: flex; gap: 8px; margin-bottom: 0.5rem; }
  .scrape-bar input { flex: 1; }
  .scrape-hint { font-size: 12px; color: var(--text3); margin-bottom: 1.25rem; display: flex; justify-content: space-between; align-items: center; }

  /* Progress */
  .progress { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px 14px; margin-bottom: 1rem; }
  .progress-status { display: flex; align-items: center; gap: 10px; font-size: 13px; color: var(--text2); margin-bottom: 10px; }
  .progress-phases { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 6px; }
  .progress-phase { }
  .progress-bar { height: 3px; border-radius: 2px; background: var(--border); margin-bottom: 3px; transition: background 0.3s; }
  .progress-bar.active { background: var(--text); animation: pulse 1.2s ease-in-out infinite; }
  .progress-label { font-size: 11px; color: var(--text3); }
  .progress-label.active { color: var(--text2); }
  .log-toggle { font-size: 11px; background: none; border: 1px solid var(--border); border-radius: var(--radius); padding: 2px 8px; cursor: pointer; color: var(--text3); }
  .log-box { background: var(--bg2); border-radius: var(--radius); padding: 10px 14px; max-height: 160px; overflow-y: auto; font-family: monospace; font-size: 11px; color: var(--text2); line-height: 1.6; margin-top: 8px; }

  /* Stats */
  .stats { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; margin-bottom: 1.5rem; }
  .stat { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 10px 14px; }
  .stat-label { font-size: 11px; color: var(--text2); margin-bottom: 3px; }
  .stat-value { font-size: 22px; font-weight: 600; }

  /* Cards */
  .card { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 14px 16px; transition: border-color 0.15s; }
  .card:hover { border-color: var(--border2); }
  .card-clickable { cursor: pointer; }
  .card-list { display: flex; flex-direction: column; gap: 8px; }
  .card-header { display: flex; justify-content: space-between; align-items: flex-start; }
  .card-title { font-weight: 600; font-size: 15px; margin-bottom: 2px; }
  .card-sub { font-size: 12px; color: var(--text2); margin-bottom: 6px; }
  .card-desc { font-size: 13px; color: var(--text2); margin-bottom: 10px; line-height: 1.5; }
  .card-count { text-align: right; flex-shrink: 0; margin-left: 16px; }
  .card-count-num { font-size: 22px; font-weight: 600; }
  .card-count-label { font-size: 11px; color: var(--text2); }

  /* Pills/badges */
  .pills { display: flex; flex-wrap: wrap; gap: 5px; }
  .pill { font-size: 12px; padding: 3px 9px; border-radius: 20px; background: var(--bg2); color: var(--text2); }
  .badge { font-size: 10px; padding: 2px 7px; border-radius: 20px; font-weight: 500; white-space: nowrap; flex-shrink: 0; }
  .badge-blue { background: var(--blue-bg); color: var(--blue-text); }
  .badge-green { background: var(--green-bg); color: var(--green-text); }
  .badge-amber { background: var(--amber-bg); color: var(--amber-text); }
  .badge-gray { background: var(--bg2); color: var(--text2); }

  /* Client list rows */
  .client-row { display: flex; justify-content: space-between; align-items: center; padding: 7px 12px; background: var(--bg2); border-radius: var(--radius); margin-bottom: 4px; }
  .client-row-left { display: flex; align-items: center; gap: 8px; min-width: 0; flex: 1; }
  .client-num { font-size: 12px; color: var(--text3); min-width: 26px; flex-shrink: 0; }
  .client-name { font-size: 14px; font-weight: 500; }
  .client-meta { font-size: 11px; color: var(--text2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px; }
  .client-right { font-size: 11px; color: var(--text2); flex-shrink: 0; margin-left: 8px; }

  /* Source breakdown */
  .sources-bar { display: flex; flex-wrap: wrap; gap: 6px; padding: 10px 12px; background: var(--bg2); border-radius: var(--radius); margin-bottom: 1rem; align-items: center; }
  .sources-bar-label { font-size: 12px; color: var(--text2); }

  /* Empty state */
  .empty { text-align: center; padding: 3rem 1rem; color: var(--text2); border: 1px dashed var(--border2); border-radius: var(--radius-lg); }
  .empty-icon { font-size: 28px; margin-bottom: 10px; }

  /* Toolbar row */
  .toolbar { display: flex; gap: 8px; margin-bottom: 1rem; align-items: center; flex-wrap: wrap; }
  .toolbar input { flex: 1; min-width: 160px; }
  .toolbar select { font-size: 12px; padding: 7px 10px; border-radius: var(--radius); border: 1px solid var(--border2); background: var(--bg); color: var(--text); }

  /* Back button */
  .back-btn { display: inline-flex; align-items: center; gap: 5px; font-size: 13px; color: var(--text2); background: none; border: none; cursor: pointer; margin-bottom: 1rem; padding: 0; }
  .back-btn:hover { color: var(--text); }

  /* Detail card */
  .detail-card { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 1.25rem; }
  .detail-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem; }
  .detail-title { font-size: 18px; font-weight: 600; margin-bottom: 4px; }
  .detail-section { border-top: 1px solid var(--border); padding-top: 1rem; margin-top: 1rem; }
  .detail-section-title { font-size: 13px; font-weight: 500; color: var(--text2); margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
  .detail-filter { font-size: 12px; padding: 5px 10px; border-radius: var(--radius); border: 1px solid var(--border2); background: var(--bg); color: var(--text); width: 150px; }

  /* Overlap */
  .overlap-card { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px 16px; margin-bottom: 8px; }
  .overlap-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .overlap-name { font-weight: 500; font-size: 14px; }

  /* Spinner */
  .spinner { display: inline-block; width: 13px; height: 13px; border-radius: 50%; border: 2px solid rgba(0,0,0,0.15); border-top-color: currentColor; animation: spin 0.8s linear infinite; flex-shrink: 0; }
  .spinner-white { border-color: rgba(255,255,255,0.3); border-top-color: #fff; }

  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }

  /* Responsive */
  @media (max-width: 600px) {
    .stats { grid-template-columns: 1fr 1fr; }
    .scrape-bar { flex-direction: column; }
    .topbar { padding: 0 1rem; }
    .main { padding: 1rem; }
    .tabs { padding: 1rem 1rem 0; }
  }
</style>
</head>
<body>

<!-- Auth screen -->
<div id="authScreen">
  <div class="auth-wrap">
    <div class="auth-card">
      <div class="auth-logo">
        <div class="auth-logo-icon">🔍</div>
        <h1>Client Intelligence</h1>
        <p>Discover who your competitors are publicly serving</p>
      </div>
      <div class="auth-box">
        <h2 id="authTitle">Welcome back</h2>
        <div id="authAlert" class="alert alert-error" style="display:none"></div>
        <div id="authInfo" class="alert alert-info" style="display:none"></div>
        <div class="field">
          <label>Email address</label>
          <input type="email" id="authEmail" placeholder="you@company.com" autocomplete="email">
        </div>
        <div id="passwordField" class="field">
          <label>Password</label>
          <input type="password" id="authPassword" placeholder="Your password" autocomplete="current-password">
        </div>
        <div id="confirmField" class="field" style="display:none">
          <label>Confirm password</label>
          <input type="password" id="authConfirm" placeholder="Repeat password">
        </div>
        <button class="btn btn-primary btn-full" id="authBtn" onclick="handleAuth()">
          Sign in
        </button>
        <div class="auth-links" id="authLinks">
          <button onclick="setMode('signup')">No account? <span>Create one</span></button>
          <button onclick="setMode('reset')">Forgot password?</button>
        </div>
        <div class="auth-links" id="authBackLinks" style="display:none">
          <button onclick="setMode('login')">← Back to sign in</button>
        </div>
      </div>
      <div class="auth-footer">Data stored per account  &middot;  Passwords hashed with SHA-256</div>
    </div>
  </div>
</div>

<!-- Main app -->
<div id="appScreen" class="app">

  <!-- Topbar -->
  <nav class="topbar">
    <div class="topbar-brand">
      <div class="topbar-brand-icon">🔍</div>
      Client Intelligence
    </div>
    <div class="topbar-right">
      <button class="avatar-btn" onclick="toggleDropdown()">
        <span class="avatar" id="avatarLetter">?</span>
        <span id="avatarEmail" style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></span>
      </button>
      <div class="dropdown" id="dropdown">
        <div class="dropdown-email">
          <strong id="dropdownEmail"></strong>
          <span id="dropdownStats"></span>
        </div>
        <button onclick="doLogout()">Sign out</button>
      </div>
    </div>
  </nav>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab active" id="tabRepo" onclick="switchTab('repo')">Companies</button>
    <button class="tab" id="tabClients" onclick="switchTab('clients')">All clients</button>
    <button class="tab" id="tabOverlap" onclick="switchTab('overlap')">Overlap</button>
  </div>

  <div class="main">

    <!-- Scrape bar (shown on all tabs) -->
    <div class="scrape-bar">
      <input type="text" id="scrapeInput" placeholder="Paste URL — e.g. https://www.flowout.com/portfolio or imagine.si" onkeydown="if(event.key==='Enter')doScrape()">
      <button class="btn btn-default" id="scrapeBtn" onclick="doScrape()">Scrape</button>
    </div>
    <div class="scrape-hint">
      <span>Direct reference/portfolio page URL gives best results  &middot;  No AI tokens used</span>
      <button class="log-toggle" id="logToggle" onclick="toggleLog()" style="display:none">Show log</button>
    </div>

    <!-- Progress -->
    <div class="progress" id="progressBox" style="display:none">
      <div class="progress-status"><span class="spinner"></span><span id="progressMsg">Starting...</span></div>
      <div class="progress-phases">
        <div class="progress-phase">
          <div class="progress-bar" id="pb1"></div>
          <div class="progress-label" id="pl1">1. Find pages</div>
        </div>
        <div class="progress-phase">
          <div class="progress-bar" id="pb2"></div>
          <div class="progress-label" id="pl2">2. Parse HTML</div>
        </div>
        <div class="progress-phase">
          <div class="progress-bar" id="pb3"></div>
          <div class="progress-label" id="pl3">3. Done</div>
        </div>
      </div>
      <div class="log-box" id="logBox" style="display:none"></div>
    </div>

    <div id="scrapeAlert" class="alert alert-error" style="display:none"></div>

    <!-- Stats row -->
    <div class="stats" id="statsRow" style="display:none">
      <div class="stat"><div class="stat-label">Companies</div><div class="stat-value" id="statCompanies">0</div></div>
      <div class="stat"><div class="stat-label">Unique clients</div><div class="stat-value" id="statClients">0</div></div>
      <div class="stat"><div class="stat-label">Shared clients</div><div class="stat-value" id="statShared">0</div></div>
      <div class="stat"><div class="stat-label">Tokens used</div><div class="stat-value">0 🎉</div></div>
    </div>

    <!-- -- PAGE: repo -- -->
    <div class="page active" id="pageRepo">
      <div id="repoEmpty" class="empty" style="display:none">
        <div class="empty-icon">🌍</div>
        <div>Paste any company URL above to start building your repository.</div>
        <div style="font-size:12px;margin-top:6px;color:var(--text3)">Works for any language — .si, .de, .fr, .hr, .com and more</div>
      </div>
      <div style="margin-bottom:1rem;display:none" id="repoSearchWrap">
        <input type="text" id="repoSearch" placeholder="Search companies or clients..." oninput="renderRepo()">
      </div>
      <div class="card-list" id="repoList"></div>
    </div>

    <!-- -- PAGE: clients -- -->
    <div class="page" id="pageClients">
      <div class="toolbar">
        <input type="text" id="clientSearch" placeholder="Search clients..." oninput="renderClients()">
        <select id="clientSource" onchange="renderClients()">
          <option value="all">All sources</option>
          <option value="table">Tables</option>
          <option value="heading">Headings</option>
          <option value="case study">Case study links</option>
          <option value="logo">Logo text</option>
          <option value="list">Lists</option>
          <option value="card">Cards</option>
        </select>
      </div>
      <div id="clientList"></div>
    </div>

    <!-- -- PAGE: overlap -- -->
    <div class="page" id="pageOverlap">
      <p style="font-size:13px;color:var(--text2);margin-bottom:1rem">Clients appearing across multiple tracked companies — useful for spotting shared accounts and market overlap.</p>
      <div id="overlapList"></div>
    </div>

    <!-- -- PAGE: detail -- -->
    <div class="page" id="pageDetail">
      <button class="back-btn" onclick="switchTab('repo')">← Back to companies</button>
      <div class="detail-card" id="detailCard"></div>
    </div>

  </div>
</div>

<script charset="utf-8">
// --- State --------------------------------------------------------------------
let state = {
  user: null,
  repo: {},
  currentTab: "repo",
  loading: false,
  logs: [],
  showLog: false,
  authMode: "login",
};

const LANG_FLAG = {slovenian:"",german:"",french:"",spanish:"",italian:"",dutch:"",polish:"",english:"",croatian:"",serbian:"",hungarian:"",romanian:"",portuguese:"",russian:"",czech:"",slovak:""};

const SOURCE_CLASS = {
  "table": "badge-green",
  "heading": "badge-blue",
  "case study link": "badge-blue",
  "list": "badge-gray",
  "card": "badge-gray",
  "grid": "badge-gray",
  "logo alt": "badge-amber",
  "logo title": "badge-amber",
  "logo filename": "badge-amber",
  "json-ld": "badge-gray",
};

function sourceBadge(source) {
  if (!source) return "";
  const cls = SOURCE_CLASS[source] || "badge-gray";
  return `<span class="badge ${cls}">${source}</span>`;
}

// --- API ----------------------------------------------------------------------
async function api(method, path, body) {
  const opts = { method, credentials: "include", headers: { "Content-Type": "application/json" } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  const ct = r.headers.get("content-type") || "";
  if (!ct.includes("application/json")) {
    const text = await r.text();
    throw new Error("Server error (" + r.status + "): " + text.slice(0, 120));
  }
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || "Request failed");
  return data;
}

// --- Init ---------------------------------------------------------------------
async function init() {
  try {
    const me = await api("GET", "/api/me");
    await loginSuccess(me.email, false);
  } catch {
    showAuth();
  }
}

function showAuth() {
  document.getElementById("authScreen").style.display = "";
  document.getElementById("appScreen").classList.remove("visible");
}

async function loginSuccess(email, loadRepo = true) {
  state.user = email;
  document.getElementById("authScreen").style.display = "none";
  document.getElementById("appScreen").classList.add("visible");
  document.getElementById("avatarLetter").textContent = email[0].toUpperCase();
  document.getElementById("avatarEmail").textContent = email;
  document.getElementById("dropdownEmail").textContent = email;
  if (loadRepo) {
    state.repo = (await api("GET", "/api/repo")) || {};
  } else {
    try { state.repo = (await api("GET", "/api/repo")) || {}; } catch {}
  }
  renderAll();
}

// --- Auth ----------------------------------------------------------------------
function setMode(mode) {
  state.authMode = mode;
  document.getElementById("authAlert").style.display = "none";
  document.getElementById("authInfo").style.display = "none";
  const titles = { login: "Welcome back", signup: "Create account", reset: "Reset password" };
  const btns   = { login: "Sign in", signup: "Create account", reset: "Send reset link" };
  document.getElementById("authTitle").textContent = titles[mode];
  document.getElementById("authBtn").textContent = btns[mode];
  document.getElementById("passwordField").style.display = mode === "reset" ? "none" : "";
  document.getElementById("confirmField").style.display = mode === "signup" ? "" : "none";
  document.getElementById("authLinks").style.display = mode === "login" ? "" : "none";
  document.getElementById("authBackLinks").style.display = mode !== "login" ? "" : "none";
  document.getElementById("authPassword").value = "";
  document.getElementById("authConfirm").value = "";
}

async function handleAuth() {
  const email = document.getElementById("authEmail").value.trim().toLowerCase();
  const password = document.getElementById("authPassword").value;
  const confirm = document.getElementById("authConfirm").value;
  const alertEl = document.getElementById("authAlert");
  const infoEl = document.getElementById("authInfo");
  alertEl.style.display = "none";
  infoEl.style.display = "none";

  const btn = document.getElementById("authBtn");
  btn.disabled = true;
  const origText = btn.textContent;
  btn.innerHTML = '<span class="spinner"></span> Please wait...';

  try {
    if (state.authMode === "login") {
      const r = await api("POST", "/api/login", { email, password });
      await loginSuccess(r.email);
    } else if (state.authMode === "signup") {
      if (password.length < 8) throw new Error("Password must be at least 8 characters");
      if (password !== confirm) throw new Error("Passwords do not match");
      const r = await api("POST", "/api/signup", { email, password });
      await loginSuccess(r.email);
    } else {
      infoEl.textContent = "If an account exists for that email, a reset link would be sent. (Email delivery requires backend SMTP config.)";
      infoEl.style.display = "";
    }
  } catch (e) {
    alertEl.textContent = e.message;
    alertEl.style.display = "";
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
  }
}

document.getElementById("authEmail").addEventListener("keydown", e => { if (e.key === "Enter") handleAuth(); });
document.getElementById("authPassword").addEventListener("keydown", e => { if (e.key === "Enter") handleAuth(); });

async function doLogout() {
  await api("POST", "/api/logout").catch(() => {});
  state.user = null;
  state.repo = {};
  document.getElementById("dropdown").classList.remove("open");
  showAuth();
}

function toggleDropdown() {
  document.getElementById("dropdown").classList.toggle("open");
}
document.addEventListener("click", e => {
  if (!e.target.closest(".topbar-right")) document.getElementById("dropdown").classList.remove("open");
});

// --- Scrape -------------------------------------------------------------------
let phaseInterval;

function setPhase(phase) {
  ["pb1","pb2","pb3"].forEach((id,i) => {
    const active = i+1 === phase;
    document.getElementById(id).className = "progress-bar" + (active ? " active" : "");
    document.getElementById(`pl${i+1}`).className = "progress-label" + (active ? " active" : "");
  });
}

function appendLog(msg) {
  state.logs.push(msg);
  const box = document.getElementById("logBox");
  const line = document.createElement("div");
  line.textContent = msg;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
  document.getElementById("progressMsg").textContent = msg.slice(0, 80);
  // Detect phase from log
  if (msg.includes("Phase 1") || msg.includes("Discovering") || msg.includes("homepage")) setPhase(1);
  else if (msg.includes("Phase 2") || msg.includes("Fetching:") || msg.includes("Scraping")) setPhase(2);
  else if (msg.includes("Done:")) setPhase(3);
}

async function doScrape() {
  const url = document.getElementById("scrapeInput").value.trim();
  if (!url || state.loading) return;
  state.loading = true;
  state.logs = [];
  document.getElementById("scrapeBtn").disabled = true;
  document.getElementById("scrapeBtn").innerHTML = '<span class="spinner"></span> Scraping...';
  document.getElementById("scrapeAlert").style.display = "none";
  document.getElementById("progressBox").style.display = "";
  document.getElementById("logBox").innerHTML = "";
  document.getElementById("logToggle").style.display = "";
  setPhase(1);

  try {
    const r = await api("POST", "/api/scrape", { url });
    (r.logs || []).forEach(appendLog);
    setPhase(3);
    // Reload repo
    state.repo = await api("GET", "/api/repo");
    renderAll();
    // Show detail of new entry
    if (r.result?.key) showDetail(r.result.key);
  } catch (e) {
    const alertEl = document.getElementById("scrapeAlert");
    alertEl.textContent = e.message || "Scraping failed. Check the URL and try again.";
    alertEl.style.display = "";
    document.getElementById("progressBox").style.display = "none";
  } finally {
    state.loading = false;
    document.getElementById("scrapeBtn").disabled = false;
    document.getElementById("scrapeBtn").textContent = "Scrape";
  }
}

function toggleLog() {
  state.showLog = !state.showLog;
  document.getElementById("logBox").style.display = state.showLog ? "" : "none";
  document.getElementById("logToggle").textContent = state.showLog ? "Hide log" : "Show log";
}

// --- Computed -----------------------------------------------------------------
function getStats() {
  const companies = Object.values(state.repo);
  const allNames = new Set(companies.flatMap(c => (c.clients||[]).map(x => x.name.toLowerCase())));
  const clientMap = buildClientMap();
  const shared = Object.values(clientMap).filter(x => x.vendors.length > 1);
  return { companies: companies.length, clients: allNames.size, shared: shared.length };
}

function buildClientMap() {
  const map = {};
  Object.values(state.repo).forEach(c => {
    (c.clients||[]).forEach(cl => {
      const k = (cl.name||"").toLowerCase().trim();
      if (!k) return;
      if (!map[k]) map[k] = { name: cl.name, vendors: [], sources: {} };
      if (!map[k].vendors.includes(c.company_name)) {
        map[k].vendors.push(c.company_name);
        map[k].sources[c.company_name] = cl.source;
      }
    });
  });
  return map;
}

// --- Render -------------------------------------------------------------------
function renderAll() {
  const stats = getStats();
  document.getElementById("statsRow").style.display = stats.companies > 0 ? "" : "none";
  document.getElementById("statCompanies").textContent = stats.companies;
  document.getElementById("statClients").textContent = stats.clients;
  document.getElementById("statShared").textContent = stats.shared;
  document.getElementById("dropdownStats").textContent = `${stats.companies} companies  &middot;  ${stats.clients} clients`;
  document.getElementById("tabRepo").textContent = `Companies${stats.companies ? ` (${stats.companies})` : ""}`;
  document.getElementById("tabClients").textContent = `All clients${stats.clients ? ` (${stats.clients})` : ""}`;
  document.getElementById("tabOverlap").textContent = `Overlap${stats.shared ? ` (${stats.shared})` : ""}`;
  renderRepo();
  renderClients();
  renderOverlap();
}

function renderRepo() {
  const companies = Object.values(state.repo);
  const search = (document.getElementById("repoSearch")?.value || "").toLowerCase();
  const filtered = companies.filter(c =>
    !search ||
    c.company_name.toLowerCase().includes(search) ||
    (c.clients||[]).some(cl => cl.name.toLowerCase().includes(search))
  );
  const emptyEl = document.getElementById("repoEmpty");
  const searchWrap = document.getElementById("repoSearchWrap");
  const listEl = document.getElementById("repoList");

  if (companies.length === 0) {
    emptyEl.style.display = "";
    searchWrap.style.display = "none";
    listEl.innerHTML = "";
    return;
  }
  emptyEl.style.display = "none";
  searchWrap.style.display = "";

  listEl.innerHTML = filtered.map(c => {
    const clients = c.clients || [];
    const preview = clients.slice(0,7).map(cl => `<span class="pill">${esc(cl.name)}</span>`).join("");
    const more = clients.length > 7 ? `<span style="font-size:12px;color:var(--text3)">+${clients.length-7} more</span>` : "";
    const flag = LANG_FLAG[c.detected_language] || "";
    const langBadge = c.detected_language ? `<span class="badge badge-gray">${flag} ${c.detected_language}</span>` : "";
    const desc = c.company_description ? `<div class="card-desc">${esc(c.company_description.slice(0,140))}${c.company_description.length>140?"...":""}</div>` : "";
    return `
      <div class="card card-clickable" onclick="showDetail('${esc(c.key)}')">
        <div class="card-header">
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:2px">
              <span class="card-title">${esc(c.company_name)}</span>
              ${langBadge}
            </div>
            <div class="card-sub">${esc(c.company_domain)}</div>
            ${desc}
            <div class="pills">${preview}${more}${clients.length===0?'<span style="font-size:12px;color:var(--text3);font-style:italic">No clients found</span>':""}</div>
          </div>
          <div class="card-count">
            <div class="card-count-num">${clients.length}</div>
            <div class="card-count-label">clients</div>
          </div>
        </div>
      </div>`;
  }).join("");
}

function renderClients() {
  const map = buildClientMap();
  const search = (document.getElementById("clientSearch")?.value || "").toLowerCase();
  const sourceFilter = document.getElementById("clientSource")?.value || "all";
  const list = Object.values(map)
    .filter(x => {
      if (search && !x.name.toLowerCase().includes(search)) return false;
      if (sourceFilter !== "all") {
        const srcs = Object.values(x.sources).join(" ").toLowerCase();
        if (!srcs.includes(sourceFilter)) return false;
      }
      return true;
    })
    .sort((a,b) => b.vendors.length - a.vendors.length);

  const el = document.getElementById("clientList");
  if (list.length === 0) {
    el.innerHTML = '<div class="empty"><div class="empty-icon"></div><div>No clients indexed yet.</div></div>';
    return;
  }
  el.innerHTML = list.map((cl,i) => {
    const src = Object.values(cl.sources)[0];
    const vendorBadges = cl.vendors.map(v => `<span class="badge badge-gray">${esc(v)}</span>`).join("");
    return `
      <div class="client-row">
        <div class="client-row-left">
          <span class="client-num">${i+1}.</span>
          <span class="client-name">${esc(cl.name)}</span>
          ${sourceBadge(src)}
        </div>
        <div style="display:flex;gap:4px;flex-wrap:wrap;justify-content:flex-end;max-width:45%;margin-left:8px">${vendorBadges}</div>
      </div>`;
  }).join("");
}

function renderOverlap() {
  const map = buildClientMap();
  const shared = Object.values(map).filter(x => x.vendors.length > 1).sort((a,b) => b.vendors.length - a.vendors.length);
  const el = document.getElementById("overlapList");
  if (shared.length === 0) {
    el.innerHTML = '<div class="empty"><div class="empty-icon"></div><div>No overlap found yet. Add more companies to discover shared clients.</div></div>';
    return;
  }
  el.innerHTML = shared.map(cl => {
    const vendorBadges = cl.vendors.map(v => `<span class="badge badge-gray">${esc(v)}</span>`).join("");
    return `
      <div class="overlap-card">
        <div class="overlap-header">
          <span class="overlap-name">${esc(cl.name)}</span>
          <span class="badge badge-amber">${cl.vendors.length} vendors</span>
        </div>
        <div class="pills">${vendorBadges}</div>
      </div>`;
  }).join("");
}

function showDetail(key) {
  const c = state.repo[key];
  if (!c) return;
  switchTab("detail");

  const flag = LANG_FLAG[c.detected_language] || "";
  const langBadge = c.detected_language ? `<span class="badge badge-gray">${flag} ${c.detected_country || c.detected_language}</span>` : "";
  const clients = c.clients || [];

  // Source breakdown
  const srcMap = {};
  clients.forEach(cl => { const s = cl.source||"unknown"; srcMap[s] = (srcMap[s]||0)+1; });
  const srcBadges = Object.entries(srcMap).sort((a,b)=>b[1]-a[1])
    .map(([src,n]) => `${sourceBadge(src)} <span style="font-size:11px;color:var(--text2)">${n}</span>`)
    .join(" ");

  const scrapedLinks = (c.sources_checked||[]).map(s => `<a href="${esc(s)}" target="_blank" style="display:block;font-size:11px;margin-bottom:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s)}</a>`).join("");

  document.getElementById("detailCard").innerHTML = `
    <div class="detail-header">
      <div style="flex:1">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">
          <span class="detail-title">${esc(c.company_name)}</span>
          ${langBadge}
        </div>
        <a href="https://${esc(c.company_domain)}" target="_blank" style="font-size:13px">${esc(c.company_domain)}</a>
        ${c.company_description ? `<p style="font-size:13px;color:var(--text2);margin-top:8px;line-height:1.5">${esc(c.company_description)}</p>` : ""}
      </div>
      <button class="btn btn-danger" onclick="deleteEntry('${esc(key)}')" style="margin-left:12px;flex-shrink:0">Remove</button>
    </div>

    ${srcBadges ? `<div class="sources-bar"><span class="sources-bar-label">Sources:</span>${srcBadges}</div>` : ""}

    <div class="detail-section">
      <div class="detail-section-title">
        <span>${clients.length} clients found</span>
        <input class="detail-filter" type="text" placeholder="Filter..." oninput="filterDetail('${esc(key)}', this.value)" id="detailFilter">
      </div>
      <div id="detailClientList">
        ${renderClientList(clients)}
      </div>
    </div>

    ${scrapedLinks ? `
    <div class="detail-section">
      <div style="font-size:12px;color:var(--text2);font-weight:500;margin-bottom:6px">Pages scraped</div>
      ${scrapedLinks}
    </div>` : ""}

    <div style="font-size:11px;color:var(--text3);margin-top:1rem">
      Scraped ${new Date(c.scraped_at).toLocaleDateString()}
    </div>
  `;
}

function renderClientList(clients, filter) {
  if (!clients || clients.length === 0) {
    return `<div style="font-size:13px;color:var(--text2);font-style:italic">No clients found. Try pasting the direct reference/portfolio page URL.</div>`;
  }
  const filtered = filter ? clients.filter(cl => cl.name.toLowerCase().includes(filter.toLowerCase())) : clients;
  return filtered.map((cl,i) => `
    <div class="client-row">
      <div class="client-row-left">
        <span class="client-num">${i+1}.</span>
        <span class="client-name">${esc(cl.name)}</span>
        ${sourceBadge(cl.source)}
        ${cl.industry ? `<span class="client-meta">${esc(cl.industry)}</span>` : ""}
      </div>
      ${(cl.country||cl.city) ? `<span class="client-right">${esc([cl.country,cl.city].filter(Boolean).join(", "))}</span>` : ""}
    </div>`).join("");
}

function filterDetail(key, filter) {
  const c = state.repo[key];
  if (!c) return;
  document.getElementById("detailClientList").innerHTML = renderClientList(c.clients||[], filter);
}

async function deleteEntry(key) {
  if (!confirm("Remove this company from your repository?")) return;
  await api("DELETE", `/api/repo/${key}`);
  state.repo = await api("GET", "/api/repo");
  renderAll();
  switchTab("repo");
}

// --- Tab switching -------------------------------------------------------------
function switchTab(tab) {
  state.currentTab = tab;
  ["repo","clients","overlap","detail"].forEach(t => {
    document.getElementById(`page${t.charAt(0).toUpperCase()+t.slice(1)}`).classList.toggle("active", t === tab);
  });
  ["repo","clients","overlap"].forEach(t => {
    const el = document.getElementById(`tab${t.charAt(0).toUpperCase()+t.slice(1)}`);
    if (el) el.classList.toggle("active", t === tab);
  });
}

// --- Utils --------------------------------------------------------------------
function esc(s) {
  return (s||"").toString().replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// --- Boot --------------------------------------------------------------------
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
