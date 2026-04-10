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
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__, template_folder="templates")
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

# ---- frontend -----------------------------------------------------------------

@app.route("/")
@app.route("/<path:path>")
def frontend(path=""):
    return send_from_directory("templates", "index.html")

# ---- run ----------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  Client Intelligence running at http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
