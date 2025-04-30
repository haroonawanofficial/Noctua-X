# RazKash v8.1 — AI‑Powered XSS Fuzzer

 **AI Powered discovers zero‑day XSS and verifying each hit in a real browser.**

---

## Key Features
- AI logic
- Tubro charged 500 000+ unique payloads
- **Super‑crawler** that walks every same‑origin link & scrapes JavaScript (`fetch`, `axios`, XHR) to surface hidden APIs. 
- **Headless Chromium verifier** that intercepts `dialog` events and DOM side‑effects to confirm exploitation.  
- **Smart protocol probing** (HTTP ⇆ HTTPS), header rotation, and human‑like timing to evade WAFs and rate limits.  
- **High‑performance, multithreaded engine** with depth, page, and thread caps for deterministic fuzzing.  
- **Lightweight Markdown reporting** (≤ 120 bytes per finding) for painless CI diffing.  
- Built‑in `--debug` and `--autotest` modes for rapid troubleshooting.
- Static & Dynamic Crawling (HTML links, JS assets, sitemaps, manifests, Playwright-driven XHR/DOM)  
- AI-Powered
- GPU Powered
- Polyglot & Context-Aware Payloads (HTML, attributes, CSS, SVG/XLink, URLs, templates, WebAssembly, service-worker cache, modern APIs)  
- Client-Side Template Injection support (AngularJS, Handlebars, Vue, React)  
- CSP & TrustedTypes Bypass stubs and gadget chains  
- Blind/OOB XSS via DNSLOG callbacks  
- WebAssembly & Service-Worker Cache Injection fuzzing  
- Modern API Fuzzing (WebGPU, WebXR, WebTransport, SharedArrayBuffer)  
- Edge-Case Encoding & Parsing Quirks (RTL override, HTTP/2 path tricks, MIME-sniffing)  
- Cross-Protocol & Cross-Origin Chains (file://, ftp://, WebSocket race)  
- Advanced DOM Clobbering & Prototype Pollution vectors  
- In-Browser Verification of sink execution via Playwright + injected JSFLAG  
- HTTP/HTTPS & WebSocket fuzzers in one tool
  
---


# Supports
- All Modern Dynamic Websites/Webpages
- All Modern Dynamic Endpoints
- All Modern Dynamic Apps
- Discovers moder under the hidden surface
- Detects more
- Full support for DNS based beacons
- Detects what others miss!


# Overview
## What XSS vector RazKash targets?
- Script‑tag injections (<script>, <mg src=x onerror=…>)
- Attribute/event‑handler injections (onload=, onclick=, etc.)
- Inline‑JS URI handlers (javascript:alert(1))
- SVG namespace vectors
- Iframe / frame src manipulations
- Media elements (video, audio, source)
- Object/Embed/Flash fallbacks
- MathML payloads
- HTML5 interactive tags (details, marquee, dialog)
- CSS/Style payloads (expression, url() data‑URIs)
- JSONP/JS callback reflections
- DOM‑only sinks (innerHTML, location.hash, setTimeout)
- Shadow‑DOM context breaks
- WebAssembly & dynamic import() primitives
- MutationObserver & DOM‑diff race vectors
- CRLF → header injection chains
- Stored, Reflected with auto Get/Post
- RLO/Unicode disguise payloads
- SMIL & SVG animation triggers
- Blind‑XSS (DNS/WebSocket beacons)
- Polyglot & multi‑context payloads (HTML+JS+CSS)


## Installation
```bash
git clone https://github.com/your‑org/razkash.git
cd razkash

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt      # Playwright installs Chromium automatically

# If Playwright skipped browser download, run:
# playwright install chromium

python razkash.py --url http://testphp.vulnweb.com

Common CLI Flags

Flag	Purpose
--depth N	Maximum crawl depth (default 3)
--threads N	Worker threads (default 20)
--pages N	Max pages to crawl (no limit if omitted)
--debug	Verbose logging + request/response dump
--autotest	Run built‑in self‑test suite and exit
Report Format
Findings are appended to reports/YYYY‑MM‑DD‑HHMM.md:

[+] http://example.com/product?id=1337
    parameter : id
    payload   : "><svg/onload=alert(1)>
```
