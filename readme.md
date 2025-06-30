# ART OF XSS - THE REINFORCEMENT

## Context Aware, Server Aware, Self Reinforcement and Waf Aware AI Based XSS Fuzzer

| **Feature**             | **old**                                                                 | **new**                                                                 | **Analysis of the Upgrade**                                                                                                                                                        |
|-------------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Core Fuzzing Logic**  | Randomized / Procedural                                                                       | Adaptive / Learning-Based                                                                  | Biggest improvement. v10.0 uses Reinforcement Learning to remember what works per target and adapts dynamically, unlike v9.4’s stateless random selection.                         |
| **Payload Selection**   | Picks randomly from `BASE_PAYLOADS`, optional AI mutation or polymorphism.                   | Uses `agent.choose(param)` (ε-greedy Q-learning strategy).                                 | v10.0 focuses on high-reward payloads while still exploring new ones, drastically improving efficiency and hit rate.                                                                 |
| **Context-Awareness**   | Optional WAF spoofing (`--detect-waf`), but not tied to payload logic.                        | Builds `(waf, server, param_type)` state for each parameter; guides payload selection.     | v10.0 learns what payloads work on Nginx but fail on Cloudflare etc. Allows adaptive behavior by server type and parameter class.                                                    |
| **Feedback Loop**       | None – no learning, each run is independent.                                                  | Explicit reward system: R_CONFIRM, R_BLOCK, R_SERROR etc.                                 | Enables learning. v10.0 continuously improves during scan by reinforcing successful actions and penalizing failed or blocked attempts.                                               |
| **Knowledge & Memory**  | Stateless – starts fresh every run.                                                           | Persistent – can save and reload Q-table (`--qtable-file`) for memory between scans.       | Huge leap in intelligence. The fuzzer becomes smarter over time and can transfer learning across targets.                                                                          |


---

## Download the full PDF
http://cyberzeus.pk/Noctua_Autonomous_XSS_Fuzzing_Comphrensive_Guide.pdf

---

## Key Features
```
- AI-Based Context-Aware Fuzzing uniquepayloads, generated on-the-fly with AI mutation
- Super-crawler: Walks every same-origin link and scrapes JavaScript (fetch, axios, XHR) to surface hidden APIs
- Headless Chromium verifier using Playwright — intercepts dialog events and DOM side effects to confirm exploitation
- Smart protocol probing: HTTP⇆HTTPS, header rotation, timing jitter to evade WAFs and rate limits
- High-performance multithreaded engine — full control over depth, pages, threads
- Lightweight Markdown reports (≤120 bytes per finding) → CI-ready, version-controllable
- Built-in --debug and --autotest modes for quick troubleshooting or testbed use
- Static + Dynamic Crawling: Links, JS assets, sitemaps, manifests, SPAs, Playwright-driven XHR/DOM analysis
- AI-powered with GPU support 
- Polyglot & Context-Aware Payloads: HTML, attributes, CSS, SVG, WebAssembly, service-worker, etc.
- Client-Side Template Injection (AngularJS, Handlebars, Vue, React)
- CSP & TrustedTypes Bypass gadgets
- Blind/OOB XSS via DNSLOG beacons
- WebAssembly & Service-Worker fuzzing
- Modern API Fuzzing: WebGPU, WebXR, WebTransport, SharedArrayBuffer
- Encoding & Parsing Quirks: RLO, BOM, HTTP/2 tricks, MIME-sniffing
- Cross-Protocol Chains: file://, ftp://, WebSocket race, iframe sandbox escapes
- Advanced DOM Clobbering & Prototype Pollution
- In-Browser Sink Verification with JSFLAGs and Playwright
- WebSocket fuzzing + injection and detection
- HTML Links + <form> + <button> auto extraction
- JS Asset Mining: fetch, axios, XHR, sourceMappingURL
- Robots.txt → sitemap.xml → <loc> recursion
- Manifest.json + nested iframe/frame crawling
- Playwright request interception & in-page DOM action simulation
- SPA route and button click automation
- Iframe JS content hook injection
- JSON-LD / RDFa / Microdata payload injection
- GraphQL schema discovery + variable fuzzing
- AI-Driven JavaScript Snippet Evolution
- Advanced Encoders: hex, Unicode, base64, ROT13, %URL, CSS hide, BOM, RTL
- Custom filter payloads: <sCrIpT>PAYLOAD</sCrIpT>, HTML comments, template, etc.
- CSP/TrustedTypes inline nonce & bypass
- Service Worker poisoning
- instantiateStreaming WebAssembly injection
- DOM & JSAPI Payloads: WebGPU, WebXR, WebTransport, BroadcastChannel, SSE
- Cross-protocol fuzzing (file://, HTTP/2 smuggling, chunked trick)
- MutationObserver triggers, Prototype pollution
- Passive WAF Fingerprinting: Cloudflare, Akamai, Imperva, Sucuri
- Adaptive header morphing (X-Random, X-Forwarded-For, Referer)
- Polymorphic traffic via --polymorph, random header ordering
- WS/HTTP/2 support planned
- Chunked encoding, compression fuzzing (future)
- Race-condition fuzzing & deferred triggers
- CSRF & Auth Cookie handling logic
- Multi-session stored XSS testing
- Auto Markdown logging (Noctua_findings.md)
- JSON/SARIF/Slack hooks (future reserved)
- ThreadPoolExecutor with --threads
- Page/Depth/WAF/SPAs/Poly/Headed flags
```

  
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
## What XSS vector Noctua targets?
```
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
- Script Tag Injection: <script>, <script src=...>, nested tags, obfuscated forms
- Attribute/Event Handler Injection: onload=, onerror=, onmouseover=, onclick=, and custom event payloads
- Inline JS URI Handlers:javascript:alert(1), data:text/html,..., vbscript:..., mixed casing, whitespaces
- SVG Namespace & Animation Vectors: <svg onload=...>, <svg><a xlink:href=...>, SMIL-based triggers
- Iframe/Frame Source Manipulation: <iframe src="javascript:...">, <frame src=...>
- Media Elements: <video>, <audio>, <object>, <embed>, <source> with onerror, data, src injection
- MathML & XML Entities: <math>, <annotation>, CDATA-based vectors, <!ENTITY xxe>
- HTML5 Interactive Tags: <details>, <dialog>, <marquee>, <textarea autofocus onfocus=...>
- CSS-Based Payloads:style, @import, expression(), list-style-image, animation, and background:url() tricks
- Meta & Link Tag Injection:<meta http-equiv="refresh" ...>, <link rel="stylesheet" href=javascript:...>
- DOM-Based Sinks:innerHTML, outerHTML, eval, Function, setTimeout, appendChild, location.hash
- Shadow DOM Breakouts:Manipulating encapsulated scopes to execute untrusted JS
- MutationObserver & Race Conditions: Triggering sinks via delayed or timed DOM mutations
- WebAssembly & dynamic import(): instantiateStreaming(), runtime JS injection within modules
- JSONP/JS Callback Reflections: Callback injection on API endpoints with ?callback= or ?cb= parameters
- Template Injection (CSTI): AngularJS, Vue, Handlebars, React (e.g., {{constructor.constructor('alert(1)')()}})
- JSON-LD / Microdata / RDFa Injection
- Prototype Pollution & DOM Clobbering
- CRLF / Header Injection → breaks into headers or scripts
- RLO / Unicode-Based Payloads (Right-To-Left Override, BOM)
- Blind XSS (Stored/OOB) via DNSLOG, WebSocket, and Beacon-like callbacks
- Polyglot Payloads - Multiple-context support for HTML + JS + CSS hybrids
- Stored, Reflected, DOM, and Blind XSS
- Cross-Protocol Vectors file://, ftp://, ws://, and iframe sandbox tricks
- Fuzzing nested or deep keys within JSON requests and GraphQL variables
- Service Worker Cache Poisoning
```

## Installation
```bash
git clone https://github.com/haroonawanofficial/Noctua.git
cd Noctua

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt      # Playwright installs Chromium automatically

# If Playwright skipped browser download, run:
# playwright install chromium

python Noctua.py --url http://testphp.vulnweb.com

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

## Real Outputs and in CTF with full automation
```
├─▶ http://xss-game.appspot.com
│   WAF detected: unknown
[static] crawling http://xss-game.appspot.com (≤100 pages, depth=0)
[static] discovered 1 endpoints
[dynamic] launching Playwright for http://xss-game.appspot.com
[dynamic] discovered 5 endpoints
│   HTTP targets: 6   WS targets: 0
- **XSS** GET `http://xss-game.appspot.com/level1/frame` payload=`<!--><script>__proto__.x=amounts</script><!-->`
│   ✓ fuzzing complete
```

## In Noctua, polymorphing includes:
- Encoding (hex, URL, unicode, base64)
- Structural rewrites (swapping attribute order, obfuscating tags)
- Wrapping in innocent-looking tags
- Inserting comments/random whitespace
- Reversing, right-to-left override
- Rebuilding payload trees (AST/JS-based)

## Why it's important:
- Static filters and WAFs often look for exact patterns
- Polymorphic payloads bypass regex/sig-based detection
- Useful in zero-day fuzzing, evasion testing, and XSS detection in hardened environments

## Generates never seen before payload on the spot 
- It generates on-the-fly AI mutation and polymorphic encoding to craft unique, never-seen-before XSS payloads tailored to each context automatically for perfect hit!
```
<!--><script>__proto__.x=amounts</script><!-->
```
