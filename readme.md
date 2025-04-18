# RazKash v4.3 — AI‑Powered XSS Fuzzer

> **AI Powered discovers zero‑day XSS by auto‑crawling an entire domain, generating novel payloads with AI, and verifying each hit in a real browser.**

---

## Key Features
- **AI‑driven payload mutation**
- **Super‑crawler** that walks every same‑origin link & scrapes JavaScript (`fetch`, `axios`, XHR) to surface hidden APIs. 
- **Headless Chromium verifier** (Playwright) that intercepts `dialog` events and DOM side‑effects to confirm exploitation.  
- **Smart protocol probing** (HTTP ⇆ HTTPS), header rotation, and human‑like timing to evade WAFs and rate limits.  
- **High‑performance, multithreaded engine** with depth, page, and thread caps for deterministic fuzzing.  
- **Lightweight Markdown reporting** (≤ 120 bytes per finding) for painless CI diffing.  
- Built‑in `--debug` and `--autotest` modes for rapid troubleshooting.

---

## Installation
```bash
git clone https://github.com/your‑org/razkash.git
cd razkash

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt      # Playwright installs Chromium automatically

# If Playwright skipped browser download, run:
# playwright install chromium

python ai_xss.py --url http://testphp.vulnweb.com

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
