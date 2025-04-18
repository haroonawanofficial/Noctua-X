# AI XSS Fuzzer – RazKash (v4.3)

AI‑powered **cross‑site‑scripting discovery engine** that auto‑crawls an entire domain, detects every parameter surface (forms, query‑strings, JS‑defined endpoints) and unleashes a huge corpus of **mutated payloads** to verify real browser‑triggered XSS.

|     Feature |
|---|---------|
| **AI‑driven payload mutation** |
| **Super‑crawler** — walks every same‑domain link and scrapes JS (`fetch()`, `axios`, XHR) for hidden APIs |
| Headless **Chromium verifier** (Playwright) for alert ( `dialog` ) confirmation & side‑effect detection |
| Smart HTTPS⇆HTTP root probing, fake‑header rotation & human‑like delays to dodge WAFs |
| Multithreaded fuzzing, slim deduped Markdown report (`≤ 120 B` per finding) |
| `--debug`, `--autotest`, page/threads caps for controlled runs |

---

## Installation

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt  # see below
sudo apt install -y chromium  # or your distro’s package```

## How to Use?
```
python ai_xss.py --url http://testph.vulnweb.com 
```

