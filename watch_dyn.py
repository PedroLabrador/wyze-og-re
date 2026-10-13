#!/usr/bin/env python3
"""Find the live authorize tab dynamically, ensure it's navigated to our URL, watch for the code."""
import asyncio, json, urllib.request, time, re, os, sys
import websockets

PK = json.load(open('~/Downloads/pkce_final.json'))
URL = PK["url"]
CODE = "~/Downloads/oauth_code.txt"

def targets():
    for _ in range(5):
        try:
            with urllib.request.urlopen("http://localhost:9222/json/list") as r:
                return json.load(r)
        except Exception:
            time.sleep(1)
    return []

def find_auth_tab():
    tabs=[t for t in targets() if t.get("type")=="page"]
    # prefer one already on authorize with our state=final2
    for t in tabs:
        if "oauth/authorize" in t.get("url","") and "state=final2" in t.get("url",""):
            return t
    for t in tabs:
        if "oauth/authorize" in t.get("url",""):
            return t
    return None

async def watch(tgt, window=30, navigate=False):
    url=tgt.get("webSocketDebuggerUrl")
    if not url: return None
    try:
        async with websockets.connect(url,max_size=None,ping_interval=None,open_timeout=5) as ws:
            await ws.send(json.dumps({"id":0,"method":"Network.enable"}))
            if navigate:
                await ws.send(json.dumps({"id":1,"method":"Page.navigate","params":{"url":URL}}))
            else:
                await ws.send(json.dumps({"id":2,"method":"Runtime.evaluate","params":{
                    "expression":"JSON.stringify({href:location.href, body:(document.body?document.body.innerText.slice(0,300):'')})",
                    "returnByValue":True}}))
            end=time.time()+window
            while time.time()<end:
                try: m=await asyncio.wait_for(ws.recv(),timeout=6)
                except asyncio.TimeoutError: continue
                except Exception: break
                o=json.loads(m); meth=o.get("method",""); p=o.get("params",{})
                if o.get("id")==2:
                    v=o.get("result",{}).get("result",{}).get("value")
                    if v:
                        d=json.loads(v)
                        print(f"  HREF {d['href'][:170]}",flush=True)
                        if d['body']: print(f"  BODY {d['body'][:200]}",flush=True)
                if meth=="Network.responseReceived":
                    r=p.get("response",{}); h=r.get("headers",{})
                    loc=h.get("location") or h.get("Location") or ""
                    if loc: print(f"  RESP {r.get('status')} -> {loc[:170]}",flush=True)
                    m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)',loc or "")
                    if m2: return m2.group(1)
                if meth=="Network.requestWillBeSent":
                    rf=p.get("redirectResponse")
                    if rf:
                        h=rf.get("headers",{}); loc=h.get("location") or h.get("Location") or ""
                        if loc: print(f"  REDIR {rf.get('status')} -> {loc[:170]}",flush=True)
                        m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)',loc or "")
                        if m2: return m2.group(1)
                    u=p.get("request",{}).get("url","")
                    if "wyze://" in u:
                        print(f"  REQ-WYZE {u[:170]}",flush=True)
                        m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)',u or "")
                        if m2: return m2.group(1)
                if meth=="Page.frameNavigated":
                    u=p.get("frame",{}).get("url","")
                    if u and not u.startswith("about:") and not u.startswith("chrome-"):
                        print(f"  FRAME {u[:170]}",flush=True)
                    m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)',u or "")
                    if m2 and "authcode-read" not in u: return m2.group(1)
    except Exception as e:
        print(f"  err {e}",flush=True)
    return None

async def main():
    navigate = "--nav" in sys.argv
    deadline=time.time()+150
    first=True
    while time.time()<deadline:
        t=find_auth_tab()
        if not t:
            print("(no authorize tab; waiting)",flush=True)
            await asyncio.sleep(2); first=True; continue
        print(f"watching tab {t['id']}",flush=True)
        code=await watch(t, window=30, navigate=(navigate and first))
        first=False
        if code:
            print("*** CODE:",code,flush=True)
            open(CODE,"w").write(code)
            return
        await asyncio.sleep(1)
    print("NO CODE",flush=True)
asyncio.run(main())
