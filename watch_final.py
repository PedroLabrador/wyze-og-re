#!/usr/bin/env python3
"""Robustly read newest authorize tab; watch for wyze:// code across reconnects."""
import asyncio, json, urllib.request, time, re, os
import websockets
CODE="~/Downloads/oauth_code.txt"

def targets():
    for _ in range(5):
        try:
            with urllib.request.urlopen("http://localhost:9222/json/list") as r:
                return json.load(r)
        except Exception:
            time.sleep(1)
    return []

async def watch_tab(tgt, window=25):
    url=tgt.get("webSocketDebuggerUrl")
    if not url: return None
    try:
        async with websockets.connect(url,max_size=None,ping_interval=None,open_timeout=5) as ws:
            await ws.send(json.dumps({"id":0,"method":"Network.enable"}))
            await ws.send(json.dumps({"id":1,"method":"Runtime.evaluate","params":{
                "expression":"JSON.stringify({href:location.href, body:(document.body?document.body.innerText.slice(0,400):'(blank)')})",
                "returnByValue":True}}))
            end=time.time()+window
            while time.time()<end:
                try: m=await asyncio.wait_for(ws.recv(),timeout=6)
                except asyncio.TimeoutError: continue
                except Exception: break
                o=json.loads(m); meth=o.get("method",""); p=o.get("params",{})
                if o.get("id")==1:
                    v=o.get("result",{}).get("result",{}).get("value")
                    if v:
                        d=json.loads(v)
                        print(f"[tab {tgt['id']}] HREF: {d['href'][:180]}",flush=True)
                        print(f"[tab {tgt['id']}] BODY: {d['body'][:250]}",flush=True)
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
                    if u and not u.startswith("about:"):
                        print(f"  FRAME {u[:170]}",flush=True)
                    m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)',u or "")
                    if m2 and "authcode-read" not in u: return m2.group(1)
    except Exception as e:
        print(f"  [tab {tgt.get('id')}] err {e}",flush=True)
    return None

async def main():
    deadline=time.time()+120
    seen_tabs=set()
    while time.time()<deadline:
        tabs=[t for t in targets() if t.get("type")=="page"]
        # prefer authorize tabs
        auth=[t for t in tabs if "oauth/authorize" in t.get("url","")]
        order=auth+[t for t in tabs if t not in auth]
        for t in order[:2]:
            code=await watch_tab(t, window=20)
            if code:
                print("*** CODE:",code,flush=True)
                open(CODE,"w").write(code)
                return
        await asyncio.sleep(1)
    print("NO CODE",flush=True)
asyncio.run(main())
