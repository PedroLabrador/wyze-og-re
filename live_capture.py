#!/usr/bin/env python3
"""With a LIVE session: navigate a tab to authorize (NO cookie clearing) and capture the 302 Location (wyze://...&code=)."""
import asyncio, json, urllib.request, time, re, os, sys
import websockets

URL = json.load(open('~/Downloads/pkce_final.json'))["url"]
CODE = "~/Downloads/oauth_code.txt"

def targets():
    for _ in range(5):
        try:
            with urllib.request.urlopen("http://localhost:9222/json/list") as r:
                return json.load(r)
        except Exception:
            time.sleep(1)
    return []

async def run_on(tgt, navigate=True):
    wsurl = tgt.get("webSocketDebuggerUrl")
    if not wsurl: return None
    try:
        async with websockets.connect(wsurl, max_size=None, ping_interval=None, open_timeout=5) as ws:
            await ws.send(json.dumps({"id":0,"method":"Network.enable"}))
            await ws.send(json.dumps({"id":1,"method":"Page.enable"}))
            if navigate:
                print(f"[{tgt['id']}] navigating...", flush=True)
                await ws.send(json.dumps({"id":2,"method":"Page.navigate","params":{"url":URL}}))
            end = time.time()+45
            while time.time() < end:
                try: m = await asyncio.wait_for(ws.recv(), timeout=8)
                except asyncio.TimeoutError: continue
                except Exception: break
                o = json.loads(m); meth=o.get("method",""); p=o.get("params",{})
                if meth=="Network.responseReceived":
                    r=p.get("response",{}); h=r.get("headers",{})
                    loc=h.get("location") or h.get("Location") or ""
                    if loc:
                        print(f"  RESP {r.get('status')} {r.get('url','')[:55]} -> {loc[:150]}", flush=True)
                        m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)', loc)
                        if m2 and ("wyze://" in loc or "id=wyze" in loc):
                            return m2.group(1)
                elif meth=="Network.requestWillBeSent":
                    rf=p.get("redirectResponse")
                    if rf:
                        h=rf.get("headers",{}); loc=h.get("location") or h.get("Location") or ""
                        if loc:
                            print(f"  REDIR {rf.get('status')} from {rf.get('url','')[:55]} -> {loc[:150]}", flush=True)
                            m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)', loc)
                            if m2 and ("wyze://" in loc or "id=wyze" in loc):
                                return m2.group(1)
                    u=p.get("request",{}).get("url","")
                    if "wyze://" in u and "code=" in u:
                        print(f"  REQ-WYZE {u[:150]}", flush=True)
                        m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)', u)
                        if m2: return m2.group(1)
                elif meth=="Page.frameNavigated":
                    u=p.get("frame",{}).get("url","")
                    if u and not u.startswith("about:"):
                        print(f"  FRAME {u[:150]}", flush=True)
                    m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)', u or "")
                    if m2 and "authcode-read" not in u:
                        return m2.group(1)
                elif o.get("id")==2:
                    if "error" in o: print("  nav err:", o["error"], flush=True)
    except Exception as e:
        print(f"  [{tgt.get('id')}] err {e}", flush=True)
    return None

async def main():
    if os.path.exists(CODE): os.remove(CODE)
    # Prefer an already-open authorize tab; else any page tab.
    tabs=[t for t in targets() if t.get("type")=="page"]
    auth=[t for t in tabs if "oauth/authorize" in t.get("url","")]
    others=[t for t in tabs if t not in auth]
    # use a non-auth tab to navigate fresh (avoid the 400/backslash one)
    cand = [t for t in others if "about:blank" in t.get("url","") or "newtab" in t.get("url","")] or others or auth
    if not cand:
        print("no tabs"); return
    tgt=cand[0]
    print("using tab", tgt["id"], flush=True)
    code = await run_on(tgt, navigate=True)
    if code:
        print("*** CODE:", code, flush=True)
        open(CODE,"w").write(code)
        # show final url of all tabs for debugging
        for t in targets():
            if t.get("type")=="page": print("  tab",t["id"],t.get("url","")[:120])
    else:
        print("NO CODE captured. final tabs:", flush=True)
        for t in targets():
            if t.get("type")=="page": print("  tab",t["id"],t.get("url","")[:130])
asyncio.run(main())
