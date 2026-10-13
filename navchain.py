#!/usr/bin/env python3
"""Clear cookies, navigate to full authorize URL, log the complete redirect chain + responses."""
import asyncio, json, urllib.request, time, sys, os
import websockets

URL = json.load(open('~/Downloads/pkce_final.json'))["url"]
TAB = sys.argv[1] if len(sys.argv)>1 else "18"
CODEFILE = "~/Downloads/oauth_code.txt"
if os.path.exists(CODEFILE): os.remove(CODEFILE)

def targets():
    with urllib.request.urlopen("http://localhost:9222/json/list") as r:
        return json.load(r)

async def main():
    tgt = next(t for t in targets() if t.get("type")=="page" and t["id"]==TAB)
    async with websockets.connect(tgt["webSocketDebuggerUrl"], max_size=None, ping_interval=None, open_timeout=5) as ws:
        # enable + clear cookies/cache
        await ws.send(json.dumps({"id":-1,"method":"Network.enable"}))
        await ws.send(json.dumps({"id":0,"method":"Network.clearBrowserCookies"}))
        await ws.send(json.dumps({"id":0,"method":"Network.clearBrowserCache"}))
        await asyncio.sleep(1)
        await ws.send(json.dumps({"id":1,"method":"Page.navigate","params":{"url":URL}}))
        print("NAVIGATING (cookies cleared)...")
        end=time.time()+30
        while time.time()<end:
            try: m=await asyncio.wait_for(ws.recv(),timeout=10)
            except asyncio.TimeoutError: break
            o=json.loads(m)
            meth=o.get("method","")
            p=o.get("params",{})
            if meth=="Network.requestWillBeSent":
                rq=p.get("request",{})
                u=rq.get("url","")
                if "auth.wyze.com" in u:
                    rf=p.get("redirectResponse")
                    if rf:
                        print(f"  <- {rf.get('status')} (redirect from {rf.get('url','')[:70]})")
                    print(f"REQ {u[:160]}")
            elif meth=="Network.responseReceived":
                resp=p.get("response",{})
                u=resp.get("url","")
                if "auth.wyze.com" in u:
                    h=resp.get("headers",{})
                    loc=h.get("location") or h.get("Location") or ""
                    print(f"RESP {resp.get('status')} {u[:100]} loc={loc[:120]}")
                    if "code=" in loc:
                        import re
                        m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)',loc)
                        if m2:
                            print("*** CODE:",m2.group(1))
                            open(CODEFILE,"w").write(m2.group(1))
            elif meth=="Page.frameNavigated":
                fr=p.get("frame",{})
                if not fr.get("parentId") and fr.get("url","").startswith("http"):
                    print("FRAME:",fr["url"][:160])
                    if "code=" in fr["url"] and "wyze://" in fr["url"]:
                        import re
                        m2=re.search(r'[?&]code=([A-Za-z0-9._~\-]+)',fr["url"])
                        if m2:
                            print("*** CODE(frame):",m2.group(1))
                            open(CODEFILE,"w").write(m2.group(1))
    # final read
    try:
        async with websockets.connect(tgt["webSocketDebuggerUrl"], max_size=None, ping_interval=None, open_timeout=5) as ws:
            await ws.send(json.dumps({"id":9,"method":"Runtime.evaluate","params":{
                "expression":"JSON.stringify({href:location.href, body:(document.body?document.body.innerText.slice(0,400):'')})",
                "returnByValue":True}}))
            e2=time.time()+6
            while time.time()<e2:
                try: m=await asyncio.wait_for(ws.recv(),timeout=5)
                except asyncio.TimeoutError: break
                o=json.loads(m)
                if o.get("id")==9:
                    v=o.get("result",{}).get("result",{}).get("value")
                    if v:
                        d=json.loads(v)
                        print("FINAL HREF:",d["href"][:250])
                        print("FINAL BODY:",d["body"][:400])
                    break
    except Exception as e:
        print("final read err",e)

asyncio.run(main())
