#!/usr/bin/env python3
"""Navigate + capture the exact network request URL Chrome sends."""
import asyncio, json, urllib.request, time, sys
import websockets

URL = json.load(open('~/Downloads/pkce_final.json'))["url"]
TAB = sys.argv[1] if len(sys.argv)>1 else "18"

def targets():
    with urllib.request.urlopen("http://localhost:9222/json/list") as r:
        return json.load(r)

async def main():
    tgt = next(t for t in targets() if t.get("type")=="page" and t["id"]==TAB)
    async with websockets.connect(tgt["webSocketDebuggerUrl"], max_size=None, ping_interval=None, open_timeout=5) as ws:
        await ws.send(json.dumps({"id":0,"method":"Network.enable"}))
        await ws.send(json.dumps({"id":1,"method":"Page.navigate","params":{"url":URL}}))
        end=time.time()+10
        while time.time()<end:
            try: m=await asyncio.wait_for(ws.recv(),timeout=8)
            except asyncio.TimeoutError: break
            o=json.loads(m)
            if o.get("method")=="Network.requestWillBeSent":
                u=o["params"]["request"]["url"]
                if "auth.wyze.com" in u:
                    print("REQ:", u)
            if o.get("method")=="Page.frameNavigated":
                u=o["params"]["frame"].get("url","")
                if u.startswith("http"):
                    print("NAV:", u)
            if o.get("id")==1:
                print("nav ok" if "error" not in o else f"nav ERR {o['error']}")
asyncio.run(main())
