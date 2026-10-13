#!/usr/bin/env python3
"""Navigate a Chrome tab to the authorize URL via CDP (no shell escaping issues)."""
import asyncio, json, urllib.request, sys, time
import websockets

URL = json.load(open('~/Downloads/pkce_final.json'))["url"]
TAB = sys.argv[1] if len(sys.argv) > 1 else "18"

def targets():
    with urllib.request.urlopen("http://localhost:9222/json/list") as r:
        return json.load(r)

async def main():
    tgt = next((t for t in targets() if t.get("type")=="page" and t["id"]==TAB), None)
    if not tgt:
        print("tab not found"); return
    print("navigating tab", TAB)
    async with websockets.connect(tgt["webSocketDebuggerUrl"], max_size=None, ping_interval=None, open_timeout=5) as ws:
        await ws.send(json.dumps({"id":1,"method":"Page.navigate","params":{"url":URL}}))
        end=time.time()+8
        while time.time()<end:
            try: m=await asyncio.wait_for(ws.recv(),timeout=6)
            except asyncio.TimeoutError: break
            o=json.loads(m)
            if o.get("id")==1:
                print("nav result:", o.get("result",{}), "err" if "error" in o else "")
                break
    await asyncio.sleep(3)
    # read final location
    async with websockets.connect(tgt["webSocketDebuggerUrl"], max_size=None, ping_interval=None, open_timeout=5) as ws:
        await ws.send(json.dumps({"id":2,"method":"Runtime.evaluate","params":{
            "expression":"JSON.stringify({href:location.href, body:(document.body?document.body.innerText.slice(0,300):'')})",
            "returnByValue":True}}))
        end=time.time()+6
        while time.time()<end:
            try: m=await asyncio.wait_for(ws.recv(),timeout=5)
            except asyncio.TimeoutError: break
            o=json.loads(m)
            if o.get("id")==2:
                v=o.get("result",{}).get("result",{}).get("value")
                if v:
                    d=json.loads(v)
                    print("HREF:", d["href"][:250])
                    print("BODY:", d["body"][:300])
                break

asyncio.run(main())
