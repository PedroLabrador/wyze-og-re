#!/usr/bin/env python3
"""One-shot: navigate a Chrome tab to OUR authorize URL and capture the code."""
import asyncio, json, urllib.request, re, base64, os
import websockets

PORT = 9222
TAB = "12"
pk = json.load(open('~/Downloads/pkce2.json'))
AUTHORIZE = pk["url"]
VERIFIER = pk["verifier"]

def targets():
    with urllib.request.urlopen(f"http://localhost:{PORT}/json/list") as r:
        return json.load(r)

async def main():
    tgt = next(t for t in targets() if t["id"] == TAB)
    wsurl = tgt["webSocketDebuggerUrl"]
    got = []
    async with websockets.connect(wsurl, max_size=None, ping_interval=None) as ws:
        await ws.send(json.dumps({"id":1,"method":"Network.enable"}))
        await ws.send(json.dumps({"id":2,"method":"Page.enable"}))
        await ws.send(json.dumps({"id":3,"method":"Page.navigate","params":{"url":AUTHORIZE}}))
        deadline = asyncio.get_event_loop().time() + 45
        while asyncio.get_event_loop().time() < deadline:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=5)
            except asyncio.TimeoutError:
                continue
            try: obj = json.loads(msg)
            except: continue
            blob = json.dumps(obj.get("params",{}))
            m = re.search(r'[?&]code=([A-Za-z0-9._~%-]+)', blob)
            if m and ("wyze://" in blob or "authcode" in blob or "code=" in blob):
                code = m.group(1)
                got.append(code)
                print("CODE:", code, flush=True)
                break
            # also detect landing on an error/HTML meaning session invalid
            u = (obj.get("params",{}).get("frame",{}) or {}).get("url","")
            if u: print("nav:", u[:90], flush=True)
    if got:
        open('~/Downloads/the_code.txt','w').write(got[0])
        print("SAVED")
    else:
        print("NO CODE")

asyncio.run(main())
