#!/usr/bin/env python3
"""Robust: clear auth.wyze.com cookies/storage on whatever tab is open. Never crashes."""
import asyncio, json, urllib.request, time
import websockets

def targets():
    try:
        with urllib.request.urlopen("http://localhost:9222/json/list") as r:
            return json.load(r)
    except Exception:
        return []

async def clear_one(tgt):
    url = tgt.get("webSocketDebuggerUrl")
    if not url: return
    try:
        async with websockets.connect(url, max_size=None, ping_interval=None, open_timeout=5) as ws:
            cmds = [
                (1,"Network.clearBrowserCookies",{}),
                (2,"Network.clearBrowserCache",{}),
                (3,"Storage.clearDataForOrigin",{"origin":"https://auth.wyze.com","storageTypes":"all"}),
                (4,"Network.deleteCookies",{"name":"kount_session_id","url":"https://auth.wyze.com"}),
                (5,"Network.deleteCookies",{"name":"JSESSIONID","url":"https://auth.wyze.com"}),
                (6,"Network.deleteCookies",{"name":"session","url":"https://auth.wyze.com"}),
            ]
            for i,m,p in cmds:
                try: await ws.send(json.dumps({"id":i,"method":m,"params":p}))
                except Exception: pass
            end = time.time()+6
            while time.time() < end:
                try: msg = await asyncio.wait_for(ws.recv(), timeout=2)
                except asyncio.TimeoutError: break
                except Exception: break
            print(f"  cleared on tab {tgt['id']}")
    except Exception as e:
        print(f"  tab {tgt.get('id')} err: {e}")

async def main():
    tgts = [t for t in targets() if t.get("type")=="page"]
    if not tgts:
        print("NO TABS"); return
    for t in tgts:
        await clear_one(t)

asyncio.run(main())
