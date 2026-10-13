#!/usr/bin/env python3
"""Poll CDP for the wyze:// redirect containing the OAuth code."""
import asyncio, json, time, urllib.request, re, sys
import websockets

OUT = "~/Downloads/oauth_code.txt"
PORT = 9222


def targets():
    try:
        with urllib.request.urlopen(f"http://localhost:{PORT}/json/list", timeout=3) as r:
            return json.load(r)
    except Exception:
        return []


async def watch(wsurl, tid):
    async with websockets.connect(wsurl, max_size=None, ping_interval=None) as ws:
        await ws.send(json.dumps({"id": 1, "method": "Network.enable"}))
        await ws.send(json.dumps({"id": 2, "method": "Page.enable"}))
        while True:
            msg = await ws.recv()
            try:
                obj = json.loads(msg)
            except Exception:
                continue
            m = obj.get("method", "")
            p = obj.get("params", {})
            blob = json.dumps(p)
            # catch the code in any navigation/request/redirect
            if "code=" in blob and ("wyze://" in blob or "authcode" in blob or "oauth" in blob):
                mm = re.search(r'code=([A-Za-z0-9._~%-]+)', blob)
                if mm:
                    code = urllib.parse.unquote(mm.group(1)) if False else mm.group(1)
                    with open(OUT, "a") as f:
                        f.write(code + "\n")
                    print("GOT CODE:", code[:40], flush=True)
            if m in ("Page.frameNavigated", "Network.requestWillBeSent", "Network.responseReceived"):
                fr = p.get("frame", {}) or {}
                u = fr.get("url") or p.get("request", {}).get("url") or p.get("response", {}).get("url", "")
                if u.startswith("wyze://"):
                    print("REDIRECT:", u[:200], flush=True)


async def main():
    seen = set()
    while True:
        for t in targets():
            tid, wsu = t.get("id"), t.get("webSocketDebuggerUrl")
            if not wsu or tid in seen:
                continue
            seen.add(tid)
            try:
                await watch(wsu, tid)
            except Exception as e:
                pass


if __name__ == "__main__":
    asyncio.run(main())
