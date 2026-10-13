#!/usr/bin/env python3
"""Attach to EVERY Chrome page; capture the OAuth code from the wyze:// 302 redirect.
Watches: response Location headers, redirectResponse Location, and frameNavigated."""
import asyncio, json, urllib.request, re, sys
import websockets

PORT = 9222
OUT = "~/Downloads/oauth_code.txt"
SEEN = set()

def targets():
    with urllib.request.urlopen(f"http://localhost:{PORT}/json/list") as r:
        return json.load(r)

def extract(blob):
    # wyze://...&code=XXX  (code before any & or end)
    m = re.search(r'[?&]code=([A-Za-z0-9._~\-]+)', blob)
    if m:
        return m.group(1)
    return None

async def watch(tgt):
    url = tgt.get("webSocketDebuggerUrl")
    if not url:
        return
    try:
        async with websockets.connect(url, max_size=None, ping_interval=None) as ws:
            await ws.send(json.dumps({"id":1,"method":"Network.enable"}))
            await ws.send(json.dumps({"id":2,"method":"Page.enable"}))
            print(f"[+] attached {tgt['id']}: {tgt.get('url','')[:60]}", flush=True)
            while True:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=10)
                except asyncio.TimeoutError:
                    continue
                try:
                    o = json.loads(msg)
                except Exception:
                    continue
                method = o.get("method","")
                p = o.get("params",{})
                blob = ""
                if method == "Network.responseReceived":
                    resp = p.get("response",{})
                    h = resp.get("headers",{})
                    blob = (h.get("location") or h.get("Location") or "") + " " + resp.get("url","")
                elif method == "Network.requestWillBeSent":
                    if p.get("redirectResponse"):
                        h = p["redirectResponse"].get("headers",{})
                        blob = (h.get("location") or h.get("Location") or "")
                    blob += " " + p.get("request",{}).get("url","")
                elif method == "Page.frameNavigated":
                    fr = p.get("frame",{})
                    blob = fr.get("url","")
                code = extract(blob)
                if code and "wyze://" in blob or (code and "authcode" in blob):
                    if code not in SEEN:
                        SEEN.add(code)
                        print(f"*** CODE={code}  from: {blob[:120]}", flush=True)
                        open(OUT,"w").write(code)
                        return True
                # also catch plain code= in an https redirect (some flows)
                elif code and "code=" in blob and "auth.wyze.com" not in blob:
                    if code not in SEEN:
                        SEEN.add(code)
                        print(f"*** CODE(https)={code} from: {blob[:120]}", flush=True)
                        open(OUT,"w").write(code)
                        return True
    except Exception as e:
        print(f"[-] {tgt.get('id')} err {e}", flush=True)

async def main():
    import os
    if os.path.exists(OUT):
        os.remove(OUT)
    done = asyncio.Event()
    while not done.is_set():
        live = {t["id"] for t in targets() if t.get("type")=="page"}
        for t in targets():
            if t.get("type")=="page" and t["id"] not in watch.seen:
                watch.seen.add(t["id"])
                asyncio.create_task(run_and_maybe_finish(t, done))
        await asyncio.sleep(1)

watch.seen = set()

async def run_and_maybe_finish(tgt, done):
    r = await watch(tgt)
    if r:
        done.set()

if __name__ == "__main__":
    asyncio.run(main())
