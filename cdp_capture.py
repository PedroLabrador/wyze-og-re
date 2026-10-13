#!/usr/bin/env python3
"""Capture Chrome network traffic from the device via CDP (adb forward :9222)."""
import asyncio, json, time, urllib.request
import websockets

OUT = "~/Downloads/cdp_capture.log"
PORT = 9222


def targets():
    try:
        with urllib.request.urlopen(f"http://localhost:{PORT}/json/list", timeout=3) as r:
            return json.load(r)
    except Exception:
        return []


async def attach(wsurl, out, tag):
    async with websockets.connect(wsurl, max_size=None, ping_interval=None) as ws:
        await ws.send(json.dumps({"id": 1, "method": "Network.enable"}))
        await ws.send(json.dumps({"id": 2, "method": "Page.enable"}))
        out.write(f"\n########## ATTACHED {tag} at {time.strftime('%H:%M:%S')} ##########\n")
        out.flush()
        n = 3
        while True:
            msg = await ws.recv()
            try:
                obj = json.loads(msg)
            except Exception:
                continue
            m = obj.get("method")
            if not m:
                continue
            p = obj.get("params", {})
            if m == "Network.requestWillBeSent":
                req = p.get("request", {})
                line = f"\n=== REQ {req.get('method')} {req.get('url')}\n"
                line += "    HDRS " + json.dumps(req.get("headers", {}), ensure_ascii=False) + "\n"
                if req.get("postData"):
                    line += "    BODY " + str(req["postData"])[:8000] + "\n"
                out.write(line)
            elif m == "Network.responseReceived":
                resp = p.get("response", {})
                hdrs = resp.get("headers", {})
                loc = hdrs.get("location") or hdrs.get("Location") or ""
                out.write(f"--- RESP {resp.get('status')} {resp.get('url')} loc={loc}\n")
                if "code=" in loc:
                    out.write(f"*** LOCATION-CODE {loc}\n")
            elif m == "Network.requestWillBeSent" and p.get("redirectResponse"):
                rurl = p.get("request", {}).get("url", "")
                rloc = p.get("redirectResponse", {}).get("headers", {}).get("location", "")
                if "code=" in rurl or "code=" in rloc:
                    out.write(f"*** REDIRECT-CODE url={rurl} loc={rloc}\n")
            elif m == "Page.frameNavigated":
                fr = p.get("frame", {})
                if not fr.get("parentId"):
                    out.write(f"*** NAVIGATE {fr.get('url')}\n")
            elif m == "Network.loadingFailed":
                out.write(f"--- FAIL {p.get('errorText')} {p.get('blockedReason','')}\n")
            out.flush()
            n += 1


async def main():
    seen = set()
    out = open(OUT, "a", buffering=1)
    out.write(f"\n===== capture started {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n")
    while True:
        attached = False
        for t in targets():
            tid, wsu, typ = t.get("id"), t.get("webSocketDebuggerUrl"), t.get("type")
            if not wsu or typ not in ("page", "iframe") or tid in seen:
                continue
            try:
                await attach(wsu, out, f"{typ}:{tid}:{t.get('url','')}")
            except Exception as e:
                out.write(f"[attach ended {tid}: {e}]\n")
            finally:
                seen.discard(tid)
                attached = True
        if not attached:
            await asyncio.sleep(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
