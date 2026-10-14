#!/usr/bin/env python3
"""Watch every camera's cloud properties and print changes as they happen.

WHY THIS EXISTS
---------------
Turning something on in the official app is the cheapest possible oracle: the
app knows the property ids we cannot enumerate.  `get_property_list` is a
read, and `set_property` reports `result: 1` for an accepted pid and `3` for a
rejected one -- so a pid the app writes can be identified by watching which
value flips, without ever guessing a write ourselves.

Run this, then toggle light / sound / anything in the app.  The pid that
changes is the one to hand to set_property.

    python3 -u propwatch.py              # poll every 3 s, forever
    python3 -u propwatch.py 300          # ...for 300 seconds
    python3 -u propwatch.py 300 CAM-1_D03F27747BB0   # one camera

STRICTLY READ-ONLY.  Nothing is ever written to a camera.
"""
import json
import os
import sys
import time

ROOT = "~/Downloads/wyze-re"
sys.path.insert(0, os.path.join(ROOT, "wyze-cam-stream"))
import wyze_client as wc                            # noqa: E402
import propread as pr                               # noqa: E402

TOKEN_PATH = os.path.join(ROOT, "wyze_token.json")
API = "https://api.wyzecam.com/app/"
SV_GET_PROPERTY_LIST = "<REDACTED>"


def get_props(access_token, did, model):
    body = {
        "sc": wc.SC, "sv": SV_GET_PROPERTY_LIST,
        "app_ver": wc.APP_VERSION, "ts": int(time.time() * 1000),
        "access_token": access_token,
        "phone_id": "e1d4fde4-f075-49cf-9c23-5d25ed13bcdc",
        "app_name": wc.APP_NAME, "did": did, "device_mac": did,
        "device_model": model,
    }
    r = pr.curl_json("POST", API + "v2/device/get_property_list",
                     {"User-Agent": wc.USER_AGENT,
                      "X-API-Key": wc.X_API_KEY}, body=body)
    data = r.get("data") or {}
    props = data.get("property_list") or []
    return {str(p.get("pid")): str(p.get("value")) for p in props}


def main():
    dur = float(sys.argv[1]) if len(sys.argv) > 1 else 0.0
    only = set(sys.argv[2:])
    access_token = pr.load_token()

    devs = json.load(open(os.path.join(ROOT, "wyze_devices.json")))
    cams = []
    for d in devs:
        did = d.get("mac") or d.get("device_params", {}).get("p2p_id")
        if not did:
            continue
        if only and did not in only:
            continue
        cams.append((did, d.get("nickname") or did, d.get("product_model", "")))
    if not cams:
        print("no cameras matched %s" % (only or "all"), flush=True)
        return

    print("watching %d camera(s); toggle things in the app now."
          % len(cams), flush=True)
    prev = {}
    for did, nick, model in cams:
        try:
            prev[did] = get_props(access_token, did, model)
            print("  %-14s %-12s %s" % (did[-6:], nick,
                                        " ".join("%s=%s" % kv for kv in
                                                 sorted(prev[did].items()))),
                  flush=True)
        except Exception as e:                      # noqa: BLE001
            print("  %-14s ERROR %s" % (did[-6:], e), flush=True)
            prev[did] = {}
    print("-" * 72, flush=True)

    t0 = time.time()
    while True:
        time.sleep(3.0)
        if dur and time.time() - t0 > dur:
            print("done (%.0fs, no further changes)" % dur, flush=True)
            return
        for did, nick, model in cams:
            try:
                now = get_props(access_token, did, model)
            except Exception:                       # noqa: BLE001
                continue        # transient; next round retries
            old = prev.get(did, {})
            if now == old:
                continue
            ts = time.strftime("%H:%M:%S")
            for pid in sorted(set(old) | set(now)):
                a, b = old.get(pid, "<absent>"), now.get(pid, "<absent>")
                if a != b:
                    print("%s  %-14s %-12s  %-8s %s -> %s"
                          % (ts, did[-6:], nick, pid, a, b), flush=True)
            prev[did] = now


if __name__ == "__main__":
    main()
