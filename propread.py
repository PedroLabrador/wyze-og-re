#!/usr/bin/env python3
"""Read-only: dump every cloud property of each camera, looking for the one
that decides live-view quality.

The app stores a "definition" in SharedPreferences (sp_definition_2) and its
own vocabulary for the P2P side is changeDefinition / setDataResource, but a
Wyze camera also carries device-level properties in the cloud
(v2/device/get_property_list, SV_GET_PROPERTY_LIST) which is what the encoder
may actually follow.  Phase 13 proved no P2P frame we can synthesise changes
the resolution, so this checks the other side.

STRICTLY READ-ONLY: get_property_list only.  Nothing is written to the camera.

Usage: python3 propread.py [did ...]
"""
import json
import os
import subprocess
import sys
import time
import urllib.parse

ROOT = "~/Downloads/wyze-re"
sys.path.insert(0, os.path.join(ROOT, "wyze-cam-stream"))
import wyze_client as wc                            # noqa: E402

TOKEN_PATH = os.path.join(ROOT, "wyze_token.json")
API = "https://api.wyzecam.com/app/"

SV_GET_PROPERTY_LIST = "<REDACTED>"


def curl_json(method, url, headers, body=None):
    cmd = ["curl", "-s", "--http1.1", "-X", method, url, "--max-time", "30",
           "-H", "Accept: */*", "-H", "Accept-Encoding: identity",
           "-H", "Connection: close"]
    for k, v in (headers or {}).items():
        cmd += ["-H", "%s: %s" % (k, v)]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json",
                "--data-binary", json.dumps(body)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    try:
        return json.loads(r.stdout)
    except Exception:
        raise RuntimeError("non-JSON: %s / %s" % (r.stdout[:300], r.stderr[:200]))


def load_token():
    tok = json.load(open(TOKEN_PATH))
    if "obtained_at_ts" not in tok and tok.get("obtained_at"):
        import calendar
        try:
            tok["obtained_at_ts"] = calendar.timegm(
                time.strptime(tok["obtained_at"], "%Y-%m-%dT%H:%M:%SZ"))
        except Exception:                                   # noqa: BLE001
            tok["obtained_at_ts"] = 0
    age = time.time() - tok.get("obtained_at_ts", 0)
    if tok.get("obtained_at_ts", 0) and age < tok.get("expires_in", 0) - 300:
        return tok["access_token"]
    print("token is stale (age %.0f s), refreshing..." % age, flush=True)
    body = {
        "grant_type": "refresh_token",
        "refresh_token": tok["refresh_token"],
        "client_id": wc.OAUTH_CLIENT_ID,
        "client_secret": wc.OAUTH_CLIENT_SECRET,
    }
    out = curl_json("POST", wc.OAUTH_TOKEN_URL,
                    {"User-Agent": wc.USER_AGENT}, body=body)
    if "access_token" not in out:
        raise RuntimeError("refresh failed: %s" % str(out)[:300])
    tok.update(out)
    tok["obtained_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tok["obtained_at_ts"] = time.time()
    json.dump(tok, open(TOKEN_PATH, "w"), indent=1)
    print("refreshed ok", flush=True)
    return tok["access_token"]


def get_props(access_token, did, model):
    body = {
        "sc": wc.SC, "sv": SV_GET_PROPERTY_LIST,
        "app_ver": wc.APP_VERSION, "ts": int(time.time() * 1000),
        "access_token": access_token,
        "phone_id": "e1d4fde4-f075-49cf-9c23-5d25ed13bcdc",
        "app_name": wc.APP_NAME, "did": did, "device_mac": did,
        "device_model": model,
    }
    return curl_json("POST", API + "v2/device/get_property_list",
                     {"User-Agent": wc.USER_AGENT, "X-API-Key": wc.X_API_KEY},
                     body=body)


def main():
    tok = json.load(open(TOKEN_PATH))
    access_token = load_token()

    devs = json.load(open(os.path.join(ROOT, "wyze_devices.json")))
    want = list(sys.argv[1:])
    for d in devs:
        did = d.get("mac") or d.get("device_params", {}).get("p2p_id")
        nick = d.get("nickname")
        if want and did not in want:
            continue
        print("\n=== %s  (%s)  fw=%s ===" % (nick, did, d.get("firmware_ver")),
              flush=True)
        try:
            res = get_props(access_token, did, d.get("product_model", ""))
        except Exception as e:                      # noqa: BLE001
            print("   ERROR: %s" % e, flush=True)
            continue
        code = res.get("code")
        if str(code) not in ("1", "1000", "0", "200"):
            print("   code=%s msg=%s" % (code, res.get("msg") or res.get("message")),
                  flush=True)
        data = res.get("data") or {}
        props = data.get("property_list") or data.get("propertyList") \
            or (data if isinstance(data, list) else [])
        if not props:
            print("   (no property_list) raw=%s" % str(data)[:400], flush=True)
            continue
        print("   %d properties" % len(props), flush=True)
        for p in props:
            pid = str(p.get("pid") or p.get("prop_name") or "")
            val = p.get("value", p.get("data"))
            print("      %-8s = %s" % (pid, val), flush=True)
        hits = []
        for p in props:
            pid = str(p.get("pid") or p.get("prop_name") or "")
            val = p.get("value", p.get("data"))
            if any(t in pid.lower() for t in
                   ("def", "qual", "res", "video", "stream", "bitrate",
                    "sub", "main", "hd", "sd", "2k", "clarity")):
                hits.append((pid, val))
        if hits:
            print("   --- quality-ish ---", flush=True)
            for pid, val in hits:
                print("      %-32s = %s" % (pid, val), flush=True)
        print("   --- all pids ---", flush=True)
        print("      " + ", ".join(sorted(
            str(p.get("pid") or p.get("prop_name")) for p in props)), flush=True)


if __name__ == "__main__":
    main()
