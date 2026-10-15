#!/usr/bin/env python3
"""Send the app's own AvStreamCtl (108 B TLV) instead of our synthesised one.

The app's stream request, read out of the PCAPdroid LAN capture over KCP, is
linktype 3 and 108 B total -- ours is 76 B.  The app's carries a trailing
32-hex-character token (the same one in its 213-byte CALLING) and an 8-byte
prefix, and its `ac` word is 2 where we send 0.

This swaps in the app's exact bytes and reports the decoded resolution.

Usage: python3 appctl.py [tid] [seconds] [app|ours] [verbatim|rewrite]
"""
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from mtp_frame import unwrap as mtp_unwrap           # noqa: E402


def load(path):
    out = []
    with open(path, "rb") as f:
        while True:
            b = f.read(4)
            if len(b) < 4:
                return out
            out.append(f.read(struct.unpack("<I", b)[0]))


def app_frames():
    dgrams = load("/tmp/applan_a2c.bin")
    calling = next(d for d in dgrams if d[:2] == b"\x7e\xa4")
    ctl = None
    for d in dgrams:
        if d[:2] != b"\xc0\x10":
            continue
        u = mtp_unwrap(d)
        if not u:
            continue
        seg = u[0]
        if len(seg) < 28 or (seg[4] & 0x0F) != 1:
            continue
        ln = struct.unpack_from("<I", seg, 20)[0]
        data = seg[24:24 + ln]
        if data[:1] == b"\x03":
            ctl = data
            break
    return calling, ctl


def resolution(path):
    try:
        out = subprocess.run(
            ["/opt/homebrew/bin/ffmpeg", "-i", path, "-f", "null", "-"],
            capture_output=True, text=True, timeout=60).stderr
    except Exception as e:
        return "ffmpeg error: %r" % (e,)
    for line in out.splitlines():
        if "Video:" in line:
            return line.strip()
    return "(ffmpeg saw no video)"


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728659223864"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 12.0
    ctl_src = sys.argv[3] if len(sys.argv) > 3 else "app"
    call_src = sys.argv[4] if len(sys.argv) > 4 else "verbatim"

    app_calling, app_ctl = app_frames()
    print("app CALLING %d B, app AvStreamCtl %d B (%s)"
          % (len(app_calling), len(app_ctl or b""), (app_ctl or b"")[:8].hex()))

    got = p2p_client.discover(duration=5.0, want_tid=tid)
    if not got:
        print("camera %s not found" % tid)
        return
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("camera %s:%s" % (ip, port), flush=True)

    if call_src == "verbatim":
        calling = app_calling
    else:
        import json
        j = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
        calling = bytes.fromhex(j["192.168.77.10"]["calling"])

    if ctl_src == "app" and app_ctl:
        p2p_client.build_avstreamctl = (lambda *a, **k: app_ctl)
        print("using the APP's AvStreamCtl")
    else:
        print("using our synthesised AvStreamCtl")

    st = p2p_client.CameraStream(ip, port, tid, calling,
                                 local_port=0, timeout=secs + 3.0,
                                 on_log=lambda m: print("   [log] %s" % m))
    h264 = bytearray()
    t0 = time.time()
    try:
        for chunk in st.raw_h264():
            h264 += chunk
            if time.time() - t0 >= secs:
                break
    except Exception as e:
        print("session error: %r" % (e,))
    el = max(0.001, time.time() - t0)
    print("\n== %.1f s ==\n  %d B of H.264 (%.0f kbps)"
          % (el, len(h264), len(h264) * 8 / el / 1000.0))
    if h264:
        open("/tmp/appctl.h264", "wb").write(bytes(h264))
        print("  %s" % resolution("/tmp/appctl.h264"))
    else:
        print("  no media received")
    st.close()


if __name__ == "__main__":
    main()
