#!/usr/bin/env python3
"""Bisect which part of the app's 108-byte AvStreamCtl unlocks 1080p.

Established: with the app's own 213-byte CALLING held constant, its own
AvStreamCtl TLV gives 1920x1080 @ ~1.2 Mbps, while our synthesised 76-byte
one gives 640x360 @ ~0.27 Mbps.  So the stream request itself is the switch.

This runs one session per variant and reports the decoded resolution, so the
necessary bytes can be narrowed down.

Usage: python3 ctlsweep.py [tid] [seconds-per-variant]
"""
import copy
import os
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
        data = seg[24:24 + struct.unpack_from("<I", seg, 20)[0]]
        if data[:1] == b"\x03":
            ctl = data
            break
    return calling, ctl


def relen(tlv):
    b = bytearray(tlv)
    b[2:4] = struct.pack("<H", len(b))
    return bytes(b)


def zero(ctl, a, b):
    out = bytearray(ctl)
    out[a:b] = b"\x00" * (b - a)
    return bytes(out)


def resolution(path):
    try:
        out = subprocess.run(
            ["/opt/homebrew/bin/ffmpeg", "-i", path, "-f", "null", "-"],
            capture_output=True, text=True, timeout=60).stderr
    except Exception as e:
        return "err %r" % (e,), 0.0
    for line in out.splitlines():
        if "Video:" in line:
            m = line.split("Video:")[1].strip().split(",")
            res = next((x.strip() for x in m if "x" in x and x.strip().split("x")[0].isdigit()), "?")
            return res, 0.0
    return "no video", 0.0


def run(st, secs):
    h264 = bytearray()
    t0 = time.time()
    try:
        for chunk in st.raw_h264():
            h264 += chunk
            if time.time() - t0 >= secs:
                break
    except Exception as e:
        print("   session error: %r" % (e,))
    el = max(0.001, time.time() - t0)
    open("/tmp/ctsweep.h264", "wb").write(bytes(h264))
    res, _ = resolution("/tmp/ctsweep.h264")
    return res, len(h264) * 8 / el / 1000.0


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728659223864"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0

    app_calling, app_ctl = app_frames()
    app_body = app_ctl[4:]
    ours = p2p_client.build_avstreamctl()                  # 76 B, saved before patch
    our_body = ours[4:]
    tok = app_body[72:104]
    import json
    _j = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
    _d = _j["devices"][tid]
    our_calling = bytes.fromhex(_d["frames"]["calling"])

    def rewrite(calling):
        """Fresh conv + our IP/port/key, re-encrypted with the mode-1 key."""
        from listreq import rc5_setup, rc5_encrypt_block, rc5_decrypt_block
        key = bytes([calling[0], calling[1], calling[2], calling[3],
                     calling[20], calling[21], calling[22], 0])
        S = rc5_setup(key)
        pt = bytearray(calling)
        pt[12:20] = rc5_decrypt_block(S, bytes(pt[12:20]), "little")
        for off in range(24, len(pt) - 7, 8):
            pt[off:off + 8] = rc5_decrypt_block(S, bytes(pt[off:off + 8]),
                                                "little")
        pt[28:32] = os.urandom(4)
        pt[120:128] = os.urandom(8)
        pt[64:68] = socket.inet_aton("192.168.77.13")
        out = bytearray(pt)
        out[12:20] = rc5_encrypt_block(S, bytes(out[12:20]), "little")
        for off in range(24, len(out) - 7, 8):
            out[off:off + 8] = rc5_encrypt_block(S, bytes(out[off:off + 8]),
                                                 "little")
        return bytes(out)

    gap = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0
    want = sys.argv[4:]

    allv = {
        "app": ("app-ctl exact", app_calling, app_ctl),
        "notoken": ("app-ctl, token zeroed", app_calling,
                    zero(app_ctl, 76, 108)),
        "noprefix": ("app-ctl, prefix[4:12] zeroed", app_calling,
                     zero(app_ctl, 4, 12)),
        "ac0": ("app-ctl, ac=0", app_calling,
                app_ctl[:24] + b"\x00\x00\x00\x00" + app_ctl[28:]),
        "no64": ("app-ctl, [64:76] zeroed", app_calling,
                 zero(app_ctl, 64, 76)),
        "notrl": ("app-ctl, body[60:72] zeroed", app_calling,
                  zero(app_ctl, 64, 76)),
        "notrl2": ("app-ctl, body[56:60] zeroed", app_calling,
                   zero(app_ctl, 60, 64)),
        "noprefix": ("app-ctl, body[0:8] zeroed", app_calling,
                     zero(app_ctl, 4, 12)),
        "ac0": ("app-ctl, body[20:24] zeroed", app_calling,
                zero(app_ctl, 24, 28)),
        "our2": ("OUR ctl + app 8B prefix", app_calling,
                 relen(app_body[0:8] + ours)),
        "our3": ("OUR ctl, our ac field = 2", app_calling,
                 ours[:16] + b"\x02\x00\x00\x00" + ours[20:]),
        "ours": ("OUR ctl (76)", app_calling, ours),
        "jsonctl": ("OUR calling + app-ctl", our_calling, app_ctl),
        "jsonours": ("OUR calling + OUR ctl", our_calling, ours),
        "freshapp": ("OUR call(fresh conv) + app-ctl", "fresh", app_ctl),
        "freshours": ("OUR call(fresh conv) + OUR ctl", "fresh", ours),
        "our5": ("OUR call + prefix+ac2 (84B)", our_calling,
                 relen(app_body[0:8] + our_body[:12]
                       + b"\x02\x00\x00\x00" + our_body[16:])),
        "randprefix": ("OUR call + app-ctl rand prefix", our_calling,
                       app_ctl[:4] + os.urandom(4) + app_ctl[8:]),
        "appshape": ("OUR call + 108B app-shape ac3", our_calling,
                     relen(app_body[:20] + b"\x03\x00\x00\x00" + app_body[24:])),
        "our7": ("OUR call + our fields+ac2, 108B", our_calling,
                 relen(app_body[0:8] + our_body[:12]
                       + b"\x02\x00\x00\x00" + our_body[16:] + b"\x00" * 24)),
        "padonly": ("OUR call + our fields ac2 padded 108", our_calling,
                    relen(our_body[:12] + b"\x02\x00\x00\x00"
                          + our_body[16:] + b"\x00" * 32)),
        "padac0": ("OUR call + our fields ac0 padded 108", our_calling,
                   relen(our_body + b"\x00" * 32)),
        "mintail": ("OUR call + app 108B head24 only", our_calling,
                    app_ctl[:28] + b"\x00" * (len(app_ctl) - 28)),
        "ac1": ("OUR call + 108B app-shape ac1", our_calling,
                relen(app_body[:20] + b"\x01\x00\x00\x00" + app_body[24:])),
        "bothapp": ("app calling + app-ctl (ctl)", app_calling, app_ctl),
        "ourtoken": ("OUR ctl + app token (108)", app_calling,
                     relen(ours + tok)),
        "ourrand": ("OUR ctl + random token (108)", app_calling,
                    relen(ours + os.urandom(16).hex().encode())),
    }
    variants = [allv[k] for k in (want or allv) if k in allv]

    got = p2p_client.discover(duration=5.0, want_tid=tid)
    if not got:
        print("camera %s not found" % tid)
        return
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("camera %s:%s   app token = %s\n" % (ip, port, tok.decode()))
    print("%-34s %-12s %s" % ("variant", "resolution", "kbps"))

    results = []
    for name, calling, ctl in variants:
        if calling == "fresh":
            calling = rewrite(our_calling)
        p2p_client.build_avstreamctl = (lambda c=ctl: c)
        res, kbps = "?", 0.0
        for attempt in range(3):
            st = p2p_client.CameraStream(ip, port, tid, calling, local_port=0,
                                         timeout=secs + 3.0)
            res, kbps = run(st, secs)
            st.close()
            if res.startswith("1920") or res.startswith("640"):
                break
            print("   %s: inconclusive (%s), retrying in 40s" % (name, res),
                  flush=True)
            time.sleep(40.0)
        results.append((name, res, kbps))
        print("%-34s %-12s %.0f" % (name, res, kbps), flush=True)
        time.sleep(gap)

    print("\n== summary ==")
    for name, res, kbps in results:
        flag = "  <== HD" if res.startswith("1920") else ""
        print("  %-34s %-10s %5.0f kbps%s" % (name, res, kbps, flag))


if __name__ == "__main__":
    main()
