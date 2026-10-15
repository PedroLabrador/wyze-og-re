#!/usr/bin/env python3
"""Replay the 3.23.1 app's real 213-byte CALLING and measure the stream.

The app's LAN dialogue (captured with PCAPdroid through the VPN, no root) shows
it speaks exactly our dialect -- 7ea4 CALLING, c090 meter, c010 KCP, 7eb9 --
but its CALLING is 213 B where the 2.50.7 CALLING we replay is 128 B.  The
extra bytes carry a 32-hex-character token at [177:209] and a `02` word at
[144:148], neither of which we have ever sent.

This probe drives a normal CameraStream session using that frame as the
CALLING (conv and AV key are read from it), then reports the received bitrate
and the decoded resolution.

Usage: python3 app213.py [tid] [seconds] [verbatim|rewrite|rewrite-fresh]
"""
import os
import socket
import struct
import subprocess
import sys
import time
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from listreq import rc5_setup, rc5_encrypt_block, rc5_decrypt_block  # noqa: E402


def load(path):
    out = []
    with open(path, "rb") as f:
        while True:
            b = f.read(4)
            if len(b) < 4:
                return out
            out.append(f.read(struct.unpack("<I", b)[0]))


def mode1_dec(buf):
    key = bytes([buf[0], buf[1], buf[2], buf[3], buf[20], buf[21], buf[22], 0])
    S = rc5_setup(key)
    out = bytearray(buf)
    out[12:20] = rc5_decrypt_block(S, bytes(out[12:20]), "little")
    for off in range(24, len(out) - 7, 8):
        out[off:off + 8] = rc5_decrypt_block(S, bytes(out[off:off + 8]), "little")
    return bytes(out)


def mode1_enc(buf):
    key = bytes([buf[0], buf[1], buf[2], buf[3], buf[20], buf[21], buf[22], 0])
    S = rc5_setup(key)
    out = bytearray(buf)
    out[12:20] = rc5_encrypt_block(S, bytes(out[12:20]), "little")
    for off in range(24, len(out) - 7, 8):
        out[off:off + 8] = rc5_encrypt_block(S, bytes(out[off:off + 8]), "little")
    return bytes(out)


def rewrite(calling, my_ip, my_port, fresh=False):
    pt = bytearray(mode1_dec(calling))
    pt[64:68] = socket.inet_aton(my_ip)
    pt[54:56] = struct.pack(">H", my_port)
    if fresh:
        pt[28:32] = os.urandom(4)                 # conv
        pt[120:128] = os.urandom(8)               # AV RC5 key
    return mode1_enc(bytes(pt))


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
    mode = sys.argv[3] if len(sys.argv) > 3 else "verbatim"

    frs = load("/tmp/applan_a2c.bin")
    raw = next(f for f in frs if f[:2] == b"\x7e\xa4")
    pt = mode1_dec(raw)
    app_port = struct.unpack(">H", pt[54:56])[0]
    print("app CALLING %d B  app IP %s  app port %d  conv 0x%08x  avkey %s"
          % (len(raw), socket.inet_ntoa(pt[64:68]), app_port,
             struct.unpack("<I", pt[28:32])[0], pt[120:128].hex()), flush=True)

    got = p2p_client.discover(duration=5.0, want_tid=tid)
    if not got:
        print("camera %s not found" % tid)
        return
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("camera %s:%s" % (ip, port), flush=True)

    calling = raw
    if mode == "rewrite":
        calling = rewrite(raw, "192.168.77.13", app_port)
    elif mode == "rewrite-fresh":
        calling = rewrite(raw, "192.168.77.13", app_port, fresh=True)
    print("mode=%s  sending %d B, local port %d"
          % (mode, len(calling), app_port), flush=True)

    st = p2p_client.CameraStream(ip, port, tid, calling,
                                 local_port=app_port, timeout=secs + 3.0,
                                 on_log=lambda m: print("   [log] %s" % m))
    h264 = bytearray()
    t0 = time.time()
    try:
        for chunk in st.raw_h264():
            if chunk[:4] == b"\x00\x00\x00\x01" or b"\x00\x00\x01" in chunk[:8]:
                h264 += chunk
            else:
                h264 += chunk
            el = time.time() - t0
            if el >= secs:
                break
    except Exception as e:
        print("session error: %r" % (e,))
    el = max(0.001, time.time() - t0)
    print("\n== %.1f s ==\n  %d B of H.264 (%.0f kbps)"
          % (el, len(h264), len(h264) * 8 / el / 1000.0))
    if h264:
        open("/tmp/app213.h264", "wb").write(bytes(h264))
        print("  %s" % resolution("/tmp/app213.h264"))
    else:
        print("  no media received")
    st.close()


if __name__ == "__main__":
    main()
