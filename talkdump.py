#!/usr/bin/env python3
"""Ordered dump of the talk session: who sends what, in what order.

Usage: python3 talkdump.py
"""
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
from mtp_frame import unwrap                              # noqa: E402
from listreq import rc5_setup, rc5_decrypt_block          # noqa: E402
from appcalling import mode1, ascii_of                    # noqa: E402


def load(path):
    out = []
    with open(path, "rb") as f:
        while True:
            b = f.read(4)
            if len(b) < 4:
                return out
            out.append(f.read(struct.unpack("<I", b)[0]))


def key_for(conv_hi):
    for d in load("/tmp/applan_a2c.bin"):
        if d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4" and len(d) > 100:
            pt = mode1(d)
            if (struct.unpack_from("<I", pt, 28)[0] | 0x80000000) == conv_hi:
                return pt[120:128]
    return None


def stream(path, conv=None):
    """[(conv, lt, body)] in arrival order."""
    buf = {}
    for d in load(path):
        if d[:2] != b"\xc0\x10":
            continue
        u = unwrap(d)
        if not u:
            continue
        s = u[0]
        if len(s) < 24 or (s[4] & 0x0F) != 1:
            continue
        c = struct.unpack_from("<I", s, 0)[0]
        ln = struct.unpack_from("<I", s, 20)[0]
        buf.setdefault(c, bytearray()).extend(s[24:24 + ln])
    out = []
    for c, b in buf.items():
        if conv is not None and c != conv:
            continue
        i = 0
        while i + 4 <= len(b):
            lt = b[i]
            ln = struct.unpack_from("<H", b, i + 2)[0]
            if ln < 4 or i + ln > len(b):
                break
            out.append((c, lt, bytes(b[i + 4:i + ln])))
            i += ln
    return out


def dec(key, b):
    S = rc5_setup(key)
    return b"".join(rc5_decrypt_block(S, b[o:o + 8], "little")
                    for o in range(0, len(b) // 8 * 8, 8))


def dump(tag, p):
    print("  --- %s (%d B) ---" % (tag, len(p)))
    for o in range(0, len(p), 16):
        print("  %3d  %-47s |%s|"
              % (o, " ".join("%02x" % x for x in p[o:o + 16]), ascii_of(p[o:o + 16])))


CONV = 0x00F82BBF
key = key_for(CONV | 0x80000000)
print("session lo conv 0x%08x, AV key %s" % (CONV, key.hex()))

print("\n===== app -> camera, ordered =====")
fr = [(lt, b) for c, lt, b in stream("/tmp/applan_a2c.bin", CONV)]
for n, (lt, b) in enumerate(fr):
    p = dec(key, b)
    print("  #%3d lt=%d len=%-4d ts[20:24]=%-12d p32=%s"
          % (n, lt, len(b), struct.unpack_from("<I", p, 20)[0] if len(p) >= 24 else -1,
             p[32:40].hex() if len(p) >= 40 else "-"))

print("\npick a few:")
for n in (0, 1, 2, 3, 4, 60, 63, 127, 128, 129):
    if n < len(fr):
        dump("#%d len=%d" % (n, len(fr[n][1])), dec(key, fr[n][1]))

print("\n===== EVEN in the app's AvStreamCtl session: camera -> app linktype 3 (72 B) =====")
for c, lt, b in stream("/tmp/applan_c2a.bin"):
    if lt == 3 and len(b) == 72:
        k = key_for(c if c & 0x80000000 else c | 0x80000000)
        if k is None:
            print("  conv=0x%08x (no key)" % c)
            continue
        p = dec(k, b)
        print("  conv=0x%08x" % c)
        dump("camera lt=3", p)
        break

print("\n===== AV keys per session =====")
for d in load("/tmp/applan_a2c.bin"):
    if d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4" and len(d) > 100:
        pt = mode1(d)
        print("  conv=0x%08x key=%s avctl-def=%s"
              % (struct.unpack_from("<I", pt, 28)[0], pt[120:128].hex(),
                 struct.unpack_from("<I", pt, 148)[0] if len(pt) > 152 else "-"))
