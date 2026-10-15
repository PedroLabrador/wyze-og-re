#!/usr/bin/env python3
"""Map the client->camera talk frame byte by byte.

Decrypts every talk frame of the session and prints, per offset, whether the
byte is constant across frames, zero, or varying -- which separates the frame
header from the audio payload without knowing the codec.

Usage: python3 talkmap.py
"""
import struct
import sys
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
from mtp_frame import unwrap                              # noqa: E402
from listreq import rc5_setup, rc5_decrypt_block          # noqa: E402
from appcalling import mode1                              # noqa: E402

CONV = 0x00F82BBF


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


def frames():
    buf = bytearray()
    for d in load("/tmp/applan_a2c.bin"):
        if d[:2] != b"\xc0\x10":
            continue
        u = unwrap(d)
        if not u:
            continue
        s = u[0]
        if len(s) < 24 or (s[4] & 0x0F) != 1:
            continue
        if struct.unpack_from("<I", s, 0)[0] != CONV:
            continue
        ln = struct.unpack_from("<I", s, 20)[0]
        buf += s[24:24 + ln]
    key = key_for(CONV | 0x80000000)
    S = rc5_setup(key)
    out, i = [], 0
    while i + 4 <= len(buf):
        lt = buf[i]
        ln = struct.unpack_from("<H", buf, i + 2)[0]
        if ln < 4 or i + ln > len(buf):
            break
        if lt == 4:
            b = bytes(buf[i + 4:i + ln])
            d = b"".join(rc5_decrypt_block(S, b[o:o + 8], "little")
                         for o in range(0, len(b) // 8 * 8, 8))
            out.append((b, d))
        i += ln
    return out


def main():
    fr = frames()
    print("%d frames" % len(fr))

    # timestamps (candidates) across the sequence
    print("\n--- how the candidate timestamp field behaves ---")
    for off in (20, 24, 34, 38, 42):
        vals = [struct.unpack_from("<I", p, off)[0] for _, p in fr[:12]
                if len(p) >= off + 4]
        if len(vals) > 2:
            d = [vals[i + 1] - vals[i] for i in range(len(vals) - 1)]
            print("  [%2d] %s  deltas %s" % (off, vals[:5], d[:5]))

    print("\n--- per-offset character (n=%d) ---" % len(fr))
    for off in range(0, 60):
        col = [p[off] for _, p in fr if len(p) > off]
        if not col:
            print("  [%2d] (absent)" % off)
            continue
        uniq = set(col)
        if uniq == {0}:
            tag = "00"
        elif len(uniq) == 1:
            tag = "%02x  CONSTANT" % col[0]
        elif max(col) - min(col) < 4:
            tag = "var small %02x..%02x" % (min(col), max(col))
        else:
            tag = "varies  %02x..%02x" % (min(col), max(col))
        print("  [%2d] %s" % (off, tag))

    print("\n--- tail of a 226-byte frame ---")
    big = [p for _, p in fr if len(p) == 226]
    if big:
        p = big[0]
        for o in range(0, 226, 16):
            print("  %3d  %s" % (o, " ".join("%02x" % x for x in p[o:o + 16])))

        print("\n--- byte histogram of candidate payload regions ---")
        for a, b in ((34, 226), (24, 226), (30, 226)):
            pl = b"".join(p[a:b] for p in big)
            c = Counter(pl)
            print("  [%d:%d] %d bytes, top: %s" % (a, b, len(pl), c.most_common(6)))

        print("\n--- is the payload 16-bit with a constant low byte? ---")
        for a in (30, 32, 34):
            lo = Counter(p[a + 1] for p in big)
            hi = Counter(p[a] for p in big)
            print("  start %d: even-offset bytes %s ; odd-offset bytes %s"
                  % (a, hi.most_common(3), lo.most_common(3)))


if __name__ == "__main__":
    main()
