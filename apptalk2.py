#!/usr/bin/env python3
"""Decode the app's client->camera AV media (the talk direction).

Session-scoped: KCP conv identifies the session, and each CALLING carries that
session's AV key, so frames decrypt cleanly instead of as a blend of sessions.

The 28-byte frame is the session's opening AV frame; the 226-byte ones are the
audio.  We know the camera->app audio layout, so the question is whether the
client->camera frame is the same shape or a different one.

Usage: python3 apptalk2.py [branch]
"""
import struct
import sys
from collections import Counter

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


def collect(path, want_conv=None):
    """Reassemble the KCP push stream, split TLVs, keep (conv, lt, body)."""
    per = {}
    for d in load(path):
        if d[:2] != b"\xc0\x10":
            continue
        u = unwrap(d)
        if not u:
            continue
        s = u[0]
        if len(s) < 24 or (s[4] & 0x0F) != 1:
            continue
        conv = struct.unpack_from("<I", s, 0)[0]
        ln = struct.unpack_from("<I", s, 20)[0]
        per.setdefault(conv, bytearray()).extend(s[24:24 + ln])
    out = []
    for conv, buf in per.items():
        if want_conv is not None and conv != want_conv:
            continue
        i = 0
        while i + 4 <= len(buf):
            lt = buf[i]
            ln = struct.unpack_from("<H", buf, i + 2)[0]
            if ln < 4 or i + ln > len(buf):
                break
            out.append((conv, lt, bytes(buf[i + 4:i + ln])))
            i += ln
    return out


def key_for(conv_hi):
    """The AV key of the session whose hi conv is `conv_hi`."""
    for d in load("/tmp/applan_a2c.bin"):
        if d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4" and len(d) > 100:
            pt = mode1(d)
            c = struct.unpack_from("<I", pt, 28)[0]
            if (c | 0x80000000) == conv_hi:
                return c, pt[120:128]
    return None, None


def dec(key, b):
    S = rc5_setup(key)
    return b"".join(rc5_decrypt_block(S, b[o:o + 8], "little")
                    for o in range(0, len(b) // 8 * 8, 8))


def main():
    CONV = 0x00F82BBF          # lo conv of the session that has the talk frames

    print("===== app -> camera media, session 0x%08x =====" % CONV)
    lo, key = key_for(CONV | 0x80000000)
    print("conv lo=0x%08x  AV key=%s" % (lo, key.hex()))
    fr = [(lt, b) for c, lt, b in collect("/tmp/applan_a2c.bin", CONV) if lt == 4]
    print("%d frames; %s" % (len(fr), sorted(Counter(len(b) for _, b in fr).items())))

    # ordered, unique
    seen = []
    for _, b in fr:
        if b not in [x[1] for x in seen]:
            seen.append((len(b), b))

    for n, (ln, b) in enumerate(seen[:6] + seen[-2:]):
        p = dec(key, b)
        print("\n--- frame len=%d n=%d ---" % (ln, n))
        for o in range(0, len(p), 16):
            print("  %3d  %-47s |%s|"
                  % (o, " ".join("%02x" % x for x in p[o:o + 16]),
                     ascii_of(p[o:o + 16])))

    # payload statistics on the big frames: mu-law silence is 0xff, PCM is 0x00
    big = [dec(key, b) for _, b in fr if len(b) == 226]
    print("\n--- 226-byte frame statistics (n=%d) ---" % len(big))
    for off in (0, 4, 6, 8, 16, 24, 28, 30, 32):
        col = [p[off] for p in big if len(p) > off]
        c = Counter(col)
        print("  [%2d] top bytes: %s" % (off, c.most_common(3)))
    payload = b"".join(p[32:] for p in big)
    c = Counter(payload)
    print("  payload[32:] bytes: %d, top: %s" % (len(payload), c.most_common(4)))

    print("\n===== camera -> app linktype 2, session 0x%08x =====" % CONV)
    lo2, key2 = key_for(CONV)
    two = [(c, lt, b) for c, lt, b in collect("/tmp/applan_c2a.bin") if lt == 2]
    for c, lt, b in two:
        p = dec(key2, b)
        sync = "SYNC" if p[:4] == b"\xff\xff\xff\x88" else "    "
        print("  conv=0x%08x lt=%d ct %s" % (c, lt, b.hex()))
        print("  %s        pt %s |%s|" % (sync, p.hex(), ascii_of(p)))


if __name__ == "__main__":
    main()
