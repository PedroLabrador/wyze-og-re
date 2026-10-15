#!/usr/bin/env python3
"""Locate the type-1 (coded slice) NALs that appear inside the audio-classified
bodies, and decide whether they are real video or coincidences in mu-law.

Input: /tmp/wh_ONLY_audio.h264, /tmp/wh_ONLY_other.h264, /tmp/wh_ALL.h264
(three candidate feeds built by whatsin.py from one 10 s capture).
"""
import collections
import re


def nals(path):
    d = open(path, "rb").read()
    out = []
    for m in re.finditer(b"\x00\x00\x01", d):
        p = m.end()
        if p >= len(d):
            continue
        out.append((m.start(), d[p] & 0x1F))
    return d, out


def main():
    d, hits = nals("/tmp/wh_ONLY_audio.h264")
    print("ONLY_audio: %d B, %d NALs" % (len(d), len(hits)))
    t1 = [(i, t) for i, t in hits if t == 1]
    print("  type-1 slices: %d" % len(t1))
    # The AV header is `ff ff ff 88 00 00 01 00` -> the `00 00 01` at offset 4
    # yields type 0 (byte at +3 is 00).  Anything typed 1 sits elsewhere.
    for i, _ in t1[:30]:
        print("  off=%-7d ctx_before=%s ctx_after=%s"
              % (i, d[max(0, i - 8):i].hex(), d[i:i + 16].hex()))

    # Where do they fall relative to a 350-byte audio AV frame?
    print("\n  offset %% 350 ->", collections.Counter(i % 350 for i, _ in t1).most_common())
    print("  offset %% 320 ->", collections.Counter(i % 320 for i, _ in t1).most_common(8))

    # Are the type-1 NAL payloads high-entropy (H.264) or mu-law-ish?
    import math
    for i, _ in t1[:6]:
        # NAL runs until the next start code
        nxt = len(d)
        for m in re.finditer(b"\x00\x00\x01", d[i + 3:]):
            nxt = i + 3 + m.start()
            break
        seg = d[i + 3:nxt]
        if not seg:
            continue
        c = collections.Counter(seg)
        n = len(seg)
        ent = -sum((v / n) * math.log2(v / n) for v in c.values())
        print("  slice@%-7d len=%-5d entropy=%.2f top=%s"
              % (i, n, ent, c.most_common(4)))

    # Overall comparison of the three feeds
    print()
    for f in ("/tmp/wh_ONLY_audio.h264", "/tmp/wh_ONLY_other.h264", "/tmp/wh_ALL.h264"):
        dd, hh = nals(f)
        c = collections.Counter(t for _, t in hh)
        print("%-26s %8d B  NALs=%-4d %s  slices(t1+t5)=%d"
              % (f.split("/")[-1], len(dd), len(hh), dict(sorted(c.items())),
                 c.get(1, 0) + c.get(5, 0)))


if __name__ == "__main__":
    main()
