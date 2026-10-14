#!/usr/bin/env python3
"""Parse a cap_relay log into a GUTES frame timeline (both 7e and 7f framing).

Frame: <magic 7e|7f> <type> <u16LE total-incl-header> <payload...>
TCP reads in the log are not frame-aligned; reassemble per direction and walk.
Prints a per-direction frame list plus a byte-total-per-type summary.
"""
import re
import sys
from collections import Counter

LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cap_relay_323.log"

# dir -> list of (label, bytes).  APP-> and T->R are app->camera.
buckets = {"a2c": [], "c2a": []}
cur = None
with open(LOG) as f:
    for line in f:
        m = re.match(r"\[\s*[\d.]+s\]\s+(APP->|T->R|T<-R|REQ|RESP|MOD|<-AWS)\s+\S+\s+len=(\d+)", line)
        if m:
            lab = m.group(1)
            cur = "a2c" if lab in ("APP->", "T->R") else ("c2a" if lab in ("T<-R", "<-AWS") else None)
            if cur:
                buckets[cur].append([lab, b""])
            continue
        m = re.match(r"\s+HEX ([0-9a-f]*)\s*$", line)
        if m and cur is not None and buckets[cur]:
            buckets[cur][-1][1] += bytes.fromhex(m.group(1))
            continue
        if re.match(r"\[\s*[\d.]+s\]", line):
            cur = None


def walk(chunks):
    blob = b"".join(c for _, c in chunks)
    i = 0
    out = []
    stray = []
    while i + 4 <= len(blob):
        mag = blob[i]
        if mag not in (0x7E, 0x7F):
            j = min(blob.find(b"\x7e", i + 1), blob.find(b"\x7f", i + 1))
            if j < 0:
                stray.append((i, blob[i:]))
                break
            stray.append((i, blob[i:j]))
            i = j
            continue
        typ = blob[i + 1]
        tot = int.from_bytes(blob[i + 2:i + 4], "little")
        if tot < 4 or i + tot > len(blob):
            stray.append((i, blob[i:]))
            break
        out.append((mag, typ, blob[i + 4:i + tot]))
        i += tot
    if i < len(blob):
        stray.append((i, blob[i:]))
    return out, stray


for name, title in (("a2c", "APP -> CAM"), ("c2a", "CAM -> APP")):
    frames, stray = walk(buckets[name])
    print("=== %s  (%d frames, %d stray regions)" % (title, len(frames), len(stray)))
    stats = Counter()
    for mag, typ, payload in frames:
        stats[(mag, typ)] += 4 + len(payload)
    for (mag, typ), n in sorted(stats.items(), key=lambda kv: -kv[1]):
        cnt = sum(1 for m2, t2, _ in frames if m2 == mag and t2 == typ)
        print("   %s%02x  frames=%-5d bytes=%d" % (chr(mag), typ, cnt, n))
    print("--- timeline (first 80) ---")
    for mag, typ, payload in frames[:80]:
        print("  %s%02x len=%-5d %s%s" % (chr(mag), typ, len(payload), payload[:24].hex(),
                                          " ..." if len(payload) > 24 else ""))
    for off, blob in stray:
        print("  STRAY @%d %d B: %s" % (off, len(blob), blob[:24].hex()))
    print()
