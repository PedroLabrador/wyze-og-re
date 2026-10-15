#!/usr/bin/env python3
"""Per-type diagnostic of the 3.23.1 app's captured GUTES frames.

Question: is the class byte at [22] a per-type *encryption mode*, and does the
frame-derived mode-1 key (f[0:4]+f[20:23]+0) actually decrypt each type?

frames_clear/analyze_calls use exactly one key rule yet are documented to work
on 14 types and fail on 0xbc.  Print, per type: lengths, class bytes, and
whether the decrypted [4:12] surfaces the device d_log (a strong check).
"""
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, "~/Downloads/wyze-re")
from listreq import rc5_setup, rc5_decrypt_block   # noqa: E402

LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cap_relay_323.log"

# per-camera d_log low words seen in the CALLING captures
DLOG = {0x0d168a, 0x0e7d09, 0x153538, 0x186d6}


def mode1(buf):
    key = bytes([buf[0], buf[1], buf[2], buf[3], buf[20], buf[21], buf[22], 0])
    S = rc5_setup(key)
    out = bytearray(buf)
    out[12:20] = rc5_decrypt_block(S, bytes(out[12:20]), "little")
    for off in range(24, len(out) - 7, 8):
        out[off:off + 8] = rc5_decrypt_block(S, bytes(out[off:off + 8]), "little")
    return bytes(out)


blob = b""
cur = None
with open(LOG) as f:
    for line in f:
        m = re.match(r"\[\s*[\d.]+s\]\s+(T->R|T<-R)\s+\S+\s+len=\d+", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"\s+HEX ([0-9a-f]*)\s*$", line)
        if m and cur == "T->R":        # app->camera only; the other direction
            blob += bytes.fromhex(m.group(1))   # is a different framing
            continue
        if re.match(r"\[\s*[\d.]+s\]", line):
            cur = None

frames = []
i = 0
while i + 4 <= len(blob):
    if blob[i] not in (0x7E, 0x7F):
        cands = [x for x in (blob.find(b"\x7e", i + 1),
                             blob.find(b"\x7f", i + 1)) if x >= 0]
        if not cands:
            break
        i = min(cands)
        continue
    tot = int.from_bytes(blob[i + 2:i + 4], "little")
    if tot < 4 or i + tot > len(blob):
        break
    frames.append(blob[i:i + tot])
    i += tot

bytype = defaultdict(list)
for f in frames:
    bytype["%02x" % f[1]].append(f)

print("%-5s %-6s %-4s %-9s %-8s %s" % ("type", "count", "len", "class", "dlog?", "m1 head"))
for t in sorted(bytype):
    fs = bytype[t]
    classes = Counter("%02x" % (f[22] >> 2) + ("(%02x)" % f[22]) for f in fs)
    lens = sorted(set(len(f) for f in fs))
    d = mode1(fs[0])
    # d_log low is a u32 anywhere in the decrypted head
    head = bytes(d[4:20])
    hit = any(
        int.from_bytes(head[o:o + 4], "little") in DLOG for o in range(0, len(head) - 3)
    ) or any(int.from_bytes(d[o:o + 4], "little") in DLOG
             for o in range(4, len(d) - 3))
    print("%-5s %-6d %-4s %-9s %-8s %s"
          % (t, len(fs), ",".join(map(str, lens)),
             ",".join("%s" % c for c in classes), "YES" if hit else "no",
             d[4:20].hex()))
