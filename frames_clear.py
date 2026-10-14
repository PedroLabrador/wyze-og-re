#!/usr/bin/env python3
"""Try to read the 3.23.1 app's captured GUTES frames in the clear.

The CALLING frame decrypted with a key derived from the frame itself
(key = frame[0:4] + frame[20:23] + 0x00, RC5 over [12:20] and [24:] in
8-byte blocks) -- the same rule the list protocol uses.  If the rest of the
app's dialogue follows the same rule, every captured frame becomes readable
and we can see exactly what the app asks the camera for.

Plausibility checks used:
  * decrypted [24:] blocks of repeated frames should stay identical (ECB)
  * the conn id 934fb1909ab4180e appears in the clear in some frames -- a
    correct decrypt should surface it in others too
  * structure (u16 length fields, ASCII) appearing where ciphertext was
"""
import re
import sys
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
from listreq import rc5_setup, rc5_decrypt_block   # noqa: E402

LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cap_relay_323.log"


def key_of(buf):
    if len(buf) < 24:
        return None
    return bytes([buf[0], buf[1], buf[2], buf[3],
                  buf[20], buf[21], buf[22], 0x00])


def rc5_dec(buf):
    k = key_of(buf)
    if not k:
        return None
    S = rc5_setup(k)
    out = bytearray(buf)
    out[12:20] = rc5_decrypt_block(S, bytes(out[12:20]), "little")
    for off in range(24, len(out) - 7, 8):
        out[off:off + 8] = rc5_decrypt_block(S, bytes(out[off:off + 8]), "little")
    return bytes(out)


def ascii_of(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


# walk both directions of the tunnel, collect 7e frames
blob = b""
cur = None
for line in open(LOG):
    m = re.match(r"\[\s*[\d.]+s\]\s+(T->R|T<-R)\s+\S+\s+len=\d+", line)
    if m:
        cur = m.group(1)
        continue
    m = re.match(r"\s+HEX ([0-9a-f]*)\s*$", line)
    if m and cur:
        blob += bytes.fromhex(m.group(1)) if cur == "T->R" else b""
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
        i = min(cands)          # both magics frame alike; take the nearer
        continue
    tot = int.from_bytes(blob[i + 2:i + 4], "little")
    if tot < 4 or i + tot > len(blob):
        break
    frames.append(blob[i:i + tot])
    i += tot

print("app->camera 7e frames: %d\n" % len(frames))
for f in frames:
    if f[0] != 0x7E:
        continue
    d = rc5_dec(f)
    if not d:
        continue
    print("%s  raw %s" % (d[:4].hex(), d[4:16].hex()))
    print("     dec %s" % d[4:].hex())
    print("     asc %s" % ascii_of(d[4:]))
