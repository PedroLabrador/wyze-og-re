#!/usr/bin/env python3
"""Read the app's 0xbc (iv_init_frm_mtp_quality, type 188) frames.

frames_clear.py's frame-derived mode-2 RC5 rule is documented NOT to apply to
type 0xbc: its [4:12] does not decrypt to d_log, and its flags word mixes modes
(0 and 2).  Phase 14 therefore recorded "no frame carries a definition code"
while silently excluding these five frames -- the only ones whose content was
never read.  Their builder is literally named iv_init_frm_mtp_quality.

This dumps every 0xbc frame from a cap_relay log, both plaintext and under the
mode-2 rule, so the true mode can be identified and the payload read.
"""
import re
import sys
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
from listreq import rc5_setup, rc5_decrypt_block   # noqa: E402

LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cap_relay_323.log"
WANT = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xBC


def ascii_of(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


# ---- walk the tunnel, both directions, reassembling non-aligned TCP reads --
blob = b""
cur = None
with open(LOG) as f:
    for line in f:
        m = re.match(r"\[\s*[\d.]+s\]\s+(T->R|T<-R|APP->)\s+\S+\s+len=\d+", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"\s+HEX ([0-9a-f]*)\s*$", line)
        if m and cur:
            blob += bytes.fromhex(m.group(1))
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

print("total frames: %d" % len(frames))
print("types: %s" % Counter("%02x" % f[1] for f in frames).most_common())

sel = [f for f in frames if f[1] == WANT]
print("\n=== %d frames of type %02x (len %s) ==="
      % (len(sel), WANT, sorted(set(len(f) for f in sel))))
for n, f in enumerate(sel):
    flags = f[20:24]
    key = bytes([f[0], f[1], f[2], f[3], f[20], f[21], f[22], 0x00])
    S = rc5_setup(key)
    m2 = bytearray(f)
    m2[12:20] = rc5_decrypt_block(S, bytes(m2[12:20]), "little")
    for off in range(24, len(m2) - 7, 8):
        m2[off:off + 8] = rc5_decrypt_block(S, bytes(m2[off:off + 8]), "little")
    print("\nframe %d  raw  %s" % (n, f.hex()))
    print("  hdr   %s  flags[20:24]=%s  class[22]=%02x"
          % (f[:12].hex(), flags.hex(), f[22]))
    print("  plain %s" % ascii_of(f[4:]))
    print("  m2dec %s" % ascii_of(bytes(m2)[4:]))
