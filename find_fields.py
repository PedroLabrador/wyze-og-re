#!/usr/bin/env python3
"""Locate the writers of the MTP-session fields that the type-0x25
'create_kcp_session' message carries.

giot_send_create_kcp_session_msg (libiotp2pav.so @ 0x53394) builds a 28-byte
frame:

    [0]     magic
    [1]     0x25                  type
    [2:4]   u16 LE = 28           total length
    [4:8]   session +0x10         == the per-cam word seen at CALLING +28
    [8:12]  0
    [12:16] session +0x1c         <-- unknown
    [16:20] session +0x20         <-- unknown
    [20:24] session +0x24         <-- unknown
    [24:28] session +0x28         <-- unknown

so this walks the disassembly looking for `str` into those offsets where the
base register was loaded from [reg, #0x94] (the session pointer) nearby.

Usage:  python3 find_fields.py [start_addr_hex] [end_addr_hex]
"""
import re
import sys

PATH = "/tmp/p2p_full.txt"

lines = []
for raw in open(PATH, errors="replace"):
    m = re.match(r"\s*([0-9a-f]{4,8}):\s+[0-9a-f]{8}\s+(.*)", raw)
    if m:
        lines.append((int(m.group(1), 16), m.group(2).strip()))

# pre-parse every ldr/str that uses a plain immediate offset
rre = re.compile(r"^(ldr|str)b?s?\s+(r\d+), \[(r\d+), #(0x[0-9a-f]+)\]")
parsed = []
for i, (addr, txt) in enumerate(lines):
    m = rre.match(txt)
    if m:
        parsed.append((i, m.group(1), m.group(2), m.group(3), m.group(4)))

targets = {"0x1c", "0x20", "0x24", "0x28"}
hits = 0
limit = int(sys.argv[1]) if len(sys.argv) > 1 else 12

for i, op, rd, base, off in parsed:
    if op[0] != "s" or off not in targets:
        continue
    for j in range(max(0, i - 40), i):
        d = re.match(r"^ldr\s+(r\d+), \[(r\d+), #0x94\]", lines[j][1])
        if d and d.group(1) == base:
            hits += 1
            print("--- write to session %s via %s ---" % (off, base))
            for k in range(max(0, j - 6), min(len(lines), i + 5)):
                mark = ">>" if k == i else "  "
                print("   %s %08x  %s" % (mark, lines[k][0], lines[k][1][:80]))
            print()
            break
    if hits >= limit:
        break

print("hits printed:", hits)

# --- also: every distinct offset ever written through a [reg,#0x94] base ---
print()
print("=== all offsets written through a session(+0x94) pointer ===")
seen = {}
for i, op, rd, base, off in parsed:
    if op[0] != "s":
        continue
    for j in range(max(0, i - 40), i):
        d = re.match(r"^ldr\s+(r\d+), \[(r\d+), #0x94\]", lines[j][1])
        if d and d.group(1) == base:
            seen.setdefault(off, 0)
            seen[off] += 1
            break
for off in sorted(seen, key=lambda s: int(s, 16)):
    print("   %-6s %d writes" % (off, seen[off]))
