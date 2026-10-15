#!/usr/bin/env python3
"""Reachability inside one function: from a start address, is a target reached?

Straight-line fallthrough + any conditional/unconditional branch whose target
lands inside the function.  `bl` calls are ignored (they are separate
functions).  Useful because objdump's annotated names hide statics and the
control flow here is what decides whether a frame type can ever be built.

    python3 reach.py <fn_start> <fn_end> <from> <to>
"""
import re
import sys

BR = re.compile(r'^\s+([0-9a-f]+):\s+[0-9a-f ]+\s+(b|beq|bne|bge|blt|bgt|ble|'
                r'bhi|bls|bcs|bcc|bmi|bpl|bvs|bvc|bhs|blo|cbz|cbnz)\s+'
                r'(?:eq|ne|ge|lt|gt|le|hi|ls|cs|cc|mi|pl|vs|vc|hs|lo)?\s*'
                r'0x([0-9a-f]+)')
INS = re.compile(r'^\s+([0-9a-f]+):\s+[0-9a-f ]+\s+([a-z]+)\s+0x([0-9a-f]+)')


def edges(path, lo, hi):
    out = {}
    for line in open(path, errors="replace"):
        m = BR.match(line)
        if m:
            a, _, t = int(m.group(1), 16), m.group(2), int(m.group(3), 16)
            if lo <= a < hi and lo <= t < hi:
                out.setdefault(a, []).append(t)
        else:
            m = re.match(r'^\s+([0-9a-f]+):\s+[0-9a-f ]+\s+(\w+)', line)
            if m:
                a, mn = int(m.group(1), 16), m.group(2)
                if lo <= a < hi and mn.startswith(("pop", "bx")):
                    out.setdefault(a, [])
    return out


def main():
    lo, hi, src, dst = (int(x, 16) for x in sys.argv[1:5])
    g = edges("/tmp/p2p_full.txt", lo, hi)
    seen, stack = {src}, [src]
    while stack:
        n = stack.pop()
        for m in (n + 4,) + tuple(g.get(n, ())):
            if lo <= m < hi and m not in seen:
                seen.add(m)
                stack.append(m)
    # report which distinct branch targets are reachable from the start
    tgts = sorted({t for v in g.values() for t in v})
    hit = [hex(t) for t in tgts if t in seen]
    print("reachable from 0x%x: %d insns" % (src, len(seen)))
    print("0x%x reachable? %s" % (dst, dst in seen))
    print("branch targets reached:", " ".join(hit[:40]),
          "... (%d)" % len(hit) if len(hit) > 40 else "")
    miss = [hex(t) for t in tgts if t not in seen]
    print("branch targets NOT reached:", " ".join(miss[:40]),
          "... (%d)" % len(miss) if len(miss) > 40 else "")


if __name__ == "__main__":
    main()
