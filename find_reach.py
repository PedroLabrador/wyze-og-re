#!/usr/bin/env python3
"""How is giot_on_rcvpkt (0x520c8) reached?

It has NO `bl` to it anywhere in the disassembly, and find_addr.py found its
absolute value 0x000520c8 exactly once in the whole ELF (the .dynsym entry at
VMA 0x1b8c) -- so no literal pool, no vtable slot, no GOT word holds it.  The
only way left to build the address is PC-relative arithmetic (add/sub rd, pc,
#imm), which find_addr.py structurally cannot see.  Scan for that.

If nothing lands there either, giot_on_rcvpkt is unreachable from inside
libiotp2pav.so, which would mean the 7e-a3 -> gat_on_rcvpkt_MTP_RES_RESPONSE
chain depends on a caller outside this library (dlsym from the Java/JNI side).
"""
import re
import sys

TARGET = 0x520c8
LO, HI = 0x520c8, 0x52690

pat = re.compile(
    r'^\s+([0-9a-f]+):\s+([0-9a-f]{8})\s+(add|sub)'
    r'\s+(r[0-9]+|lr|sp),\s*pc(?:,\s*#(-?0x[0-9a-f]+|-?[0-9]+))?')


def main(path='/tmp/p2p_full.txt'):
    near, inside = [], []
    for line in open(path):
        m = pat.search(line)
        if not m:
            continue
        a = int(m.group(1), 16)
        op = m.group(3)
        imm = int(m.group(5), 0) if m.group(5) else 0
        if op == 'add':
            v = a + 8 + imm
        elif op == 'sub':
            v = a + 8 - imm
        else:
            continue
        if abs(v - TARGET) < 0x40:
            near.append((a, op, imm, v, line.strip()))
        if LO <= v <= HI:
            inside.append(line.strip())

    print('PC-relative computations landing within 0x40 of 0x520c8: %d'
          % len(near))
    for a, op, imm, v, raw in near:
        print('  0x%x %s #%s -> 0x%x   %s' % (a, op, hex(imm), v, raw[:80]))
    print()
    print('add/sub rd,pc,#N landing inside giot_on_rcvpkt: %d' % len(inside))
    for raw in inside[:20]:
        print('  ', raw[:100])

    if not near and not inside:
        print()
        print('VERDICT: nothing in .text computes 0x520c8.  Combined with the')
        print('absence of a bl and of any literal, giot_on_rcvpkt is NOT called')
        print('from within libiotp2pav.so -- its only entry is external.')
    return 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:2]))
