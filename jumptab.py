#!/usr/bin/env python3
"""Decode an ARM PC-relative jump table in libiotp2pav.so (armeabi-v7a).

Why this exists
---------------
`giot_on_rcvpkt @ 0x520c8` is the top-level GUTES dispatcher.  It looks like:

    0x520fc  ldr  r0, [sp, #0x14]      ; r0 = &frame
    0x52100  ldrb r0, [r0, #0x1]       ; r0 = frame[1]  (the GUTES type byte)
    0x52104  sub  r0, r0, #1           ; zero-based index
    0x52108  cmp  r0, #219             ; types 1..220 only
    0x52110  bhi  <default>
    0x5211c  add  r2, pc, #4           ; r2 = 0x5211c+8+4 = 0x52128  <-- BASE AND TABLE
    0x52120  ldr  r1, [r1, r2]         ; r1 = table[idx]
    0x52124  add  pc, r1, r2           ; pc  = BASE + table[idx]

So: **type_byte = idx + 1**, and every target = BASE + s32(table[idx]).

NOTE the ARM `pc` rule: reading `pc` yields *this instruction's address + 8*.
It is easy to get this wrong by 4 and then land at `target-4` -- one instruction
before the block you wanted, which is usually the previous block's `b epilogue`.
The giveaway is that every resolved target sits 4 bytes before an
    ldr r0, [r11, #-0x10] / ldr r1, [r11, #-0xc] / bl handler / b epilogue
block.  Verify a table against a known handler before trusting it.
`objdump` renders the table words as junk ARM (`andeq r0, r0, ...`), so they
have to be read straight out of the ELF.

Usage
-----
    jumptab.py                                # the giot_on_rcvpkt table (default)
    jumptab.py 0x52124 0x52128 220            # base, table, count
    jumptab.py 0x52124 0x52128 220 -m mtp     # only entries whose symbol matches
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resolve_cb import DATA, sym, s32            # noqa: E402

# The giot_on_rcvpkt table, derived from the disassembly above.
#   base  = 0x5211c + 8 + 4 = 0x52128   (add r2, pc, #4)
#   table = same register, so also 0x52128
DEFAULT = (0x52128, 0x52128, 220)


def main():
    a = [x for x in sys.argv[1:] if not x.startswith("-")]
    pat = None
    if "-m" in sys.argv:
        pat = sys.argv[sys.argv.index("-m") + 1].lower()

    base, table, count = DEFAULT
    if len(a) >= 3:
        base, table, count = int(a[0], 0), int(a[1], 0), int(a[2], 0)

    print("jump table: base=%#x table=%#x count=%d" % (base, table, count))
    print("  type_byte = index + 1\n")

    rows = []
    for i in range(count):
        w = s32(table + i * 4)
        tgt = (base + w) & 0xFFFFFFFF
        name = sym(tgt)
        rows.append((i + 1, tgt, name))

    # Show the dispatch chain in memory order so empty slots stay visible.
    shown = 0
    for t, tgt, name in rows:
        label = name
        if pat and pat not in name.lower():
            continue
        # Skip the trivial "no handler" entries unless they were asked for.
        if not pat and name.startswith("iv_on_rcv_mtpCtrl_pkt"):
            continue
        print("  type %-4d -> %#08x  %s" % (t, tgt, label))
        shown += 1
        if shown > 400:
            break

    if pat:
        print()
        print("=== matches for %r ===" % pat)
        for t, tgt, name in rows:
            if pat in name.lower():
                print("  ** type %d -> %#08x  %s" % (t, tgt, name))


if __name__ == "__main__":
    main()
