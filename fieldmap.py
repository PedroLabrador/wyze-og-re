#!/usr/bin/env python3
"""
Map every access to the local record copy inside a function.

    python3 fieldmap.py 0x410d0 0x41ab0

iv_addRmtP2pSrv does  sub r11, sp, #24  /  sub sp, sp, #240  and
    mov r2, r11-64 ; memcpy(r2, rec, 0x24)
so the 36-byte record copy lives at r11-64.  Any  [r11, #-K]  therefore
reads record offset (64-K).  We print record-offset -> instruction so the
wire layout falls straight out.
"""
import re
import sys

DUMP = "/tmp/p2p_full.txt"
LOCAL = 64  # record copy sits at r11-LOCAL

REC = re.compile(r"\[r11, #(-?0x[0-9a-f]+|-?\d+)\]")
INSTR = re.compile(r"^\s*([0-9a-f]{4,8}):\s+[0-9a-f ]+\s+(.*)$")


def main():
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16) if len(sys.argv) > 2 else start + 0x400

    hits = {}
    for line in open(DUMP):
        m = INSTR.match(line.rstrip("\n"))
        if not m:
            continue
        addr = int(m.group(1), 16)
        if not (start <= addr < end):
            continue
        text = m.group(2)
        for a in REC.findall(text):
            off = LOCAL + int(a, 0)  # -K -> 64-K
            if 0 <= off < 36:
                hits.setdefault(off, []).append((addr, text))

    for off in sorted(hits):
        print("record+%d" % off)
        for addr, text in hits[off]:
            print("    %08x  %s" % (addr, text))


if __name__ == "__main__":
    main()
