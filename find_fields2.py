#!/usr/bin/env python3
"""Find who writes the four unknown type-0x25 payload words.

giot_send_create_kcp_session_msg (0x53394) builds the 28-byte inner frame:

    [4:8]   session +0x10     (== the per-cam word at CALLING +28)
    [8:12]  0
    [12:16] session +0x1c     <-- UNKNOWN
    [16:20] session +0x20     <-- UNKNOWN
    [20:24] session +0x24     <-- UNKNOWN
    [24:28] session +0x28     <-- UNKNOWN

where `session` is *(ctx + 0x94).  A plain look-back for

    ldr rX, [rY, #0x94]     ...     str rZ, [rX, #0x1c]

finds nothing, because the pointer is almost always spilled to a stack slot
(`str r1, [sp, #N]`) and reloaded through `[sp, #N]` before the store.

So this does it properly: per function, collect every register that ever
holds ctx+0x94 (direct load, or a copy), then report every store into
0x1c/0x20/0x24/0x28 whose base is one of those registers.

Usage: python3 find_fields2.py
"""
import bisect
import re

DIS = "/tmp/p2p_full.txt"
SYM = "/tmp/nm_p2p.txt"

TARGETS = {"0x1c", "0x20", "0x24", "0x28"}


def load_symbols():
    out = []
    for line in open(SYM):
        p = line.split()
        if len(p) >= 3:
            try:
                out.append((int(p[0], 16), p[2]))
            except ValueError:
                pass
    out.sort()
    return out


def load_insns():
    """[(addr, mnemonic_text, full_line)]"""
    out = []
    for raw in open(DIS, errors="replace"):
        m = re.match(r"\s*([0-9a-f]{4,8}):\s+[0-9a-f]{8}\s+(.*)", raw)
        if m:
            out.append((int(m.group(1), 16), m.group(2).strip(), raw.rstrip()))
    return out


LDR94 = re.compile(r"^ldr\s+(r\d+), \[(r\d+), #0x94\]")
STRIMM = re.compile(r"^(str|strb|strh)\s+(r\d+), \[(r\d+), #(0x[0-9a-f]+)\]")
# register-to-register moves, used to follow the session pointer around
MOV = re.compile(r"^(mov|movs)\s+(r\d+), (r\d+)$")
LDRSP = re.compile(r"^ldr\s+(r\d+), \[sp, #(0x[0-9a-f]+)\]")


def main():
    syms = load_symbols()
    insns = load_insns()
    addrs = [a for a, _, _ in insns]

    # function index for each instruction
    starts = [s[0] for s in syms]

    def func_of(addr):
        i = bisect.bisect_right(starts, addr) - 1
        return syms[i][1] if i >= 0 else "?"

    # group instruction indices by function
    per_func = {}
    for idx, (addr, txt, _) in enumerate(insns):
        per_func.setdefault(func_of(addr), []).append(idx)

    hits = []
    for fn, idxs in per_func.items():
        if len(idxs) > 20000:
            continue
        session_regs = set()
        spilled = {}          # sp offset -> set of regs it may hold
        observed = []          # (idx, reg) stores into a target offset

        for i in idxs:
            txt = insns[i][1]
            m = LDR94.match(txt)
            if m:
                session_regs.add(m.group(1))
                continue
            m = MOV.match(txt)
            if m and m.group(2) in session_regs:
                session_regs.add(m.group(3))
                continue
            m = LDRSP.match(txt)
            if m and ("sp" + m.group(2)) in spilled:
                session_regs.add(m.group(1))
                continue
            m = STRIMM.match(txt)
            if m:
                base, off = m.group(3), m.group(4)
                if off in TARGETS:
                    observed.append((i, base, off))
                # a store of the session pointer into a stack slot?
                # (sp-keyed so stack offsets never collide with struct offsets)
                if m.group(1) == "str" and m.group(2) in session_regs:
                    spilled.setdefault("sp" + off, set()).add(base)
                continue

        for i, base, off in observed:
            if base in session_regs:
                hits.append((fn, insns[i][0], off, base, i))

    if not hits:
        print("no direct hits -- the pointer is probably copied in a way this")
        print("does not track.  Falling back to: functions containing BOTH a")
        print("load of [reg,#0x94] and a store to a target offset.\n")
        for fn, idxs in per_func.items():
            if len(idxs) > 20000:
                continue
            has94 = any(LDR94.match(insns[i][1]) for i in idxs)
            tgt = [i for i in idxs
                   if (m := STRIMM.match(insns[i][1])) and m.group(4) in TARGETS]
            if has94 and tgt:
                print("  %-42s  %d candidate store(s)"
                      % (fn, len(tgt)))
                for i in tgt[:6]:
                    m = STRIMM.match(insns[i][1])
                    print("        %08x  %-40s" % (insns[i][0], insns[i][1][:40]))
        return

    for fn, addr, off, base, i in hits:
        print("--- %s: store to +%s via %s @ %08x ---" % (fn, off, base, addr))
        for j in range(max(0, i - 8), min(len(insns), i + 3)):
            mark = ">>" if j == i else "  "
            print("   %s %08x  %s" % (mark, insns[j][0], insns[j][1][:76]))
        print()


if __name__ == "__main__":
    main()
