#!/usr/bin/env python3
"""Find every reference to a symbol, including GOT function pointers.

WHY THIS EXISTS
---------------
callers.py only resolves DIRECT calls (`bl <plt stub>`).  That systematically
misses every function reached through a FUNCTION POINTER, which this library
uses heavily.  Two proved examples:

  send_session_socket (0x563d0)      <-- zero direct callers, yet it runs
      send_rcv_map_port (0x566ec) loads the literal 0x729ec at 0x567f0, then
      `ldr r3,[pc,r0]` at 0x5674c computes GOT slot 0x56754+0x729ec = 0xc9140,
      which is a .rel.dyn GLOB_DAT slot for send_session_socket, and passes it
      to ivtimer_create as a 10 ms callback.

  giot_on_rcvpkt (0x520c8)           <-- "unreachable by bl" for weeks
      GOT slot 0xc9068 -> session+0xe4 -> `blx ctx->0xe4` @ 0x2c604.

So "no callers" from callers.py means only "no direct call".  Always check here
before concluding a function is unreachable.

HOW A GOT SLOT IS CONSUMED (armeabi-v7a, this build)
----------------------------------------------------
The linker-relocated slot S is computed PC-relatively in two steps:

    ldr  rA, [pc, #imm]   @ A     ; reads the literal L at A+8+imm
    ldr  rT, [pc, rA]     @ B     ; reads *(B + 8 + L)  == S

so  S == B + 8 + L.  Given S and a candidate literal value L, the consuming
instruction must sit at exactly  B = S - 8 - L.  We verify B really holds an
`ldr rt,[pc,rm]` (encoding 0xE79F_xxxx) before reporting it, which kills the
false positives you get from blindly matching `addr+8+word==S` against every
word in the file.

USAGE
    python3 gotrefs.py --name send_session_socket
    python3 gotrefs.py --name iv_mtp_kcp_create
    python3 gotrefs.py 0x563d0
"""
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(
    HERE,
    "com.hualai_2.50.7.487-62187_minAPI24(arm64-v8a,armeabi-v7a)"
    "(nodpi)_apkmirror.com/lib/armeabi-v7a/libiotp2pav.so")
DIS = "/tmp/p2p_full.txt"

RTYPE = {0: "R_ARM_NONE", 2: "R_ARM_ABS32", 3: "R_ARM_REL32",
         21: "R_ARM_GLOB_DAT (function pointer)", 22: "R_ARM_JUMP_SLOT (PLT)",
         23: "R_ARM_RELATIVE"}


def load_elf(path):
    d = open(path, "rb").read()
    e_shoff = struct.unpack_from("<I", d, 0x20)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x2E)[0]
    e_shnum = struct.unpack_from("<H", d, 0x30)[0]
    e_shstrndx = struct.unpack_from("<H", d, 0x32)[0]
    shs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        shs.append(dict(
            name=struct.unpack_from("<I", d, o)[0],
            typ=struct.unpack_from("<I", d, o + 4)[0],
            addr=struct.unpack_from("<I", d, o + 12)[0],
            off=struct.unpack_from("<I", d, o + 16)[0],
            size=struct.unpack_from("<I", d, o + 20)[0],
            entsz=struct.unpack_from("<I", d, o + 36)[0]))
    strsh = shs[e_shstrndx]
    for s in shs:
        s["n"] = d[strsh["off"] + s["name"]:].split(b"\x00", 1)[0].decode()
    return d, {s["n"]: s for s in shs}, shs


def main():
    a = sys.argv[1:]
    want_addr = None
    want_name = None
    if a and a[0] == "--name":
        want_name = a[1]
    elif a:
        want_addr = int(a[0], 16)

    d, by, shs = load_elf(SO)
    dynsym, dynstr = by[".dynsym"], by[".dynstr"]

    def sym(idx):
        o = dynsym["off"] + idx * 16
        nmoff = struct.unpack_from("<I", d, o)[0]
        val = struct.unpack_from("<I", d, o + 4)[0]
        return d[dynstr["off"] + nmoff:].split(b"\x00", 1)[0].decode(), val

    hits = []
    for rn in (".rel.plt", ".rel.dyn"):
        r = by[rn]
        for i in range(r["size"] // 8):
            o = r["off"] + i * 8
            roff, info = struct.unpack_from("<II", d, o)
            nm, val = sym(info >> 8)
            if (want_name and nm == want_name) or \
               (want_addr is not None and val == want_addr):
                hits.append((rn, roff, info & 0xFF, nm, val))
    if not hits:
        print("no relocation matches for %s" % (want_name or hex(want_addr)))
        return 1

    words = {}
    if os.path.exists(DIS):
        rx = re.compile(r"\s*([0-9a-f]{5,8}):\s+([0-9a-f]{8})\s")
        for L in open(DIS):
            m = rx.match(L)
            if m:
                words[int(m.group(1), 16)] = int(m.group(2), 16)

    LDR_PCREG = 0xE79F0000
    LDR_MASK = 0xFFFF0FF0
    LDR_IMM = 0xE59F0000          # ldr rt, [pc, #imm12]
    IMM_MASK = 0xFFFF0000

    print("symbol: %s  (0x%x)" % (hits[0][3], hits[0][4]))
    for rn, roff, rtyp, nm, val in hits:
        print("  %-9s slot=0x%05x  %s" % (rn, roff, RTYPE.get(rtyp, rtyp)))
        for addr, w in sorted(words.items()):
            # addr is where the literal VALUE L sits; the consumer is at
            # B = slot - 8 - L.  Require B to be ldr rt,[pc,rm] AND require
            # the literal to have been loaded into rm by the ldr rt,[pc,#imm]
            # a few instructions earlier.  Without that second test every PIC
            # log call matches by coincidence (44 false positives here).
            B = roff - 8 - w
            if B not in words:
                continue
            bw = words[B]
            if (bw & LDR_MASK) != LDR_PCREG:
                continue
            rm = bw & 0xF
            for back in (4, 8, 12, 16, 20):
                A = B - back
                if A not in words:
                    continue
                aw = words[A]
                if (aw & IMM_MASK) != LDR_IMM:
                    continue
                if ((aw >> 12) & 0xF) != rm:
                    continue
                if A + 8 + (aw & 0xFFF) == addr:
                    print("      literal 0x%08x @0x%05x <- ldr @0x%05x, "
                          "consumed by ldr/blx @0x%05x" % (w, addr, A, B))
                    break
    return 0


if __name__ == "__main__":
    sys.exit(main())
