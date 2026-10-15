#!/usr/bin/env python3
"""Find every place the raw ELF bytes contain a given absolute address.

`giot_on_rcvpkt` (0x520c8) has no `bl` anywhere, so it must be wired up as a
function pointer (literal pool -> `ldr rX, [pc, #N]` -> stored into a callback
slot) or dead.  Searching the machine code for the little-endian address finds
those literals, and the nearest preceding `bl`/symbol tells us who registers it.

    python3 find_addr.py 0x520c8
"""
import re
import struct
import sys

PATH = ("~/Downloads/wyze-re/com.hualai_2.50.7.487-62187_minAPI24"
        "(arm64-v8a,armeabi-v7a)(nodpi)_apkmirror.com/lib/armeabi-v7a/"
        "libiotp2pav.so")


def load(path):
    d = open(path, "rb").read()
    assert d[:4] == b"\x7fELF"
    is64 = d[4] == 2                      # armeabi-v7a is ELF32
    if is64:
        e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
    else:
        e_phoff = struct.unpack_from("<I", d, 0x1C)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x2A)
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags = struct.unpack_from("<II", d, o)
            p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
                "<QQQQQQ", d, o + 8)
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, _, p_flags, _ = \
                struct.unpack_from("<IIIIIIII", d, o)
        if p_type == 1 and p_filesz:            # PT_LOAD
            segs.append((p_vaddr, p_offset, p_filesz))
    return d, segs


def off_of(segs, vma):
    for v, o, s in segs:
        if v <= vma < v + s:
            return o + (vma - v)
    return None


def vma_of(segs, off):
    for v, o, s in segs:
        if o <= off < o + s:
            return v + (off - o)
    return None


def symbols():
    out = []
    for line in open("/tmp/p2p_full.txt", errors="replace"):
        m = re.match(r'^([0-9a-f]{8}) <([a-zA-Z_0-9.+]+)>:', line)
        if m:
            out.append((int(m.group(1), 16), m.group(2)))
    return out


def main():
    want = int(sys.argv[1], 16)
    d, segs = load(PATH)
    needle = struct.pack("<I", want)
    syms = symbols()
    hits = []
    for v, o, s in segs:
        start = o
        while True:
            i = d.find(needle, start, o + s)
            if i < 0:
                break
            hits.append(v + (i - o))
            start = i + 1
    print("0x%x found %d time(s)" % (want, len(hits)))
    for h in sorted(set(hits)):
        # the literal is usually loaded by an ldr within ~1 kB before it
        owner = max((s for s in syms if s[0] <= h), default=(0, "?"),
                    key=lambda s: s[0])
        # nearest preceding instruction
        prev = None
        for line in open("/tmp/p2p_full.txt", errors="replace"):
            m = re.match(r'^\s+([0-9a-f]+):', line)
            if not m:
                continue
            a = int(m.group(1), 16)
            if a <= h:
                prev = line.rstrip()
            elif prev:
                break
        print("  @ 0x%x  inside %s+0x%x" % (h, owner[1], h - owner[0]))
        print("      prev insn: %s" % (prev or "").strip()[:110])


if __name__ == "__main__":
    main()
