#!/usr/bin/env python3
"""
Read one function out of the existing disassembly dump and annotate it.

    python3 disfn.py 0x4ad64 0x4b804          # dump that range
    python3 disfn.py 0x4ad64 --calls          # only the call graph
    python3 disfn.py 0x4ad64 --fields         # only load/store offsets

Depends on:
    /tmp/p2p_full.txt   objdump -d -j .text lib/armeabi-v7a/libiotp2pav.so
    /tmp/plt_p2p.txt    "<addr> <symbol>" lines for the PLT stubs

Regenerate those with:
    objdump -d -j .text libiotp2pav.so > /tmp/p2p_full.txt
    python3 mkplt.py libiotp2pav.so > /tmp/plt_p2p.txt
"""
import re
import sys

DUMP = "/tmp/p2p_full.txt"
PLT = "/tmp/plt_p2p.txt"

ADDR_RE = re.compile(r"^\s*([0-9a-f]{4,8}):\s+[0-9a-f ]+\s+(.*)$")
CALL_RE = re.compile(r"\b(bl|blx)\s+(0x[0-9a-f]+)")


def load_plt():
    m = {}
    try:
        for line in open(PLT):
            parts = line.split(None, 1)
            if len(parts) == 2:
                m[int(parts[0], 16)] = parts[1].strip()
    except OSError:
        pass
    return m


def load_syms():
    """Local/global symbol addresses straight from the dump's own labels."""
    m = {}
    sym_re = re.compile(r"^([0-9a-f]{6,8}) <([^>]+)>:")
    for line in open(DUMP):
        g = sym_re.match(line)
        if g:
            m[int(g.group(1), 16)] = g.group(2)
    return m


def main():
    args = sys.argv[1:]
    mode = "full"
    if "--calls" in args:
        mode, args = "calls", [a for a in args if a != "--calls"]
    elif "--fields" in args:
        mode, args = "fields", [a for a in args if a != "--fields"]

    start = int(args[0], 16)
    end = int(args[1], 16) if len(args) > 1 else start + 0x400

    plt = load_plt()
    syms = load_syms()

    rows = []
    for line in open(DUMP):
        g = ADDR_RE.match(line.rstrip("\n"))
        if not g:
            continue
        addr = int(g.group(1), 16)
        if not (start <= addr < end):
            continue
        text = g.group(2).rstrip()

        def repl(m):
            tgt = int(m.group(2), 16)
            name = plt.get(tgt) or syms.get(tgt)
            return "%s %s%s" % (m.group(1), m.group(2),
                                " <%s>" % name if name else "")

        rows.append((addr, CALL_RE.sub(repl, text)))

    if mode == "calls":
        for addr, text in rows:
            if re.search(r"\b(bl|blx|b|bx)\b", text) and "<" in text:
                print("%08x  %s" % (addr, text))
        return

    if mode == "fields":
        for addr, text in rows:
            if re.search(r"\b(str|ldr|strb|ldrb|strh|ldrh)\b", text):
                print("%08x  %s" % (addr, text))
        return

    for addr, text in rows:
        print("%08x  %s" % (addr, text))


if __name__ == "__main__":
    main()
