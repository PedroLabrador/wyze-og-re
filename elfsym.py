#!/usr/bin/env python3
"""Read .dynsym/.symtab out of any ELF (32- or 64-bit), no readelf needed.

    python3 elfsym.py <lib.so>            # every defined FUNC symbol
    python3 elfsym.py <lib.so> --all      # + UNDEF (imports)
    python3 elfsym.py <lib.so> --grep p2p  # filter by substring

Why this exists
---------------
The project's other ELF tools (pltmap.py, relocs.py, gotrefs.py) hard-assert
ELF32/armeabi-v7a because they were written for v2.50.7's libiotp2pav.so.
App 3.0.0 and 3.23.1 ship **arm64-v8a only**, so those tools cannot open them
and nothing about the newer stack could be compared.  This parses the header
by class byte instead:

    EI_CLASS @4  1 => ELF32 (u32 fields, shdr is 40 B, sym is 16 B)
                 2 => ELF64 (u64 fields, shdr is 64 B, sym is 24 B)

Section header layout (10 u32 for ELF32, 6 u64 + 2 u32 for ELF64) only
differs in the field order, which is why the struct formats are split.
"""
import struct
import sys

SHF_UNDEF = 0

# SHT_SYMTAB = 2, SHT_DYNSYM = 11, SHT_STRTAB = 3
SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB = 2, 11, 3


def parse(path):
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF":
        raise ValueError("%s: not ELF" % path)
    cls = data[4]
    if cls == 1:
        u, i16, i32 = "<H", "<h", "I"
        shdr_fmt, shdr_len, sym_fmt, sym_len = "<10I", 40, "<IIIBBH", 16
        sh_fields = 10
    elif cls == 2:
        u, i16, i32 = "<H", "<h", "Q"
        # ELF64 Shdr is 2 u32, 4 u64, 2 u32, 2 u64 -> NOT "6I4Q": link/info
        # sit in the MIDDLE, after sh_size, and they are u32.
        shdr_fmt, shdr_len, sym_fmt, sym_len = "<II4QII2Q", 64, "<IBBHQQ", 24
        sh_fields = 6
    else:
        raise ValueError("EI_CLASS=%d" % cls)
    is64 = cls == 2
    endian = "<"
    if data[5] != 1:
        raise ValueError("big-endian unsupported")

    if is64:
        (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
        (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 0x3A)
    else:
        (e_shoff,) = struct.unpack_from("<I", data, 0x20)
        (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 0x2E)

    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        if is64:
            name, typ, flags, addr, off, size, link, info, align, entsz = \
                struct.unpack_from("<II4QII2Q", data, o)
        else:
            name, typ, flags, addr, off, size, link, info, align, entsz = \
                struct.unpack_from("<10I", data, o)
        secs.append(dict(name=name, typ=typ, addr=addr, off=off, size=size,
                         link=link, entsz=entsz))

    shstr = secs[e_shstrndx]
    strtab = data[shstr["off"]:shstr["off"] + shstr["size"]]

    def n(off, blob):
        end = blob.find(b"\x00", off)
        return blob[off:end].decode("utf-8", "replace")

    def section_name(s):
        return n(s["name"], strtab)

    out = {}
    for s in secs:
        if s["typ"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        strsec = secs[s["link"]]
        stroff = strsec["off"]
        blob = data[s["off"]:s["off"] + s["size"]]
        entsz = s["entsz"] or (sym_len)
        syms = []
        for j in range(0, len(blob), entsz):
            rec = blob[j:j + entsz]
            if len(rec) < sym_len:
                break
            if is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from("<IBBHQQ", rec)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = \
                    struct.unpack_from("<IIIBBH", rec)
            nm = n(st_name, data[stroff:]) if st_name else ""
            bind = st_info >> 4
            typ = st_info & 0xF
            syms.append((nm, st_value, st_size, typ, bind, st_shndx))
        out[section_name(s).lstrip(".")] = syms
    return out, {section_name(s).lstrip("."): s for s in secs}


BIND = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
TYPE = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE",
        10: "TLS"}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    path = args[0]
    want_all = "--all" in flags
    sub = None
    for f in flags:
        if f.startswith("--grep"):
            sub = f.split("=", 1)[1] if "=" in f else None
    if sub is None:
        for i, a in enumerate(sys.argv):
            if a == "--grep":
                sub = sys.argv[i + 1]

    out, secs = parse(path)
    # .so/.dynsym names arrive as ".dynsym"; parse() strips the dot.
    cls = "ELF64" if open(path, "rb").read(5)[4] == 2 else "ELF32"
    print("# %s  [%s]" % (path, cls))
    print("# sections parsed: %s" % sorted(out))
    for name in ("dynsym", "symtab"):
        if name not in out:
            continue
        syms = out[name]
        print("# %s: %d symbols" % (name, len(syms)))
        n = 0
        for nm, val, size, typ, bind, shndx in syms:
            if not nm:
                continue
            if not want_all and shndx == 0:
                continue          # UNDEF = import
            if sub and sub.lower() not in nm.lower():
                continue
            n += 1
            print("  0x%08x %6d %-8s %-7s %s"
                  % (val, size, TYPE.get(typ, typ), BIND.get(bind, bind), nm))
        print("# printed %d" % n)


if __name__ == "__main__":
    main()
