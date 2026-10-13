#!/usr/bin/env python3
"""Resolve ARM PC-relative literals in libiotp2pav.so (armeabi-v7a).

Why this exists
---------------
Callbacks in this library are wired up PC-relatively, e.g. in `iv_create_kcb`:

    0x5c14c  ldr  lr, [pc, #0x70]   @ 0x5c1c4     ; lr = word at 0x5c1c4
    0x5c150  add  lr, pc, lr                       ; lr = (0x5c150+8) + lr
    0x5c158  str  lr, [r4, #0xfc]                  ; kcb->output = lr

`objdump` gives you the literal address in its `@ ...` annotation but not the
*resolved* target, and the target is usually an **unexported static**, so `nm`
does not list it and `objdump` mislabels it as `prevSymbol+offset`
(see P2P_PROTOCOL.md section 8 for why that misleads).

Usage
-----
    resolve_cb.py <add_insn_addr> <literal_addr>       resolve one target
    resolve_cb.py --pool <start> <end>                 dump words in a range
    resolve_cb.py --sym <addr>                         name one address

Examples
--------
    python3 resolve_cb.py 0x5c150 0x5c1c4     # kcb->output -> 0x5c1d8
    python3 resolve_cb.py --pool 0x5c1b0 0x5c1d8
    python3 resolve_cb.py --sym 0x5c1d8
"""
import bisect
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# The armeabi-v7a copy — the one the device actually runs (abilist=armeabi-v7a,armeabi).
SO_CANDIDATES = [
    os.path.join(
        HERE,
        "com.hualai_2.50.7.487-62187_minAPI24(arm64-v8a,armeabi-v7a)(nodpi)"
        "_apkmirror.com/lib/armeabi-v7a/libiotp2pav.so"),
    "/tmp/libiotp2pav_v7a.so",
]


def _open_so():
    for p in SO_CANDIDATES:
        if os.path.exists(p):
            return open(p, "rb").read(), p
    sys.exit("libiotp2pav.so not found; tried:\n  " + "\n  ".join(SO_CANDIDATES))


DATA, SO_PATH = _open_so()

# --- ELF program headers -> VMA-to-file-offset mapping (readelf is NOT installed) ---
_e_phoff = struct.unpack_from("<I", DATA, 0x1C)[0]
_e_phents = struct.unpack_from("<H", DATA, 0x2A)[0]
_e_phnum = struct.unpack_from("<H", DATA, 0x2C)[0]
_LOADS = []
for _i in range(_e_phnum):
    _o = _e_phoff + _i * _e_phents
    _t, _off, _va, _pa, _fsz, _msz, _fl, _al = struct.unpack_from("<IIIIIIII", DATA, _o)
    if _t == 1:                       # PT_LOAD
        _LOADS.append((_va, _off, _fsz))


def foff(vma):
    for va, off, sz in _LOADS:
        if va <= vma < va + sz:
            return off + (vma - va)
    raise KeyError("VMA %#x not in any PT_LOAD" % vma)


def load_symbols():
    """(vma, name) pairs, sorted. `nm -D` only lists exports, which is the point:
    statics are absent, so we can tell a real gap from a named symbol."""
    out = []
    nm = "/tmp/nm_p2p.txt"
    if not os.path.exists(nm):
        return out
    for line in open(nm):
        p = line.split()
        if len(p) >= 3:
            try:
                out.append((int(p[0], 16), p[2]))
            except ValueError:
                pass
    out.sort()
    return out


_SYMS = load_symbols()
_STARTS = [s[0] for s in _SYMS]


def sym(addr):
    """Name an address. If it lands inside an exported symbol, say +offset;
    if it lands past that symbol's obvious size we still say +offset, so a
    'name+0x16c' answer means *objdump's guess*, not certainty."""
    i = bisect.bisect_left(_STARTS, addr)
    if i and _STARTS[i - 1] <= addr:
        off = addr - _STARTS[i - 1]
        return _SYMS[i - 1][1] if off == 0 else "%s+0x%x" % (_SYMS[i - 1][1], off)
    return "<unexported>"


def s32(lit):
    return struct.unpack_from("<i", DATA, foff(lit))[0]


def u32(lit):
    return struct.unpack_from("<I", DATA, foff(lit))[0]


def main():
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)

    if a[0] == "--sym":
        v = int(a[1], 0)
        print("0x%08x  %s" % (v, sym(v)))
        return

    if a[0] == "--pool":
        lo, hi = int(a[1], 0), int(a[2], 0)
        print("literal pool %#x..%#x (%s)" % (lo, hi, SO_PATH))
        for v in range(lo & ~3, hi, 4):
            w = u32(v)
            # A word whose +offset form lands in .text is almost certainly a
            # PC-relative reference to code (a static function or a string).
            note = ""
            try:
                note = "  -> %#x %s" % (w, sym(w)) if w < 0x200000 else ""
            except Exception:
                pass
            print("  [%#08x] = 0x%08x  (%d)%s" % (v, w, s32(v), note))
        return

    # default: resolve one callback. ARM PC = instruction address + 8.
    add_addr, lit = int(a[0], 0), int(a[1], 0)
    w = s32(lit)
    target = (add_addr + 8 + w) & 0xFFFFFFFF
    print("literal [%#08x] = 0x%08x (%d)" % (lit, u32(lit), w))
    print("  add @%#x  ->  target = %#08x  %s" % (add_addr, target, sym(target)))
    print("  NOTE: '%s' is objdump's guess when this is an unexported static." % sym(target))


if __name__ == "__main__":
    main()
