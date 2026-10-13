#!/usr/bin/env python3
"""Map PLT stub addresses to the real imported symbols, straight from the ELF.

    python3 pltmap.py                 # write /tmp/pltmap.json
    python3 pltmap.py 0x13a34         # resolve one stub address

Why this exists
---------------
Every cross-function call in this library goes through a PLT stub:

    53f00:  bl  0x13a34                                       <- the caller
    00053394 <giot_send_create_kcp_session_msg>:              <- the real addr

so `grep bl 0x53394` finds nothing, and `grep '<name>'` only ever finds the
definition line.  That is precisely how "no callers" was wrongly concluded for
iv_start_process_calling and giot_on_rcvpkt.  Correct call-graph work has to
resolve stub -> symbol first.

Stub shape (armeabi-v7a, this build), decoded from the raw words:

    +0  e28fc600   add ip, pc, #0          ; ip = this+8
    +4  e28ccab5   add ip, ip, #0xb5000
    +8  e5bcfec0   ldr pc, [ip, #0xec0]    ; pc = GOT slot

Each stub computes its own GOT slot, so the slot is derived per-stub rather
than from a fixed offset.  Empirically the stub stride is 12 bytes (0xc) -- the
resolver preamble is 20 bytes and every stub after it is three instructions --
and 890 distinct slots are recovered, matching .rel.plt's 890 entries exactly.

The `ldr pc` immediate is NOT constant: it is `slot - ip` and differs per stub
(ec0, ee0, ...), so matching the word e5bcfec0 finds only one stub.  The
reliable anchor is the stub ENTRY word, `add ip, pc, #0` == e28fc600.

  .plt      vma=0x012574 size=0x29cc
  .rel.plt  vma=0x0109a4 size=0x1bd0 entsz=8   (890 entries)
  .dynsym   entsz=16  .dynstr  (sh_link is a section INDEX: .dynsym=2 here)
"""
import json
import struct
import sys

SO = ("com.hualai_2.50.7.487-62187_minAPI24(arm64-v8a,armeabi-v7a)"
      "(nodpi)_apkmirror.com/lib/armeabi-v7a/libiotp2pav.so")
LDR_PC = 0xe28fc600     # "add ip, pc, #0" -- every stub's entry instruction


def shdrs(data):
    e_shoff = struct.unpack_from('<I', data, 0x20)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x2e)[0]
    e_shnum = struct.unpack_from('<H', data, 0x30)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x32)[0]
    sh = [struct.unpack_from('<10I', data, e_shoff + i * e_shentsize)
          for i in range(e_shnum)]
    shstr = sh[e_shstrndx][4]
    idx = {}
    for i, s in enumerate(sh):
        o = shstr + s[0]
        idx[data[o:data.index(b'\0', o)].decode('latin-1')] = i
    return sh, idx


def rot12(v):
    """Decode ARM data-processing immediate: rotate-right by 2*rotate."""
    rot, imm = (v >> 8) & 0xf, v & 0xff
    return ((imm >> (2 * rot)) | (imm << (32 - 2 * rot))) & 0xffffffff


def got_slot(data, stub):
    """Resolve a stub's GOT slot from its own three instructions.

    insn+4 is `add ip, ip, #imm12` and insn+8 is `ldr pc, [ip, #imm12]`.
    The ldr immediate varies per stub, so there is nothing to validate
    against -- just compute."""
    add_ip = struct.unpack_from('<I', data, stub + 4)[0]
    ldr_pc = struct.unpack_from('<I', data, stub + 8)[0]
    ip = (stub + 8) + rot12(add_ip & 0xfff)
    return ip + (ldr_pc & 0xfff)


def build(path=SO):
    data = open(path, 'rb').read()
    sh, idx = shdrs(data)

    def fld(s, *off):
        return tuple(sh[idx[s]][o] for o in off)

    pv, po, ps = fld('.plt', 3, 4, 5)
    rv, ro, rs, rel_link, re_ = fld('.rel.plt', 3, 4, 5, 6, 9)
    so, doff = sh[rel_link][4], sh[idx['.dynstr']][4]

    def symname(i):
        st_name = struct.unpack_from('<I', data, so + i * 16)[0]
        o = doff + st_name                       # offset into .dynstr
        return data[o:data.index(b'\0', o)].decode('latin-1')

    rel = {}
    for i in range(rs // re_):
        off, info = struct.unpack_from('<II', data, ro + i * re_)
        rel[off] = symname(info >> 8)

    m, missing = {}, 0
    # NB: scan the VMA range, not the file offset.  po (file offset) and pv
    # (VMA) happen to be equal for many sections in this build, but the loop
    # index is an address fed to got_slot() as one, so it must be a VMA.
    for a in range(pv, pv + ps, 4):
        if struct.unpack_from('<I', data, po + (a - pv))[0] == LDR_PC:
            slot = got_slot(data, a)
            if slot in rel:
                m[a] = rel[slot]
            else:
                missing += 1
    return m, missing


def main():
    m, missing = build()
    json.dump({'0x%x' % k: v for k, v in m.items()}, open('/tmp/pltmap.json', 'w'))
    print('mapped %d stubs (%d without a .rel.plt entry) -> /tmp/pltmap.json'
          % (len(m), missing))
    for a in sys.argv[1:]:
        v = int(a, 16)
        print('  0x%x -> %s' % (v, m.get(v, '<not a PLT stub>')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
