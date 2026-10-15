#!/usr/bin/env python3
"""List ELF32 dynamic relocations (no readelf available), and look one up.

    python3 relocs.py            # count + any that touch interesting VMAs
    python3 relocs.py 0x2d8f4    # is this literal relocated?

Why this matters: iv_gute_session_new does
    ldr r2, [pc, #0x58]   -> r2 = *(u32*)0x2d8f4   (file value 0x0009b7c8)
    ldr r2, [pc, r2]      -> r2 = *(u32*)(0x2d8a0 + r2)  = *(u32*)0x9e668
and 0x9e668 holds 0xef90f775, an instruction word, not a pointer.  If a
relocation rewrites 0x2d8f4 (or 0x9e668) at load time, the file bytes are a
lie and the real slot -- and therefore the real receive callback -- is
somewhere else entirely.
"""
import struct
import sys

SO = ("com.hualai_2.50.7.487-62187_minAPI24(arm64-v8a,armeabi-v7a)"
      "(nodpi)_apkmirror.com/lib/armeabi-v7a/libiotp2pav.so")

# ARM ELF32 relocation types we care about
TYPES = {
    0: 'R_ARM_NONE', 1: 'R_ARM_PC24', 2: 'R_ARM_ABS32', 3: 'R_ARM_REL32',
    20: 'R_ARM_GOT_BREL', 21: 'R_ARM_PLT32', 22: 'R_ARM_COPY',
    23: 'R_ARM_GLOB_DAT', 24: 'R_ARM_JUMP_SLOT', 25: 'R_ARM_RELATIVE',
}


def main():
    path = SO
    want = [int(a, 16) for a in sys.argv[1:]]
    data = open(path, 'rb').read()
    assert data[:4] == b'\x7fELF' and data[4] == 1

    # section headers
    e_shoff = struct.unpack_from('<I', data, 0x20)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x2e)[0]
    e_shnum = struct.unpack_from('<H', data, 0x30)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x32)[0]
    sh = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, _, vaddr, off, size, link, info, align, entsize = \
            struct.unpack_from('<10I', data, o)
        sh.append((name, typ, vaddr, off, size, link, info, entsize))
    shstr_off = sh[e_shstrndx][3]

    def nm(idx):
        o = shstr_off + sh[idx][0]
        return data[o:data.index(b'\0', o)].decode()

    total = 0
    for idx, (name, typ, vaddr, off, size, link, info, entsize) in enumerate(sh):
        n = nm(idx)
        if not n.startswith('.rel'):
            continue
        entsz = entsize or 8
        cnt = size // entsz
        print('%-12s vma=0x%06x off=0x%06x size=0x%05x entries=%d'
              % (n, vaddr, off, size, cnt))
        total += cnt
        symtab = sh[link]
        strtab_off = sh[symtab[5]][3]
        for i in range(cnt):
            r_off, r_info = struct.unpack_from('<II', data, off + i * entsz)
            r_type = r_info & 0xff
            r_sym = r_info >> 8
            label = ''
            if r_sym and symtab[5]:
                so = symtab[3] + r_sym * 16
                st_name = struct.unpack_from('<I', data, so)[0]
                end = data.index(b'\0', strtab_off + st_name)
                label = data[strtab_off + st_name:end].decode(errors='replace')
            if want:
                for w in want:
                    if w <= r_off < w + 4:
                        print('    !! 0x%06x  %-16s sym=%s' % (r_off, TYPES.get(r_type, r_type), label))
            elif r_type in (23, 24, 25, 2) or label:
                print('    0x%06x  %-16s %s'
                      % (r_off, TYPES.get(r_type, r_type), label))
    print('total relocations: %d' % total)
    if want:
        print('looked for offsets near: %s'
              % ', '.join('0x%x' % w for w in want))
    return 0


if __name__ == '__main__':
    sys.exit(main())
