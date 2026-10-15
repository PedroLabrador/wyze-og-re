#!/usr/bin/env python3
"""Read raw 32-bit words at given VMAs from an ELF32 (no readelf available).

    python3 peek.py 0x9e668 0x2d8f4

Used to resolve the value that iv_gute_session_new stores into session->0xe4:
    ldr r2, [pc, #0x58]   -> r2 = *(u32*)0x2d8f4 = 0x0009b7c8
    ldr r2, [pc, r2]      -> r2 = *(u32*)(0x2d8a0 + r2)
so session->0xe4 is the static word at the resulting address.  Printing it
tells us which function the GUTES layer hands received frames to -- the
missing link between iv_gutes_on_rcvpkt and the type dispatcher.
"""
import struct
import sys

SO = ("com.hualai_2.50.7.487-62187_minAPI24(arm64-v8a,armeabi-v7a)"
      "(nodpi)_apkmirror.com/lib/armeabi-v7a/libiotp2pav.so")


def load(path):
    """Return (data, list of (vaddr, offset, filesz, memsz)) for PT_LOAD."""
    data = open(path, 'rb').read()
    assert data[:4] == b'\x7fELF' and data[4] == 1, 'not ELF32'
    e_phoff = struct.unpack_from('<I', data, 0x1c)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x2a)[0]
    e_phnum = struct.unpack_from('<H', data, 0x2c)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from(
            '<IIIIII', data, off)
        if p_type == 1:                     # PT_LOAD
            segs.append((p_vaddr, p_offset, p_filesz, p_memsz))
    return data, segs


def vma_to_off(data, segs, vma):
    for v, o, fs, ms in segs:
        if v <= vma < v + ms:
            if vma - v < fs:
                return o + (vma - v)
            return None                     # .bss
    return None


def read_words(data, segs, vma, n=1):
    off = vma_to_off(data, segs, vma)
    if off is None:
        return None
    return struct.unpack_from('<%dI' % n, data, off)


def main():
    path = sys.argv[-1] if sys.argv[-1].endswith('.so') else SO
    args = [a for a in sys.argv[1:] if a.startswith('0x') or a.isdigit()]
    data, segs = load(path)
    for a in args:
        vma = int(a, 16) if a.lower().startswith('0x') else int(a)
        w = read_words(data, segs, vma, 1)
        if w is None:
            print('0x%08x  <not in a file-backed segment>' % vma)
            continue
        v = w[0]
        note = ''
        if 0x14f40 <= v < 0xb93b0 and v % 4 == 0:
            note = '   <- looks like a code address in .text'
        elif 0xcd64 <= v < 0xc8d58:
            note = '   <- .rodata'
        print('0x%08x  =  0x%08x (%d)%s' % (vma, v, v, note))
    return 0


if __name__ == '__main__':
    sys.exit(main())
