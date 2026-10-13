#!/usr/bin/env python3
"""Decode every unique UDP frame the app sent while it was dialling US.

Captured by forge_call.py (see P2P_PROTOCOL.md 5e).  Three frame types were
observed, all arriving on the *camera's* P2P port, all from the app's single
session socket:

    74 B   c0 90 02 09   ...        17 pkts   sent first
   128 B   7e a4 80 00   type 0xa4  56 pkts   CALLING   (iv_init_frm_CALLING)
    76 B   7e b9 4c 00   type 0xb9  42 pkts   sent after CALLING

Frame crypto follows the same rule as LIST frames (P2P_PROTOCOL.md 4a/9):
    key   = frame[0:4] || frame[0x14:0x17] || 0x00
    block = 8 B, 6 rounds, RC5, ECB, little-endian block words
    encrypted regions: [12:20] and [24:]   (i.e. everything but the header)

Note frame[0] on the wire is 0x7e even though iv_init_frm_CALLING writes 0x7f:
iv_gutes_add_send_pkt overwrites buf[0] with 126 whenever ctx->mode == 2, and
in the same guarded block replaces buf[4:12] with a session word from
ctx+0xde8/0xdec (libiotp2pav.so @ 0x2eb04).

Usage:  python3 analyze_calls.py [/tmp/forge_in_*.bin]
"""
import glob
import os
import struct
import sys

sys.path.insert(0, ".")
from listreq import rc5_setup, rc5_decrypt_block

DECRYPT = True


def decrypt(frame):
    key = frame[0:4] + frame[20:23] + b"\x00"
    st = rc5_setup(key)
    out = bytearray(frame)
    for off in list(range(12, 20, 8)) + list(range(24, len(frame), 8)):
        if off + 8 > len(out):
            break
        out[off:off + 8] = rc5_decrypt_block(st, bytes(frame[off:off + 8]),
                                             "little")
    return bytes(out)


def hexdump(b, base=0):
    lines = []
    for off in range(0, len(b), 16):
        c = b[off:off + 16]
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in c)
        lines.append("  %4d  %-47s  |%s|" % (base + off,
                                             " ".join("%02x" % x for x in c),
                                             asc))
    return "\n".join(lines)


def field(v):
    return "%-18s 0x%016x  %d" % (struct.pack("<Q", v).hex(), v, v)


def main():
    pat = sys.argv[1] if len(sys.argv) > 1 else "/tmp/forge_in_*.bin"
    files = sorted(glob.glob(pat))
    if not files:
        print("no captures found for", pat)
        return 1

    # group by exact bytes so we only decode each distinct frame once
    uniq = {}
    for fn in files:
        d = open(fn, "rb").read()
        uniq.setdefault(d, []).append(os.path.basename(fn))

    order = sorted(uniq, key=lambda d: (-len(uniq[d]), d[:4]))
    print("=== %d files, %d distinct frames ===\n" % (len(files), len(uniq)))

    for d in order:
        names = uniq[d]
        print("-" * 78)
        print("%d B   magic=%02x type=%02x len=%d   seen %dx   e.g. %s"
              % (len(d), d[0], d[1], struct.unpack_from("<H", d, 2)[0],
                 len(names), names[0]))
        if d[0] != 0x7e:
            print("  (not a GUTES/0x7e frame - printed raw)")
            print(hexdump(d))
            print()
            continue

        pt = decrypt(d) if DECRYPT else d
        flags = struct.unpack_from("<I", d, 20)[0]
        print("  flags[20:24]=0x%08x  (key=%s)"
              % (flags, (d[0:4] + d[20:23] + b"\x00").hex()))
        print(hexdump(pt))
        if len(pt) >= 48:
            print("  +4   :", field(struct.unpack_from("<Q", pt, 4)[0]))
            print("  +28  :", "0x%08x (per-cam word)"
                  % struct.unpack_from("<I", pt, 28)[0])
            print("  +32  :", field(struct.unpack_from("<Q", pt, 32)[0]))
            print("  +40  :", field(struct.unpack_from("<Q", pt, 40)[0]))
        if len(pt) >= 68:
            print("  +54  : local port %d" % struct.unpack_from("<H", pt, 54)[0])
            print("  +64  : local ip  %d.%d.%d.%d" % tuple(pt[64:68]))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
