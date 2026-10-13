#!/usr/bin/env python3
"""MTP framing (the 0xc0 layer) -- encode, decode, verify.

Reverse-engineered from iv_mtp_chnnel_send_mtp_frm (libiotp2pav.so @ 0x5b148)
and iv_mtpfrm_calc_chval (@ 0x5f110).  This is the layer used by
giot_send_create_kcp_session_msg (type 0x25), and it is what the 74-byte
"c0 90 02 09" packets actually are -- see P2P_PROTOCOL.md 5e.

Wire layout, 6-byte header + payload:

    [0]     0xc0  magic (written literally: mov r1,#192 / strb)
    [1]     0x10 | (class << 7)     <-- bit7 is the PACKET CLASS selector
    [2]     (length & 7)            + leftover bits preserved by  &~7
    [3]     (length >> 3)           length = TOTAL frame length (header+payload)
    [4:6]   u16 LE = chval ^ u16LE(p[2:4])
    [6:]    payload   (length - 6 bytes)

BIT7 IS NOT COSMETIC -- it selects the receive handler (the UDP receive
router at 0x340c4 in libiotp2pav.so):

    wire[0] == 0xc0 && wire[1] bit7 == 1 && bit4 == 1  ->  C0 90
            iv_on_rcv_mtpCtrl_pkt   (MTP control: hello, type 0x25, meter)
    wire[0] == 0xc0 && wire[1] bit7 == 0 && bit4 == 1  ->  C0 10
            iv_on_rcv_kcpdata_pkt   (a raw KCP segment follows at [6:])
    wire[0] == 0xc0 && bit4 == 0                        ->  C0 80 / C0 00
            iv_on_rcv_pkt_as_relay

Bits 5..6 of [1] are the "extra 8-byte header" selector read by every
handler as `(wire[1] >> 5) & 3`; the send path masks them off (& 0x9f), so
they are always 0 and the payload always starts at [6:].

Sending a control command with flag=0 puts it in the KCP bucket, where the
first 4 payload bytes are read as a KCP conv id -- which is why the first
type-0x25 probe was silently dropped.

iv_mtpfrm_calc_chval over the FIRST 24 BYTES OF PAYLOAD only:

    chval = 0
    for i in 0..11:
        v = u16LE(payload[2*i : 2*i+2])
        chval ^= rotl16(v, i)          # 16-bit rotate left by i
    return chval & 0xffff

Note the checksum covers payload[0:24], NOT the whole payload -- and it is
folded with u16LE(p[2:4]) (the length field) when stored.

Verified against every 74-byte frame captured from the real app.
"""
import glob
import os
import struct
import sys

MAGIC = 0xC0


def rotl16(v, n):
    n &= 15
    return ((v << n) | (v >> (16 - n))) & 0xFFFF


def chval(payload):
    """iv_mtpfrm_calc_chval -- first 24 bytes of payload, rotating per index."""
    acc = 0
    for i in range(12):
        off = 2 * i
        if off + 2 > len(payload):
            break
        v = struct.unpack_from("<H", payload, off)[0]
        acc ^= rotl16(v, i)
    return acc & 0xFFFF


def wrap(payload, flag=1):
    """Build a complete MTP frame around `payload`.

    flag defaults to 1 because that is what the wire actually shows: every
    genuine frame starts `c0 90`, and the producer is

        p[1] = ((prev & 0x9f) | 0x10) & 0x7f | (flag << 7)     @ 0x5b214..0x5b248

    With a freshly-zeroed buffer (prev = 0) flag=0 yields 0x10 and flag=1
    yields 0x90.  The three real callers of iv_mtp_chnnel_send_mtp_frm pass:
        0x5c008  iv_mtp_chnnel_send_meter_frm   r3 = 1
        0x5c360  iv_create_kcb                  r3 = 0
        0x53598  giot_send_create_kcp_session   r3 = its own arg3
    """
    total = len(payload) + 6
    if total > 0x7FF:
        raise ValueError("MTP length field is 11 bits")
    b2 = (total & 7)
    b3 = (total >> 3) & 0xFF
    b1 = 0x10 | ((flag & 1) << 7)
    word24 = (b2 | (b3 << 8))          # u16 LE of p[2:4]
    chk = chval(payload) ^ word24
    return bytes([MAGIC, b1, b2, b3]) + struct.pack("<H", chk) + bytes(payload)


def unwrap(frame):
    """Return (payload, total_len, flag, ok) for a MTP frame, else None."""
    if len(frame) < 6 or frame[0] != MAGIC:
        return None
    total = (frame[2] & 7) | (frame[3] << 3)
    flag = (frame[1] >> 7) & 1
    payload = frame[6:total]
    ok = (struct.unpack_from("<H", frame, 4)[0]
          == (chval(payload) ^ struct.unpack_from("<H", frame, 2)[0]))
    return payload, total, flag, ok


def hexdump(b, base=0):
    out = []
    for off in range(0, len(b), 16):
        c = b[off:off + 16]
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in c)
        out.append("  %4d  %-47s  |%s|"
                   % (base + off, " ".join("%02x" % x for x in c), asc))
    return "\n".join(out)


def main():
    files = sorted(glob.glob("/tmp/forge_in_*.bin"))
    if len(sys.argv) > 1:
        files = sorted(glob.glob(sys.argv[1]))
    print("=== verify iv_mtpfrm_calc_chval against captured frames ===")
    good = bad = other = 0
    for fn in files:
        d = open(fn, "rb").read()
        if d[0] != MAGIC:
            other += 1
            continue
        r = unwrap(d)
        if r is None:
            other += 1
            continue
        payload, total, flag, ok = r
        if ok:
            good += 1
        else:
            bad += 1
            print("  MISMATCH %s len=%d expected=%04x got=%04x"
                  % (os.path.basename(fn), len(d),
                     struct.unpack_from("<H", d, 4)[0],
                     chval(payload) ^ struct.unpack_from("<H", d, 2)[0]))
    print("  MTP frames ok=%d bad=%d   (non-MTP frames skipped=%d)"
          % (good, bad, other))

    if files:
        d = open(files[0], "rb").read()
        print()
        print("=== decode %s ===" % os.path.basename(files[0]))
        print(hexdump(d))
        if d[0] == MAGIC:
            payload, total, flag, ok = unwrap(d)
            print("  magic=0x%02x flag=%d total=%d payload=%d chval_ok=%s"
                  % (d[0], flag, total, len(payload), ok))
            print("  --- payload ---")
            print(hexdump(payload, 6))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
