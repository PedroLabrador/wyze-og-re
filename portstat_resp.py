#!/usr/bin/env python3
"""Forge a mode-1 `7f cb` (GATFRM_PortStatResp) frame and send it to a camera.

WHY THIS FRAME (the KCP unblock, 2026-10-13)
--------------------------------------------
Run 3 of the forge produced 24 `7e a3 20 00` acks and STILL zero KCP.  The
`7e a3` (MTP_RES_RESPONSE) path is fully working -- it reaches
gat_on_rcvpkt_MTP_RES_RESPONSE, adds relay addresses (creating the type-135
channel), creates a session (proven: the camera's hello word == our conv), and
arms the send_rcv_map_port watchdog timer.  But that timer re-arms itself
forever until the byte `obj+0x4ec` becomes nonzero, and the ONLY writer of that
byte in the entire binary is gat_on_rcvpkt_GATFRM_PortStatResp.  KCP cannot
start until that flag is set.

So the missing handshake step is a PortStatResp.  It is a normal LAN-routable
GUTES frame exactly like 7e a3 -- no relay needed to deliver it.

FRAME LAYOUT (decoded from gat_on_rcvpkt_GATFRM_PortStatResp @ 0x51a40)
----------------------------------------------------------------------
  buf[0]      0x7f          GUTES magic (0x7e/0x7f/0x70 all route to GUTES)
  buf[1]      0xcb (203)    type.  giot_on_rcvpkt does index=frame[1]-1=202,
                            cmp #219, bhi default -> table[202] = 0x5264c,
                            which tail-calls PortStatResp.  (202/0xca is the
                            request PortStatReq; 203/0xcb is this response.)
  buf[2:4]    u16LE 36      total length incl. the 4-byte header
  buf[20:24]  FLAGS1        bit25=1 bypasses the 0x7e connection-id check
                            (same silent-drop fix as the 7e a3 forge)
  buf[24:26]  0x0004        u16LE; the handler reads (u16LE(frame[24])>>1)&3
                            and requires it == 1 or == 2.  0x4 -> 2.
  buf[32:36]  conv          frame[0x20], the iv_find_mtp_session key

The handler reads ONLY these three fields (frame[0x20], u16LE(frame[24]), and
the already-set session+0x4ec flag) -- verified: every other ldr in the
function is a stack/canary/GOT load, and both early-out branches are plain
`pop {r4,r5,r11,pc}` returns.  buf[24:26] and buf[32:36] are inside the RC5
mode-1 encrypted region (which starts at 24), so we set them in plaintext and
let the shared encryptor handle it; the camera decrypts before reading.

iv_find_mtp_session (0x5d96c) matches if conv == node->0x10|0x80000000 OR
(node->0x10 & mask)==conv, so send both bit forms (see p2p_call.py phase E).

USAGE (dry run prints the frame; --to actually sends)
    python3 portstat_resp.py --conv 0xef34cbd9
    python3 portstat_resp.py --conv 0xef34cbd9 --to 192.168.77.17 --dport 48171
"""
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from listreq import checksum, payload_len, rc5_encrypt_block, rc5_setup  # noqa: E402
from mtp_res import FLAGS1  # noqa: E402  (the proven bit25 id-skip flag)

MAGIC, TYPE, TOTAL = 0x7F, 0xCB, 36


def build(conv, seq=0, id8=b"\x00" * 8, gate=4, flags=FLAGS1):
    """Return a ready-to-send mode-1 `7f cb` PortStatResp.

    gate   the u16LE at frame[24].  The handler needs (gate>>1)&3 in {1,2};
           4 (->2) is the default.  Only bits 1-2 matter.
    conv   session lookup key written at frame[0x20] (= buf[32:36]).
    """
    buf = bytearray(TOTAL)
    buf[0], buf[1] = MAGIC, TYPE
    struct.pack_into("<H", buf, 2, TOTAL)
    buf[4:12] = id8[:8].ljust(8, b"\x00")
    struct.pack_into("<I", buf, 12, seq)
    struct.pack_into("<I", buf, 20, flags)
    struct.pack_into("<H", buf, 24, gate)              # >>1&3 must be 1 or 2
    struct.pack_into("<I", buf, 32, conv & 0xFFFFFFFF)  # frame[0x20] conv key

    struct.pack_into("<I", buf, 16, checksum(buf))

    # mode-1 RC5: header key buf[0..3]||buf[0x14..0x16]||0x00; encrypt [12:20]
    # then every 8-byte block from 24.
    key = bytes([buf[0], buf[1], buf[2], buf[3],
                 buf[0x14], buf[0x15], buf[0x16], 0x00])
    st = rc5_setup(key)
    buf[12:20] = rc5_encrypt_block(st, bytes(buf[12:20]), "little")
    for i in range(payload_len(buf) >> 3):
        off = 24 + i * 8
        buf[off:off + 8] = rc5_encrypt_block(st, bytes(buf[off:off + 8]),
                                             "little")
    return bytes(buf)


def selftest():
    """Structural checks only (no camera).  Verify header + that the plaintext
    fields land where the handler reads them after a decrypt round-trip."""
    from mtp_res import decrypt_plain
    conv = 0xEF34CBD9
    got = build(conv)
    ok = True

    def chk(name, cond, extra=""):
        nonlocal ok
        print("  %-34s %s  %s" % (name, "OK" if cond else "FAIL", extra))
        ok = ok and cond

    chk("length", len(got) == TOTAL, "%d" % len(got))
    chk("magic 0x7f", got[0] == 0x7F)
    chk("type 0xcb (203)", got[1] == 0xCB)
    chk("len field", struct.unpack_from("<H", got, 2)[0] == TOTAL)
    dec = decrypt_plain(got)
    chk("gate (frame[24]>>1)&3 in {1,2}",
        (struct.unpack_from("<H", dec, 24)[0] >> 1) & 3 in (1, 2),
        "%d" % ((struct.unpack_from("<H", dec, 24)[0] >> 1) & 3))
    chk("conv @ frame[0x20]=buf[32]",
        struct.unpack_from("<I", dec, 32)[0] == conv,
        "0x%08x" % struct.unpack_from("<I", dec, 32)[0])
    chk("flags bit25 set", (got[23] & 0x02) != 0, "0x%08x"
        % struct.unpack_from("<I", got, 20)[0])
    print("  selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a or not a:
        return selftest()

    def val(name, default=None):
        return a[a.index(name) + 1] if name in a else default

    conv = int(val("--conv", "0"), 0)
    target = val("--to")
    dport = int(val("--dport", "48171"))
    for bit31 in (0, 0x80000000):
        frame = build(conv | bit31)
        print("built %d B mode-1 7f cb  conv=0x%08x  -> %s:%d"
              % (len(frame), conv | bit31, target or "(dry run)", dport))
        print(frame.hex())
        if not target:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(frame, (target, dport))
        s.close()
        print("  sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
