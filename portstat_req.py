#!/usr/bin/env python3
"""Forge a mode-1 `7f ca` (GATFRM_PortStatReq) frame and send it to a camera.

WHY THE REQUEST, NOT THE RESPONSE (2026-10-13, run 4 -> run 5)
-------------------------------------------------------------
portstat_resp.py forges `7f cb` (the RESPONSE).  Run 4 showed the camera acks
it and echoes the gate, but KCP never starts.  Two findings killed that theory:

  1. There are ZERO `7f ca` / `7f cb` frames in ANY capture (wire/p2p_frames.json
     and /tmp/cap_relay.log).  The app's whole LAN dialogue is CALLING (7e a4)
     -> hello (C0 90) -> AvStreamCtl (7e b9).  PortStat is a RELAY-plane
     exchange, so the camera does not wait for it on the LAN.
  2. The MTP control plane (C0 90, jump table 0x57f18, types 1..37) has only
     8 real handlers: 1=iv_rcv_meter_req, 2=iv_rcv_meter_ack,
     34=iv_rcv_tcp_link_close, 37=iv_rcv_kcp_create_msg, and 3/4/33/35 are
     empty `b` returns.  Everything else is the default.  Decisively,
     iv_rcv_kcp_create_msg (0x619f8) is a NO-OP: it compares
     session->0x10 == p[4], logs, and returns.  It never creates KCP and never
     replies.  So the camera cannot be TALKED into creating KCP.

What the PortStatReq handler DOES do (0x51788..0x51a20, one function -- the
movw r2,#203 inside it builds the reply, confirmed by the pop at 0x51a20):

    session = iv_find_mtp_session(ctx->8, frame[0x24])   # key offset 0x24 here
    if !session: return
    session->0x4c..0x58 = buf[0x10..0x20]    # <-- stores the PEER ADDRESS
    gat_send_online_socket(session)          # sends its own 7f ca, len 52
    build 7f cb len 36 and ivudp_sendto(.., buf+16)   # replies to the sender

So a `7f ca` is what makes the camera RECORD OUR ADDRESS and open the
port-mapping exchange (send_rcv_map_port == "send/receive map port", a NAT
punch).  We had only ever sent the response, which records nothing.

FRAME LAYOUT (decoded from gat_send_online_socket @ 0x4b960, the only sender)
----------------------------------------------------------------------------
  buf[0]      0x7f           GUTES magic
  buf[1]      0xca (202)     type -> giot_on_rcvpkt index 201 -> PortStatReq
  buf[2:4]    u16LE 52       total length
  buf[4:12]   id8            session+0xc->0x240 / ->0x244 (opaque; bit25 skips
                             the id check so a zero id8 is fine)
  buf[0x14]   FLAGS1         bit25=1 bypasses the 0x7e connection-id check.
                             0x7f already skips that check by construction
                             (iv_gutes_on_rcvpkt @ 0x2c348 tests
                             `cmp r0,#126; bne 0x2c3c0`, i.e. only 0x7e is
                             id-checked), but bit25 is harmless and keeps this
                             forger interchangeable with mtp_res.py's.
  buf[0x1c]   session->0x24  opaque
  buf[0x20]   session->0x28  opaque
  buf[0x24]   conv           *** the session lookup key ***
  buf[0x29]   3              the field PortStatReq reads: {1,2}->gate 2,
                             3->gate 4, else 0.  3 is what the real sender
                             hardcodes, so use 3.

iv_find_mtp_session (0x5d96c) matches iff conv == node->0x10|0x80000000 OR
(node->0x10 & mask)==conv, so send both bit forms (see p2p_call.py phase E).

USAGE
    python3 portstat_req.py --selftest
    python3 portstat_req.py --conv 0xef34cbd9 --to 192.168.77.17 --dport 48171
"""
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from listreq import checksum, payload_len, rc5_encrypt_block, rc5_setup  # noqa: E402
from mtp_res import FLAGS1  # noqa: E402  (the proven bit25 id-skip flag)

MAGIC, TYPE, TOTAL = 0x7F, 0xCA, 52


def build(conv, seq=0, id8=b"\x00" * 8, port_stat=3, flags=FLAGS1):
    """Return a ready-to-send mode-1 `7f ca` PortStatReq.

    conv       written at frame[0x24] -- the iv_find_mtp_session key.
    port_stat  the byte at frame[0x29].  The camera turns {1,2} into gate 2
               and 3 into gate 4 in its `7f cb` reply.  3 is the real value.
    """
    buf = bytearray(TOTAL)
    buf[0], buf[1] = MAGIC, TYPE
    struct.pack_into("<H", buf, 2, TOTAL)
    buf[4:12] = id8[:8].ljust(8, b"\x00")
    struct.pack_into("<I", buf, 12, seq)
    struct.pack_into("<I", buf, 0x14, flags)
    struct.pack_into("<I", buf, 0x24, conv & 0xFFFFFFFF)   # session lookup key
    buf[0x29] = port_stat & 0xFF                            # gate selector

    struct.pack_into("<I", buf, 16, checksum(buf))

    # mode-1 RC5: header key buf[0..3]||buf[0x14..0x16]||0x00; encrypt [12:20]
    # then every 8-byte block from 24.  The camera derives the same header key
    # from the flags mode, so it decrypts without our knowing the session key.
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
    """Structural checks plus a decrypt round-trip of the handler's fields."""
    from mtp_res import decrypt_plain
    conv = 0xEF34CBD9
    got = build(conv)
    ok = True

    def chk(name, cond, extra=""):
        nonlocal ok
        print("  %-36s %s  %s" % (name, "OK" if cond else "FAIL", extra))
        ok = ok and cond

    chk("length", len(got) == TOTAL, "%d" % len(got))
    chk("magic 0x7f", got[0] == 0x7F)
    chk("type 0xca (202)", got[1] == 0xCA)
    chk("len field", struct.unpack_from("<H", got, 2)[0] == TOTAL)
    chk("flags bit25 set", (got[0x17] & 0x02) != 0,
        "0x%08x" % struct.unpack_from("<I", got, 0x14)[0])
    dec = decrypt_plain(got)
    chk("conv @ frame[0x24] (handler key)",
        struct.unpack_from("<I", dec, 0x24)[0] == conv,
        "0x%08x" % struct.unpack_from("<I", dec, 0x24)[0])
    chk("frame[0x29] == 3 (real sender's value)", dec[0x29] == 3, "%d" % dec[0x29])
    chk("checksum round-trips",
        struct.unpack_from("<I", dec, 16)[0] == checksum(dec))
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
        print("built %d B mode-1 7f ca  conv=0x%08x  -> %s:%d"
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
