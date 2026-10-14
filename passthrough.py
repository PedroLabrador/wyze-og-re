#!/usr/bin/env python3
"""Forge a mode-1 GUTES type-185 (PASSTHROUGH_MSG) frame -- the KCP trigger.

WHY THIS IS THE MISSING FRAME (2026-10-13)
-------------------------------------------
Six probe runs got camera acks for everything yet never one `C0 10` (KCP).
Root cause: the wrong trigger frame.  The chain that actually creates KCP on
the far side is not PortStat and not the MTP-control type-0x25:

  * giot_on_rcvpkt's 220-entry type table (0x52128) maps **type 185 (0xb9)**
    -> gat_on_rcvpkt_PASSTHROUGH_MSG (0x504fc).  Full decoded map in the doc.
  * The app's captured frame we have been calling "avstreamctl" IS `7e b9`,
    i.e. a PASSTHROUGH_MSG carrying an inner command -- we were replaying cmd
    0 the whole time.
  * Inside gat_on_rcvpkt_PASSTHROUGH_MSG, `inner = frame + 52`, and

        switch inner[0]:
            0 -> chan->0x16c = inner[0xc]; iv_start_process_reset(chan)
            1 -> iv_mtp_kcp_create(iv_find_mtp_session(ctx->8, inner[4:8]))
            2 -> chan->0x16c = 0x4e2a; (chan->0x94)->0x34 = 1
            3 -> chan->0x16c = 0x4e27; (chan->0x94)->0x34 = 1
            4 -> free matching sessions
            6 -> relay-address report (copies inner+24, 92 B)

  * `iv_mtp_kcp_create` has exactly TWO callers in the whole binary:
      - 0x535b8 in giot_send_create_kcp_session_msg (the LOCAL/client side)
      - 0x50904 in gat_on_rcvpkt_PASSTHROUGH_MSG  (the REMOTE side)  <--
    so this is the only inbound frame that makes the camera build a KCP
    object.  Everything else we tried was a dead end:
        MTP control type 37 (0x25) -> iv_rcv_kcp_create_msg (0x619f8) is a
        NO-OP: it compares session->0x10 == p[4], logs, and returns.
        PortStatResp sets obj+0x4ec but that only stops the watchdog.

VALIDATION ON THE REAL CAPTURED FRAME
-------------------------------------
decrypting wire/p2p_frames.json[..]['avstreamctl'] gives, at the offsets this
module writes:

    frame[52:56] = 00 00 00 00            -> cmd 0
    frame[56:60] = d9 cb 34 ef = 0xef34cbd9   -> inner[4:8], the session word
    frame[64:68] = 22 4e 00 00 = 0x4e22       -> inner[0xc], exactly the state
                                                constant cmd 0 stores
so the field map is confirmed against a genuine app frame, not guessed.

THE TWO PRE-GATES (0x5052c..0x50574) -- BOTH MUST PASS
-------------------------------------------------------
    frame[0x18] & 1 must be 1                        (frame[24] odd)
    frame[4:8]  ^ ctx->0x240  |  frame[8:12] ^ ctx->0x244  == 0
The second is a connection-id check, so frame[4:12] must be the camera's own
id8.  Reuse the id8 from that camera's captured frame (CALLING or avstreamctl)
-- those are known-accepted.  frame[24] is written as 3, matching the capture.

USAGE
    python3 passthrough.py --selftest
    python3 passthrough.py --cmd 1 --conv 0xef34cbd9 --to 192.168.77.17 \
                           --id8 6601b08a27860c8d
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from listreq import checksum, payload_len, rc5_encrypt_block, rc5_setup  # noqa: E402
from mtp_res import decrypt_plain, FLAGS1  # noqa: E402

MAGIC, TYPE = 0x7E, 0xB9          # 185 -> gat_on_rcvpkt_PASSTHROUGH_MSG
TOTAL = 60                        # 60 B puts conv at [56:60] just past the
                                  # last RC5 block, so it stays plaintext
CMD_KCP_CREATE = 1
CMD_INIT_STATE = 0
CMD_STATES = {0: "init/state", 1: "CREATE KCP", 2: "state 0x4e2a",
              3: "state 0x4e27", 4: "teardown", 6: "relay addrs"}


def build(cmd, conv, id8, seq=0, flags=FLAGS1, total=TOTAL, state=3):
    """Return a ready-to-send type-185 PASSTHROUGH_MSG.

    cmd   inner[0], see CMD_STATES.  1 is the one that makes the far side
          call iv_mtp_kcp_create.
    conv  written at frame[56:60] == inner[4:8]; the camera looks its session
          up with it (iv_find_mtp_session(ctx->8, inner[4:8])).
    id8   frame[4:12]; MUST be the camera's connection id or the pre-gate at
          0x50550 silently drops the whole frame.
    state frame[24]; the low bit is tested (`frame[0x18] & 1`), so it must be
          odd.  3 is what the genuine app frame carries.
    """
    buf = bytearray(total)
    buf[0], buf[1] = MAGIC, TYPE
    struct.pack_into("<H", buf, 2, total)
    buf[4:12] = id8[:8].ljust(8, b"\x00")
    struct.pack_into("<I", buf, 12, seq)
    struct.pack_into("<I", buf, 0x14, flags)
    buf[24] = state & 0xFF
    struct.pack_into("<I", buf, 52, cmd & 0xFF)   # inner[0]
    struct.pack_into("<I", buf, 56, conv & 0xFFFFFFFF)  # inner[4:8]

    struct.pack_into("<I", buf, 16, checksum(buf))

    # mode-1 RC5: header key buf[0..3]||buf[0x14..0x16]||0x00; covers [12:20]
    # then every 8-byte block from 24.  The far side derives the same key from
    # the flags mode, which is why we can forge without the session key.
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
    ok = True

    def chk(name, cond, extra=""):
        nonlocal ok
        print("  %-40s %s  %s" % (name, "OK" if cond else "FAIL", extra))
        ok = ok and cond

    conv, id8 = 0xEF34CBD9, bytes.fromhex("6601b08a27860c8d")
    got = build(CMD_KCP_CREATE, conv, id8)
    dec = decrypt_plain(got)

    chk("length", len(got) == TOTAL, "%d" % len(got))
    chk("magic 0x7e", got[0] == 0x7E)
    chk("type 0xb9 (185 PASSTHROUGH_MSG)", got[1] == 0xB9)
    chk("len field", struct.unpack_from("<H", got, 2)[0] == TOTAL)
    chk("id8 preserved (pre-gate 0x50550)", dec[4:12] == id8)
    chk("pre-gate: frame[24] odd", dec[24] & 1 == 1, "%d" % dec[24])
    chk("cmd == 1 (CREATE KCP)", dec[52] == 1, "%d" % dec[52])
    chk("inner[4:8] == conv", struct.unpack_from("<I", dec, 56)[0] == conv,
        "0x%08x" % struct.unpack_from("<I", dec, 56)[0])
    chk("checksum round-trips",
        struct.unpack_from("<I", dec, 16)[0] == checksum(dec))
    chk("flags bit25 set", (dec[0x17] & 0x02) != 0,
        "0x%08x" % struct.unpack_from("<I", dec, 20)[0])
    chk("mode == 1 (header key)",
        (struct.unpack_from("<I", dec, 20)[0] >> 16) & 3 == 1)
    print("  selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a or not a:
        return selftest()

    def val(name, default=None):
        return a[a.index(name) + 1] if name in a else default

    cmd = int(val("--cmd", "1"))
    conv = int(val("--conv", "0"), 0)
    id8 = bytes.fromhex(val("--id8", "00" * 8))
    target, dport = val("--to"), int(val("--dport", "48171"))
    print("cmd %d (%s)" % (cmd, CMD_STATES.get(cmd, "?")))
    for bit31 in (0, 0x80000000):
        frame = build(cmd, conv | bit31, id8)
        print("built %dB type-185 cmd=%d conv=0x%08x -> %s:%d"
              % (len(frame), cmd, conv | bit31, target or "(dry run)", dport))
        if not target:
            continue
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(frame, (target, dport))
        s.close()
        print("  sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
