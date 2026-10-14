#!/usr/bin/env python3
"""Sweep the ONLY AvStreamCtl field the camera reads: w160 (u16 @ pkt[62:64]).

WHY THIS FIELD
--------------
iv_rcvpkt_AVSTREAMCTL_INITREQ (libiotp2pav 0x56f4c), after the state checks,
reads exactly two fields out of the packet:

    ldrh r2, [pkt, #62]      ->  chn->0x160        (and pkt_ctx->0x18)
    ldr  r2, [pkt, #0x4]     ->  chn->0x164 / 0x8c (id164)

It never touches pkt[0x10] (ac), pkt[0x14] (b0) or the 32-byte blob at
[24:56].  So every previous sweep of ac/b0/blob was sweeping fields the
camera discards, and the one field it does consume, w160, was only ever
tried with the value 20 (an fps guess).

On the send side the value comes from ctx->0x1a8 -> 0x160, which
iv_start_av_link copies from a u16 argument and iv_start_process_calling
mirrors into ctx->0x160.  It is a u16, so plausible readings are a width
(1920/1280/640), a height (1080/720/360) or a definition code (2/3/4).

The message is also <cmd @ [8:12]> <subcmd @ [0xc]> -- iv_send_av_stream_ctl_frm
writes those two independently, and the camera sends us cmd=3/subcmd=7 --
so the subcmd byte is swept too.

Each variant uses a fresh random id164, the way iv_start_process_calling
generates it ((rand()<<20)|(rand()<<10)|(rand()&0x3ff), retried until
non-zero), and we watch the AV header for a new width/height after each.

Usage: python3 -u w160probe.py [tid] [seconds]
"""
import random
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
import kcpav                                         # noqa: E402
import p2p_client                                    # noqa: E402
from mtp_frame import wrap as mtp_wrap               # noqa: E402
from defsend import Probe, load_calling              # noqa: E402


def fresh_id164():
    """iv_start_process_calling's id: 30 random bits, retried if zero."""
    while True:
        v = ((random.getrandbits(32) << 20) & 0xffffffff
             | (random.getrandbits(32) << 10) & 0xffffffff
             | (random.getrandbits(32) & 0x3ff)) & 0x3fffffff
        if v:
            return v


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 120.0

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("tid %s  camera %s:%s" % (tid, ip, port), flush=True)

    st = Probe(ip, port, tid, load_calling(tid), local_port=0, timeout=secs)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi

    def pump(n):
        for _ in range(int(n / 0.5)):
            st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])

    def push(frame):
        for kc in (lo, hi):
            for _ in range(3):                      # retransmit
                kc.push(frame)
        for kc in (lo, hi):
            for pkt in kc.take_packets():
                st._send(mtp_wrap(pkt, 0))

    pump(6.0)
    print("baseline headers: %s  tlv: %s" % (st.headers or "none",
                                             st.tlv_counts), flush=True)
    if not st.headers:
        print("no AV header -- camera did not stream; aborting")
        return

    w160_cases = [1920, 1280, 1080, 720, 640, 360, 2560,
                  2, 3, 4, 5, 20, 30, 1, 0]
    print("\n== sweep w160 @ pkt[62:64] (cmd=1 subcmd=1, id164 random) ==",
          flush=True)
    for w in w160_cases:
        frame = kcpav.avstreamctl(kcpav.ACT_START, id164=fresh_id164(),
                                  w160=w)
        before = list(st.headers)
        push(frame)
        pump(3.0)
        print("w160=%-5d -> headers=%s%s" % (w, st.headers,
              "   <-- CHANGED" if st.headers != before else ""), flush=True)

    print("\n== sweep subcmd @ [0xc] (cmd=1, w160=1920) ==", flush=True)
    for sub in (2, 3, 4, 5, 7):
        frame = bytearray(kcpav.avstreamctl(kcpav.ACT_START,
                                            id164=fresh_id164(), w160=1920))
        frame[0xC] = sub
        before = list(st.headers)
        push(bytes(frame))
        pump(3.0)
        print("subcmd=%-3d -> headers=%s%s" % (sub, st.headers,
              "   <-- CHANGED" if st.headers != before else ""), flush=True)

    print("\n== sweep cmd @ [8:12] (subcmd=7, w160=1920) ==", flush=True)
    for cmd in (2, 3, 4, 5):
        frame = bytearray(kcpav.avstreamctl(kcpav.ACT_START,
                                            id164=fresh_id164(), w160=1920))
        frame[0xC] = 7
        frame[8:12] = struct.pack("<I", cmd)
        before = list(st.headers)
        push(bytes(frame))
        pump(3.0)
        print("cmd=%-3d -> headers=%s%s" % (cmd, st.headers,
              "   <-- CHANGED" if st.headers != before else ""), flush=True)

    pump(4.0)
    print("\nfinal headers: %s" % (st.headers,), flush=True)
    st.close()


if __name__ == "__main__":
    main()
