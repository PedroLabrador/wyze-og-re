#!/usr/bin/env python3
"""Does the camera's session word come from OUR CALLING, or is it already there?

Why this is the last unproven link
----------------------------------
Our forged `7e a3` now provably reaches gat_on_rcvpkt_MTP_RES_RESPONSE (the
whole chain is verified: bit21==0 -> blx ctx->0xe4 -> GOT slot 0xc9068 ->
giot_on_rcvpkt -> type 163).  The only gate left before add_udp_relay is

    iv_find_mtp_session(arg0->8, frame[0x1c])

which needs a session holding conv == our word.  That session is supposed to
be created when the camera dispatches our replayed CALLING (type 164 ->
gat_on_rcvpkt_CALLING_REQ), and iv_on_rcv_calling stores frame[0x1c] into
session+0x10.

But nothing so far PROVES our CALLING created a session: the camera acks it
before dispatching, and the ack tells us nothing about what followed.  The
camera's own 74-byte `c0 90 02 09` hellos carry a word at payload[4:8], and
it currently happens to equal CALLING[0x1c] on every camera.  Two readings:

  * the word IS session state  -> it can only match because our CALLING set
                                  it, so the session exists and the lookup
                                  should hit;
  * the word is pre-existing    -> the match proves nothing at all, and the
                                  camera may have no session for our conv.

This separates them by watching the word BEFORE and AFTER sending the CALLING.

    python3 hello_watch.py [camera-ip]
"""
import select
import socket
import struct
import sys
import time

sys.path.insert(0, ".")
from mtp_frame import unwrap                     # noqa: E402
from p2p_call import (CALLING_LEN, CALLING_PORT,  # noqa: E402
                      discover, load_templates)

PRE = 5.0        # seconds of listening before we send anything
POST = 5.0       # seconds after


def word_of(hello):
    r = unwrap(hello)
    if not r or len(r[0]) < 8:
        return None
    return struct.unpack_from("<I", r[0], 4)[0]


def collect(sock, seconds, seen):
    t0 = time.time()
    while time.time() - t0 < seconds:
        r, _, _ = select.select([sock], [], [], 0.2)
        if not r:
            continue
        data, addr = sock.recvfrom(4096)
        if len(data) != 74 or data[:2] != b"\xc0\x90":
            continue
        w = word_of(data)
        if w is None:
            continue
        seen.setdefault(addr[0], []).append((time.time() - t0, w))


def main():
    wanted = sys.argv[1] if sys.argv[1:] else None

    cams = {}
    for attempt in range(1, 6):
        cams = discover(5.0)
        if cams and (not wanted or wanted in cams):
            break
        print("[discover] attempt %d incomplete, retrying" % attempt,
              flush=True)
    if wanted:
        cams = {k: v for k, v in cams.items() if k == wanted}
    if not cams:
        print("[!] no cameras found")
        return 1

    tpl = load_templates()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", CALLING_PORT))
    sock.setblocking(False)

    pre = {}
    print("[phase 0] passive: %gs, sending NOTHING" % PRE, flush=True)
    collect(sock, PRE, pre)

    # send the captured CALLING, byte for byte, to every camera that has one
    print("[phase 1] replay the captured CALLING", flush=True)
    for ip, dev in sorted(cams.items()):
        frames = tpl.get(dev["tid"])
        if not frames or CALLING_LEN not in frames:
            print("  %-16s no captured CALLING" % ip, flush=True)
            continue
        sock.sendto(frames[CALLING_LEN], (ip, dev["p2p_port"]))
        print("  %-16s sent %d B" % (ip, len(frames[CALLING_LEN])), flush=True)

    post = {}
    print("[phase 2] listening %gs" % POST, flush=True)
    collect(sock, POST, post)
    sock.close()

    print()
    print("%-16s %-26s %s" % ("camera", "word BEFORE our CALLING",
                               "word AFTER"))
    print("-" * 78)
    verdict = None
    for ip in sorted(set(pre) | set(post)):
        w0 = sorted({w for _, w in pre.get(ip, [])})
        w1 = sorted({w for _, w in post.get(ip, [])})
        n0, n1 = len(pre.get(ip, [])), len(post.get(ip, []))
        a = " ".join("0x%08x" % x for x in w0) or "(no hellos)"
        b = " ".join("0x%08x" % x for x in w1) or "(no hellos)"
        print("%-16s %-26s %-26s n=%d/%d" % (ip, a, b, n0, n1))
        if w0 and w1:
            verdict = ("word is already present BEFORE we send -> it is NOT "
                       "set by our CALLING; the match proves nothing"
                       if w0 == w1 else
                       "word CHANGED after our CALLING -> it IS session state")

    print()
    if verdict is None:
        print("verdict: not enough hellos to compare")
        return 1
    print("verdict:", verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main())
