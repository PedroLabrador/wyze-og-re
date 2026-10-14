#!/usr/bin/env python3
"""Bisect why the forged mode-1 `7e a3` gets no KCP.

THE OBSERVATION
---------------
We send a mode-1 `7e a3` MTP_RES_RESPONSE at a camera and get **nothing** back:
zero `7e a3 20 00`, zero KCP, ever (see /tmp/p2p_mtpres1.log, ...2.log).

WHY AN ACK WOULD TELL US WHERE IT DIES
--------------------------------------
`iv_gutes_on_rcvpkt` (0x2c158) is the only thing that decrypts a `7e` frame, and
it can only be sitting in one of these states when our frame shows up:

    0x2c184  iv_gutes_frm_decrypt(...)          -> ret < 0
    0x2c210  (flags>>18)&3 == 1  ->  send_ack(r2=1) @ 0x2c278   [FAILURE ack]
    0x2c320  (flags>>25)&1 == 0  ->  0x7e id check @ 0x2c344
    0x2c358  frame[4:12] must == *(*ctx+0xde8:0xdec)  else 0x2c3b4 return 0
    0x2c3a4  *(*ctx+0xc0) must == 2                 else 0x2c3b4 return 0
                                             ^^ SILENT DROP, no ack at all
    0x2c464  (flags>>21)&1 == 0  ->  0x2c4f0 (switch on the ack field)
                                     == 1  ->  send_ack(r2=0) @ 0x2c4cc  [SUCCESS ack]

Two ack sites, and they disagree about `frame[4:12]`:
    0x2c278 (failure) runs BEFORE the overwrite at 0x2c444  -> echoes OUR id8
    0x2c4cc/0x2c594 (success) run AFTER it                  -> echoes the ctx id
So the id8 in the reply also tells us whether decrypt succeeded.
And `iv_gutes_pkt_send_ack` really does copy it: `str r2,[r3,#0x4]` @ 0x2f1f0.

Every real frame the app sends has **bit25 = 1**, which skips the id check.
Our FLAGS1 = 0x00050000 has **bit25 = 0**, so we walk into an id comparison on
bytes we copied blindly from the CALLING and get dropped without a word.  That
is the leading hypothesis; the probes below measure it.

Also note bit25 lives in `buf[0x17]`, which is in NEITHER the RC5 key
(`buf[0..3] || buf[0x14..0x16] || 0x00`) NOR the checksum seed (masked
`0x00FFFFFF`), so toggling it is crypto-neutral.

THE PROBES
----------
    P0  replay the captured CALLING          expect `7e a4 20 00` (pipeline alive)
    P1  flags 0x02250000, corrupt checksum   expect `7e a3 20 00` ALWAYS if the
        (bit21=1, bit25=1)                  frame reaches iv_gutes_on_rcvpkt:
                                             bit21=1 acks on success (0x2c4cc) and
                                             on failure (0x2c278), and bit25=1
                                             bypasses the id check.  This is the
                                             ARRIVAL control.
    P2  flags 0x00050000                     the current build (known silence)
    P3  flags 0x02050000                     bit25=1 alone -> bypass the id check
    P4  flags 0xd2050000                     the high byte every AvStreamCtl carries

P1 acking while P2 does not => arrival + decrypt are fine and the gate is the
flags.  P1 NOT acking => the frame never reaches iv_gutes_on_rcvpkt at all, and
the bug is upstream (router on 0x340c4), which reframes the whole search.

Usage:
    python3 flags_probe.py            # auto-discover, probe every live camera
    python3 flags_probe.py 192.168.77.10
"""
import select
import socket
import struct
import sys
import time

sys.path.insert(0, ".")
from analyze_calls import decrypt                       # noqa: E402
from p2p_call import (CALLING_LEN, CALLING_PORT,        # noqa: E402
                      discover, local_ip_for, load_templates)
import mtp_res                                          # noqa: E402

# mode=(>>16)&3=1, ack=(>>18)&3=1, bit20=0, bit21, bit25, bit0=0
PROBES = [
    ("P1 arrival  b21=1 b25=1 badchk", 0x02250000, True),
    ("P2 current  b21=0 b25=0        ", 0x00050000, False),
    ("P3 bit25    b21=0 b25=1        ", 0x02050000, False),
    ("P4 high 0xd2 b21=0 b25=1       ", 0xD2050000, False),
]
WINDOW = 1.2          # seconds to listen after each probe


def label(frame):
    """Classify a reply by its first bytes."""
    if len(frame) >= 4 and frame[0] == 0x7E:
        return "7e %02x %02x %02x" % (frame[1], frame[2], frame[3])
    if len(frame) >= 4 and frame[0] == 0xC0:
        return "c0 %02x %02x %02x" % (frame[1], frame[2], frame[3])
    return "%dB %s" % (len(frame), frame[:4].hex())


def drain(sock, seconds, sink):
    """Append (t_rel, frame) to sink until `seconds` elapse."""
    t0 = time.time()
    while True:
        left = t0 + seconds - time.time()
        if left <= 0:
            return
        r, _, _ = select.select([sock], [], [], min(left, 0.1))
        if not r:
            continue
        data, addr = sock.recvfrom(4096)
        sink.append((time.time() - t0, data, addr))


def probe(sock, ip, port, frames, word):
    """Run P0 + the flag sweep against one camera; return the findings."""
    print("\n=== %s:%d   conv=0x%08x ===" % (ip, port, word), flush=True)
    myip = local_ip_for(ip)
    got = []
    hits = [0]

    # P0 -- the captured CALLING, byte for byte.  Baseline: proves our socket,
    # our source port and the camera's GUTES stack are all still answering.
    if CALLING_LEN in frames:
        print("  P0  replay captured CALLING (%d B)" % len(frames[CALLING_LEN]),
              flush=True)
        sock.sendto(frames[CALLING_LEN], (ip, port))
        drain(sock, WINDOW, got)
        n = sum(1 for _, f, _ in got if label(f).startswith("7e a4"))
        print("      -> %d x `7e a4 20 00` %s"
              % (n, "OK" if n else "*** SILENT - pipeline is dead ***"),
              flush=True)

    for i, (name, flags, bad) in enumerate(PROBES, start=1):
        id8 = b"PRB%d\x00\x00\x00\x00" % i
        frame = mtp_res.build(word, myip, port, id8=id8, seq=i, flags=flags,
                              corrupt_chk=bad)
        before = len(got)
        sock.sendto(frame, (ip, port))
        drain(sock, WINDOW, got)
        fresh = got[before:]

        print("  %s  flags=0x%08x %s (%d B)"
              % (name.split()[0], flags, "corrupt chk" if bad else "valid chk",
                 len(frame)), flush=True)
        if not fresh:
            print("      -> NO REPLY AT ALL", flush=True)
            continue
        for t, f, _ in fresh:
            tag = label(f)
            extra = ""
            if f[:2] == b"\x7e\xa3" and len(f) >= 12:
                echo = f[4:12]
                if echo == id8:
                    extra = ("   echoes OUR id8 -> "
                             "FAILURE path 0x2c278 (decrypt REJECTED)")
                elif echo != b"\x00" * 8:
                    extra = "   id8=%s -> ctx id, SUCCESS path (decrypt OK)" \
                            % echo.hex()
            print("      +%.2fs  %-16s%s" % (t, tag, extra), flush=True)
            if f[:2] == b"\x7e\xa3":
                hits[0] += 1

    return hits[0]


def main():
    wanted = sys.argv[1] if sys.argv[1:2] else None

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
        print("[!] no cameras found", flush=True)
        return 1

    tpl = load_templates()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", CALLING_PORT))
    sock.setblocking(False)
    print("[listen] local port %d" % CALLING_PORT, flush=True)

    live = 0
    for ip, dev in sorted(cams.items()):
        frames = tpl.get(dev["tid"])
        if not frames or CALLING_LEN not in frames:
            print("  %-16s no captured CALLING (tid %d) - skipped"
                  % (ip, dev["tid"]), flush=True)
            continue
        # conv = the CALLING's [0x1c], mode 1 only
        if (struct.unpack_from("<I", frames[CALLING_LEN], 20)[0] >> 16) & 3 != 1:
            print("  %-16s CALLING is not mode 1 - skipped" % ip, flush=True)
            continue
        word = struct.unpack_from("<I", decrypt(frames[CALLING_LEN]), 28)[0]
        try:
            probe(sock, ip, dev["p2p_port"], frames, word)
            live += 1
        except OSError as e:
            print("  %-16s unreachable: %s" % (ip, e), flush=True)

    sock.close()
    print("\n%d camera(s) probed." % live, flush=True)
    return 0 if live else 1


if __name__ == "__main__":
    sys.exit(main())
