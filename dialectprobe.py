#!/usr/bin/env python3
"""Does the 3.23.1 CALLING dialect alone change the stream the camera sends?

Our client replays a CALLING captured from the 2.50.7 app: a 128-byte frame
whose plaintext tail [120:128] is the AV RC5 key.  The 3.23.1 app sends a
completely different CALLING -- 66 bytes, different field layout -- and then
runs a dozen GUTES frame types we never emit, and it receives ~1.4 Mbps
where we receive ~400 kbps.

This probe replays the NEW app's CALLING verbatim against a free camera and
measures only the raw inbound rate, so no decryption is needed:

    * rate stays ~400 kbps  -> the CALLING is not the switch
    * rate jumps ~1.4 Mbps  -> the CALLING dialect IS the switch
    * nothing flows         -> the new dialect needs more handshake; the
                              datagram log shows what the camera expects

Usage: python3 -u dialectprobe.py [tid] [seconds]
"""
import os
import re
import select
import socket
import sys
import time
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from mtp_frame import unwrap as mtp_unwrap           # noqa: E402


def app_calling(log="/tmp/cap_relay_323.log"):
    """The first CALLING the 3.23.1 app sent, in the clear."""
    m = re.search(r"HEX (7ea6[0-9a-f]+)", open(log).read())
    return bytes.fromhex(m.group(1))


def freshen(c):
    """Randomise the per-session fields, keeping the 3.23.1 layout.

    [0:16] nonce, [20:36] session id, [36:44]+[44:52] conn id (sent twice).
    [16:20] and the trailing 10 bytes are left as the app wrote them --
    [16:20] carries the retransmit flag (byte 3 toggles 0x00/0x10) and the
    tail is likely the AV key, which the camera reads back out of the frame.
    """
    c = bytearray(c)
    c[4:20] = os.urandom(16)                 # nonce (payload[0:16])
    c[24:40] = os.urandom(16)                # session id (payload[20:36])
    cid = os.urandom(8)
    c[40:48] = cid                           # conn id (payload[36:44])
    c[48:56] = cid                           # conn id again ([44:52])
    return bytes(c)


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 25.0
    mode = sys.argv[3] if len(sys.argv) > 3 else "fresh"

    calling = app_calling()
    if mode == "fresh":
        calling = freshen(calling)
    print("sending the 3.23.1 CALLING, mode=%s (%d B): %s"
          % (mode, len(calling), calling.hex()), flush=True)

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("tid %s  camera %s:%s" % (tid, ip, port), flush=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    s.setblocking(False)

    s.sendto(calling, (ip, port))
    print("CALLING sent at %.2fs" % time.time(), flush=True)

    t0 = time.time()
    nbyte = 0
    kinds = Counter()
    samples = []
    last_meter = 0.0
    while time.time() - t0 < secs:
        r, _, _ = select.select([s], [], [], 0.5)
        now = time.time()
        if r:
            try:
                data, _ = s.recvfrom(65535)
            except OSError:
                continue
            nbyte += len(data)
            head = data[:2].hex()
            kinds[head] += 1
            if len(samples) < 40:
                samples.append((now - t0, len(data), data[:24].hex()))
            # keep the old dialect's meter step alive, in case the camera
            # still wants it before it will stream
            if data[:2] == b"\xc0\x90" and now - last_meter > 0.4:
                ack = p2p_client.make_meter_ack(data)
                if ack:
                    s.sendto(ack, (ip, port))
                    last_meter = now
        el = time.time() - t0
        if el > 3 and int(el) != int(el - 0.5):
            print("  t=%4.1fs  %8d B  %6.1f kbps   %s"
                  % (el, nbyte, nbyte * 8 / el / 1000.0,
                     ", ".join("%s x%d" % kv for kv in kinds.most_common(4))),
                  flush=True)

    print("\n== totals over %.1fs ==" % (time.time() - t0))
    print("  %d B  =  %.1f kbps" % (nbyte, nbyte * 8 / secs / 1000.0))
    for k, v in kinds.most_common():
        print("  prefix %s  x%d" % (k, v))
    print("\n== first datagrams ==")
    for el, n, hx in samples:
        print("  t=%5.2f len=%-5d %s" % (el, n, hx))
    s.close()


if __name__ == "__main__":
    main()
