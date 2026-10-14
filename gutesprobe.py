#!/usr/bin/env python3
"""Enumerate the whole control-plane dialogue of one live session.

Everything our client does today is: CALLING (GUTES 0xa4) -> meter_ack ->
AvStreamCtl over KCP.  Video flows at 640x360.

The app's own session (cap_relay.log) additionally sends GUTES 0xa0, 0xa1,
0xa5, 0xa7, 0xaa, 0xb7, 0xb8, 0xb9 and 0xbc -- types we never emit.  It also
receives things we silently discard.

This probe runs a normal session and accounts for EVERY frame in both
directions, so the missing replies are visible as "camera sent it, we never
answered".  A camera that hands the sub-stream to a client it considers
half-initialised would explain 640x360 vs the app's 1920x1080 (measured at
1487 kbps on the phone vs our 400 kbps).

Usage: python3 -u gutesprobe.py [tid] [seconds]
       Leave >=40s between runs; the camera holds its session slot.
"""
import json
import select
import struct
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
import kcpav                                         # noqa: E402
from analyze_calls import decrypt                    # noqa: E402
from mtp_frame import wrap as mtp_wrap, unwrap as mtp_unwrap   # noqa: E402


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 18.0

    doc = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
    rec = doc["devices"][tid]["frames"]
    calling = bytes.fromhex(rec["calling"] if isinstance(rec["calling"], str)
                            else "".join("%02x" % b for b in rec["calling"]))
    key = decrypt(calling)[120:128]

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("tid %s  camera %s:%s" % (tid, ip, port), flush=True)

    st = p2p_client.CameraStream(ip, port, tid, calling, local_port=0,
                                 timeout=8.0)

    # Record EVERY datagram from the first byte we send.  _pump() only
    # understands C0 90 / C0 10 and silently discards everything else, which
    # is exactly where the camera's GUTES replies to our CALLING live -- so
    # an earlier version of this probe could only ever conclude "the camera
    # sent us nothing", having thrown the handshake away before it looked.
    st._send(st.calling)
    hs = []
    end = time.time() + 2.0
    while time.time() < end:
        r, _, _ = select.select([st.sock], [], [],
                                max(0.0, end - time.time()))
        if not r:
            continue
        try:
            data, _ = st.sock.recvfrom(65535)
        except OSError:
            continue
        hs.append(data)
        if data[:2] == b"\xc0\x90":
            a = p2p_client.make_meter_ack(data)
            if a:
                st._send(a)

    print("\n== every datagram the camera sent after our CALLING ==")
    for d in hs:
        if d[0] in (0x7E, 0x7F) and len(d) >= 4:
            print("   prefix 0x%02x  [1]=0x%02x  len=%-5d %s"
                  % (d[0], d[1], len(d), d[:24].hex()))
        else:
            print("   %-6s len=%-5d %s"
                  % (d[:2].hex(), len(d), d.hex()))
    print("   (%d datagrams)" % len(hs), flush=True)

    lo, hi = st.conv & 0x7FFFFFFF, st.conv | 0x80000000
    st.kcp_lo = kcpav.KCP(lo, mtu=p2p_client.MTU)
    st.kcp_hi = kcpav.KCP(hi, mtu=p2p_client.MTU)
    for kc in (st.kcp_lo, st.kcp_hi):
        kc.push(kcpav.avstreamctl())
        for pkt in kc.take_packets():
            st._send(mtp_wrap(pkt, 0))
    st._started = True

    rx_gutes = Counter()
    rx_gutes_head = defaultdict(list)
    rx_mtp = Counter()
    rx_kcp_lt = Counter()
    rx_other = Counter()
    n_av = n_nal = 0
    hdr = None

    end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([st.sock], [], [], 0.25)
        if not r:
            for kc in (st.kcp_lo, st.kcp_hi):
                for pkt in kc.take_packets():
                    st._send(mtp_wrap(pkt, 0))
            continue
        try:
            data, _ = st.sock.recvfrom(65535)
        except OSError:
            continue

        b0 = data[0]
        if b0 in (0x7E, 0x7F) and len(data) >= 4:
            t = data[1]
            rx_gutes[t] += 1
            if len(rx_gutes_head[t]) < 1:
                rx_gutes_head[t].append(data[:48].hex())
            continue
        if data[:2] == b"\xc0\x90":
            rr = mtp_unwrap(data)
            inner = rr[0] if rr else b""
            ityp = inner[1] if len(inner) > 1 else -1
            rx_mtp[ityp] += 1
            a = p2p_client.make_meter_ack(data)
            if a:
                st._send(a)
            continue
        if data[:2] != b"\xc0\x10":
            rx_other[data[:2].hex()] += 1
            continue
        rr = mtp_unwrap(data)
        if not rr or not rr[3]:
            continue
        for kc in (st.kcp_lo, st.kcp_hi):
            kc.input(rr[0])
            for payload, sn in kc.take_received():
                rx_kcp_lt[payload[0]] += 1
                if payload[0] == 4:
                    ln = struct.unpack_from("<H", payload, 2)[0]
                    dec = p2p_client.rc5_decrypt_stream(key, payload[4:ln])
                    n_av += 1
                    if (len(dec) >= 28 and dec[0:4] == b"\xff\xff\xff\x88"
                            and dec[5] == 1):
                        hdr = (struct.unpack_from("<I", dec, 20)[0],
                               struct.unpack_from("<I", dec, 24)[0], dec[19])
                    n = dec.find(b"\x00\x00\x01")
                    while n >= 0:
                        n_nal += 1
                        n = dec.find(b"\x00\x00\x01", n + 3)
            for pkt in kc.take_packets():
                st._send(mtp_wrap(pkt, 0))
    st.close()

    print("\n== GUTES frames the CAMERA sent us (0x7e/0x7f) ==")
    print("   %-6s %-7s %s" % ("type", "count", "first 24 B"))
    for t in sorted(rx_gutes):
        print("   0x%02x  %-7d %s" % (t, rx_gutes[t],
                                      rx_gutes_head[t][0][:48]))
    print("   types: %s" % ", ".join("0x%02x" % t for t in sorted(rx_gutes)))

    print("\n== MTP control (C0 90) inner types from the camera ==")
    for t in sorted(rx_mtp):
        print("   inner type %d  x%d" % (t, rx_mtp[t]))

    print("\n== KCP payload link types from the camera ==")
    for t in sorted(rx_kcp_lt):
        name = {2: "user-data", 3: "AvStreamCtl", 4: "AV data"}.get(t, "?")
        print("   linktype %d (%s)  x%d" % (t, name, rx_kcp_lt[t]))

    if rx_other:
        print("\n== other datagrams ==")
        for h, c in sorted(rx_other.items()):
            print("   %s  x%d" % (h, c))

    print("\n== app's own GUTES types (cap_relay.log) vs ours ==")
    app_types = [0xa0, 0xa1, 0xa4, 0xa5, 0xa7, 0xaa, 0xb7, 0xb8, 0xb9, 0xbc]
    for t in app_types:
        print("   app sends 0x%02x ; camera sent it to us: %s"
              % (t, "YES x%d" % rx_gutes[t] if t in rx_gutes else "no"))

    print("\nav frames=%d  nals=%d  header=%s" % (n_av, n_nal, hdr))


if __name__ == "__main__":
    main()
