#!/usr/bin/env python3
"""Replay the app's own post-CALLING dialogue and watch the AV header.

gutesprobe.py showed the camera sends us NOTHING but meter_req + KCP during a
live session, while cap_relay.log shows the app sends a whole dialogue we
never emit:

    app -> camera   0xa6 (62 B) x2, 0xa7 (32 B), 0xaa (32 B), 0xa0 (48 B)
    camera -> app   0xa6 (32 B) x2, 0xa7 (1132 B), 0xaa (923 B)

0xa7 / 0xaa carry ~1 KB of what look like capability blobs.  A camera that
only upgrades a client to the 1080p encoder after that exchange would explain
our 640x360 @ 400 kbps versus the app's 1920x1080 @ 1487 kbps (measured).

The captured bytes embed the relay session's connection id, so an exact match
is not guaranteed -- but "any CALLING works for any camera" already showed the
camera is lax about session ids, so verbatim replay is worth one session.

Usage: python3 -u replay_app.py [tid] [observe_seconds]
       Leave >=40s between runs; the camera holds its session slot.
"""
import json
import re
import select
import struct
import sys
import time
from collections import OrderedDict

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
import kcpav                                         # noqa: E402
from analyze_calls import decrypt                    # noqa: E402
from mtp_frame import wrap as mtp_wrap, unwrap as mtp_unwrap   # noqa: E402

LOG = "/tmp/cap_relay.log"


def parse_relay(path=LOG):
    """Return {direction: [frame_bytes,...]} from the relay capture."""
    out = {"->": [], "<-": []}
    cur = None
    for line in open(path, errors="replace"):
        m = re.match(r"\s*\[\s*[\d.]+s\]\s+(T->R|T<-R)\s+\S+\s+len=(\d+)", line)
        if m:
            cur = (out["->" if m.group(1) == "T->R" else "<-"], int(m.group(2)))
            continue
        if line.startswith("  HEX") and cur:
            blob, reclen = cur
            h = line[5:].strip()
            cur = None
            if not h:
                continue
            data = bytes.fromhex(h)
            i = 0
            while i + 4 <= len(data):
                if data[i] not in (0x7E, 0x7F):
                    break
                ln = struct.unpack_from("<H", data, i + 2)[0]
                if ln < 4 or i + ln > len(data):
                    ln = len(data) - i          # header length disagrees: take rest
                blob.append(data[i:i + ln])
                i += ln
    return out


def read_header(body):
    if len(body) >= 28 and body[0:4] == b"\xff\xff\xff\x88" and body[5] == 1:
        return (struct.unpack_from("<I", body, 20)[0],
                struct.unpack_from("<I", body, 24)[0], body[19])
    return None


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    obs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0

    rx = parse_relay()
    bytype = OrderedDict()
    for f in rx["->"]:
        bytype.setdefault(f[1], []).append(f)
    print("== app -> camera frames captured in the relay ==")
    for t, fs in bytype.items():
        print("   type 0x%02x  x%d  sizes %s"
              % (t, len(fs), sorted(set(len(x) for x in fs))))
    replay = [f for t, fs in bytype.items() if t != 0xa4 for f in fs]
    print("   (will replay %d frames, CALLING excluded)" % len(replay),
          flush=True)

    doc = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
    rec = doc["devices"][tid]["frames"]
    calling = bytes.fromhex(rec["calling"] if isinstance(rec["calling"], str)
                            else "".join("%02x" % b for b in rec["calling"]))
    key = decrypt(calling)[120:128]

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("\ntid %s  camera %s:%s" % (tid, ip, port), flush=True)

    st = p2p_client.CameraStream(ip, port, tid, calling, local_port=0,
                                 timeout=8.0)
    st._send(st.calling)
    st._pump(1.5, [])
    lo, hi = st.conv & 0x7FFFFFFF, st.conv | 0x80000000
    st.kcp_lo = kcpav.KCP(lo, mtu=p2p_client.MTU)
    st.kcp_hi = kcpav.KCP(hi, mtu=p2p_client.MTU)
    for kc in (st.kcp_lo, st.kcp_hi):
        kc.push(kcpav.avstreamctl())
        for pkt in kc.take_packets():
            st._send(mtp_wrap(pkt, 0))
    st._started = True

    state = {"hdr": None, "n": 0, "nals": 0, "gutes": set()}

    def pump(seconds):
        end = time.time() + seconds
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
            if data[0] in (0x7E, 0x7F) and len(data) >= 4:
                state["gutes"].add(data[1])
                continue
            if data[:2] == b"\xc0\x90":
                a = p2p_client.make_meter_ack(data)
                if a:
                    st._send(a)
                continue
            if data[:2] != b"\xc0\x10":
                continue
            rr = mtp_unwrap(data)
            if not rr or not rr[3]:
                continue
            for kc in (st.kcp_lo, st.kcp_hi):
                kc.input(rr[0])
                for payload, sn in kc.take_received():
                    if payload[0] != 4:
                        continue
                    ln = struct.unpack_from("<H", payload, 2)[0]
                    dec = p2p_client.rc5_decrypt_stream(key, payload[4:ln])
                    state["n"] += 1
                    h = read_header(dec)
                    if h:
                        state["hdr"] = h
                    n = dec.find(b"\x00\x00\x01")
                    while n >= 0:
                        state["nals"] += 1
                        n = dec.find(b"\x00\x00\x01", n + 3)
                for pkt in kc.take_packets():
                    st._send(mtp_wrap(pkt, 0))

    pump(5.0)
    print("\nbaseline hdr=%s avframes=%d nals=%d gutes_from_cam=%s"
          % (state["hdr"], state["n"], state["nals"],
             sorted(hex(t) for t in state["gutes"])), flush=True)

    n0 = state["n"]
    for f in replay:
        st._send(f)
    print("replayed %d app frames (%s)"
          % (len(replay), ", ".join("0x%02x" % f[1] for f in replay)),
          flush=True)
    pump(obs)
    print("after replay: hdr=%s avframes=%d(+%d) nals=%d gutes_from_cam=%s"
          % (state["hdr"], state["n"], state["n"] - n0, state["nals"],
             sorted(hex(t) for t in state["gutes"])), flush=True)
    st.close()

    if state["hdr"] and state["hdr"][0] >= 1280:
        print("\n  *** SUCCESS: replaying the app's dialogue switches the "
              "camera to 1080p ***")
    else:
        print("\n  no resolution change (still %s)" % (state["hdr"],))


if __name__ == "__main__":
    main()
