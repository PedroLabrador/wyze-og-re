#!/usr/bin/env python3
"""Sweep the AvStreamCtl fields that our client fills with zeros.

iv_init_frm_AvStreamCtl (0x53274) builds the only frame our client authors
itself, and three of its fields come straight out of the session ctx:

    buf[0x10:0x14] = ctx->0xac     <-- we send 0
    buf[0x14:0x18] = ctx->0xb0     <-- we send 0
    buf[0x18:0x38] = 32 B from ctx+0x1a4   <-- we send 32 zero bytes
    buf[62:64]     = u16 ctx->0x160 <-- we send 0

ctlprobe.py echoed the CAMERA'S OWN reply back and nothing happened, but the
camera's reply has zeros in all four too -- it copies out of *its* ctx, so that
experiment could never tell us whether the fields matter.  They are the only
client-authored knobs left, so sweep them directly and read the camera's AV
header after each restart.

Ground truth that motivates the values tried here: the app requests its
profile at session start, not afterwards --
    SpUtils.getDefinitionToSp(deviceId)  ->  MonitorPlayer.setDataResource(did, x)
        ->  new PlayerUserData(x)        ->  PlayerUserData.definition = x
        ->  IoTVideoPlayer_SetDataResource -> IoTVideoPlayerImpl->0xc
telemetry on the live app reads `video_definition=2`, and reviseNativeDefinition
only ever writes that same byte, so 0 / 1 / 2 are the profile selectors and
1920x1080 is the target.

Usage: python3 -u sweepprobe.py [tid] [observe_seconds]
       Leave >=40s between runs; the camera holds its session slot.
"""
import json
import select
import struct
import sys
import time

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
import kcpav                                         # noqa: E402
from analyze_calls import decrypt                    # noqa: E402
from mtp_frame import wrap as mtp_wrap, unwrap as mtp_unwrap   # noqa: E402


def read_header(body):
    if len(body) >= 28 and body[0:4] == b"\xff\xff\xff\x88" and body[5] == 1:
        return (struct.unpack_from("<I", body, 20)[0],
                struct.unpack_from("<I", body, 24)[0],
                body[19])
    return None


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    obs = float(sys.argv[2]) if len(sys.argv) > 2 else 4.0

    doc = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
    rec = doc["devices"][tid]["frames"]
    calling = bytes.fromhex(rec["calling"] if isinstance(rec["calling"], str)
                            else "".join("%02x" % b for b in rec["calling"]))
    key = decrypt(calling)[120:128]
    print("tid %s  avkey %s" % (tid, key.hex()), flush=True)

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("camera %s:%s" % (ip, port), flush=True)

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
    print("streaming lo=0x%08x hi=0x%08x" % (lo, hi), flush=True)

    state = {"hdr": None, "n": 0, "nals": 0}

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
    print("\nbaseline hdr=%s avframes=%d nals=%d"
          % (state["hdr"], state["n"], state["nals"]), flush=True)

    # (label, ac@0x10, b0@0x14, w160@62, blob)
    def blob32(w, h):
        return (struct.pack("<II", w, h) * 4)[:32]

    cases = [
        ("ac=1920 b0=1080 w160=20",        1920, 1080, 20, None),
        ("ac=1080 b0=1920 w160=20",        1080, 1920, 20, None),
        ("ac=2 b0=2 w160=2 (definition)",     2,    2,  2, None),
        ("ac=1 b0=1 w160=1",                  1,    1,  1, None),
        ("ac=4000 b0=4000 w160=20 (kbps)", 4000, 4000, 20, None),
        ("w160=20 only",                       0,    0, 20, None),
        ("blob=1920x1080 only",                0,    0,  0, blob32(1920, 1080)),
        ("all: 1920/1080/20 + blob",        1920, 1080, 20, blob32(1920, 1080)),
    ]

    for label, ac, b0, w160, blob in cases:
        n0, nals0 = state["n"], state["nals"]
        h0 = state["hdr"]
        frame = kcpav.avstreamctl(action=kcpav.ACT_START, ac=ac, b0=b0,
                                  w160=w160, blob=blob)
        st.kcp_hi.push(frame)
        for pkt in st.kcp_hi.take_packets():
            st._send(mtp_wrap(pkt, 0))
        pump(obs)
        flag = ""
        if state["hdr"] and state["hdr"][0] >= 1280:
            flag = "   <<<< RESOLUTION CHANGED"
        print("  %-32s -> hdr=%-16s (was %-16s) +av=%-4d +nals=%-5d%s"
              % (label, str(state["hdr"]), str(h0), state["n"] - n0,
                 state["nals"] - nals0, flag), flush=True)

    st.close()
    print("\nfinal hdr=%s" % (state["hdr"],))
    if state["hdr"] and state["hdr"][0] >= 1280:
        print("  *** SUCCESS: a client-authored AvStreamCtl knob sets "
              "resolution ***")


if __name__ == "__main__":
    main()
