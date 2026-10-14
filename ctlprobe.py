#!/usr/bin/env python3
"""Is the resolution decided by the AvStreamCtl we send?

defprobe.py proved the app's changeDefinition(2) frame (inner-user-data CMD 5,
17-byte ff ff ff 88 / type 2 TLV) does NOT change the camera's resolution in
any of 6 plausible KCP framings -- and it is harmless in all of them.  That
matches iotv2.log, where the APP'S OWN changeDefinition timed out
(`changeDefinition onError definition:0; errorCode:22001; errorMsg:time out`)
yet iv_recv_avheader still reported 1920x1080.  Conclusion: the resolution is
decided when the AV stream is *started*, not afterwards.

The only thing our client authors itself is the 76-byte AvStreamCtl
(iv_init_frm_AvStreamCtl @ 0x53274):

    memset(buf, 0, 0x4c)
    buf[0]      = 3                     link type
    buf[4:8]    = ctx->0x164            session id
    buf[8:12]   = action                1=start 2=alt 6=stop
    buf[0x10:14]= ctx->0xac             <-- we send 0
    buf[0x14:18]= ctx->0xb0             <-- we send 0
    buf[0x18:38]= 32 B copied from ctx+0x1a4   <-- we send 32 zero bytes
    buf[62:64]  = u16 ctx->0x160        <-- we send 0
    (action==1 sets buf[1] |= 2)

We fill ac / b0 / the 32-B blob / w160 with zeros.  The camera still streams
(640x360), so it is answering the blank request with the lowest profile.

This probe captures the CAMERA'S OWN AvStreamCtl reply, hexdumps it, then
echoes it back verbatim and field-by-field, watching the AV header after each.

Usage: python3 -u ctlprobe.py [tid] [observe_seconds]
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


def hexdump(tag, b):
    print("  %s (%d B)" % (tag, len(b)))
    for i in range(0, len(b), 16):
        print("    %02x:" % i, " ".join("%02x" % c for c in b[i:i + 16]))


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    obs = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0

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

    ours = kcpav.avstreamctl()
    state = {"hdr": None, "n": 0, "nals": 0, "ctl": []}

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
                    t = payload[0]
                    ln = struct.unpack_from("<H", payload, 2)[0]
                    body = payload[4:ln]
                    if t == 3:
                        state["ctl"].append(payload)
                    elif t == 4:
                        state["n"] += 1
                        dec = p2p_client.rc5_decrypt_stream(key, body)
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
    print("\nbaseline hdr=%s avframes=%d nals=%d ctlframes=%d"
          % (state["hdr"], state["n"], state["nals"], len(state["ctl"])),
          flush=True)
    hexdump("WHAT WE SENT (avstreamctl)", ours)
    for i, c in enumerate(state["ctl"]):
        hexdump("CAMERA REPLY #%d" % (i + 1), c)
    json.dump({"tid": tid,
               "ours": ours.hex(),
               "camera_ctl": [c.hex() for c in state["ctl"]]},
              open("/tmp/avctl_frames.json", "w"))
    print("  (saved to /tmp/avctl_frames.json)", flush=True)

    if not state["ctl"]:
        print("\nno AvStreamCtl reply captured; nothing to echo")
        st.close()
        return

    rep = state["ctl"][0]
    b = bytearray(rep)
    variants = [("echo camera reply verbatim", bytes(b))]
    b2 = bytearray(rep)
    b2[8:12] = struct.pack("<I", 1)
    b2[0x0c] = 1
    b2[1] |= 2
    variants.append(("camera reply w/ action=1 (start)", bytes(b2)))

    mine = bytearray(kcpav.avstreamctl())
    mine[0x18:0x38] = rep[0x18:0x38]
    variants.append(("ours w/ camera's 32-B blob", bytes(mine)))

    mine = bytearray(kcpav.avstreamctl())
    mine[0x10:0x14] = rep[0x10:0x14]
    mine[0x14:0x18] = rep[0x14:0x18]
    mine[62:64] = rep[62:64]
    variants.append(("ours w/ camera's ac/b0/w160", bytes(mine)))

    for label, frame in variants:
        n0, nals0 = state["n"], state["nals"]
        st.kcp_hi.push(frame)
        for pkt in st.kcp_hi.take_packets():
            st._send(mtp_wrap(pkt, 0))
        pump(obs)
        flag = ""
        if state["hdr"] and state["hdr"][0] >= 1280:
            flag = "   <<<< RESOLUTION CHANGED"
        print("  %-34s -> hdr=%-16s +av=%-4d +nals=%-5d%s"
              % (label, str(state["hdr"]), state["n"] - n0,
                 state["nals"] - nals0, flag), flush=True)

    st.close()
    print("\nfinal hdr=%s" % (state["hdr"],))
    if state["hdr"] and state["hdr"][0] >= 1280:
        print("  *** SUCCESS ***")


if __name__ == "__main__":
    main()
