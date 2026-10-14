#!/usr/bin/env python3
"""Decrypt and dump the FIRST type-0x04 AV payloads of a session.

iv_rcv_tlvfrm (0x628e8) decrypts frame[4:] in 8-byte RC5 blocks; the app then
logs `iv_recv_avheader VideoWidth/Height/videoFrameRate`.  We have always
thrown away frame[0:4] and piped the rest to ffmpeg, so if the camera's AV
header rides in-band as the first AV packet we have been silently feeding it
to ffmpeg as junk (it resyncs past it) AND never reading the parameters.

Prints, for the first N AV payloads, the decrypted bytes in hex + as u32s so a
width/height/fps struct is visible immediately.
"""
import json
import struct
import sys
import time

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client  # noqa: E402
import kcpav        # noqa: E402
from analyze_calls import decrypt  # noqa: E402
from mtp_frame import wrap as mtp_wrap, unwrap as mtp_unwrap  # noqa: E402
import select       # noqa: E402

NPAY = int(sys.argv[2]) if len(sys.argv) > 2 else 60
CONVS = set()          # every conv the camera transmits on, seen this session
PAYCONV = []           # conv each captured payload arrived on


def main():
    doc = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    rec = doc["devices"][tid]["frames"]
    calling = bytes.fromhex(rec["calling"] if isinstance(rec["calling"], str)
                            else "".join("%02x" % b for b in rec["calling"]))
    # NB: the AV key lives in the RC5-encrypted region of the CALLING, so it
    # must be read from the PLAINTEXT (p2p_client does pt = decrypt(calling))
    # -- taking calling[120:128] straight off the wire decrypts to noise.
    key = decrypt(calling)[120:128]
    print("tid %s  avkey %s" % (tid, key.hex()), flush=True)

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("camera %s:%s" % (ip, port), flush=True)

    st = p2p_client.CameraStream(ip, port, tid, calling, local_port=0,
                                 timeout=6.0)
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

    got_ctl = []
    got_av = []
    end = time.time() + 14
    while time.time() < end and len(got_av) < NPAY:
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
        for s in kcpav.parse_all(rr[0]):
            CONVS.add(s["conv"])
        for conv, kc in ((st.kcp_lo.conv, st.kcp_lo),
                         (st.kcp_hi.conv, st.kcp_hi)):
            kc.input(rr[0])
            for payload, sn in kc.take_received():
                t = payload[0]
                if t == 3 and not got_ctl:
                    got_ctl.append(payload)
                elif t == 4 and len(got_av) < NPAY:
                    got_av.append(payload)
                    PAYCONV.append(conv)
            for pkt in kc.take_packets():
                st._send(mtp_wrap(pkt, 0))
    st.close()

    if got_ctl:
        p = got_ctl[0]
        print("\n== camera's AvStreamCtl reply (%d B) ==" % len(p))
        for i in range(0, len(p), 16):
            print("  %02x:" % i, " ".join("%02x" % c for c in p[i:i + 16]))
        if len(p) >= 12:
            print("  action =", struct.unpack_from("<I", p, 8)[0])

    from collections import Counter
    print("\n== convs the camera transmitted on this session ==")
    for c in sorted(CONVS):
        print("   conv 0x%08x   %d AV payloads captured here"
              % (c, sum(1 for x in PAYCONV if x == c)))
    print("   (ours: lo=0x%08x hi=0x%08x)   all seen: %s"
          % (st.kcp_lo.conv, st.kcp_hi.conv, sorted(hex(c) for c in CONVS)))
    if CONVS - {st.kcp_lo.conv, st.kcp_hi.conv}:
        print("   *** camera used a conv we DO NOT handle ***")

    print("\n== first %d AV payloads: length + does the plaintext contain "
          "H.264 start codes? ==" % len(got_av))
    # persist raw payloads so key/structure hypotheses can be tested offline
    # without burning another 40s camera session
    import json as _json
    _json.dump({"tid": tid,
                "key": key.hex(),
                "calling_pt": decrypt(calling).hex(),
                "calling_raw": calling.hex(),
                "payloads": [p.hex() for p in got_av]},
               open("/tmp/av_payloads.json", "w"))
    print("  (raw payloads saved to /tmp/av_payloads.json)")
    odd = []
    for n, p in enumerate(got_av):
        t, flags, ln = p[0], p[1], struct.unpack_from("<H", p, 2)[0]
        body = p[4:ln]
        dec = p2p_client.rc5_decrypt_stream(key, body) if body else b""
        nstart = 0
        i = dec.find(b"\x00\x00\x01")
        while i >= 0:
            nstart += 1
            i = dec.find(b"\x00\x00\x01", i + 3)
        mark = "" if nstart else "   <-- NO NAL START CODES"
        if n == 0 or not nstart or ln < 400:
            print("  av[%3d] len=%4d body=%4d startcodes=%d%s"
                  % (n, ln, len(body), nstart, mark))
        if not nstart:
            odd.append((n, ln, dec))
    print("\n  payloads whose plaintext is NOT H.264: %d"
          % len(odd))
    for n, ln, dec in odd[:4]:
        print("\n  == av[%d] len=%d full plaintext ==" % (n, ln))
        for i in range(0, len(dec), 16):
            print("     %02x:" % i, " ".join("%02x" % c for c in dec[i:i + 16]))
        if len(dec) >= 24:
            u16 = [struct.unpack_from("<H", dec, i)[0]
                   for i in range(0, min(len(dec), 64), 2)]
            u32 = [struct.unpack_from("<I", dec, i)[0]
                   for i in range(0, min(len(dec), 64), 4)]
            print("     u16:", u16)
            print("     u32:", u32)


if __name__ == "__main__":
    main()
