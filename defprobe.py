#!/usr/bin/env python3
"""Ask the camera for 1920x1080 the way the app does: changeDefinition(2).

Ground truth from the decompiled 2.50.7 SDK
(com/tencentcs/iotvideo/iotvideoplayer/IoTVideoPlayer.smali):

    changeDefinition(B def, ...)                       # def is 0 / 1 / 2
        sendInnerUserData((byte)5, new byte[]{def}, …) # inner-user-data CMD 5

    IoTVideoPlayer$28.subscribe():
        seq  = ByteUtils.lowBit32(System.currentTimeMillis())
        data = addHeader((byte)0, (byte)5, seq, payload)   # 8-B header

    addHeader(BBBJ[B):                                   # IoTVideoPlayer:1102
        buf = new byte[8 + len(payload)]
        buf[0] = arg0                       # 0
        buf[1] = cmd                        # 5  = changeDefinition
        buf[2] = third & 0xff               # 0
        buf[3] = 0                          # untouched
        buf[4..8] = seq as u32 LITTLE-ENDIAN
        buf[8..] = payload                  # [0x02] for HD

    IoTVideoPlayerImpl::sendUserData(uint8_t*,int,bool)  @ 0xfa349 (Thumb)
        hdr = sequence ? 0x1c : 8
        buf[0..4] = ff ff ff 88 00
        buf[5]    = sequence ? 3 : 2        # AV link type
        *(u16*)(buf+6) = len
        memcpy(buf+hdr, data, len)
        sequence ? iv_send_data_link_chn(...) : iv_send_user_data_link_chn(...)

        iv_send_user_data_link_chn -> giot_eif_send_user_data
                                    -> iv_ringbuf_write(ctx->0x4c0, buf, len)

So the changeDefinition(2) TLV is 17 bytes:

    ff ff ff 88 00 02 09 00 | 00 05 00 00 <seq:u32LE> 02

How that TLV is re-framed for KCP is the one thing static analysis did not
pin down (iv_ringbuf_write hands it to a drainer we did not follow), so this
probe tries every plausible framing in ONE session and watches the camera's
own AV header -- the free readout, decoded from the first bytes of a
decrypted type-4 body:

    body[0:4]   ff ff ff 88      body[19] = fps
    body[5]     1 (AV-header TLV)  body[20:24] = VideoWidth   (u32 LE)
    body[20:24] VideoWidth        body[24:28] = VideoHeight   (u32 LE)

If any framing makes width/height come back 1920x1080, that framing IS the
app's definition-change command and the quality gap is closed.

Usage:  python3 -u defprobe.py <tid> [observe_seconds_per_variant]
        (run discovery first; leave >=40s between runs -- the camera holds
        its session slot after a successful stream)
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
from listreq import rc5_setup, rc5_encrypt_block     # noqa: E402
from mtp_frame import wrap as mtp_wrap, unwrap as mtp_unwrap   # noqa: E402


def rc5_encrypt_stream(key, data):
    """Inverse of p2p_client.rc5_decrypt_stream (RC5-ECB, 8-B blocks, LE)."""
    st = rc5_setup(key)
    out = bytearray()
    n = len(data) - (len(data) % 8)
    for i in range(0, n, 8):
        out += rc5_encrypt_block(st, bytes(data[i:i + 8]), "little")
    out += data[n:]
    return bytes(out)


def hd_payload(defn=2):
    """The 9-byte inner-user-data payload addHeader() produces for CMD 5."""
    seq = int(time.time() * 1000) & 0xFFFFFFFF
    return (bytes([0x00, 0x05, 0x00, 0x00])
            + struct.pack("<I", seq)
            + bytes([defn]))


def av_tlv(defn=2):
    """The 17-byte AV-link frame sendUserData() hands to the ring buffer."""
    p = hd_payload(defn)
    return b"\xff\xff\xff\x88\x00\x02" + struct.pack("<H", len(p)) + p


def read_header(body):
    """Return (width, height, fps) if `body` is an AV-header TLV, else None."""
    if len(body) >= 28 and body[0:4] == b"\xff\xff\xff\x88" and body[5] == 1:
        return (struct.unpack_from("<I", body, 20)[0],
                struct.unpack_from("<I", body, 24)[0],
                body[19])
    return None


def nal_count(buf):
    n, i = 0, buf.find(b"\x00\x00\x01")
    while i >= 0:
        n += 1
        i = buf.find(b"\x00\x00\x01", i + 3)
    return n


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    obs = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0

    doc = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
    rec = doc["devices"][tid]["frames"]
    calling = bytes.fromhex(rec["calling"] if isinstance(rec["calling"], str)
                            else "".join("%02x" % b for b in rec["calling"]))
    key = decrypt(calling)[120:128]          # AV key lives in the RC5 region
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
    print("streaming on lo=0x%08x hi=0x%08x" % (lo, hi), flush=True)

    tlv = av_tlv(2)
    enc = rc5_encrypt_stream(key, tlv)
    raw = hd_payload(2)                      # no AV-link wrapper at all
    ctl = tlv                                # wrapper, plaintext (type-3 style)

    # (label, kcp, linktype, body)
    variants = [
        ("lo  linktype2 plaintext inner-user-data", st.kcp_lo, 2, raw),
        ("lo  linktype2 plaintext wrapped TLV",    st.kcp_lo, 2, ctl),
        ("lo  linktype2 RC5-wrapped TLV",          st.kcp_lo, 2, enc),
        ("lo  linktype4 RC5-wrapped TLV",          st.kcp_lo, 4, enc),
        ("hi  linktype3 plaintext wrapped TLV",    st.kcp_hi, 3, ctl),
        ("hi  linktype2 plaintext inner-user-data", st.kcp_hi, 2, raw),
    ]

    state = {"hdr": None, "n": 0, "nals": 0, "ctl": 0}

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
                        state["ctl"] += 1
                    elif t == 4:
                        state["n"] += 1
                        dec = p2p_client.rc5_decrypt_stream(key, body)
                        h = read_header(dec)
                        if h:
                            state["hdr"] = h
                        state["nals"] += nal_count(dec)
                for pkt in kc.take_packets():
                    st._send(mtp_wrap(pkt, 0))

    pump(5.0)
    print("\nbaseline: hdr=%s  avframes=%d  nals=%d  ctl=%d"
          % (state["hdr"], state["n"], state["nals"], state["ctl"]), flush=True)
    base_n, base_nals = state["n"], state["nals"]
    verdict = []

    for label, kc, lt, body in variants:
        n0, nals0 = state["n"], state["nals"]
        frame = bytes([lt, 0]) + struct.pack("<H", 4 + len(body)) + body
        kc.push(frame)
        for pkt in kc.take_packets():
            st._send(mtp_wrap(pkt, 0))
        pump(obs)
        new = state["n"] - n0
        alive = state["nals"] - nals0
        flag = ""
        if state["hdr"] and state["hdr"][0] >= 1280:
            flag = "   <<<< RESOLUTION CHANGED"
        print("  %-42s -> hdr=%-16s +av=%-4d +nals=%-5d%s"
              % (label, str(state["hdr"]), new, alive, flag), flush=True)
        verdict.append((label, state["hdr"], new, alive))

    st.close()

    print("\n== summary ==")
    print("  baseline hdr: %s" % (state["hdr"],))
    for label, h, new, alive in verdict:
        print("  %-42s hdr=%-16s" % (label, str(h)))
    print("\n  avframes before=%d after=%d  nals before=%d after=%d"
          % (base_n, state["n"], base_nals, state["nals"]))
    if state["hdr"] and state["hdr"][0] >= 1280:
        print("\n  *** SUCCESS: camera switched resolution ***")
    else:
        print("\n  no framing changed the header (still %s)" % (state["hdr"],))


if __name__ == "__main__":
    main()
