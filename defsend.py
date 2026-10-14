#!/usr/bin/env python3
"""Ask the camera for a higher resolution using the SDK's own definition frame.

WHAT THIS IS BASED ON
---------------------
IoTVideoPlayerImpl::sendUserData (libiotvideo 0xfa348) builds an AV-link
user-data frame:

    ff ff ff 88 00 <type> <u16LE len> <payload>          type 2 -> 8 B header
    ff ff ff 88 00 03 <u16LE len> <20 B seq/timestamps>  type 3 -> 28 B header

and hands it to iv_send_data_link_chn.  The definition request is one of
these: the SDK's changeDefinition path builds the 9-byte payload

    00 05 00 00 <seq:u32LE> <definition>

and GwDefinitionLogEnum gives the definition values:

    2 = DEF_SD   3 = DEF_HD   4 = DEF_2K   (0,1 = the two HD-ish presets)

Our client has NEVER sent one of these frames -- it only sends AvStreamCtl
(linktype 3) -- which would explain 640x360 forever.  The camera answers a
definition change by restarting its encoder and emitting a fresh AV header,
so we watch for a second `ff ff ff 88` header with new width/height.

Variants swept in ONE session (the camera holds one slot while streaming):
linktype 3 vs 4 (plaintext vs RC5 with the AV key), AV type 2 vs 3, and the
definition values 3 (HD), 4 (2K), 1 (SD) and 2 (SD control).

Usage: python3 -u defsend.py [tid] [seconds]
"""
import struct
import sys
import time

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from listreq import rc5_setup, rc5_encrypt_block     # noqa: E402
from mtp_frame import wrap as mtp_wrap               # noqa: E402


def rc5_encrypt_stream(key, data):
    st = rc5_setup(key)
    out = bytearray()
    n = len(data) - (len(data) % 8)
    for i in range(0, n, 8):
        out += rc5_encrypt_block(st, bytes(data[i:i + 8]), "little")
    out += data[n:]
    return bytes(out)


def avlink_body(avtype, payload, with_seq=False):
    """ff ff ff 88 00 <avtype> <u16LE len> <payload>."""
    hdr = bytearray(b"\xff\xff\xff\x88\x00")
    hdr.append(3 if with_seq else 2)
    if with_seq:
        hdr += b"\x00" * 20                     # seq + timestamps, zeroed
    hdr[6:8] = struct.pack("<H", len(payload))
    return bytes(hdr[:8] if not with_seq else hdr[:28]) + payload


def tlv(linktype, body, key):
    """KCP TLV: [linktype][0][u16LE total] <body, RC5 for linktype 4>."""
    data = rc5_encrypt_stream(key, body) if linktype == 4 else body
    return bytes([linktype, 0]) + struct.pack("<H", 4 + len(data)) + data


class Probe(p2p_client.CameraStream):
    def __init__(self, *a, **k):
        p2p_client.CameraStream.__init__(self, *a, **k)
        self.headers = []
        self.tlv_counts = {}
        self.raw_seen = []

    def _on_tlv(self, payload):
        self.tlv_counts[payload[0] if payload else -1] = \
            self.tlv_counts.get(payload[0] if payload else -1, 0) + 1
        if len(payload) >= 4 and payload[0] == 4:
            ln = struct.unpack_from("<H", payload, 2)[0]
            body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
            if len(body) >= 32:
                # RC5 is 8-byte-blocked: decrypt at least 32 B or the height
                # u32 at [24:28] stays ciphertext.
                pt = p2p_client.rc5_decrypt_stream(self.key, body[:32])
                if len(self.raw_seen) < 3:
                    self.raw_seen.append((len(body), pt[:28].hex()))
                if pt[:4] == b"\xff\xff\xff\x88":
                    w = struct.unpack_from("<I", pt, 20)[0]
                    h = struct.unpack_from("<I", pt, 24)[0]
                    if 0 < w < 4000 and 0 < h < 3000:
                        rec = (w, h, pt[5], pt[19])
                        if not self.headers or self.headers[-1] != rec:
                            self.headers.append(rec)
        p2p_client.CameraStream._on_tlv(self, payload)


def load_calling(tid):
    """The captured 2.50.7 CALLING for this camera (wire/p2p_frames.json)."""
    import json
    doc = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
    rec = doc["devices"][tid]["frames"]
    c = rec["calling"]
    return bytes.fromhex(c if isinstance(c, str) else "".join("%02x" % b for b in c))


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 45.0

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("tid %s  camera %s:%s" % (tid, ip, port), flush=True)

    st = Probe(ip, port, tid, load_calling(tid), local_port=0,
               timeout=secs)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi

    def pump(n):
        for _ in range(int(n / 0.5)):
            st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])

    pump(6.0)
    print("headers: %s  tlv: %s  buf=%d B" % (st.headers or "none",
                                              st.tlv_counts, len(st._buf)),
          flush=True)
    for n, hx in st.raw_seen:
        print("   first bodies: len=%d  %s" % (n, hx), flush=True)
    if not st.headers:
        print("no AV header -- camera did not stream; aborting")
        return

    seq = 0
    variants = []
    for value in (3, 4, 1, 2):                      # HD, 2K, SD, SD-control
        for linktype in (4, 3):
            for with_seq in (False, True):
                variants.append((value, linktype, with_seq))

    for value, linktype, with_seq in variants:
        payload = b"\x00\x05\x00\x00" + struct.pack("<I", seq) + bytes([value])
        seq += 1
        body = avlink_body(2 if not with_seq else 3, payload, with_seq)
        frame = tlv(linktype, body, st.key)
        for kc in (lo, hi):
            for _ in range(3):                      # retransmit
                kc.push(frame)
        for kc in (lo, hi):
            for pkt in kc.take_packets():
                st._send(mtp_wrap(pkt, 0))
        before = list(st.headers)
        pump(3.0)
        print("sent definition=%d linktype=%d avtype=%s  headers=%s%s"
              % (value, linktype, 3 if with_seq else 2, st.headers,
                 "   <-- CHANGED" if st.headers != before else ""),
              flush=True)

    pump(4.0)
    print("\n-- now try the same frames immediately BEFORE re-requesting the "
          "stream --", flush=True)
    for value in (3, 4, 2):
        payload = b"\x00\x05\x00\x00" + struct.pack("<I", seq) + bytes([value])
        seq += 1
        for linktype in (4, 3):
            frame = tlv(linktype, avlink_body(2, payload), st.key)
            for kc in (lo, hi):
                for _ in range(3):
                    kc.push(frame)
        for kc in (lo, hi):
            for pkt in kc.take_packets():
                st._send(mtp_wrap(pkt, 0))
        pump(0.8)
        before = list(st.headers)
        for kc in (lo, hi):
            kc.push(p2p_client.build_avstreamctl())
        for kc in (lo, hi):
            for pkt in kc.take_packets():
                st._send(mtp_wrap(pkt, 0))
        pump(5.0)
        print("definition=%d then AvStreamCtl -> headers=%s%s"
              % (value, st.headers,
                 "   <-- CHANGED" if st.headers != before else ""), flush=True)

    pump(4.0)
    print("\nfinal headers: %s" % (st.headers,), flush=True)
    st.close()


if __name__ == "__main__":
    main()
