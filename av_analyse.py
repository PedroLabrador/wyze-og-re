#!/usr/bin/env python3
"""Analyse a captured AV payload set (from avhdr_probe.py) offline.

    python3 av_analyse.py [dump_index]

Prints, for every captured payload: length, NAL types found in the
plaintext, and the first 32 plaintext bytes.  Payloads that are NOT H.264
are printed in full -- one of those (78 B, seen once) is the candidate for
the camera's AV HEADER, i.e. the record that in the app's logcat looks like

    iv_recv_avheader VideoType:1 VideoWidth:1920 VideoHeight:1080
                      videoFrameRate:20 AudioType:2 ...
"""
import json
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client  # noqa: E402

NAL = {1: "SLICE", 5: "IDR", 6: "SEI", 7: "SPS", 8: "PPS", 9: "AUD"}


def nals(buf):
    out = []
    i = buf.find(b"\x00\x00\x01")
    while i >= 0:
        t = buf[i + 3] & 0x1F if i + 3 < len(buf) else -1
        out.append(t)
        i = buf.find(b"\x00\x00\x01", i + 3)
    return out


def main():
    doc = json.load(open("/tmp/av_payloads.json"))
    key = bytes.fromhex(doc["key"])
    raws = [bytes.fromhex(h) for h in doc["payloads"]]
    print("key %s   %d payloads" % (key.hex(), len(raws)))

    for n, p in enumerate(raws):
        ln = struct.unpack_from("<H", p, 2)[0]
        body = p[4:ln]
        dec = p2p_client.rc5_decrypt_stream(key, body)
        ts = nals(dec)
        labels = [NAL.get(t, "type%d" % t) for t in ts]
        print("[%3d] len=%4d flags=0x%02x  nals=%-18s  head=%s"
              % (n, ln, p[1], ",".join(labels[:6]) or "-",
                 dec[:24].hex()))

    if len(sys.argv) > 1:
        n = int(sys.argv[1])
        p = raws[n]
        ln = struct.unpack_from("<H", p, 2)[0]
        dec = p2p_client.rc5_decrypt_stream(key, p[4:ln])
        print("\n=== payload %d full plaintext ===" % n)
        for i in range(0, len(dec), 16):
            print("  %03x:" % i, " ".join("%02x" % c for c in dec[i:i + 16]))


if __name__ == "__main__":
    main()
