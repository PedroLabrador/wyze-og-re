#!/usr/bin/env python3
"""Offline: does the app's captured talk audio run at 1x or 2x slow?

If the app fed 16 kHz samples to an 8 kHz AMR-NB encoder, the declared
timeline would be 2x the wall clock: 6 frames (120 ms declared) would have to
leave every ~60 ms to keep up.  If the app fed 8 kHz samples, declared == wall.

Reads the raw pcap directly because pcapparse.read_pcap throws timestamps away.
"""
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
from mtp_frame import unwrap                      # noqa: E402
from listreq import rc5_setup, rc5_decrypt_block  # noqa: E402
from appcalling import mode1                      # noqa: E402

TALK_CONV = 0x00F82BBF
PKT_BYTES = 226
FRAME_BYTES = 32


def read_pcap_ts(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = gh[:4]
        end = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
               b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}[magic]
        linktype = struct.unpack_from(end + "I", gh, 20)[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            ts, tus, incl, _ = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield ts + tus / 1e6, linktype, data


def udp_payload(linktype, data):
    off = 0
    if linktype == 1:
        if len(data) < 14:
            return None
        et = struct.unpack_from(">H", data, 12)[0]
        if et != 0x0800:
            return None
        off = 14
    if len(data) < off + 20:
        return None
    ihl = (data[off] & 0x0F) * 4
    if data[off + 9] != 17:
        return None
    o = off + ihl
    if len(data) < o + 8:
        return None
    ulen = struct.unpack_from(">H", data, o + 4)[0]
    return data[o + 8:o + 8 + max(0, ulen - 8)]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ctrltalk.pcap"
    key = None
    for _, lt, data in read_pcap_ts(path):
        d = udp_payload(lt, data)
        if not d or len(d) < 100:
            continue
        if d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4":
            pt = mode1(d)
            if struct.unpack_from("<I", pt, 28)[0] == TALK_CONV:
                key = pt[120:128]
                break
    if key is None:
        raise SystemExit("no CALLING for conv %08x in %s" % (TALK_CONV, path))
    print("AV key: %s" % key.hex())
    S = rc5_setup(key)

    hits = []
    for ts, lt, data in read_pcap_ts(path):
        d = udp_payload(lt, data)
        if not d or d[:2] != b"\xc0\x10":
            continue
        u = unwrap(d)
        if not u:
            continue
        s = u[0]
        if len(s) < 24 or (s[4] & 0x0F) != 1:
            continue                      # 1 = from the client (talk direction)
        if struct.unpack_from("<I", s, 0)[0] != TALK_CONV:
            continue
        ln = struct.unpack_from("<I", s, 20)[0]
        buf = s[24:24 + ln]
        i = 0
        while i + 4 <= len(buf):
            tlv = struct.unpack_from("<H", buf, i + 2)[0]
            if tlv < 4 or i + tlv > len(buf):
                break
            b = bytes(buf[i + 4:i + tlv])
            p = b"".join(rc5_decrypt_block(S, b[o:o + 8], "little")
                         for o in range(0, len(b) // 8 * 8, 8)) \
                + b[len(b) // 8 * 8:]
            if len(p) == PKT_BYTES:
                cnt = struct.unpack_from("<I", p, 20)[0]
                tocs = [p[34 + k * FRAME_BYTES] for k in range(6)]
                nz = sum(1 for k in range(6)
                         if any(p[35 + k * FRAME_BYTES:34 + (k + 1) * FRAME_BYTES]))
                hits.append((ts, cnt, tocs, nz))
            i += tlv

    if not hits:
        raise SystemExit("no talk media frames found")
    span = hits[-1][0] - hits[0][0]
    declared = len(hits) * 6 * 0.02
    print("talk packets: %d   wall span: %.2f s   declared audio: %.2f s"
          % (len(hits), span, declared))
    print("ratio declared/wall: %.3f   (1.0 = natural, 2.0 = content is 2x slow)"
          % (declared / span))
    dts = [hits[i + 1][0] - hits[i][0] for i in range(len(hits) - 1)]
    dts.sort()
    print("inter-packet gap: p50 %.3f s  p90 %.3f s  max %.3f s"
          % (dts[len(dts) // 2], dts[int(len(dts) * 0.9)], dts[-1]))
    cnts = [h[1] for h in hits]
    steps = sorted(set((cnts[i + 1] - cnts[i]) & 0xFFFFFFFF
                       for i in range(len(cnts) - 1)))
    print("counter step between packets: %s" % steps[:8])
    print("ToC octets seen: %s" % sorted(set(t for h in hits for t in h[2])))
    print("frames with a non-zero payload: %d of %d"
          % (sum(h[3] for h in hits), len(hits) * 6))


if __name__ == "__main__":
    main()
