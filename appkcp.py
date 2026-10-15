#!/usr/bin/env python3
"""Dump the app's KCP TLV stream from the PCAPdroid LAN capture.

The app<->camera dialogue is c010 (MTP) carrying raw ikcp segments.  Pushed
segments concatenate into a TLV stream: [0]=linktype [1]=? [2:4]=u16LE len.
Our client only ever sends/receives linktype 3 (AvStreamCtl) and 4 (media), so
anything else here is something we have never emitted.

Usage: python3 appkcp.py [a2c|c2a]
"""
import struct
import sys
from collections import Counter, OrderedDict

sys.path.insert(0, "~/Downloads/wyze-re")
from mtp_frame import unwrap as mtp_unwrap                 # noqa: E402
import p2p_client                                          # noqa: E402


def load(path):
    out = []
    with open(path, "rb") as f:
        while True:
            b = f.read(4)
            if len(b) < 4:
                return out
            out.append(f.read(struct.unpack("<I", b)[0]))


def pushed(dgrams):
    """Concatenate the data of ikcp PUSH segments, in arrival order."""
    buf = bytearray()
    cmdhist = Counter()
    for d in dgrams:
        if d[:2] != b"\xc0\x10":
            continue
        u = mtp_unwrap(d)
        if not u:
            continue
        seg = u[0]
        if len(seg) < 24:
            continue
        cmd = seg[4]
        cmdhist["%02x" % cmd] += 1
        # this KCP dialect uses 0x51/0x52 where ikcp uses 0x81/0x82
        if (cmd & 0x0F) != 1:                      # not a PUSH
            continue
        ln = struct.unpack_from("<I", seg, 20)[0]
        buf += seg[24:24 + ln]
    return bytes(buf), cmdhist


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "a2c"
    dgrams = load("/tmp/applan_%s.bin" % which)
    stream, cmdhist = pushed(dgrams)
    print("%s: %d datagrams, pushed stream %d B" % (which, len(dgrams), len(stream)))
    print("  ikcp cmd histogram: %s" % cmdhist.most_common())

    tlvs = []
    i = 0
    while i + 4 <= len(stream):
        lt = stream[i]
        ln = struct.unpack_from("<H", stream, i + 2)[0]
        if ln < 4 or i + ln > len(stream):
            tlvs.append((lt, None, stream[i:i + 24]))
            break
        tlvs.append((lt, stream[i + 4:i + ln], None))
        i += ln

    hist = Counter(lt for lt, _, _ in tlvs)
    print("  TLVs: %d, linktype histogram %s"
          % (len(tlvs), sorted(hist.items())))

    seen = OrderedDict()
    for lt, body, raw in tlvs:
        if lt not in seen:
            seen[lt] = (body, raw, tlvs.index((lt, body, raw)))
    for lt, (body, raw, n) in seen.items():
        print("\n=== linktype %d (first at TLV #%d) ===" % (lt, n))
        if raw is not None:
            print("  short/truncated: %s" % raw.hex())
            continue
        print("  body %d B: %s" % (len(body), body.hex()))

    # every distinct body of the less common types
    for lt in hist:
        if lt == 4:
            continue
        uniq = OrderedDict()
        for l2, body, raw in tlvs:
            if l2 != lt or body is None:
                continue
            uniq.setdefault(body.hex(), 0)
            uniq[body.hex()] += 1
        print("\n--- linktype %d: %d distinct bodies ---" % (lt, len(uniq)))
        for hx, cnt in list(uniq.items())[:12]:
            print("  x%-3d %s" % (cnt, hx[:160]))


if __name__ == "__main__":
    main()
