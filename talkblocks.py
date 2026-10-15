#!/usr/bin/env python3
"""Talk frame internals: sub-block structure and true send interval.

The 226-byte frame is 34 header bytes + 6 x 32-byte blocks.  If every block
begins with the same byte the frame is carrying six sub-frames; combined with
the real wire interval (taken from pcap timestamps, not a guess) that fixes the
audio framing we must reproduce.

Usage: python3 talkblocks.py
"""
import struct
import sys
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import pcapparse                                          # noqa: E402
from mtp_frame import unwrap                              # noqa: E402
from listreq import rc5_setup, rc5_decrypt_block          # noqa: E402
from appcalling import mode1, ascii_of                    # noqa: E402

CONV = 0x00F82BBF
PCAP = "/tmp/ctrltalk.pcap"
CAM = "192.168.77.10"
CAM_PORT = 55013


def load(path):
    out = []
    with open(path, "rb") as f:
        while True:
            b = f.read(4)
            if len(b) < 4:
                return out
            out.append(f.read(struct.unpack("<I", b)[0]))


def key_for(conv_hi):
    for d in load("/tmp/applan_a2c.bin"):
        if d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4" and len(d) > 100:
            pt = mode1(d)
            if (struct.unpack_from("<I", pt, 28)[0] | 0x80000000) == conv_hi:
                return pt[120:128]


def frames(key):
    buf = bytearray()
    for d in load("/tmp/applan_a2c.bin"):
        if d[:2] != b"\xc0\x10":
            continue
        u = unwrap(d)
        if not u:
            continue
        s = u[0]
        if len(s) < 24 or (s[4] & 0x0F) != 1:
            continue
        if struct.unpack_from("<I", s, 0)[0] != CONV:
            continue
        ln = struct.unpack_from("<I", s, 20)[0]
        buf += s[24:24 + ln]
    S = rc5_setup(key)
    out, i = [], 0
    while i + 4 <= len(buf):
        ln = struct.unpack_from("<H", buf, i + 2)[0]
        if ln < 4 or i + ln > len(buf):
            break
        b = bytes(buf[i + 4:i + ln])
        d = b"".join(rc5_decrypt_block(S, b[o:o + 8], "little")
                     for o in range(0, len(b) // 8 * 8, 8))
        out.append(d + b[len(b) // 8 * 8:])      # the <8-byte tail is plaintext
        i += ln
    return out


def pcap_records(path):
    """Yield (ts_seconds_float, record_bytes) -- talkblocks needs timestamps."""
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = gh[:4]
        end = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        pcapparse.LINKTYPE[0] = struct.unpack_from(end + "I", gh, 20)[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            sec, usec, incl, _ = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield sec + usec / 1e6, data


def main():
    key = key_for(CONV | 0x80000000)
    fr = frames(key)

    print("sub-block first bytes (blocks at 34+32k, 6 blocks in a 226 B frame):")
    for k in range(6):
        off = 34 + 32 * k
        c = Counter(p[off] for p in fr if len(p) >= off + 1)
        print("  block %d @%-3d %s" % (k, off, c.most_common(4)))

    print("\nlast bytes of the 226 B frames:")
    for off in range(220, 226):
        c = Counter(p[off] for p in fr if len(p) > off)
        print("  [%3d] %s" % (off, c.most_common(4)))

    big = [p for p in fr if len(p) == 226]
    print("\nfull speech frame (the 40th 226 B frame) hex:")
    p = big[40]
    for o in range(0, 226, 16):
        print("  %3d  %-47s |%s|"
              % (o, " ".join("%02x" % x for x in p[o:o + 16]), ascii_of(p[o:o + 16])))
    print("\nfull silence frame hex:")
    p = big[0]
    for o in range(0, 226, 16):
        print("  %3d  %-47s |%s|"
              % (o, " ".join("%02x" % x for x in p[o:o + 16]), ascii_of(p[o:o + 16])))

    # ---- real interval, from pcap timestamps -----------------------------
    print("\n--- wire timing of the app's media datagrams (pcap) ---")
    times = []
    for ts, rec in pcap_records(PCAP):
        et, off = pcapparse.parse_eth(rec)
        if et != 0x0800:
            continue
        ip = pcapparse.parse_ip4(rec, off)
        if not ip or ip["proto"] != 17 or ip["dst"] != CAM:
            continue
        o = ip["off"]
        dport = struct.unpack_from(">H", rec, o + 2)[0]
        if dport != CAM_PORT:
            continue
        ulen = struct.unpack_from(">H", rec, o + 4)[0]
        payload = rec[o + 8:o + 8 + max(0, ulen - 8)]
        u = unwrap(payload)
        if not u:
            continue
        s = u[0]
        if len(s) < 24:
            continue
        if struct.unpack_from("<I", s, 0)[0] != CONV:
            continue
        if (s[4] & 0x0F) != 1:
            continue
        times.append((ts, struct.unpack_from("<I", s, 20)[0]))
    print("  %d media-carrying datagrams captured" % len(times))
    if len(times) > 3:
        gaps = [times[i + 1][0] - times[i][0] for i in range(len(times) - 1)]
        gaps = [g for g in gaps if g > 0]
        if gaps:
            gaps.sort()
            print("  interval ms: min %.2f  p50 %.2f  p90 %.2f  max %.2f"
                  % (gaps[0] * 1000, gaps[len(gaps) // 2] * 1000,
                     gaps[int(len(gaps) * 0.9)] * 1000, gaps[-1] * 1000))
            print("  mean %.2f ms -> %.1f frames/s"
                  % (sum(gaps) / len(gaps) * 1000, 1.0 / (sum(gaps) / len(gaps))))


if __name__ == "__main__":
    main()
