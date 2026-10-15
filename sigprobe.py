#!/usr/bin/env python3
"""Identify the header-less type-4 bodies: audio? second video stream? junk?

Facts so far (vfragprobe):
  * every sync-carrying body IS H.264 (439/439 have an Annex-B start code)
  * the header-less bodies are 39.5% of all media bytes, contribute only
    3 start codes in 150 KB, and their AV-key plaintext looks random
    (mean |diff| 80.8, hi-frac 0.635 == uniform)

So they are neither video fragments nor obviously mu-law.  This probe looks
for container/codec signatures in the plaintext, measures the arrival cadence
(a periodic cadence means a real media stream), and checks whether the
ciphertext is even encrypted under the AV key.

Usage: python3 -u sigprobe.py [tid] [secs]
"""
import struct
import sys
import time
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402

SIGS = {
    "JPEG SOI": b"\xff\xd8\xff",
    "JPEG EOI": b"\xff\xd9",
    "Annex-B 0001": b"\x00\x00\x00\x01",
    "Annex-B 001": b"\x00\x00\x01",
    "AMR magic": b"#!AMR",
    "ADTS AAC": None,               # handled specially
    "ID3": b"ID3",
    "RIFF": b"RIFF",
    "ftyp": b"ftyp",
    "OggS": b"OggS",
    "ac-3 sync": None,
    "NAL HEVC": None,
    "RTP v2": None,
}


class SP(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.events = []                  # (t, is_video, len, plaintext)
        self.lt_hist = Counter()

    def _on_tlv(self, payload):
        if not payload:
            return
        self.lt_hist[payload[0]] += 1
        if payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        self.events.append((time.time(),
                            pt[:4] == b"\xff\xff\xff\x88", len(pt), pt, bytes(body)))


def ent(b):
    """Shannon entropy in bits/byte."""
    if not b:
        return 0.0
    c = Counter(b)
    import math
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = SP(ip, got[ip]["p2p_port"], tid, any_calling(tid),
            local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    print("linktype histogram: %s" % st.lt_hist.most_common(), flush=True)
    vid = [(t, n, p, r) for t, v, n, p, r in st.events if v]
    non = [(t, n, p, r) for t, v, n, p, r in st.events if not v]
    print("sync bodies: %d   header-less: %d   window %.1fs"
          % (len(vid), len(non), secs), flush=True)
    if not non:
        return

    print("\n=== size histogram (header-less) ===", flush=True)
    for n, c in Counter(n for _, n, _, _ in non).most_common(12):
        print("  %-6d %d" % (n, c), flush=True)

    print("\n=== signature scan over ALL header-less plaintext ===", flush=True)
    blob = b"".join(p for _, _, p, _ in non)
    for name, sig in SIGS.items():
        if sig is None:
            continue
        n = blob.count(sig)
        if n:
            print("  %-14s %d" % (name, n), flush=True)
    # ADTS: 0xfff with layer bits 00
    adts = sum(1 for i in range(len(blob) - 1)
               if blob[i] == 0xFF and (blob[i + 1] & 0xF6) == 0xF0)
    print("  ADTS-like fff_       %d" % adts, flush=True)
    # RTP v2: 10xxxxxx
    rtp = sum(1 for b in blob[:20000] if (b & 0xC0) == 0x80)
    print("  bytes with v2 bits   %d/20000 (random=12500)" % rtp, flush=True)

    print("\n=== entropy ===", flush=True)
    print("  header-less plaintext %.3f bits/byte" % ent(blob[:60000]), flush=True)
    vblob = b"".join(p for _, _, p, _ in vid)
    print("  video plaintext       %.3f bits/byte" % ent(vblob[:60000]), flush=True)
    print("  header-less CIPHER    %.3f bits/byte"
          % ent(b"".join(r for _, _, _, r in non)[:60000]), flush=True)

    print("\n=== byte histogram of header-less plaintext (top 10) ===", flush=True)
    c = Counter(blob[:60000])
    tot = sum(c.values())
    print("  " + "  ".join("%02x:%.2f%%" % (v, 100.0 * n / tot)
                           for v, n in c.most_common(10)), flush=True)
    print("  (uniform would be 0.39%% per value; min=%d max=%d)"
          % (min(c.values()), max(c.values())), flush=True)

    print("\n=== arrival cadence ===", flush=True)
    for label, grp in (("video", vid), ("header-less", non)):
        ts = [t for t, _, _, _ in grp]
        if len(ts) < 3:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        gaps.sort()
        print("  %-12s n=%-5d rate=%5.1f/s  gap med=%.1fms p10=%.1f p90=%.1f"
              % (label, len(grp), len(grp) / secs, 1000 * gaps[len(gaps) // 2],
                 1000 * gaps[len(gaps) // 10], 1000 * gaps[9 * len(gaps) // 10]),
              flush=True)

    # Does the header-less stream have a fixed period independent of video?
    # Bucket by 100 ms and see if the pattern is regular.
    print("\n=== per-100ms bucket counts (header-less) ===", flush=True)
    t0 = non[0][0]
    buckets = Counter(int((t - t0) * 10) for t, _, _, _ in non)
    print("  " + " ".join(str(buckets.get(i, 0)) for i in range(40)), flush=True)

    print("\n=== mean |diff| of each class ===", flush=True)
    for label, grp in (("video", vid), ("header-less", non)):
        ds = []
        for _, _, p, _ in grp:
            if len(p) > 32:
                m = min(len(p) - 1, 400)
                ds.append(sum(abs(p[i] - p[i - 1]) for i in range(1, m + 1)) / m)
        print("  %-12s %.1f" % (label, sum(ds) / len(ds)), flush=True)

    open("/tmp/headerless.bin", "wb").write(blob)
    print("\nwrote /tmp/headerless.bin (%d B)" % len(blob), flush=True)


if __name__ == "__main__":
    main()
