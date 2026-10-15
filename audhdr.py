#!/usr/bin/env python3
"""What exactly does an audio AV-frame look like?

classify.py proved the split works (video: 0 decode errors; audio: mu-law with
66% digital-zero) but the audio still has ~3.7% of samples pinned at -32124,
which smells like we are feeding a per-frame sub-header in as samples.

Structure hypothesised from the descriptor body:

    ff ff ff 88 00 00 01 00   8 B  AV header
    00 x 12                   12 B
    tt tt tt tt 87 00 00 00 40 01   10 B   (320 = samples per frame)
    <320 bytes of mu-law>     350 B total

This dumps every audio-classified body's first 40 bytes and its length so the
header can be nailed down exactly.

Usage: python3 -u audhdr.py [tid] [secs]
"""
import math
import struct
import sys
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402

SYNC = b"\xff\xff\xff\x88"


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


class A(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.audio = []          # (len, pt)
        self.video = []
        self.other = []

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        if pt[:4] != SYNC:
            self.other.append((len(pt), pt))
            return
        pay = pt[8:]
        if entropy(pay[:2000]) < 6.5:
            self.audio.append((len(pt), pt))
        else:
            self.video.append((len(pt), pt))


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = A(ip, got[ip]["p2p_port"], tid, any_calling(tid),
           local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    print("audio=%d video=%d continuation=%d  (%.1fs)"
          % (len(st.audio), len(st.video), len(st.other), secs), flush=True)
    print("audio rate = %.1f frames/s" % (len(st.audio) / secs), flush=True)

    print("\n=== audio body size histogram ===", flush=True)
    for n, c in Counter(n for n, _ in st.audio).most_common(8):
        print("  %d B x %d" % (n, c), flush=True)

    print("\n=== first 40 bytes of each of the first 8 audio bodies ===", flush=True)
    for n, pt in st.audio[:8]:
        print("  len=%-4d %s" % (n, pt[:40].hex()), flush=True)

    print("\n=== which byte offsets are CONSTANT across all audio bodies? ===", flush=True)
    maxlen = max((n for n, _ in st.audio), default=0)
    same = []
    for off in range(min(maxlen, 48)):
        vals = {pt[off] for _, pt in st.audio if off < len(pt)}
        if len(vals) == 1:
            same.append((off, next(iter(vals))))
    print("  constant offsets: %s"
          % (" ".join("%d=%02x" % (o, v) for o, v in same) or "none"), flush=True)

    print("\n=== per-offset value histograms for offsets 0..31 ===", flush=True)
    for off in range(32):
        c = Counter(pt[off] for _, pt in st.audio if off < len(pt))
        top = c.most_common(3)
        print("  [%2d] %s" % (off, " ".join("%02x:%d" % (v, k) for v, k in top)), flush=True)

    # Now decode assuming header is the first H bytes of each body
    import audioop, array
    for hdr in (8, 20, 30):
        d = b"".join(pt[hdr:] for _, pt in st.audio)
        pcm = audioop.ulaw2lin(d, 2)
        a = array.array("h")
        a.frombytes(pcm)
        nzero = sum(1 for x in a if x == 0) / len(a)
        fullscale = sum(1 for x in a if abs(x) > 31000) / len(a)
        print("\n  header=%-2d bytes=%-7d (%.0f B/s) frac_zero=%.3f frac_fullscale=%.4f"
              % (hdr, len(d), len(d) / secs, nzero, fullscale), flush=True)


if __name__ == "__main__":
    main()
