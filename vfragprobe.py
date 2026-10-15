#!/usr/bin/env python3
"""Video bodies vs header-less bodies: are they the same kind of bytes?

The hypothesis under test: the header-less type-4 bodies are H.264
CONTINUATION FRAGMENTS (a frame split across several TLV bodies, only the
first carrying the ff ff ff 88 sync).  If so their plaintext statistics will
match real video frames, and dropping them truncates frames mid-NAL --
exactly the "unwatchable video" regression.

Usage: python3 -u vfragprobe.py [tid] [secs]
"""
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402


def stats(b):
    if len(b) < 16:
        return (0, 0, 0)
    m = min(len(b) - 1, 400)
    d = sum(abs(b[i] - b[i - 1]) for i in range(1, m + 1)) / m
    hi = sum(1 for x in b if x >= 0x60) / len(b)
    sc = (1 if (b"\x00\x00\x01" in b or b"\x00\x00\x00\x01" in b) else 0)
    return (d, hi, sc)


class VP(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.seq = []                       # (is_video, plaintext) in ARRIVAL order

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        self.seq.append((pt[:4] == b"\xff\xff\xff\x88", pt))


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = VP(ip, got[ip]["p2p_port"], tid, any_calling(tid),
            local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    video = [(len(p), p) for v, p in st.seq if v]
    other = [(len(p), p) for v, p in st.seq if not v]

    print("video (with sync):   %d bodies" % len(video), flush=True)
    print("header-less:         %d bodies" % len(other), flush=True)

    for label, grp in (("VIDEO", video), ("NO-HEADER", other)):
        if not grp:
            continue
        ds = [stats(b) for _, b in grp]
        print("\n=== %s ===" % label, flush=True)
        print("  sizes: %s" % sorted({n for n, _ in grp})[:14], flush=True)
        print("  mean diff      = %.1f  (random 85)" % (sum(d for d, _, _ in ds) / len(ds)),
              flush=True)
        print("  mean hi-frac   = %.3f" % (sum(h for _, h, _ in ds) / len(ds)), flush=True)
        print("  start-code hit = %d/%d" % (sum(s for _, _, s in ds), len(ds)), flush=True)
        print("  diff range     = %.1f .. %.1f"
              % (min(d for d, _, _ in ds), max(d for d, _, _ in ds)), flush=True)

    # The decisive question: what does each candidate feed look like to ffmpeg?
    #   A = sync frames only  (what the product does NOW)
    #   B = everything, in arrival order (what the product did BEFORE audio)
    #   C = everything, but sync frames only written when they carry a start code
    only = b"".join(p for v, p in st.seq if v)
    allb = b"".join(p for v, p in st.seq)
    open("/tmp/sync_only.h264", "wb").write(only)
    open("/tmp/sync_plus_rest.h264", "wb").write(allb)
    print("\nwrote /tmp/sync_only.h264 (%d B) and /tmp/sync_plus_rest.h264 (%d B)"
          % (len(only), len(allb)), flush=True)
    dropped = len(allb) - len(only)
    print("bytes the current header check drops: %d of %d (%.1f%%)"
          % (dropped, len(allb), 100.0 * dropped / max(1, len(allb))), flush=True)

    # how many start codes are in each?
    for f in ("/tmp/sync_only.h264", "/tmp/sync_plus_rest.h264"):
        d = open(f, "rb").read()
        print("  %s: %d Annex-B start codes" % (f, d.count(b"\x00\x00\x01")), flush=True)


if __name__ == "__main__":
    main()
