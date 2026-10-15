#!/usr/bin/env python3
"""Dump the plaintext of one sync body and one header-less body, plus the
byte histogram of each, so we can see what the two classes really are."""
import struct
import sys
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402


class D(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.sync = []
        self.nosync = []

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        (self.sync if pt[:4] == b"\xff\xff\xff\x88" else self.nosync).append(
            (bytes(body), pt))


def hist(b, label):
    c = Counter(b)
    n = len(b)
    print("  %s len=%d entropy-ish top: %s"
          % (label, n, " ".join("%02x:%.1f%%" % (v, 100.0 * k / n)
                                for v, k in c.most_common(8))), flush=True)
    print("     zeros=%.1f%%  >=0x80=%.1f%%  mean|diff|=%.1f"
          % (100.0 * c.get(0, 0) / n, 100.0 * sum(k for v, k in c.items() if v >= 0x80) / n,
             sum(abs(b[i] - b[i - 1]) for i in range(1, len(b))) / max(1, len(b) - 1)),
          flush=True)


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 6.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = D(ip, got[ip]["p2p_port"], tid, any_calling(tid),
           local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    print("sync bodies: %d   header-less: %d" % (len(st.sync), len(st.nosync)), flush=True)

    print("\n=== sync body plaintext (first one, 354 B) ===", flush=True)
    for raw, pt in st.sync[:1]:
        print("  cipher[0:32] %s" % raw[:32].hex(), flush=True)
        print("  plain [0:96] %s" % pt[:96].hex(), flush=True)
        print("  plain [96:192] %s" % pt[96:192].hex(), flush=True)
        hist(pt, "SYNC")

    print("\n=== header-less bodies (first 4) ===", flush=True)
    for raw, pt in st.nosync[:4]:
        print("  len=%d cipher[0:32] %s" % (len(pt), raw[:32].hex()), flush=True)
        print("             plain [0:96] %s" % pt[:96].hex(), flush=True)
        hist(pt, "NOSYNC")

    # Aggregate histograms
    print("\n=== aggregate ===", flush=True)
    for label, grp in (("SYNC", st.sync), ("NOSYNC", st.nosync)):
        if grp:
            blob = b"".join(p for _, p in grp)
            hist(blob, label)

    # raw (undecrypted) comparison
    print("\n=== header-less RAW ciphertext (undecrypted) ===", flush=True)
    blob = b"".join(r for r, _ in st.nosync)
    hist(blob, "RAW")
    blob2 = b"".join(r for r, _ in st.sync)
    hist(blob2, "RAWSYNC")


if __name__ == "__main__":
    main()
