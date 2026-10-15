#!/usr/bin/env python3
"""Dump the RAW TLV header bytes of every type-4 body, tagged by whether the
decrypted plaintext begins with the ff ff ff 88 sync.

The header-less bodies turn out to be essential H.264 data (feeding them back
to ffmpeg drops decode errors 26 -> 2), so the sync byte is the WRONG way to
split them.  What actually distinguishes a frame-start from a continuation
must be visible in the outer TLV header:

    payload[0]  linktype
    payload[1]  flags
    payload[2:4] u16 LE length
    len(payload)

Usage: python3 -u tlvhdr.py [tid] [secs]
"""
import struct
import sys
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402


class TH(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.rows = []          # (lt, flags, ln, paylen, has_sync, pt_head)

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        self.rows.append((payload[0], payload[1], ln, len(payload),
                          pt[:4] == b"\xff\xff\xff\x88",
                          pt[:8].hex(), len(pt)))


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = TH(ip, got[ip]["p2p_port"], tid, any_calling(tid),
            local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    print("rows: %d" % len(st.rows), flush=True)
    print("\n=== (flags, ln==paylen?, has_sync) ===", flush=True)
    c = Counter((f, "ln==paylen" if ln == pl else "ln%s paylen" % (
        ">" if ln > pl else "<"), s) for _, f, ln, pl, s, _, _ in st.rows)
    for k, n in sorted(c.items(), key=lambda x: -x[1]):
        print("  flags=%-3d %-14s sync=%-5s  %d" % (k[0], k[1], k[2], n), flush=True)

    print("\n=== flags histogram split by sync ===", flush=True)
    cf = Counter((s, f) for _, f, _, _, s, _, _ in st.rows)
    for k, n in sorted(cf.items()):
        print("  sync=%-5s flags=%-3d  %d" % (k[0], k[1], n), flush=True)

    print("\n=== ln vs len(payload) ===", flush=True)
    cl = Counter((s, ln == pl, ln <= pl) for _, _, ln, pl, s, _, _ in st.rows)
    for k, n in sorted(cl.items()):
        print("  sync=%-5s ln==paylen=%-5s ln<=paylen=%-5s  %d"
              % (k[0], k[1], k[2], n), flush=True)

    print("\n=== length fields ===", flush=True)
    for label, sel in (("SYNC", True), ("NO-SYNC", False)):
        rows = [r for r in st.rows if r[4] == sel]
        if not rows:
            continue
        lns = Counter(r[2] for r in rows)
        pls = Counter(r[3] for r in rows)
        print("  %-8s n=%-4d top ln=%s top paylen=%s"
              % (label, len(rows), lns.most_common(5), pls.most_common(5)), flush=True)

    print("\n=== first 24 rows in arrival order ===", flush=True)
    print("  lt flags  ln   paylen sync  pt_head", flush=True)
    for r in st.rows[:24]:
        print("  %-2d %-5d %-4d %-7d %-5s %s" % r[:6], flush=True)

    print("\n=== ...rows 100..124 ===", flush=True)
    for r in st.rows[100:124]:
        print("  %-2d %-5d %-4d %-7d %-5s %s" % r[:6], flush=True)


if __name__ == "__main__":
    main()
