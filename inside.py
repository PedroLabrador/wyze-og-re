#!/usr/bin/env python3
"""Classify EVERY type-4 body by what is actually inside it.

Two facts that break the old model:
  * the AV sync `ff ff ff 88 00 00 01 00` itself CONTAINS `00 00 01`, so the
    old "has an Annex-B start code" test matched the header, not the payload;
  * the sync-carrying bodies' byte histogram is ff:14.5% 7f:11.3% 7e:10.8%
    fe:7.6% -- the mu-law signature, not a H.264 one (H.264 is near-uniform).

So we split each decrypted body on EVERY `ff ff ff 88`, and score each
sub-frame's payload (bytes after the 8-byte AV header) as H.264 or mu-law.

H.264 payload: near-uniform byte histogram (entropy ~7.5) and an Annex-B
               start code within the first few bytes.
mu-law payload: heavily skewed toward ff/7f/7e/fe, mean |diff| low.

Usage: python3 -u inside.py [tid] [secs]
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


def mean_diff(b, n=400):
    if len(b) < 16:
        return 0.0
    m = min(len(b) - 1, n)
    return sum(abs(b[i] - b[i - 1]) for i in range(1, m + 1)) / m


class IN(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.rows = []          # (has_sync_at_0, n_sync, body_len, payload_len,
                                #  ent, mdiff, first_startcode_off, pt_head)

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        n = pt.count(SYNC)
        # payload = everything after the first 8-byte AV header, if present
        pay = pt[8:] if pt[:4] == SYNC else pt
        sc = pay.find(b"\x00\x00\x01")
        self.rows.append((pt[:4] == SYNC, n, len(pt), len(pay),
                          entropy(pay[:2000]), mean_diff(pay), sc, pt[:16].hex()))


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = IN(ip, got[ip]["p2p_port"], tid, any_calling(tid),
            local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    rows = st.rows
    print("bodies=%d" % len(rows), flush=True)

    print("\n=== how many ff ff ff 88 markers per body ===", flush=True)
    for k, v in sorted(Counter(n for _, n, _, _, _, _, _, _ in rows).items()):
        print("  %d sync(s): %d bodies" % (k, v), flush=True)

    print("\n=== sync-at-0  x  payload entropy bucket ===", flush=True)
    c = Counter()
    for h0, n, bl, pl, e, md, sc, _ in rows:
        c[(h0, "ent<6.5 (mu-law-ish)" if e < 6.5 else "ent>=6.5 (h264-ish)")] += 1
    for k, v in sorted(c.items(), key=lambda x: -x[1]):
        print("  sync_at_0=%-5s %-24s %d" % (k[0], k[1], v), flush=True)

    print("\n=== start-code offset in payload (>=0 means real H.264) ===", flush=True)
    c = Counter()
    for h0, n, bl, pl, e, md, sc, _ in rows:
        if sc < 0:
            c[(h0, "none")] += 1
        elif sc == 0:
            c[(h0, "at 0")] += 1
        else:
            c[(h0, "offset %d.." % (sc // 16 * 16))] += 1
    for k, v in sorted(c.items(), key=lambda x: -x[1])[:14]:
        print("  sync_at_0=%-5s %-16s %d" % (k[0], k[1], v), flush=True)

    print("\n=== bytes by class ===", flush=True)
    tot = sum(bl for _, _, bl, _, _, _, _, _ in rows)
    for lbl, pred in (
        ("sync at 0", lambda r: r[0]),
        ("no sync", lambda r: not r[0]),
        ("sync & ent<6.5 (mu-law?)", lambda r: r[0] and r[4] < 6.5),
        ("sync & ent>=6.5 (h264?)", lambda r: r[0] and r[4] >= 6.5),
        ("nosync & ent<6.5", lambda r: not r[0] and r[4] < 6.5),
        ("nosync & ent>=6.5", lambda r: not r[0] and r[4] >= 6.5),
    ):
        g = [r for r in rows if pred(r)]
        print("  %-28s n=%-4d bytes=%-7d (%4.1f%%) mean|diff|=%s"
              % (lbl, len(g), sum(r[2] for r in g),
                 100.0 * sum(r[2] for r in g) / tot,
                 "%.1f" % (sum(r[5] for r in g) / len(g)) if g else "-"), flush=True)

    print("\n=== examples ===", flush=True)
    print("  sync_at_0, low entropy (candidate AUDIO):", flush=True)
    for r in [x for x in rows if x[0] and x[4] < 6.5][:5]:
        print("    len=%-5d ent=%.2f diff=%.1f sc=%-4d head=%s"
              % (r[2], r[4], r[5], r[6], r[7]), flush=True)
    print("  sync_at_0, high entropy (candidate VIDEO):", flush=True)
    for r in [x for x in rows if x[0] and x[4] >= 6.5][:5]:
        print("    len=%-5d ent=%.2f diff=%.1f sc=%-4d head=%s"
              % (r[2], r[4], r[5], r[6], r[7]), flush=True)
    print("  no sync (continuation?):", flush=True)
    for r in [x for x in rows if not x[0]][:5]:
        print("    len=%-5d ent=%.2f diff=%.1f sc=%-4d head=%s"
              % (r[2], r[4], r[5], r[6], r[7]), flush=True)


if __name__ == "__main__":
    main()
