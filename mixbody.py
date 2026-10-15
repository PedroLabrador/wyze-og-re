#!/usr/bin/env python3
"""Dump the bodies that are structurally audio AND contain a real H.264 slice.

whatsin.py found 21 type-1 slice NALs hiding inside bodies the 30-byte-header
test calls audio.  Without knowing where they sit we cannot slice the frame
safely, so this captures fresh and prints full hex for:
  * bodies matching the audio header that ALSO carry a type-1 NAL
  * plain audio bodies for comparison
  * a video body for comparison

Usage: python3 -u mixbody.py [tid] [secs]
"""
import re
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402

SYNC = b"\xff\xff\xff\x88"
AUD_HDR = SYNC + b"\x00\x00\x01\x00"
AUD_TAIL = b"\x87\x00\x00\x00\x40\x01"


def is_audio(pt):
    return (len(pt) >= 350 and pt[:8] == AUD_HDR
            and pt[8:20] == b"\x00" * 12
            and pt[24:30] == AUD_TAIL)


def slice_offsets(pt, start=8):
    """Offsets of type-1 (or type-5) NAL start codes inside pt, ignoring the
    AV header's own `00 00 01` at offset 4..6."""
    out = []
    for m in re.finditer(b"\x00\x00\x01", pt[start:]):
        p = start + m.end()
        if p >= len(pt):
            continue
        if pt[p] & 0x1F in (1, 5):
            out.append(start + m.start())
    return out


class M(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.rows = []          # (pt, is_audio, slice_offsets)

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        self.rows.append((pt, is_audio(pt), slice_offsets(pt)))


def dump(label, pt, offs, n=0):
    print("  %s len=%d slices@%s" % (label, len(pt), offs), flush=True)
    for k in range(0, min(len(pt), 350 * (n + 1)), 16):
        mark = " <<<" if any(k <= o < k + 16 for o in offs) else ""
        print("    %4d %s%s" % (k, pt[k:k + 16].hex(), mark), flush=True)
    if offs:
        for o in offs:
            print("    slice@%d ctx=%s" % (o, pt[max(0, o - 20):o + 24].hex()),
                  flush=True)


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = M(ip, got[ip]["p2p_port"], tid, any_calling(tid),
           local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    aud = [(p, o) for p, a, o in st.rows if a]
    non = [(p, o) for p, a, o in st.rows if not a]
    print("bodies=%d  audio-classified=%d  other=%d  (%.0fs)"
          % (len(st.rows), len(aud), len(non), secs), flush=True)

    mixed = [(p, o) for p, o in aud if o]
    print("audio-classified WITH a real slice: %d" % len(mixed), flush=True)
    print("other-classified with a real slice: %d"
          % sum(1 for p, o in non if o), flush=True)

    sizes = {}
    for p, a, o in st.rows:
        sizes[(a, len(p))] = sizes.get((a, len(p)), 0) + 1
    print("size histogram (is_audio, len): %s"
          % sorted(sizes.items(), key=lambda x: -x[1])[:8], flush=True)

    print("\n=== MIXED bodies (audio header + real slice) ===", flush=True)
    for p, o in mixed[:3]:
        dump("MIXED", p, o)
    print("\n=== plain audio bodies ===", flush=True)
    for p, o in [x for x in aud if not x[1]][:2]:
        dump("AUDIO", p, o)
    print("\n=== other-classified body ===", flush=True)
    for p, o in non[:1]:
        dump("OTHER", p, o)

    # Where do the slices sit relative to the 30-byte audio header?
    print("\n=== slice offsets inside mixed bodies ===", flush=True)
    for p, o in mixed[:10]:
        print("  len=%-5d slice_at=%s  delta_from_30=%s"
              % (len(p), o, [x - 30 for x in o]), flush=True)

    open("/tmp/mixed.bin", "wb").write(b"".join(p for p, _ in mixed))
    print("\nwrote /tmp/mixed.bin (%d B)"
          % sum(len(p) for p, _ in mixed), flush=True)


if __name__ == "__main__":
    main()
