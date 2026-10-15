#!/usr/bin/env python3
"""Which header-less bodies are video continuations and which are audio?

Captures ONE session, then builds several candidate H.264 feeds and lets
ffmpeg score each one (decode errors at -v error, frames read).

  A  sync bodies only               = what the product does NOW
  B  everything in arrival order    = what the product did BEFORE audio
  C  sync + header-less size 1008
  D  sync + header-less size <1008
  E  sync + header-less with low |diff|   (the "it's H.264" subset)
  F  sync + header-less with high |diff|

Usage: python3 -u fragsplit.py [tid] [secs]
"""
import struct
import subprocess
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402


def diff_of(b, n=400):
    if len(b) < 32:
        return 0.0
    m = min(len(b) - 1, n)
    return sum(abs(b[i] - b[i - 1]) for i in range(1, m + 1)) / m


class FS(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.seq = []              # (has_sync, size, diff, plaintext)

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        self.seq.append((pt[:4] == b"\xff\xff\xff\x88", len(pt), diff_of(pt), pt))


def score(path):
    """Return (frames, error_lines) for an Annex-B file."""
    p = subprocess.run(["ffprobe", "-v", "error", "-f", "h264", "-i", path,
                        "-count_frames", "-show_entries", "stream=nb_read_frames",
                        "-of", "csv=p=0"], capture_output=True, text=True)
    frames = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else "?"
    q = subprocess.run(["ffmpeg", "-v", "error", "-f", "h264", "-i", path,
                        "-f", "null", "-"], capture_output=True, text=True)
    errs = [l for l in q.stderr.splitlines() if l.strip()]
    return frames, len(errs)


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = FS(ip, got[ip]["p2p_port"], tid, any_calling(tid),
            local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    seq = st.seq
    sync = [(s, d, p) for h, s, d, p in seq if h]
    non = [(s, d, p) for h, s, d, p in seq if not h]
    print("sync=%d  header-less=%d" % (len(sync), len(non)), flush=True)

    # classify the header-less bodies
    hi1008 = [x for x in non if x[0] == 1008]
    small = [x for x in non if x[0] < 1008]
    lowd = [x for x in non if x[1] < 60]
    highd = [x for x in non if x[1] >= 60]
    for lbl, g in (("1008", hi1008), ("<1008", small),
                   ("diff<60", lowd), ("diff>=60", highd)):
        if g:
            print("  %-9s n=%-4d bytes=%-7d mean diff=%.1f"
                  % (lbl, len(g), sum(s for s, _, _ in g),
                     sum(d for _, d, _ in g) / len(g)), flush=True)

    variants = {
        "A_sync_only": [p for h, _, _, p in seq if h],
        "B_all": [p for _, _, _, p in seq],
    }
    # C/D/E/F: insert the selected header-less bodies at their arrival slot
    def build(pred):
        return [p for h, _, _, p in seq if h or pred((len(p), diff_of(p), p))]
    variants["C_plus1008"] = build(lambda x: x[0] == 1008)
    variants["D_plussmall"] = build(lambda x: x[0] < 1008)
    variants["E_pluslowdiff"] = build(lambda x: x[1] < 60)
    variants["F_plushidiff"] = build(lambda x: x[1] >= 60)

    print("\n%-16s %8s %8s %8s" % ("variant", "frames", "errors", "KB"), flush=True)
    for name, parts in variants.items():
        path = "/tmp/v_%s.h264" % name
        open(path, "wb").write(b"".join(parts))
        fr, er = score(path)
        print("%-16s %8s %8d %8.0f" % (name, fr, er, len(b"".join(parts)) / 1024),
              flush=True)


if __name__ == "__main__":
    main()
