#!/usr/bin/env python3
"""Validate the STRUCTURAL audio classifier against the entropy one.

Audio AV-frame layout (constant offsets across 304/304 audio bodies):

    [0:8]   ff ff ff 88 00 00 01 00
    [8:20]  00 x 12
    [20:24] u32 timestamp (low 3 bytes vary, top byte 0xab)
    [24:28] 87 00 00 00
    [28:30] 40 01   = 320 samples per frame
    [30:350] 320 bytes of mu-law  -> 20 ms at 16 kHz

Classifying on that instead of "payload entropy < 6.5" cannot mistake a quiet
scene's video for audio.  This probe builds both candidate feeds and scores
them with ffmpeg.

Usage: python3 -u valstruct.py [tid] [secs]
"""
import math
import struct
import subprocess
import sys
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402

SYNC = b"\xff\xff\xff\x88"
AUD_HDR = SYNC + b"\x00\x00\x01\x00"          # [0:8]
AUD_TAIL = b"\x87\x00\x00\x00\x40\x01"        # [24:30]


def is_audio(pt):
    return (len(pt) >= 350 and pt[:8] == AUD_HDR
            and pt[8:20] == b"\x00" * 12
            and pt[24:30] == AUD_TAIL)


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


class V(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.rows = []          # (pt, is_struct_audio, ent_audio)

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        if pt[:4] == SYNC:
            ent_a = entropy(pt[8:2008]) < 6.5
        else:
            ent_a = False
        self.rows.append((pt, is_audio(pt), ent_a))


def score(path):
    p = subprocess.run(["ffprobe", "-v", "error", "-f", "h264", "-i", path,
                        "-count_frames", "-show_entries",
                        "stream=width,height,nb_read_frames", "-of", "csv=p=0"],
                       capture_output=True, text=True)
    frames = " ".join(p.stdout.split())
    q = subprocess.run(["ffmpeg", "-v", "error", "-f", "h264", "-i", path,
                        "-f", "null", "-"], capture_output=True, text=True)
    return frames, len([l for l in q.stderr.splitlines() if l.strip()])


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = V(ip, got[ip]["p2p_port"], tid, any_calling(tid),
           local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    rows = st.rows
    ns = sum(1 for _, s, _ in rows if s)
    ne = sum(1 for _, _, e in rows if e)
    both = sum(1 for _, s, e in rows if s and e)
    print("bodies=%d  struct_audio=%d  entropy_audio=%d  both=%d"
          % (len(rows), ns, ne, both), flush=True)
    print("struct_audio rate = %.1f/s (50 expected for 20 ms frames)"
          % (ns / secs), flush=True)

    sizes = Counter(len(p) for p, s, _ in rows if s)
    print("struct_audio sizes: %s" % sizes.most_common(6), flush=True)

    # does the structural test ever eat a video frame?
    lost = [(len(p), entropy(p[8:2008]))
            for p, s, _ in rows if s and entropy(p[8:2008]) >= 6.5]
    print("struct_audio but high entropy (would-be video): %d %s"
          % (len(lost), lost[:4]), flush=True)

    variants = {
        "ALL": b"".join(p for p, _, _ in rows),
        "VID_struct": b"".join(p for p, s, _ in rows if not s),
        "VID_entropy": b"".join(p for p, _, e in rows if not e),
    }
    print("\n%-12s %-22s %s" % ("variant", "ffprobe", "errors"), flush=True)
    for name, data in variants.items():
        path = "/tmp/val_%s.h264" % name
        open(path, "wb").write(data)
        fr, er = score(path)
        print("%-12s %-22s %d" % (name, fr, er), flush=True)

    # audio payload sizes as the product would slice them
    aud = b"".join(p[30:] for p, s, _ in rows if s)
    open("/tmp/val_audio.ulaw", "wb").write(aud)
    print("\naudio payload %d B = %.0f B/s (16000 expected at 16 kHz)"
          % (len(aud), len(aud) / secs), flush=True)


if __name__ == "__main__":
    main()
