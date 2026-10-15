#!/usr/bin/env python3
"""Are the 350-byte 'audio' bodies really audio, or are they video too?

valstruct.py showed that deleting them from the feed turns
(196 frames, 0 errors) into (124 frames, 164 errors) -- so either they carry
video, or the feed needs them for some framing reason.

Tests:
  1. start-code count in each subset
  2. byte histogram of the 320-byte payload alone
  3. feed ONLY the audio-classified bodies to ffmpeg
  4. feed ONLY the video-classified bodies, but re-inserting nothing

Usage: python3 -u whatsin.py [tid] [secs]
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
AUD_HDR = SYNC + b"\x00\x00\x01\x00"
AUD_TAIL = b"\x87\x00\x00\x00\x40\x01"


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


class W(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.rows = []

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        self.rows.append((pt, is_audio(pt)))


def score(path):
    p = subprocess.run(["ffprobe", "-v", "error", "-f", "h264", "-i", path,
                        "-count_frames", "-show_entries",
                        "stream=width,height,nb_read_frames", "-of", "csv=p=0"],
                       capture_output=True, text=True)
    q = subprocess.run(["ffmpeg", "-v", "error", "-f", "h264", "-i", path,
                        "-f", "null", "-"], capture_output=True, text=True)
    return " ".join(p.stdout.split()), len([l for l in q.stderr.splitlines() if l.strip()])


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = W(ip, got[ip]["p2p_port"], tid, any_calling(tid),
           local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    aud = [p for p, a in st.rows if a]
    vid = [p for p, a in st.rows if not a]
    print("audio bodies=%d (%d B)   other bodies=%d (%d B)"
          % (len(aud), sum(map(len, aud)), len(vid), sum(map(len, vid))), flush=True)

    print("\n=== 1. Annex-B start codes (excluding the AV header's own 00 00 01) ===",
          flush=True)
    for lbl, grp in (("audio bodies", aud), ("other bodies", vid)):
        raw = b"".join(grp)
        # skip the first 8 bytes of each body when counting
        stripped = b"".join(b[8:] for b in grp)
        print("  %-13s full=%-5d  after[8:]=%d"
              % (lbl, raw.count(b"\x00\x00\x01"), stripped.count(b"\x00\x00\x01")),
              flush=True)

    print("\n=== 2. byte histogram of the 320-byte payload (audio bodies) ===",
          flush=True)
    pay = b"".join(p[30:] for p in aud)
    c = Counter(pay)
    print("  %s" % " ".join("%02x:%.1f%%" % (v, 100.0 * k / len(pay))
                            for v, k in c.most_common(10)), flush=True)
    print("  entropy=%.2f  mean|diff|=%.1f"
          % (entropy(pay),
             sum(abs(pay[i] - pay[i - 1]) for i in range(1, min(len(pay), 40000)))
             / min(len(pay) - 1, 39999)), flush=True)

    print("\n=== 3/4. ffmpeg on each subset ===", flush=True)
    for name, data in (("ONLY_audio", b"".join(aud)),
                       ("ONLY_other", b"".join(vid)),
                       ("ALL", b"".join(p for p, _ in st.rows))):
        path = "/tmp/wh_%s.h264" % name
        open(path, "wb").write(data)
        fr, er = score(path)
        print("  %-11s %-20s errors=%d  (%d B)" % (name, fr, er, len(data)), flush=True)

    # is the audio payload periodic / does it look like a codec stream?
    print("\n=== 5. audio payload: first frame vs second frame ===", flush=True)
    for p in aud[:3]:
        print("  hdr=%s payload[:32]=%s"
              % (p[:30].hex(), p[30:62].hex()), flush=True)


if __name__ == "__main__":
    main()
