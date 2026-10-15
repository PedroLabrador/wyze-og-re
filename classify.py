#!/usr/bin/env python3
"""Split type-4 bodies into (video, audio) and prove each half is right.

Model now supported by the data:
  * AV frames are wrapped in an 8-byte `ff ff ff 88 ...` header.
  * VIDEO frames: high-entropy payload (CABAC, entropy ~7.7).  A video frame
    bigger than one TLV body is split; only the first chunk carries the sync,
    the rest arrive with NO sync (36.8% of all bytes).
  * AUDIO frames: low-entropy payload (entropy ~1.6, dominated by ff/7f/7e/fe,
    mean |diff| ~26) -- they DO carry the sync.

This writes /tmp/vid.h264 and /tmp/aud.ulaw and scores both.

Usage: python3 -u classify.py [tid] [secs]
"""
import math
import struct
import sys
import wave
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


class C(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.chunks = []         # (is_video, plaintext) in arrival order

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 8:
            return
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        if pt[:4] == SYNC:
            pay = pt[8:]
            # an audio frame's payload is extremely concentrated; video's is not
            is_video = entropy(pay[:2000]) >= 6.5
            self.chunks.append((is_video, pt))            # keep the AV header
        else:
            self.chunks.append((True, pt))                # continuation = video


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = C(ip, got[ip]["p2p_port"], tid, any_calling(tid),
           local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    vid = b"".join(p for v, p in st.chunks if v)
    aud = b"".join(p[8:] for v, p in st.chunks if not v)
    nv = sum(1 for v, _ in st.chunks if v)
    na = len(st.chunks) - nv
    print("chunks: video=%d audio=%d" % (nv, na), flush=True)
    print("video bytes=%d  audio bytes=%d (=%.0f B/s over %.0fs)"
          % (len(aud and vid or vid), len(aud), len(aud) / secs, secs), flush=True)

    open("/tmp/vid.h264", "wb").write(vid)
    open("/tmp/aud.ulaw", "wb").write(aud)
    print("wrote /tmp/vid.h264 (%d B), /tmp/aud.ulaw (%d B)" % (len(vid), len(aud)),
          flush=True)

    # ---- score the video half ----
    import subprocess
    q = subprocess.run(["ffmpeg", "-v", "error", "-f", "h264", "-i", "/tmp/vid.h264",
                        "-f", "null", "-"], capture_output=True, text=True)
    errs = [l for l in q.stderr.splitlines() if l.strip()]
    p = subprocess.run(["ffprobe", "-v", "error", "-f", "h264", "-i", "/tmp/vid.h264",
                        "-count_frames", "-show_entries",
                        "stream=width,height,nb_read_frames", "-of", "csv=p=0"],
                       capture_output=True, text=True)
    print("VIDEO  ffprobe=%s  decode errors=%d" % (p.stdout.strip().replace("\n", " "),
                                                   len(errs)), flush=True)
    for e in errs[:3]:
        print("        %s" % e, flush=True)

    # ---- score the audio half ----
    try:
        import audioop
    except ImportError:
        audioop = None
    if audioop and aud:
        pcm = audioop.ulaw2lin(aud, 2)
        n = len(pcm) // 2
        import array
        a = array.array("h")
        a.frombytes(pcm[:n * 2])
        rms = audioop.rms(pcm, 2)
        peak = max(abs(x) for x in a)
        # lag-1 autocorrelation: real audio >> 0, noise ~0
        num = sum(a[i] * a[i - 1] for i in range(1, min(n, 40000)))
        den = math.sqrt(sum(x * x for x in a[:min(n, 40000)]) *
                        sum(x * x for x in a[1:min(n, 40000) + 1]))
        corr = num / den if den else 0.0
        print("AUDIO  ulaw->pcm: %d samples (%.1fs @16k) rms=%d peak=%d "
              "lag1_corr=%.3f" % (n, n / 16000.0, rms, peak, corr), flush=True)
        # write a wav at a couple of candidate rates for a human to check
        for hz in (8000, 16000):
            w = wave.open("/tmp/aud_%d.wav" % hz, "wb")
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(hz)
            w.writeframes(pcm)
            w.close()
        print("wrote /tmp/aud_8000.wav and /tmp/aud_16000.wav", flush=True)

    # byte histogram of the audio payload
    c = Counter(aud)
    print("audio byte top: %s"
          % " ".join("%02x:%.1f%%" % (v, 100.0 * k / len(aud))
                     for v, k in c.most_common(8)), flush=True)
    print("audio entropy=%.2f bits/byte  mean|diff|=%.1f"
          % (entropy(aud), mean_diff(aud)), flush=True)


if __name__ == "__main__":
    main()
