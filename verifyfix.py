#!/usr/bin/env python3
"""End-to-end check of the patched p2p_client._on_tlv.

Runs ONE pump loop for N seconds (exactly like CameraStreamThread in
server.py) with the real CameraStream code path, then scores both feeds:

  video  -> ffprobe frame count + ffmpeg decode errors
  audio  -> bytes/s, frame count, μ-law->PCM sanity (zeros, RMS, lag-1 corr)

Before the fix this reported (0 audio frames) and 20+ decode errors.

Usage: python3 -u verifyfix.py [tid] [secs]
"""
import audioop                              # noqa: E402  (deprecated but fine)
import collections
import struct
import subprocess
import sys
import time

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402


class V(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.aframes = 0
        self.bodies = collections.Counter()
        self.body_bytes = 0

    def _on_tlv(self, payload):
        if payload and payload[0] == 4:
            self.bodies["t4"] += 1
        p2p_client.CameraStream._on_tlv(self, payload)

    def _take_audio_frames(self, pt):
        before = len(self._abuf)
        p2p_client.CameraStream._take_audio_frames(self, pt)
        if len(self._abuf) > before:
            self.aframes += 1


def score_video(path):
    p = subprocess.run(["ffprobe", "-v", "error", "-f", "h264", "-i", path,
                        "-count_frames", "-show_entries",
                        "stream=width,height,nb_read_frames", "-of", "csv=p=0"],
                       capture_output=True, text=True)
    q = subprocess.run(["ffmpeg", "-v", "error", "-f", "h264", "-i", path,
                        "-f", "null", "-"], capture_output=True, text=True)
    errs = [l for l in q.stderr.splitlines() if l.strip()]
    return " ".join(p.stdout.split()), len(errs), errs[:6]


def score_audio(path, secs):
    d = open(path, "rb").read()
    if len(d) < 320:
        return "empty (%d B)" % len(d), []
    pcm = audioop.ulaw2lin(d, 2)
    n = len(pcm) // 2
    samples = [struct.unpack_from("<h", pcm, 2 * i)[0] for i in range(0, n, 7)]
    zero = sum(1 for s in samples if s == 0) / len(samples)
    full = sum(1 for s in samples if abs(s) >= 32124) / len(samples)
    rms = audioop.rms(pcm, 2)
    lag1 = (sum(samples[i] * samples[i - 1] for i in range(1, len(samples)))
            / max(1, sum(s * s for s in samples[:-1])))
    lines = [
        "bytes=%d  frames=%d (%.1f/s)  expected_%.0fs=%.0f B  ratio=%.0f%%"
        % (len(d), len(d) // 320, len(d) // 320 / secs, secs, secs * 16000,
           100.0 * len(d) / (secs * 16000)),
        "frac_zero=%.3f  frac_fullscale=%.3f  rms=%d  lag1_corr=%.3f"
        % (zero, full, rms, lag1),
        "duration_at_16kHz=%.2fs (capture %.1fs)"
        % (len(d) / 16000.0, secs),
    ]
    # per-second RMS: a flat line of ~0 means the camera is transmitting
    # silence, varying values mean we are reading a real signal.
    per = []
    step = 16000
    for k in range(0, len(pcm), step):
        per.append(audioop.rms(pcm[k:k + step], 2))
    lines.append("per-second rms: %s" % per)
    c = collections.Counter(d)
    lines.append("payload top: " + " ".join(
        "%02x:%.0f%%" % (v, 100.0 * k / len(d)) for v, k in c.most_common(6)))
    return "\n  ".join(lines), []


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 12.0

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    st = V(ip, got[ip]["p2p_port"], tid, any_calling(tid),
           local_port=0, timeout=secs + 15)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    t0 = time.time()
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    actual = time.time() - t0
    st.close()

    vid = bytes(st._buf)
    aud = bytes(st._abuf)
    open("/tmp/vf.h264", "wb").write(vid)
    open("/tmp/vf.ulaw", "wb").write(aud)

    print("capture %.1fs  linktype-4 bodies=%d  video=%d B  audio=%d B"
          % (actual, st.bodies.get("t4", 0), len(vid), len(aud)), flush=True)
    print("audio AV frames extracted: %d (%.1f/s)" % (st.aframes, st.aframes / actual),
          flush=True)

    fr, er, errs = score_video("/tmp/vf.h264")
    print("\nVIDEO  %s\n  decode errors=%d" % (fr, er), flush=True)
    for e in errs:
        print("    " + e, flush=True)

    print("\nAUDIO\n  " + score_audio("/tmp/vf.ulaw", actual)[0], flush=True)


if __name__ == "__main__":
    main()
