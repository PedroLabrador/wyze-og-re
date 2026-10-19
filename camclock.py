#!/usr/bin/env python3
"""Does the CAMERA deliver in real time, or is the delay ours?

Every audio AV frame carries, at offset 20, a u32 microsecond timestamp that
is the camera's own capture clock (it advances exactly 0x4e20 = 20000 us per
320-sample frame).  So for each frame we have:

    wall_recv = wall_capture + transit
    cam_ts    = cam_capture + clock_offset

=>  wall_recv - cam_ts = (transit + a constant we cannot know)

We cannot recover the absolute transit (the camera's clock epoch is unknown),
but the *slope* of that quantity over time is decisive:

    slope ~ 0   -> camera->us is real time and we keep up.  The delay a viewer
                    sees is NOT in the transport, so it is browser-side
                    (MJPEG <img> or audio element buffering).
    slope > 0   -> we are accumulating delay, at `slope` ms per second.

This deliberately uses NO ffmpeg and NO threads: just the KCP pump.  That
rules out the pipeline entirely and answers the question in one number.

Also reports the arrival rate against the expected 50 frames/s, which shows
whether the camera itself is pacing at real time or bursting.

Usage: python3 -u camclock.py [tid] [secs]
"""
import struct
import sys
import time

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
from defsend import Probe, any_calling               # noqa: E402

US = 1_000_000
PERIOD = 20000          # us per audio frame


class Clock(Probe):
    """Records (wall_us, cam_ts_us) per audio frame, nothing else."""

    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.pairs = []
        self.vframes = 0
        self.vhead = []

    def _take_audio_frames(self, pt):
        now = time.monotonic_ns() // 1000
        n = len(pt)
        i = 0
        while True:
            i = pt.find(b"\xff\xff\xff\x88", i)
            if i < 0:
                break
            if (i + 30 <= n
                    and pt[i + 8:i + 20] == b"\x00" * 12):
                self.pairs.append((now, struct.unpack_from("<I", pt, i + 20)[0]))
                i += 30 + 320
                continue
            if i + 28 <= n:
                self.vframes += 1
                if len(self.vhead) < 4:
                    self.vhead.append(pt[i:i + 28].hex())
            i += 1
        p2p_client.CameraStream._take_audio_frames(self, pt)


def slope(xs, ys):
    n = len(xs)
    if n < 5:
        return 0.0, 0.0
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return 0.0, 0.0
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    syy = sum((y - my) ** 2 for y in ys)
    if syy == 0:
        return 0.0, 0.0
    return sxy / sxx, sxy / (sxx * syy) ** 0.5


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    print("camera %s (%s)" % (ip, tid), flush=True)

    st = Clock(ip, got[ip]["p2p_port"], tid, any_calling(tid),
               local_port=0, timeout=secs + 20)
    t0 = time.time()
    st.start()
    print("handshake %.2fs" % (time.time() - t0), flush=True)

    lo, hi = st.kcp_lo, st.kcp_hi
    n_h264 = 0
    t_start_us = time.monotonic_ns() // 1000   # anchor: streaming requested now
    t0 = time.time()
    while time.time() - t0 < secs:
        st._pump(0.05, [(lo.conv, lo), (hi.conv, hi)])
        if st._buf:
            n_h264 += len(st._buf)
            del st._buf[:]
        if st._abuf:
            del st._abuf[:]
    actual = time.time() - t0
    st.close()

    p = st.pairs
    print("\ncapture %.1fs   audio frames=%d (%.1f/s)   h264=%d B (%.0f B/s)"
          % (actual, len(p), len(p) / actual, n_h264, n_h264 / actual),
          flush=True)
    if st.vhead:
        print("video AV header samples:", flush=True)
        for h in st.vhead:
            print("   " + h, flush=True)

    if len(p) < 10:
        print("too few audio frames to regress", flush=True)
        return

    # --- 1. does the camera's capture clock advance at real time? ----------
    dts = [(p[i + 1][1] - p[i][1]) / 1000.0 for i in range(len(p) - 1)]
    dts = [d for d in dts if 0 < d < 10000]
    if dts:
        mean_dt = sum(dts) / len(dts)
        print("\ncamera clock: mean %.2f ms between frames (expected %.1f)"
              % (mean_dt, PERIOD / 1000.0), flush=True)
        print("  -> camera produces %.1f frames/s of real time"
              % (1000.0 / mean_dt), flush=True)

    # --- 2. wall_recv - cam_ts drift ---------------------------------------
    xs = [w / US for w, _ in p]
    ys = [(w - c) / US for w, c in p]      # both already in microseconds
    m, r = slope(xs, ys)
    print("\nwall_recv - cam_ts:  min %.1f ms   max %.1f ms   spread %.1f ms"
          % (1000 * min(ys), 1000 * max(ys), 1000 * (max(ys) - min(ys))),
          flush=True)
    print("drift slope = %+.3f ms per wall-second (r=%.3f)"
          % (1000 * m, r), flush=True)
    if m > 0.02:
        print("  -> GROWING: we accumulate %.1f ms of delay per second "
              "(%.1f s of extra delay over a %.0f s view)"
              % (1000 * m, m * actual / 1000.0, actual), flush=True)
    elif m < -0.02:
        print("  -> SHRINKING: camera clock runs fast relative to us "
              "(clock skew, not delay)", flush=True)
    else:
        print("  -> FLAT: the camera->us path is real time and we keep up.",
              flush=True)
        print("     So the delay a viewer sees is downstream of our socket:",
              flush=True)
        print("     the browser (MJPEG <img> / audio element buffering).",
              flush=True)

    # --- 3. absolute camera->us transit ------------------------------------
    # The camera's clock is *uptime*, so its epoch is unknown and the drift
    # above cannot see a constant delay.  But the first audio frame after we
    # asked for the stream was captured essentially at that moment, which
    # pins the epoch and turns the offset into a real number:
    #
    #   wall_capture(N) ~ t_start - cam_ts_first + cam_ts(N)
    #   transit(N)      = wall_recv(N) - wall_capture(N)
    #
    # That transit INCLUDES the camera's own encoder/sender buffering, which
    # is the part we cannot see any other way.
    off = t_start_us - p[0][1]         # camera's clock epoch in our timebase
    tr = sorted((w - (off + c)) / 1000.0 for w, c in p)   # milliseconds
    n = len(tr)
    print("\ncamera->us transit (anchored on the AvStreamCtl request):",
          flush=True)
    print("  min %.1f ms   p10 %.1f   p50 %.1f   p90 %.1f   max %.1f"
          % (tr[0], tr[n // 10], tr[n // 2], tr[9 * n // 10], tr[-1]),
          flush=True)
    if tr[n // 2] > 700:
        print("  -> the CAMERA itself is holding ~%.1f s before it emits "
              "frames; our transport is not the cause."
              % (tr[n // 2] / 1000.0), flush=True)
    elif tr[n // 2] < 250:
        print("  -> transport is quick (%.0f ms).  Any larger delay a viewer "
              "sees is added after our socket."
              % tr[n // 2], flush=True)


if __name__ == "__main__":
    main()
