#!/usr/bin/env python3
"""How much delay does the ffmpeg stage itself add?

Feeds a captured H.264 stream (/tmp/vf.h264) into the *same* ffmpeg command
CameraStreamThread uses, but paced at the real rate it arrived (the capture is
591968 B over 12.0 s, ~49 KB/s), and measures:

  residual = t(last JPEG out) - t(last byte in)

If the decoder held no buffered frames they would have come out before EOF, so
`residual` is exactly the number of frames sitting inside ffmpeg waiting to be
emitted, converted to seconds at the stream's frame rate.

Also reports JPEGs out and wall-clock duration, so a variant that silently
drops frames is visible.

Usage: python3 -u fflag.py [file] [secs]
"""
import os
import subprocess
import sys
import time

PATH = sys.argv[1] if len(sys.argv) > 1 else "/tmp/vf.h264"
SECS = float(sys.argv[2]) if len(sys.argv) > 2 else 12.0

data = open(PATH, "rb").read()
rate = len(data) / SECS
print("%s  %d B  pacing at %.0f B/s over %.1f s\n"
      % (PATH, len(data), rate, SECS))

BASE = ["ffmpeg", "-loglevel", "error",
        "-probesize", "32", "-analyzeduration", "0"]

VARIANTS = [
    ("A current (as shipped)", []),
    ("B -fflags nobuffer", ["-fflags", "nobuffer"]),
    ("C -threads 1", ["-threads", "1"]),
    ("D B+C", ["-fflags", "nobuffer", "-threads", "1"]),
    ("E D + -flags low_delay",
     ["-fflags", "nobuffer", "-threads", "1", "-flags", "low_delay"]),
    ("F E + -max_delay 0",
     ["-fflags", "nobuffer", "-threads", "1", "-flags", "low_delay",
      "-max_delay", "0"]),
]


def run(label, inopts):
    cmd = BASE + inopts + ["-f", "h264", "-i", "pipe:0",
                           "-an",
                           "-vf", "scale=%d:-2" % 640,
                           "-f", "mjpeg", "-q:v", "5", "pipe:1"]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    os.set_blocking(p.stdout.fileno(), False)   # drain must not break pacing
    out = bytearray()
    outs = []                       # wall time of every JPEG boundary

    def drain():
        """1 = consumed bytes, 0 = nothing available now, -1 = EOF."""
        try:
            b = p.stdout.read1(1 << 20)
        except (BlockingIOError, ValueError):
            return 0
        if not b:
            return -1
        out.extend(b)
        while True:
            i = out.find(b"\xff\xd8")
            if i < 0:
                break
            j = out.find(b"\xff\xd9", i)
            if j < 0:
                if i:
                    del out[:i]
                break
            del out[:j + 2]
            outs.append(time.time())
        return 1

    t0 = time.time()
    chunk = 2048                    # ~40 ms of stream
    n = 0
    while n < len(data):
        p.stdin.write(data[n:n + chunk])
        n += chunk
        while drain() == 1:
            pass
        # pace: real time must track the original capture timeline
        target = t0 + SECS * (n / len(data))
        d = target - time.time()
        if d > 0:
            time.sleep(d)
    eof = time.time()
    p.stdin.close()
    # flush the tail
    deadline = time.time() + 6.0
    while time.time() < deadline:
        if drain() == -1:                     # EOF from ffmpeg
            break
        time.sleep(0.01)
    try:
        p.kill()
    except Exception:
        pass
    err = p.stderr.read().decode("utf-8", "replace").strip()

    residual = (outs[-1] - eof) if outs else float("nan")
    fps = (len(outs) - 1) / SECS if len(outs) > 1 else 0.0
    print("%-26s JPEGs=%-4d fps=%-5.1f  residual=%.3f s  %s"
          % (label, len(outs), fps, residual,
             ("ERR: " + err[:70]) if err else ""))
    return residual


for label, opts in VARIANTS:
    try:
        run(label, opts)
    except Exception as e:
        print("%-26s failed: %r" % (label, e))
