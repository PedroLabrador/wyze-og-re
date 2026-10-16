#!/usr/bin/env python3
"""What actually changes in the stream when a camera switches to night mode?

Night vision has three layers and only one of them is about the feed:

  1. the *control* -- "night-shot" / "infrared-mode", a cloud thing-model
     property (see assets/get_capabilities_mock_response_api.json), which the
     camera also drives itself from its ambient light sensor in Auto;
  2. the *picture* -- the IR-cut filter slides out and the IR LEDs light up, so
     the sensor sees infrared and the image usually goes monochrome;
  3. the *feed* -- H.264, the profile we asked for (definition=2, 1080p), the
     frame rate, and whatever the encoder spends on the new picture.

This measures 2 and 3 together, silently, and never talks to a camera: it reads
the server's own /snapshot (the newest decoded frame, which the server keeps
alongside the viewer deque precisely so a still cannot steal a frame from a live
viewer) and /api/state.  Safe to run while the page is streaming.

    python3 nightprobe.py --secs 40 [--port 8080] [--tid N] [--interval 2]

Two independent readings per sample:

  * **chroma** decides day vs night.  IR-cut out plus firmware monochrome
    processing collapses colour, so mean chroma falls to near zero; that is the
    signal, not brightness, because IR lighting can make a night frame *brighter*
    than a dim day frame.
  * **jpeg bytes/frame** is what the encoder is spending.  Sensor noise at high
    gain compresses badly, so night frames usually get LARGER at the same
    quality, or the camera lowers quality to hold the bitrate.

Decoding is done by ffmpeg downscaled to 64x36, so per-sample cost is trivial
and independent of resolution.
"""

import argparse
import json
import statistics
import struct
import subprocess
import sys
import time
import urllib.request

FFMPEG = "/opt/homebrew/bin/ffmpeg"


def jpeg_size(jpg):
    """(width, height) from the JPEG's SOF marker, or (None, None)."""
    if jpg[:2] != b"\xff\xd8":
        return None, None
    i, n = 2, len(jpg)
    while i + 9 < n:
        if jpg[i] != 0xFF:
            i += 1
            continue
        m = jpg[i + 1]
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        seglen = struct.unpack_from(">H", jpg, i + 2)[0]
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack_from(">HH", jpg, i + 5)
            return w, h
        i += 2 + seglen
    return None, None


def picture_stats(jpg):
    """(mean_luma, mean_chroma) from a 64x36 RGB decode, or (None, None).

    luma is 0..255.  chroma is the mean distance of a pixel from grey, i.e. how
    much colour there is at all -- ~0 is a monochrome image.
    """
    try:
        p = subprocess.run(
            [FFMPEG, "-v", "error", "-i", "pipe:0", "-vf", "scale=64:36",
             "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"],
            input=jpg, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    raw = p.stdout
    if len(raw) < 64 * 36 * 3:
        return None, None
    luma = chroma = 0.0
    for i in range(0, 64 * 36 * 3, 3):
        r, g, b = raw[i], raw[i + 1], raw[i + 2]
        luma += 0.299 * r + 0.587 * g + 0.114 * b
        chroma += max(r, g, b) - min(r, g, b)
    n = 64 * 36
    return luma / n, chroma / n


def state(port):
    with urllib.request.urlopen("http://127.0.0.1:%d/api/state" % port,
                                timeout=10) as f:
        return json.loads(f.read())


def snap(port, tid):
    with urllib.request.urlopen("http://127.0.0.1:%d/snapshot/%d.jpg" % (port, tid),
                                timeout=10) as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--tid", type=int, default=None,
                    help="camera id (default: the first one streaming)")
    ap.add_argument("--secs", type=float, default=40)
    ap.add_argument("--interval", type=float, default=2.0)
    args = ap.parse_args()

    if args.tid is None:
        for c in state(args.port)["cameras"]:
            if c["status"] == "streaming":
                args.tid = c["tid"]
                break
    if args.tid is None:
        print("no camera is streaming; start the server first", file=sys.stderr)
        return 1
    print("probing camera %d every %.1fs for %.0fs  (silent: server snapshots "
          "only, nothing is sent to a camera)\n" % (args.tid, args.interval, args.secs))

    hdr = ("  time   fps   size      jpeg B   luma  chroma   verdict")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    t0 = time.time()
    rows = []
    while time.time() - t0 < args.secs:
        try:
            jpg = snap(args.port, args.tid)
            w, h = jpeg_size(jpg)
            luma, chroma = picture_stats(jpg)
            fps = 0.0
            for c in state(args.port)["cameras"]:
                if c["tid"] == args.tid:
                    fps = c["stats"]["fps"]
            if luma is None:
                print("  %5.1f  %4.1f  %s  %6d   decode failed"
                      % (time.time() - t0, fps, "?" , len(jpg)))
            else:
                # ~0 chroma is a monochrome image; 8 is generously above the
                # noise floor of a genuinely grey room in colour mode.
                night = chroma < 8.0
                rows.append((luma, chroma, len(jpg), night))
                print("  %5.1f  %4.1f  %4dx%-4d %6d  %5.1f  %5.1f   %s"
                      % (time.time() - t0, fps, w, h, len(jpg), luma, chroma,
                         "NIGHT (monochrome)" if night else "day (colour)"))
        except Exception as e:
            print("  %5.1f  error: %s" % (time.time() - t0, e))
        sys.stdout.flush()
        time.sleep(args.interval)

    if rows:
        day = [r for r in rows if not r[3]]
        night = [r for r in rows if r[3]]
        print("\nsummary  day samples %d / night samples %d" % (len(day), len(night)))
        for name, set_ in (("day", day), ("night", night)):
            if set_:
                print("  %-5s luma %.1f  chroma %.1f  jpeg bytes median %d"
                      % (name, statistics.mean(r[0] for r in set_),
                         statistics.mean(r[1] for r in set_),
                         statistics.median(r[2] for r in set_)))
        if day and night:
            print("\n  chroma %.1f -> %.1f, jpeg bytes %d -> %d (%+.0f%%)"
                  % (statistics.mean(r[1] for r in day),
                     statistics.mean(r[1] for r in night),
                     statistics.median(r[2] for r in day),
                     statistics.median(r[2] for r in night),
                     100.0 * (statistics.median(r[2] for r in night)
                              / statistics.median(r[2] for r in day) - 1.0)))
        else:
            print("\n  only one state was seen -- darken (or light) the room and "
                  "run again to compare")
    return 0


if __name__ == "__main__":
    sys.exit(main())
