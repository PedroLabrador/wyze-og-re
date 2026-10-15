#!/usr/bin/env python3
"""Does a slow viewer stay live, or fall permanently behind?

Starts server.py, opens one MJPEG stream, and reads it deliberately slower
than the camera produces (the browser equivalent of a busy tab or a stalled
socket).  Meanwhile it polls /api/state and records two numbers the stream
handler now publishes per connection:

    lag_ms    how stale the OLDEST frame about to be written is
    dropped   how many frames we chose not to replay

Before MAX_LAG was added, take() returned everything past the cursor, so a
slow reader accumulated a backlog, replayed it, and stayed that far behind
reality for the rest of the session -- a permanent invisible delay.  The
passing criterion here is therefore simple: lag_ms must stay bounded near
MAX_LAG instead of climbing with time, and dropped must grow.

Usage: python3 -u lagtest.py [port] [secs] [slow|fast]

  slow  reads ~33 kB/s against a ~50 kB/s camera, so it MUST fall behind;
        passing means lag stays bounded near MAX_LAG and `dropped` grows.
  fast  reads as fast as it can, which is what a real browser does; passing
        means dropped == 0 and lag is a few ms -- the bound must never touch
        a viewer that is keeping up.
"""
import json
import subprocess
import sys
import time
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8088
SECS = float(sys.argv[2]) if len(sys.argv) > 2 else 16.0
MODE = (sys.argv[3] if len(sys.argv) > 3 else "slow").lower()
HERE = "~/Downloads/wyze-re/wyze-cam-stream"

# ~2 kB every 60 ms is ~33 kB/s, comfortably under one camera's ~50 kB/s of
# JPEG, so the reader is guaranteed to fall behind if it can.
if MODE == "fast":
    READ_CHUNK, READ_SLEEP = 262144, 0.0
else:
    READ_CHUNK, READ_SLEEP = 2000, 0.060


def main():
    proc = subprocess.Popen(
        [sys.executable, "-u", "server.py", "--host", "127.0.0.1",
         "--port", str(PORT)],
        cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        def state():
            d = urllib.request.urlopen(
                "http://127.0.0.1:%d/api/state" % PORT, timeout=10).read()
            return json.loads(d)

        up = False
        for _ in range(60):
            time.sleep(1)
            if proc.poll() is not None:
                print("server died:\n" + proc.stdout.read())
                return 1
            try:
                state()
                up = True
                break
            except Exception:
                pass
        if not up:
            print("server never came up")
            return 1

        cams = (state().get("cameras") or [])
        live = [c for c in cams if c.get("tid")]
        if not live:
            print("no camera in state")
            return 1
        tid = str(live[0]["tid"])
        print("watching tid %s, reading %d B every %.0f ms (%s)"
              % (tid, READ_CHUNK, READ_SLEEP * 1000,
                 "fast, as a browser would" if MODE == "fast"
                 else "slow on purpose"), flush=True)

        r = urllib.request.urlopen(
            "http://127.0.0.1:%d/stream/%s.mjpg" % (PORT, tid), timeout=25)

        samples, t0 = [], time.time()
        stop = [False]

        def poller():
            while not stop[0] and time.time() - t0 < SECS:
                try:
                    doc = state()
                    for c in doc.get("cameras") or []:
                        if str(c.get("tid")) != tid:
                            continue
                        s = c.get("stats") or {}
                        if "lag_ms" in s:
                            samples.append((time.time() - t0,
                                            s["lag_ms"],
                                            s.get("dropped", 0),
                                            s.get("served", 0),
                                            s.get("pub", 0)))
                except Exception:
                    pass
                time.sleep(1.0)

        import threading
        th = threading.Thread(target=poller, daemon=True)
        th.start()

        while time.time() - t0 < SECS:
            try:
                if not r.read(READ_CHUNK):
                    break
            except Exception:
                break
            time.sleep(READ_SLEEP)
        stop.append(True)
        th.join(timeout=2.0)

        if not samples:
            print("no lag samples -- the stream ended early")
            return 1

        lags = [s[1] for s in samples]
        dropped = samples[-1][2]
        print("\n  t     lag_ms  dropped  served    pub")
        for t, lag, dr, sv, pb in samples:
            print("  %4.0fs  %7.1f  %7d  %6d  %6d" % (t, lag, dr, sv, pb))
        print("\nlag_ms:  first %.1f   max %.1f   last %.1f"
              % (lags[0], max(lags), lags[-1]))
        print("dropped: %d" % dropped)

        # MAX_LAG is 0.5 s; allow one 1 s poll interval of slack on top.
        limit = 1600.0
        if MODE == "fast":
            # A reader that keeps up must receive every frame.  The bound has
            # to be invisible here, or it is costing healthy viewers quality.
            ok = max(lags) <= limit and dropped == 0
            print("\n%s  max lag %.1f ms <= %.0f ms AND dropped == 0"
                  % ("PASS" if ok else "FAIL", max(lags), limit))
        else:
            # The reader is ~1.5x too slow, so over SECS it falls ~0.5*SECS s
            # behind if nothing bounds it.  Bounded means max lag stays under
            # the limit AND the backlog was skipped rather than replayed.
            ok = max(lags) <= limit and dropped > 0
            print("\n%s  max lag %.1f ms <= %.0f ms AND backlog was dropped"
                  % ("PASS" if ok else "FAIL", max(lags), limit))
        return 0 if ok else 1
    finally:
        if proc.poll() is None:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
