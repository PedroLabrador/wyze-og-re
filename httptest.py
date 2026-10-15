#!/usr/bin/env python3
"""End-to-end HTTP test: start server.py, hit every endpoint, stop it.

Checks:
  * /            serves the page, and the old emoji entities are gone
  * /api/state   lists a camera
  * /stream/..   multipart MJPEG with a JPEG SOI inside
  * /audio/..    WAV header == PCM1, 1 ch, 16000 Hz, 16 bit, then PCM data

Usage: python3 -u httptest.py [port]
"""
import json
import struct
import subprocess
import sys
import time
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8087
HERE = "~/Downloads/wyze-re/wyze-cam-stream"


def get(path, n=None, timeout=20):
    r = urllib.request.urlopen("http://127.0.0.1:%d%s" % (PORT, path),
                               timeout=timeout)
    data = r.read(n) if n else r.read()
    return r.status, r.headers, data


def main():
    proc = subprocess.Popen(
        [sys.executable, "-u", "server.py", "--host", "127.0.0.1",
         "--port", str(PORT)],
        cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        # the server scans the LAN first (up to ~3 x 3 s)
        up = False
        for _ in range(60):
            time.sleep(1)
            if proc.poll() is not None:
                print("server died:\n" + proc.stdout.read())
                return 1
            try:
                get("/", n=1024, timeout=2)
                up = True
                break
            except Exception:
                pass
        if not up:
            print("server never came up")
            return 1
        print("server up on %d" % PORT)

        # -- page ----------------------------------------------------------
        st, hdr, body = get("/")
        html = body.decode("utf-8", "replace")
        print("\nGET /          -> %d  %d B  %s" % (st, len(body),
                                                    hdr.get("Content-Type")))
        for ent in ("&#128266;", "&#128263;", "&#128247;", "&#128269;"):
            if ent in html:
                print("   !! emoji entity still present: %s" % ent)
        print("   emoji entities checked; SND/FS/JPG labels present: %s"
              % all(x in html for x in ("SND", "FS", "JPG")))
        print("   'textContent =' entity bug present: %s"
              % ("textContent = '&#" in html))

        # -- state ---------------------------------------------------------
        st, hdr, body = get("/api/state")
        doc = json.loads(body)
        cams = doc.get("cameras") or doc.get("devices") or []
        print("\nGET /api/state -> %d  %s" % (st, list(doc)[:6]))
        tids = [c.get("tid") for c in cams if c.get("tid")]
        if not tids:
            print("   no camera in state: %s" % json.dumps(doc)[:400])
            return 0
        tid = str(tids[0])
        print("   using tid %s" % tid)

        # -- mjpeg ---------------------------------------------------------
        st, hdr, body = get("/stream/%s.mjpg" % tid, n=400000, timeout=25)
        print("\nGET /stream    -> %d  %d B  %s" % (st, len(body),
                                                    hdr.get("Content-Type")))
        print("   multipart: %s  jpeg SOI: %s  jpeg EOI: %s"
              % (b"--frame" in body, b"\xff\xd8" in body, b"\xff\xd9" in body))

        # -- audio ---------------------------------------------------------
        st, hdr, body = get("/audio/%s.wav" % tid, n=131072, timeout=25)
        print("\nGET /audio     -> %d  %d B  %s" % (st, len(body),
                                                    hdr.get("Content-Type")))
        if body[:4] == b"RIFF" and body[8:12] == b"WAVE":
            tag, ch, rate, brate, align, bits = struct.unpack_from(
                "<HHIIHH", body, 20)
            print("   fmt=%d ch=%d rate=%d byterate=%d align=%d bits=%d"
                  % (tag, ch, rate, brate, align, bits))
            data = body[44:]
            n = len(data) // 2
            if n:
                sm = struct.unpack_from("<%dh" % n, data)
                nz = sum(1 for x in sm if x)
                peak = max(abs(x) for x in sm)
                print("   samples=%d nonzero=%.1f%% peak=%d"
                      % (n, 100.0 * nz / n, peak))
        else:
            print("   NOT a WAV: %r" % body[:60])

        print("\n--- server log ---")
        for _ in range(3):
            time.sleep(0.5)
        proc.terminate()
        time.sleep(1)
        try:
            for line in proc.stdout.read().splitlines()[-25:]:
                print("  " + line)
        except Exception:
            pass
        return 0
    finally:
        if proc.poll() is None:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
