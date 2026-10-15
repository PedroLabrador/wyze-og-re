#!/usr/bin/env python3
"""End-to-end HTTP test: start server.py, hit every endpoint, stop it.

Checks:
  * /            serves the page, and the old emoji entities are gone
  * /            page <script> parses (node --check) and every getElementById
                 prefix has a matching id in the markup
  * /api/state   lists a camera
  * /feed        one connection carrying every camera, framed <Q tid><Q ms>
                 <I len> + JPEG
  * /stream/..   multipart MJPEG with a JPEG SOI inside
  * /audio/..    WAV header == PCM1, 1 ch, 16000 Hz, 16 bit, then PCM data

Usage: python3 -u httptest.py [port]
"""
import json
import os
import re
import shutil
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
        for ent in ("&#128266;", "&#128263;", "&#128247;", "&#128269;",
                    "&#9974;", "&#8635;", "&#10005;"):
            if ent in html:
                print("   !! emoji entity still present: %s" % ent)
        # The emoji entities and then the SND/FS/JPG text labels are both gone:
        # buttons are inline SVG now (see ICON in the page).
        print("   emoji entities checked; inline SVG icons: %s"
              % ("<svg" in html and "const ICON" in html))
        gone = not any(x in html for x in ("&gt;FS&lt;", ">FS<", ">SND<",
                                           ">JPG<", ">Close<", ">Fullscreen<"))
        print("   old text labels gone: %s" % gone)
        print("   fullscreen audio control present: %s" % ('id="fssound"' in html))
        print("   gain selector present: %s" % ('id="gain"' in html))
        print("   'textContent =' entity bug present: %s"
              % ("textContent = '&#" in html))
        # Regression guards for the connection-pool fix: the page must not go
        # back to one MJPEG socket (<img>) per camera.
        print("   video rendered to canvas, not <img>: %s"
              % ('id="view' in html and 'id="img' not in html))
        print("   one video connection via fetch('/feed'): %s"
              % ("fetch('/feed" in html))
        print("   snapshot taken from the canvas: %s"
              % ("cv.toBlob" in html))
        # The badge must describe the picture, not echo the worker's status
        # word over a frozen frame (see JOURNAL Phase 18).
        print("   badge distinguishes a frozen picture: %s"
              % ("'stalled'" in html and "'no video'" in html))

        # -- page JavaScript ------------------------------------------------
        # No browser is available here, so these are the two cheap guards: the
        # page's <script> must parse, and every getElementById('x'+tid) must
        # have an id="x..." somewhere in the served markup.
        m = re.search(r"<script>\n(.*?)\n</script>", html, re.S)
        if not m:
            print("   !! no <script> block found")
        elif not shutil.which("node"):
            print("   node not installed; skipped JS syntax check")
        else:
            js_path = os.path.join(HERE, "_page.js")
            with open(js_path, "w") as fh:
                fh.write(m.group(1))
            p = subprocess.run(["node", "--check", js_path],
                               capture_output=True, text=True)
            print("   JS parses (node --check): %s %s"
                  % (p.returncode == 0, p.stderr.strip()[:200]))
            # Exercise the page's own feed parser (feedtest.js pulls the
            # function out of the served script) -- the framing is now the
            # single point of failure for ALL video on the page.
            ft = os.path.join(os.path.dirname(HERE), "feedtest.js")
            if os.path.exists(ft):
                q = subprocess.run(["node", ft, js_path],
                                   capture_output=True, text=True, timeout=60)
                lines = [x for x in q.stdout.splitlines() if x.strip()]
                print("   feed framing test: %s  %s"
                      % (q.returncode == 0,
                         lines[-1].strip() if lines else q.stderr.strip()[:150]))
                if q.returncode != 0:
                    print(q.stdout)
            os.unlink(js_path)
            ids = set(re.findall(r'id="([A-Za-z]+)', html))
            ids |= set(re.findall(r"\.id = '([A-Za-z]+)'", m.group(1)))
            used = set(re.findall(r"getElementById\('([A-Za-z]+)'", m.group(1)))
            missing = sorted(used - ids)
            print("   getElementById prefixes %s -> ids present: %s"
                  % (sorted(used), not missing))
            if missing:
                print("   !! no element id starts with: %s" % ", ".join(missing))

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

        # -- feed: every camera multiplexed onto ONE connection -------------
        # This is what keeps the page inside the browser's six-connection
        # per-origin budget, so the framing has to be exactly right.
        r = urllib.request.urlopen("http://127.0.0.1:%d/feed" % PORT,
                                   timeout=30)
        print("\nGET /feed      -> %d  %s"
              % (r.status, r.headers.get("Content-Type")))
        raw = r.read(400000)
        r.close()
        ok = bad = 0
        seen, age = set(), None
        off = 0
        while off + 20 <= len(raw):
            ftid, fms, flen = struct.unpack_from("<QQI", raw, off)
            if flen > (4 << 20) or off + 20 + flen > len(raw):
                break
            jpg = raw[off + 20:off + 20 + flen]
            if jpg[:2] == b"\xff\xd8" and jpg[-2:] == b"\xff\xd9":
                ok += 1
                seen.add(ftid)
                if ftid == int(tid):
                    age = time.time() * 1000.0 - fms
            else:
                bad += 1
            off += 20 + flen
        print("   frames ok=%d bad=%d cameras=%d  bytes used=%d/%d"
              % (ok, bad, len(seen), off, len(raw)))
        print("   end-to-end age of the newest local camera frame: %s"
              % ("%.0f ms" % age if age is not None else "n/a"))

        # -- mjpeg ---------------------------------------------------------
        st, hdr, body = get("/stream/%s.mjpg" % tid, n=400000, timeout=25)
        print("\nGET /stream    -> %d  %d B  %s" % (st, len(body),
                                                    hdr.get("Content-Type")))
        print("   multipart: %s  jpeg SOI: %s  jpeg EOI: %s"
              % (b"--frame" in body, b"\xff\xd8" in body, b"\xff\xd9" in body))
        # X-Time is the publish instant, so a client on this host can subtract
        # it from Date.now() to read the frame's true end-to-end age.
        ts = body.find(b"X-Time: ")
        print("   X-Time stamp: %s" % (body[ts:ts + 24].decode(
            "ascii", "replace").strip() if ts >= 0 else "MISSING"))

        # -- audio ---------------------------------------------------------
        st, hdr, body = get("/audio/%s.wav?gain=32" % tid, n=131072, timeout=25)
        print("\nGET /audio?gain=32 -> %d  %d B  %s" % (st, len(body),
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
                print("   samples=%d nonzero=%.1f%% peak=%d (unity would be "
                      "~%d)" % (n, 100.0 * nz / n, peak, peak // 32))
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
