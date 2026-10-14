#!/usr/bin/env python3
"""Local web server: open a browser and watch every camera at once.

**No login, no cloud credentials, no internet.**  This is worth stating up
front because it is not obvious: the whole pipeline below runs on the LAN with
zero authentication.

  * discovery is a broadcast probe on port 8899; cameras answer anyone
  * the CALLING frame is a bare UDP packet the camera accepts unconditionally
    -- we proved this by replaying camera 2's frame at camera 4 and getting a
    full stream out of it
  * KCP, AvStreamCtl and the RC5 video cipher are negotiated within that one
    session, using a key we chose ourselves (``CALLING[120:128]``)
  * the camera's ``accessToken`` / IOTC credentials that the *app* fetches from
    Wyze's ``regist_gw_user`` endpoint are never used on this path

Cloud credentials are only needed for things this server does not do: device
management, wake-on-LAN pushes, event history.  Camera **nicknames** would
normally come from the cloud device list, but those are already cached in
``wyze_devices.json`` and read locally -- no network call.

Three reverse-engineered facts make this work, each of which independently
blocked progress (evidence in ``../P2P_PROTOCOL.md``, chronology in
``../JOURNAL.md``):

1. **Any CALLING works for any camera.**  The 128-byte ``7e a4`` frame carries
   no camera-bound field: the peer adopts the `conv` and the AV key straight
   out of it.  So we don't need a per-camera capture, and a camera without one
   is not a special case.

2. **The meter exchange.**  The camera sends ``C0 90`` meter *requests*
   (inner ``[1] == 1``).  Echoing them loops forever -- ``iv_rcv_meter_req``
   fires up to 5 more UDP replies per echo.  You must answer with inner
   ``[1] == 2`` (``iv_rcv_meter_ack``).  Only then does KCP start.

3. **KCP de-duplication.**  The camera retransmits ~9x (576 PUSH segments for
   64 unique ones) because it races ahead of our ACKs.  Concatenating every
   PUSH splices duplicates into the H.264 stream and the decoder desyncs
   permanently -- ffmpeg produced *zero* frames before the fix.  ``kcpav.KCP``
   now ACKs every segment but delivers only in-order, unique ones.

Video path per camera::

    discover -> CALLING -> meter_ack -> KCP -> AvStreamCtl (inside KCP)
        -> RC5-ECB AV decrypt (key = CALLING[120:128]) -> H.264 -> ffmpeg -> MJPEG

Usage::

    python3 server.py                  # http://127.0.0.1:8080
    python3 server.py --port 9000 --bind 0.0.0.0
    python3 server.py --discover       # scan the LAN once and exit

Only the Python standard library and an ``ffmpeg`` on PATH are required.
"""
import argparse
import collections
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                      # wyze-re/
for _p in (ROOT, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from p2p_client import CameraStream, discover        # noqa: E402
import p2p_call                                       # noqa: E402

DEVICES_FILE = os.path.join(ROOT, "wyze_devices.json")

# Discovery is flaky (~3 s window, sometimes silent) -- retry rather than
# concluding a camera is offline after one bad sample.
DISCOVER_ATTEMPTS = 3
DISCOVER_DURATION = 3.0
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"


# --------------------------------------------------------------------------
# camera names -- read from the local cache, never fetched at runtime
# --------------------------------------------------------------------------
def load_devices_file():
    """Nicknames keyed by the "CAM-1_xxxxxxxxxxxx" id discovery reports."""
    if not os.path.exists(DEVICES_FILE):
        return {}
    try:
        raw = json.load(open(DEVICES_FILE))
    except Exception:
        return {}
    out = {}
    for d in (raw if isinstance(raw, list) else []):
        mac = d.get("mac") or d.get("device_id")
        if mac:
            out[mac] = d
    return out


# --------------------------------------------------------------------------
# one camera's video pipeline
# --------------------------------------------------------------------------
class CameraStreamThread(threading.Thread):
    """Keep one camera decoded and ready to serve.

    Runs ``discover -> handshake -> ffmpeg`` in a loop, publishing the newest
    JPEG to ``self.frame``.  Restarts with backoff on failure -- a camera that
    is physically powered off must not take the server down (there are 4
    cameras here and at least one is usually unplugged).
    """

    def __init__(self, camera, on_status=None):
        super().__init__(daemon=True)
        self.camera = camera                      # tid, ip, name, calling
        self.status = "starting"
        self.error = None
        self.frame = b""
        self.seq = 0
        # Frames are buffered, not just "latest wins": ffmpeg hands JPEGs over
        # in bursts (the producer spends its time decrypting network packets,
        # so the pipe accumulates).  With a single `self.frame` slot a burst of
        # 7 collapsed into ONE delivery -- measured 19 frames served out of 132
        # published, because `seq = cur` jumped over the skipped ones.
        self.frames = collections.deque(maxlen=120)
        self.stats = {"h264": 0, "jpg": 0, "fps": 0.0, "last": 0.0}
        self._cond = threading.Condition()
        self._stop = threading.Event()
        self._on_status = on_status
        self._log = []

    # -- helpers -----------------------------------------------------------
    def log(self, msg):
        self._log = (self._log + ["%s %s" % (time.strftime("%H:%M:%S"), msg)])[-40:]

    def set_status(self, s, err=None):
        self.status, self.error = s, err
        if self._on_status:
            try:
                self._on_status()
            except Exception:
                pass

    def take(self, since_seq=0):
        """Return `(frames, cursor)` for every frame newer than `since_seq`.

        Nothing is consumed: several browsers (or a browser plus a test
        client) can watch the same camera at once.  A draining take() would
        hand each frame to exactly one viewer and split the stream between
        them.  Each caller keeps its own cursor; frames age out of the bounded
        deque once 120 have accumulated, so a viewer that falls that far behind
        skips ahead rather than growing without limit.
        """
        with self._cond:
            got = [(s, j) for s, j in self.frames if s > since_seq]
            return [j for _, j in got], (got[-1][0] if got else since_seq)

    def _publish(self, jpeg):
        with self._cond:
            self.seq += 1
            self.frames.append((self.seq, jpeg))
            self.frame = jpeg            # newest, for anything that wants it
            self._cond.notify_all()

    # -- the pipeline ------------------------------------------------------
    def run(self):
        backoff = 1.0
        while not self._stop.is_set():
            try:
                self._cycle()
                backoff = 1.0
            except Exception as e:
                self.set_status("error", "%s: %s" % (type(e).__name__, e))
                self.log("error: %r" % (e,))
                # the port it had is no longer good -- discovery is not stable
                # between sessions, so force a re-scan before the next try
                self.camera.pop("p2p_port", None)
            if self._stop.is_set():
                break
            time.sleep(backoff)
            backoff = min(backoff * 2, 15.0)

    def _cycle(self):
        # Reuse the hub's discovery result.  Running a broadcast probe per
        # worker makes multiple cameras collide with each other, so only
        # rescan when we don't have an address yet (or after a failure).
        if not self.camera.get("p2p_port"):
            self.set_status("discovering")
            found = self._discover()
            if not found:
                self.set_status("offline", "camera not answering discovery")
                raise RuntimeError("no discovery reply")
            self.camera["ip"] = found.get("ip") or self.camera["ip"]
            self.camera["p2p_port"] = found["p2p_port"]
            self.camera["wyze_id"] = found.get("wyze_id")

        self.set_status("connecting")
        # local_port=0 is essential: every worker must bind its own socket.
        # The app advertises a fixed 48171, but two cameras sharing it means
        # the second bind fails with EADDRINUSE -- and we verified the camera
        # replies to the UDP *source* port, so an ephemeral one is fine.
        # timeout bounds the DATA phase only (raw_h264 refreshes it on every
        # chunk, and the handshake has its own fixed pumps) -- so 12 s of
        # silence means re-handshake rather than showing a frozen frame for
        # half a minute.
        st = CameraStream(self.camera["ip"], self.camera["p2p_port"],
                          self.camera["tid"], self.camera["calling"],
                          local_port=0, timeout=12.0, on_log=self.log)
        ff = subprocess.Popen(
            ["ffmpeg", "-loglevel", "error",
             "-probesize", "32", "-analyzeduration", "0",
             "-f", "h264", "-i", "pipe:0",
             "-an",
             "-vf", "scale=%d:-2" % int(os.environ.get("WYZE_WIDTH", 640)),
             "-f", "mjpeg", "-q:v", "5", "pipe:1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self.set_status("streaming")

        # Drain ffmpeg's stdout on its OWN thread.
        #
        # Without this the two pipes deadlock.  The loop below wrote to
        # ff.stdin first and only read ff.stdout afterwards, so once ffmpeg's
        # output backed up (a few dozen KB of JPEGs fill the pipe) it blocked
        # writing stdout, stopped reading stdin, and our ff.stdin.write()
        # blocked forever.  The symptom is perfectly disguised: `h264` freezes,
        # nothing raises, status stays "streaming" -- because the stall check
        # lives inside the `for chunk` body, which never runs when the loop is
        # wedged.  All four cameras froze ~8 s in; with two cameras the race
        # was occasionally won, which is why earlier tests looked fine.
        stop_drain = threading.Event()

        def _drain():
            pending = bytearray()
            n_window = 0
            window = time.time()
            while not stop_drain.is_set():
                try:
                    b = ff.stdout.read1(1 << 20)   # blocks until ffmpeg writes
                except (OSError, ValueError):
                    break
                if not b:
                    break                          # ffmpeg exited
                pending += b
                while True:
                    i = pending.find(JPEG_SOI)
                    if i < 0:
                        break
                    j = pending.find(JPEG_EOI, i)
                    if j < 0:
                        if i:
                            del pending[:i]        # keep a possible partial SOI
                        break
                    jpg = bytes(pending[i:j + 2])
                    del pending[:j + 2]
                    self._publish(jpg)
                    self.stats["jpg"] += 1
                    self.stats["last"] = time.time()
                    n_window += 1
                if time.time() - window >= 1.0:
                    self.stats["fps"] = n_window / (time.time() - window)
                    window, n_window = time.time(), 0

        drain = threading.Thread(target=_drain, daemon=True,
                                 name="drain-%s" % self.camera["tid"])
        drain.start()

        last_h264 = time.time()
        try:
            for chunk in st.raw_h264():
                if self._stop.is_set():
                    break
                self.stats["h264"] += len(chunk)
                last_h264 = time.time()
                try:
                    ff.stdin.write(chunk)
                    ff.stdin.flush()
                except (BrokenPipeError, ValueError, OSError):
                    break

                # a camera that stops talking must be re-handshaked
                if time.time() - last_h264 > 8.0:
                    raise RuntimeError("stream stalled")

            if time.time() - last_h264 > 8.0:
                raise RuntimeError("stream ended")
        finally:
            stop_drain.set()
            for closer in (lambda: ff.stdin.close(), ff.kill, st.close):
                try:
                    closer()
                except Exception:
                    pass
            try:
                drain.join(timeout=2.0)
            except Exception:
                pass
            self.set_status("reconnecting")

    def _discover(self):
        for _ in range(DISCOVER_ATTEMPTS):
            if self._stop.is_set():
                return None
            got = discover(DISCOVER_DURATION, want_tid=self.camera["tid"])
            if got:
                # discover() returns {ip: {...}}; we want the one record that
                # matched our TID filter
                return next(iter(got.values()))
        return None

    def stop(self):
        self._stop.set()
        with self._cond:
            self._cond.notify_all()


# --------------------------------------------------------------------------
# the hub
# --------------------------------------------------------------------------
class Hub:
    def __init__(self):
        self.lock = threading.Lock()
        self.workers = {}          # tid -> CameraStreamThread
        self.cameras = {}          # tid -> {tid, ip, mac, name, calling}
        self.calling = self._load_calling()
        self.names = load_devices_file()

    @staticmethod
    def _load_calling():
        """A captured CALLING -- any camera's will do (see module docstring).

        We deliberately bypass ``p2p_call.load_templates``'s preference for
        ``/tmp/forge_in_*.bin`` so a clean checkout behaves identically to a
        machine that happened to run the phone-side capture.
        """
        path = os.path.join(ROOT, "wire", "p2p_frames.json")
        try:
            doc = json.load(open(path))
        except Exception:
            return None
        for tid in sorted(doc.get("devices", {})):
            rec = doc["devices"][tid].get("frames", {}).get("calling")
            if not rec:
                continue
            raw = bytes.fromhex(rec) if isinstance(rec, str) else bytes(rec)
            if len(raw) == 128:
                return raw
        return None

    # -- discovery ---------------------------------------------------------
    def refresh(self, progress=None):
        """Scan the LAN and reconcile it with the cached name list."""
        found = {}
        for attempt in range(1, DISCOVER_ATTEMPTS + 1):
            found = discover(DISCOVER_DURATION)
            if found:
                break
            if progress and attempt < DISCOVER_ATTEMPTS:
                progress("discovery attempt %d returned nothing, retrying"
                         % attempt)
        if not found:
            return found

        with self.lock:
            for ip, d in found.items():
                tid = int(d["tid"])
                mac = d.get("wyze_id") or ""
                # discovery reports "CAM-1_xxxxxxxxxxxx", which is exactly the
                # `mac` field the cached device list is keyed by
                name = (self.names.get(mac) or {}).get("nickname") \
                    or ("Camera %s" % tid)
                rec = self.cameras.get(tid) or {}
                rec.update({"tid": tid, "ip": ip, "mac": mac, "name": name,
                            "p2p_port": d["p2p_port"]})
                self.cameras[tid] = rec
            tids = list(self.cameras)

        # Start a worker for every camera right away.  The grid should show
        # live video on page load with nothing to click; making the browser
        # request /stream first would work too, but it couples the UI to an
        # ordering (and a stale cached page would deadlock waiting for a
        # status that only changes once something asks for the stream).
        # Powered-off cameras just cycle through discovery backoff.
        for tid in tids:
            try:
                self.ensure(tid)
            except Exception:
                pass
        return found

    # -- streaming ---------------------------------------------------------
    def ensure(self, tid):
        with self.lock:
            cam = self.cameras.get(int(tid))
            if not cam:
                return None, "unknown camera (run discovery first)"
            if not self.calling:
                return None, "no CALLING frame in wire/p2p_frames.json"
            w = self.workers.get(int(tid))
            # A live worker self-heals (it re-runs discovery + handshake with
            # backoff), so never spawn a second one -- two workers on one
            # camera would fight over the stream.
            if w and w.is_alive():
                return w, None
            if w:
                sys.stderr.write(
                    "ensure(%s): replacing DEAD worker (status=%s err=%s)\n"
                    % (tid, w.status, w.error))
                w.stop()
            cam = dict(cam, calling=self.calling)
            w = CameraStreamThread(cam)
            self.workers[int(tid)] = w
            w.start()
            sys.stderr.write("ensure(%s): started new worker %d\n"
                             % (tid, id(w)))
            return w, None

    def stop_all(self):
        with self.lock:
            ws = list(self.workers.values())
            self.workers.clear()
        for w in ws:
            w.stop()
        for w in ws:
            w.join(timeout=2.0)

    def state(self):
        with self.lock:
            out = []
            for tid, cam in sorted(self.cameras.items()):
                w = self.workers.get(tid)
                out.append({
                    "tid": tid, "ip": cam.get("ip"), "name": cam.get("name"),
                    "mac": cam.get("mac"),
                    "status": w.status if w else "idle",
                    "error": w.error if w else None,
                    "seq": w.seq if w else 0,
                    "stats": w.stats if w else {},
                    "log": w._log[-6:] if w else [],
                })
            return out


HUB = Hub()


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
PAGE = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wyze cameras</title>
<style>
 :root { color-scheme: dark; }
 * { box-sizing: border-box; }
 body { margin:0; background:#0d1117; color:#e6edf3;
        font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
 header { display:flex; align-items:center; gap:16px; padding:14px 20px;
          background:#161b22; border-bottom:1px solid #30363d;
          position:sticky; top:0; z-index:5; }
 h1 { font-size:16px; margin:0; font-weight:600; letter-spacing:.2px; }
 h1 span { color:#58a6ff; }
 .spacer { flex:1; }
 .sub { color:#8b949e; font-size:12px; }
 button { background:#21262d; color:#e6edf3; border:1px solid #30363d;
          border-radius:6px; padding:7px 13px; font-size:13px; cursor:pointer; }
 button:hover { background:#30363d; }
 button:disabled { opacity:.5; cursor:default; }
 #grid { display:grid; gap:14px; padding:18px;
         grid-template-columns:repeat(auto-fit,minmax(360px,1fr)); }
 .tile { background:#161b22; border:1px solid #30363d; border-radius:10px;
         overflow:hidden; }
 .tile .head { display:flex; align-items:center; gap:8px; padding:9px 12px;
               font-size:13px; }
 .dot { width:8px; height:8px; border-radius:50%; background:#484f58; flex:none; }
 .dot.streaming { background:#3fb950; box-shadow:0 0 0 3px rgba(63,185,80,.18); }
 .dot.offline, .dot.error { background:#f85149; }
 .dot.connecting, .dot.discovering, .dot.reconnecting {
   background:#d29922; animation:p 1.2s ease-in-out infinite; }
 @keyframes p { 50% { opacity:.35; } }
 .name { font-weight:600; }
 .ip { color:#8b949e; font-size:12px; font-variant-numeric:tabular-nums; }
 .badge { margin-left:auto; font-size:11px; color:#8b949e; }
 .shot { position:relative; background:#000; aspect-ratio:16/9; }
 .shot img { width:100%; height:100%; object-fit:contain; display:block; }
 .shot .ph { position:absolute; inset:0; display:flex; align-items:center;
             justify-content:center; color:#484f58; font-size:13px;
             text-align:center; padding:10px; }
 .foot { padding:7px 12px; font-size:11px; color:#8b949e;
         border-top:1px solid #21262d; display:flex; gap:12px;
         font-variant-numeric:tabular-nums; min-height:30px; }
 .err { color:#f85149; }
 #banner { background:#9e6a03; color:#fff; padding:8px 20px; font-size:13px; }
 .hidden { display:none; }
</style>

<header>
  <h1><span>Wyze</span> cameras</h1>
  <span class="sub" id="cnt"></span>
  <div class="spacer"></div>
  <button id="refresh">&#8635; Re-discover</button>
</header>
<div id="banner" class="hidden"></div>
<div id="grid"></div>

<script>
const $ = s => document.querySelector(s);

async function j(u, o) {
  const r = await fetch(u, o);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

function tile(c) {
  let el = document.getElementById('c' + c.tid);
  if (!el) {
    el = document.createElement('div');
    el.className = 'tile'; el.id = 'c' + c.tid;
    el.innerHTML =
      '<div class="head"><div class="dot"></div><div class="name"></div>' +
      '<div class="ip"></div><div class="badge"></div></div>' +
      '<div class="shot"><div class="ph">connecting&hellip;</div>' +
      '<img class="hidden" alt=""></div>' +
      '<div class="foot"><span class="f1"></span>' +
      '<span class="f2 err"></span></div>';
    $('#grid').appendChild(el);
  }
  el.querySelector('.name').textContent = c.name || ('Camera ' + c.tid);
  el.querySelector('.ip').textContent = c.ip || '\\u2014';
  el.querySelector('.dot').className = 'dot ' + (c.status || '');
  el.querySelector('.badge').textContent = c.status || '';

  const img = el.querySelector('img'), ph = el.querySelector('.ph');
  // Attach the MJPEG socket as soon as the camera is listed -- requesting it
  // is what makes the server create the worker (HUB.ensure).  Waiting for
  // status === 'streaming' deadlocks: the status can never become 'streaming'
  // unless something asks for the stream first.
  const attach = c.status !== 'offline';
  if (attach && img.classList.contains('hidden')) {
    // Cache-buster so a re-attach always opens a fresh socket rather than
    // reusing a dead one.
    img.src = '/stream/' + c.tid + '.mjpg?r=' + c.seq + '-' + Date.now();
    img.classList.remove('hidden');
    ph.classList.add('hidden');
    img.onerror = () => {
      img.classList.add('hidden');
      ph.classList.remove('hidden');
      ph.textContent = 'waiting for video\\u2026';
    };
  } else if (!attach && !img.classList.contains('hidden')) {
    // Drop the socket when the camera is unreachable; the worker keeps
    // retrying underneath, and we re-attach as soon as it reports anything.
    img.removeAttribute('src');
    img.classList.add('hidden');
    ph.classList.remove('hidden');
  }
  if (img.classList.contains('hidden')) {
    ph.classList.remove('hidden');
    ph.textContent = c.error ? c.error
      : (c.status === 'offline' ? 'camera offline (powered off?)'
        : (c.status || 'starting') + '\\u2026');
  } else {
    ph.classList.add('hidden');
  }

  const s = c.stats || {};
  el.querySelector('.f1').textContent =
    s.jpg ? ((s.fps || 0).toFixed(1) + ' fps \\u00b7 ' + s.jpg + ' frames')
          : (c.status === 'streaming' ? 'starting\\u2026' : '');
  el.querySelector('.f2').textContent = c.error || '';
  if (c.log && c.log.length) el.querySelector('.foot').title = c.log.join('\\n');
}

async function tick() {
  try {
    const d = await j('/api/state');
    const cams = d.cameras || [];
    cams.forEach(tile);
    $('#cnt').textContent = cams.length + (cams.length === 1 ? ' camera' : ' cameras');
    const warn = d.cameras.length === 0
      ? 'No cameras answered discovery. They may be powered off \\u2014 hit Re-discover.'
      : (d.warning || '');
    $('#banner').classList.toggle('hidden', !warn);
    if (warn) $('#banner').textContent = warn;
  } catch (e) {
    $('#banner').classList.remove('hidden');
    $('#banner').textContent = 'server error: ' + e.message;
  }
}

$('#refresh').addEventListener('click', async () => {
  $('#refresh').disabled = true;
  $('#banner').classList.remove('hidden');
  $('#banner').textContent = 'scanning the LAN\\u2026';
  try { await j('/api/discover', {method: 'POST'}); await tick(); }
  catch (e) { $('#banner').textContent = e.message; }
  finally { $('#refresh').disabled = false; }
});

tick();
setInterval(tick, 2000);
</script>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "WyzeCam/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        if os.environ.get("WYZE_HTTP_LOG"):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code, **kw):
        self._send(code, kw)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8", "replace"))
        except Exception:
            return {}

    # -- routes ------------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
        elif path == "/api/state":
            names = load_devices_file()
            self._json(200, cameras=HUB.state(),
                       warning=None if names else
                       "wyze_devices.json not found \\u2014 camera names are "
                       "generic.")
        elif path.startswith("/stream/") and path.endswith(".mjpg"):
            self._stream(path.split("/")[2].split(".")[0])
        else:
            self._json(404, error="not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        self._body()
        if path == "/api/discover":
            notes = []
            found = HUB.refresh(progress=lambda m: notes.append(m))
            if not found:
                notes.append("nothing answered %d broadcast attempts"
                             % DISCOVER_ATTEMPTS)
            self._json(200, found=len(found), ips=sorted(found),
                       note="; ".join(notes))
        else:
            self._json(404, error="not found")

    # -- video -------------------------------------------------------------
    def _stream(self, tid):
        try:
            tid = int(tid)
        except ValueError:
            self._json(404, error="bad camera id")
            return
        w, err = HUB.ensure(tid)
        if err:
            self._json(503, error=err)
            return

        self.send_response(200)
        self.send_header("Content-Type",
                         "multipart/x-mixed-replace; boundary=frame")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        # Drain-and-write polling loop.  Two lessons cost a lot of time here:
        #
        #  1. Waiting on a Condition delivered wakeups at only ~1.7 Hz while the
        #     producer holds the GIL doing pure-Python RC5 -- 29 of 185 frames
        #     served, with socket writes costing 0.00 s.  Every sleep() releases
        #     the GIL, so polling is both simpler and faster here.
        #
        #  2. Keeping only "the newest frame" loses frames outright.  ffmpeg
        #     hands JPEGs over in bursts (the producer is busy decrypting, so the
        #     pipe accumulates), and `seq = cur` jumped over the rest of the
        #     burst: 19 frames served out of 132 published.  take() drains the
        #     whole burst instead.
        served, dead = 0, 0
        # Start at the current head: a new viewer should get LIVE frames, not
        # a burst of up-to-120 stale ones buffered for earlier viewers.
        cursor = w.seq
        t_write = 0.0
        # Per-connection diagnostics.  Only touch keys THIS handler writes --
        # popping a producer-owned key (jpg/h264/fps) races with the worker's
        # `self.stats["h264"] += n` and raises KeyError, which tears down the
        # stream.  Baselines let us report per-connection totals instead.
        for k in ("served", "loops", "t_write", "first_frame_at"):
            w.stats.pop(k, None)
        w.stats["t0"] = time.time()
        w.stats["nconn"] = w.stats.get("nconn", 0) + 1
        base_jpg = w.stats.get("jpg", 0)
        w.stats["base_jpg"] = base_jpg
        try:
            while True:
                frames, cursor = w.take(cursor)
                w.stats["pub"] = w.stats.get("jpg", 0) - base_jpg
                if frames:
                    if served == 0:
                        w.stats["first_frame_at"] = round(
                            time.time() - w.stats["t0"], 1)
                    served += len(frames)
                    w.stats["served"] = served
                    try:
                        t0 = time.time()
                        # one write carrying every frame that accumulated --
                        # a burst must not collapse into a single image
                        self.wfile.write(b"".join(
                            (b"--frame\r\nContent-Type: image/jpeg\r\n"
                             b"Content-Length: %d\r\n\r\n" % len(f))
                            + f + b"\r\n" for f in frames))
                        self.wfile.flush()
                        t_write += time.time() - t0
                        w.stats["t_write"] = round(t_write, 2)
                    except (BrokenPipeError, ConnectionResetError):
                        break
                    dead = 0
                else:
                    time.sleep(0.03)
                    w.stats["loops"] = w.stats.get("loops", 0) + 1
                    if not w.is_alive():
                        dead += 1
                        if dead > 100:      # worker gone for ~3 s
                            break
        except Exception as e:
            w.log("mjpeg stopped: %r" % (e,))
        finally:
            w.log("mjpeg served %d frames (write %.1fs)"
                  % (served, t_write))


def main():
    ap = argparse.ArgumentParser(description="Wyze camera web viewer (LAN only)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default: localhost only)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--discover", action="store_true",
                    help="scan the LAN once and exit")
    args = ap.parse_args()

    if args.discover:
        found = {}
        for _ in range(DISCOVER_ATTEMPTS):
            found = discover(DISCOVER_DURATION)
            if found:
                break
        devs = load_devices_file()
        for ip, d in sorted(found.items()):
            mac = d.get("wyze_id") or ""
            print("%-16s tid=%s port=%-6s %-12s %s"
                  % (ip, d.get("tid"), d.get("p2p_port"),
                     (devs.get(mac) or {}).get("nickname") or "?", mac))
        if not found:
            print("no cameras answered %d attempts" % DISCOVER_ATTEMPTS)
        return 0

    if not HUB.calling:
        print("WARNING: no CALLING frame found in wire/p2p_frames.json;")
        print("         streaming will not work until one is captured.")

    devs = load_devices_file()
    print("Scanning the LAN for cameras...")
    found = HUB.refresh(progress=lambda m: print("  " + m))
    if not found:
        print("  no cameras answered (they may be off) "
              "-- the UI retries every 2 s.")
    for ip, d in sorted(found.items()):
        mac = d.get("wyze_id") or ""
        print("  %-15s %-12s %s"
              % (ip, (devs.get(mac) or {}).get("nickname") or "?", mac))

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    print("\n  ->  http://%s:%d   (Ctrl-C to stop)" % (args.host, args.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        HUB.stop_all()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
