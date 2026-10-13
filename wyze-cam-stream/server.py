#!/usr/bin/env python3
"""
Wyze Cam Stream Server
======================
Stream your own Wyze OG camera through a local web server, using the same
cloud auth + KVS live-view flow as the Hualai/Wyze app (reverse-engineered
from the com.hualai 2.50.7.487 APK — see README.md for the evidence).

Usage:
  pip install requests
  export WYZE_EMAIL=you@example.com WYZE_PASSWORD=secret
  python3 server.py            # serves on http://127.0.0.1:8080
  open http://127.0.0.1:8080    # log in, pick a camera, watch

Endpoints (JSON):
  POST /api/auth                {"email","password"}  -> tokens cached in memory
  GET  /api/devices             list your cameras
  GET  /api/live/{did}?model=   fetch KVS play_url for a camera
  GET  /stream/{did}/live.m3u8  HLS playlist proxy (segments auto-proxied)
  GET  /stream/{did}/proxy?u=   upstream byte proxy (segments)
  GET  /stream/{did}/live.mjpg  MJPEG transcode via ffmpeg (simple <img> tag)
"""

import base64
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import requests

from wyze_client import APP_VERSION, WyzeClient

# ---------------------------------------------------------------- state
_client: WyzeClient | None = None
_client_lock = threading.Lock()
_ffmpeg_path = os.environ.get("FFMPEG", "ffmpeg")


def get_client() -> WyzeClient:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = WyzeClient(app_version=APP_VERSION)
    return _client


# ---------------------------------------------------------------- HLS proxy
def _rewrite_playlist(text: str, base_url: str, did: str) -> str:
    """Rewrite segment/variant URIs in an HLS playlist to local proxy URLs."""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue
        from urllib.parse import urljoin
        abs_uri = urljoin(base_url, stripped)
        enc = base64.urlsafe_b64encode(abs_uri.encode()).decode().rstrip("=")
        out.append(f"/stream/{did}/proxy?u={enc}&m3u8=1")
    return "\n".join(out) + "\n"


def proxy_upstream(url: str, as_playlist: bool, did: str, client: WyzeClient):
    """Fetch an upstream playlist/segment; rewrite playlists, stream bytes."""
    r = requests.get(url, headers={"User-Agent": "Wyze/2.50"}, timeout=30,
                     stream=not as_playlist)
    r.raise_for_status()
    if as_playlist:
        ctype = "application/vnd.apple.mpegurl"
        body = _rewrite_playlist(r.text, url, did).encode()
    else:
        ctype = r.headers.get("Content-Type", "video/MP2T")
        body = r.content
    return ctype, body


# ---------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    server_version = "WyzeCamStream/1.0"

    def log_message(self, fmt, *args):  # quieter logs
        pass

    # ---- helpers --------------------------------------------------------
    def _json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code: int, body: str, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _bytes(self, code: int, data: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---- routes ----------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        parts = [p for p in path.split("/") if p]

        try:
            if path == "/" or path == "/index.html":
                return self._text(200, UI_HTML)
            if path == "/api/devices":
                return self._json(200, {"devices": get_client().device_list()})

            if len(parts) == 3 and parts[0] == "api" and parts[1] == "live":
                did = parts[2]
                model = parse_qs(urlparse(self.path).query).get("model", [""])[0]
                client = get_client()
                try:
                    url = client.kvs_live_url(did, model)
                except RuntimeError:
                    client.refresh()
                    url = client.kvs_live_url(did, model)
                return self._json(200, {"play_url": url, "device_id": did})

            if len(parts) == 3 and parts[0] == "stream":
                did, kind = parts[1], parts[2]
                if kind == "live.m3u8":
                    return self._hls_playlist(did, master=True)
                if kind == "live.mjpg":
                    return self._mjpeg(did)

            if len(parts) == 3 and parts[0] == "stream" and parts[2] == "proxy":
                did = parts[1]
                q = parse_qs(urlparse(self.path).query)
                url = base64.urlsafe_b64decode(
                    unquote(q.get("u", [""])[0]) + "===").decode()
                ctype, body = proxy_upstream(
                    url, as_playlist="m3u8" in q, did=did, client=get_client())
                return self._bytes(200, body, ctype)

            return self._json(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": str(e)})

    def do_POST(self):
        path = urlparse(self.path).path
        client = get_client()
        if path == "/api/auth":
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
                data = client.login(payload["email"], payload["password"])
                if data.get("mfa_required"):
                    return self._json(200, {"mfa_required": True})
                return self._json(200, {"ok": True, "user_id": data.get("user_id")})
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"error": str(e)})
        if path == "/api/mfa/send":
            try:
                client.mfa_send_code()
                return self._json(200, {"ok": True})
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"error": str(e)})
        if path == "/api/mfa/verify":
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
                data = client.mfa_verify_code(payload["code"])
                return self._json(200, {"ok": True, "user_id": data.get("user_id")})
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"error": str(e)})
        return self._json(404, {"error": "not found"})

    # ---- stream helpers --------------------------------------------------
    def _hls_playlist(self, did: str, master: bool):
        client = get_client()
        # Re-resolve the live URL (fresh, short-lived) and proxy the playlist.
        devices = client.device_list()
        dev = next((d for d in devices if d.get("did") == did), None)
        if dev is None:
            return self._json(404, {"error": f"device {did} not found"})
        model = dev.get("product_model") or ""
        try:
            url = client.kvs_live_url(did, model)
        except RuntimeError:
            client.refresh()
            url = client.kvs_live_url(did, model)
        ctype, body = proxy_upstream(url, as_playlist=True, did=did, client=client)
        return self._bytes(200, body, ctype)

    def _mjpeg(self, did: str):
        client = get_client()
        devices = client.device_list()
        dev = next((d for d in devices if d.get("did") == did), None)
        if dev is None:
            return self._json(404, {"error": f"device {did} not found"})
        url = client.kvs_live_url(did, dev.get("product_model") or "")
        proc = subprocess.Popen(
            [_ffmpeg_path, "-hide_banner", "-loglevel", "error",
             "-headers", "User-Agent: Wyze/2.50\r\n",
             "-i", url, "-f", "mjpeg", "-q:v", "4", "-r", "8", "-"],
            stdout=subprocess.PIPE,
        )

        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        self.end_headers()
        try:
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.kill()


UI_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Wyze Cam Stream</title>
<style>
 body{font-family:system-ui;max-width:960px;margin:2rem auto;padding:0 1rem;background:#0f1115;color:#e6e6e6}
 input,button{padding:.5rem .8rem;border-radius:6px;border:1px solid #444;background:#1c1f26;color:#eee}
 button{cursor:pointer;background:#2f6fed;border:none}
 .row{display:flex;gap:.5rem;margin:.5rem 0;flex-wrap:wrap}
 video,img{max-width:100%;border-radius:8px;background:#000}
 .dev{padding:.6rem;border:1px solid #333;border-radius:8px;margin:.4rem 0;display:flex;justify-content:space-between;align-items:center}
</style></head><body>
<h1>Wyze Cam Stream</h1>
<div class="row">
 <input id="email" placeholder="email" size="24">
 <input id="pw" type="password" placeholder="password" size="20">
 <button onclick="auth()">Log in</button>
 <span id="msg"></span>
</div>
<div class="row" id="mfa" style="display:none">
 <input id="mfaCode" placeholder="2FA code (sent to your email)" size="20">
 <button onclick="mfaVerify()">Verify code</button>
</div>
<div id="cams"></div>
<div id="view"></div>
<script>
async function auth(){
  const r = await fetch('/api/auth',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:email.value,password:pw.value})});
  const d = await r.json();
  if(d.mfa_required){
    msg.textContent = '2FA required — enter the code sent to your email';
    mfa.style.display='flex';
    await fetch('/api/mfa/send',{method:'POST'});   // trigger the email code
    mfaCode.focus();
    return;
  }
  msg.textContent = d.ok ? ('logged in as '+d.user_id) : ('error: '+d.error);
  if(d.ok) loadCams();
}
async function mfaVerify(){
  const r = await fetch('/api/mfa/verify',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({code:mfaCode.value})});
  const d = await r.json();
  if(d.ok){ msg.textContent='logged in as '+d.user_id; mfa.style.display='none'; loadCams(); }
  else msg.textContent = 'error: '+(d.error||'bad code');
}
async function loadCams(){
  const d = await (await fetch('/api/devices')).json();
  cams.innerHTML = (d.devices||[]).map(x=>
    `<div class="dev"><span>${x.nickname||x.did} <small>(${x.product_model})</small></span>
     <button onclick="play('${x.did}','${x.product_model||''}')">Live</button></div>`).join('') || 'no devices';
}
async function play(did, model){
  view.innerHTML = 'starting stream…';
  view.innerHTML = `<video id="v" controls autoplay></video>
    <div class="row"><button onclick="still('${did}')">MJPEG fallback</button></div>`;
  if (Hls.isSupported()) {
    const hls = new Hls();
    hls.loadSource(`/stream/${did}/live.m3u8`);
    hls.attachMedia(document.getElementById('v'));
  } else if (document.getElementById('v').canPlayType('application/vnd.apple.mpegurl')) {
    document.getElementById('v').src = `/stream/${did}/live.m3u8`;
  } else {
    still(did);
  }
}
function still(did){
  view.innerHTML = `<img src="/stream/${did}/live.mjpg">`;
}
</script>
<script src="https://cdn.jsdelivr.net/npm/hls.js@1"></script>
</body></html>"""


def main():
    host = os.environ.get("WYZE_HOST", "127.0.0.1")
    port = int(os.environ.get("WYZE_PORT", "8080"))
    if os.environ.get("WYZE_EMAIL") and os.environ.get("WYZE_PASSWORD"):
        c = get_client()
        c.login(os.environ["WYZE_EMAIL"], os.environ["WYZE_PASSWORD"])
        print(f"[wyze] logged in as {c.email} (user {c.user_id})")
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"[wyze] serving http://{host}:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
