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

Browser side -- ONE connection for all video, not one per camera::

    GET /feed   fetch() once, every camera multiplexed  ->  <canvas> per tile

Sockets the page holds: 1 for /feed plus one ``<audio>`` per camera you switch
on.  This matters more than it sounds: Chrome allows only six HTTP/1.1
connections per origin, so the old one-MJPEG-socket-per-camera design used four
slots on video alone and left ``/api/state`` polls and the snapshot button
queued in "pending" forever -- that, not the camera or the decoder, is what made
the page feel slow.  Frame sizes are ~34 KB, so four cameras is ~1.4 MB/s on the
LAN; the snapshot button now re-encodes the canvas locally and needs no
connection at all.

Each frame carries the instant it was published, so the page prints the real
end-to-end delay (published -> painted) in every tile's footer, measured by the
browser itself.  On this Mac it reads single digits to low tens of ms.

Focus::

    Fullscreen a tile and the page reopens its one /feed as
    ``/feed?focus=<tid>`` -- the other tiles freeze on their last frame and,
    after a short grace, Hub._supervise drops those cameras' workers entirely
    (ffmpeg + P2P session + memory).  Leaving fullscreen returns to the grid
    and everything reconnects cold.  Partly this is bandwidth; mostly it is
    that the P2P sessions are exclusive per camera, so an unfocused server
    should not be holding them.

Usage::

    python3 server.py                  # http://127.0.0.1:8080
    python3 server.py --port 9000 --bind 0.0.0.0
    python3 server.py --discover       # scan the LAN once and exit

Only the Python standard library and an ``ffmpeg`` on PATH are required.
"""
import argparse
import collections
import contextlib
import json
import os
import shutil
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
from discover import broadcast_addrs, local_ipv4      # noqa: E402
import p2p_call                                       # noqa: E402
import wiregrab                                       # noqa: E402

DEVICES_FILE = os.path.join(ROOT, "wyze_devices.json")

# Discovery is flaky (~3 s window, sometimes silent) -- retry rather than
# concluding a camera is offline after one bad sample.
DISCOVER_ATTEMPTS = 3
DISCOVER_DURATION = 3.0
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
# How stale a frame may be before a viewer stops replaying it and jumps to the
# newest one instead.  At ~20 fps this is ~10 frames.  It has to sit well above
# ffmpeg's natural output burst (we have seen 7 JPEGs arrive at once, because
# the producer spends its time decrypting and the pipe fills in between), or it
# would drop frames from healthy viewers.  Chosen so a viewer can never be more
# than half a second behind the camera.
MAX_LAG = 0.5

# Focus (see Hub.viewing / Hub._supervise): a camera that has lost every viewer
# keeps running only through this dwell before its session is dropped.  Long
# enough that a quick fullscreen open/close costs no cold re-handshake, short
# enough that the other cameras really do stop streaming while one is focused.
# The supervisor ticks twice a second.
PAUSE_DWELL = 3.0
PAUSE_TICK = 0.5

# The worker feeds ffmpeg through a blocking stdin pipe.  If ffmpeg ever stops
# consuming it, that write never returns and no in-loop check can run -- the
# camera shows "streaming" while frozen until the server is restarted.  An
# independent watchdog kills ffmpeg after this long without a completed loop
# iteration; write() then raises and the normal reconnect path takes over.
# A healthy iteration is a 50 ms pump plus one write, so this is ~200x headroom.
PIPE_STALL = 12.0
# Input can keep arriving while the decoder itself is wedged (or fed a stream
# it cannot parse).  If no JPEG has been published for this long even though
# H.264 is flowing, recycle the session rather than showing a frozen picture.
DECODER_STALL = 15.0
# Last-resort Hub check: a worker that still says "streaming" but has published
# nothing for this long is wedged somewhere the in-worker watchdog cannot see
# (or could not break).  The Hub then closes its socket/kills ffmpeg so the
# thread can unwind and be replaced.  Well above both timeouts above, so the
# normal recovery path always gets there first.
WORKER_STALL = 40.0

# The stream request (AvStreamCtl) can ask the camera for either its 1080p
# profile (definition 2) or the 640x360 sub-stream (0).  A camera that refuses
# the HD request answers with no media at all, not with the SD fallback, so a
# run that produced zero bytes of H.264 is the signal to try again -- and only
# after this many consecutive empty runs does the worker stop asking.
# Override the starting value with WYZE_DEFINITION.
HD_RETRIES = 3

# ...but a refusal is a pause, not a verdict.  The common cause is that our own
# previous session has not timed out on the camera yet -- which is exactly what
# killing and restarting the server looks like from the camera's side -- and it
# clears by itself within a minute.  So after serving this long on the SD
# sub-stream the worker asks for HD again, doubling the pause after each further
# refusal (60 s, 2 min, 4 min ... capped at SD_REPROBE_MAX).  Without this, one
# unlucky cold start costs 1080p for the life of the worker, with no way back
# short of another restart.
SD_REPROBE = 60.0
SD_REPROBE_MAX = 600.0

# The camera sends G.711 mu-law, one byte per sample.  Every audio AV frame
# carries exactly 320 samples and its u32 timestamp advances 20000 us
# (measured: 377 of 487 successive gaps were exactly 0x4e20, and the whole
# timestamp span came out at 11.94 s against a 12.00 s wall clock -- so the
# unit really is microseconds).  320 samples / 20 ms = 16 kHz, NOT the 8 kHz
# this used to claim, and browsers vary in whether they decode a mu-law WAV,
# so convert to 16 kHz mono PCM16 here and serve plain PCM.  audioop is gone
# in Python 3.13, hence the hand-rolled table.
SAMPLE_RATE = 16000

# -- client -> camera audio ("talk") ---------------------------------------
#
# This is the only thing the page SENDS.  The camera keeps ONE session per
# conv, so our audio cannot open its own CameraStream -- it would fight the
# video worker for the session.  It rides the socket the worker is already
# pumping, and the worker (not the HTTP thread) does the packing, because that
# socket has exactly one owner.
#
# Wire format, and why the encoder is told 8 kHz, are in ../P2P_PROTOCOL.md 13.
TALK_MIC_HZ = 16000            # what the page asks for, and usually gets
TALK_MIC_MIN_HZ = 8000         # ... but it is the browser's choice, so the
TALK_MIC_MAX_HZ = 96000        # client reports what it really captured (talk_begin)
TALK_FRAMES_PER_PKT = 6        # six 20 ms AMR-NB frames = 120 ms per packet
TALK_PKT_SECONDS = 0.120
TALK_IDLE_TIMEOUT = 2.0        # no PCM for this long -> close the session
# HOW FAST THE CAMERA EATS WHAT WE SEND.  Measured on Camera 1 (2026-10-16,
# JOURNAL Phase 22): its talk output runs a 16 kHz DAC over our 8 kHz AMR, so
# it plays each 160-sample (20 ms) frame in 10 ms -- 2x fast, matching the
# 16 kHz / 320 samples that the app's own open frame declares.  A 1 kHz tone
# whose wire content we verified with ffmpeg came out of the camera's speaker
# at 2000 Hz, and at a 1x feed it spoke for only 51% of the time.  Two
# consequences, and the fix is the inverse of each:
#   1. pitch and timeline -- anything we hand over comes back an octave up and
#      2x fast, so we hand over content that is deliberately 2x SLOW
#      (asetrate=8000) and the camera's 2x puts it back to natural.
#   2. starvation -- it consumes 2.0 declared seconds per real second, so a
#      120 ms packet has to leave every 60 ms.  Feeding at 1x left it silent
#      half the time, which is what "sounds cut, sounds cut" was.
TALK_CAMERA_PLAYOUT = 0.5      # real seconds the camera spends per declared s
TALK_PKT_REAL_SECONDS = TALK_PKT_SECONDS * TALK_CAMERA_PLAYOUT    # 60 ms
# The content rate for the default 16 kHz client; talk_begin derives the same
# number from whatever rate the page reports it actually captured at.
TALK_CONTENT_HZ = int(TALK_MIC_HZ * TALK_CAMERA_PLAYOUT)          # 8000
# Head start given to the camera's own jitter buffer when talk opens.  It is
# pure added latency, so it is deliberately small: enough to cover the pump
# loop's jitter, not enough to be heard as an echo.
TALK_PREBUFFER = 3 * TALK_PKT_REAL_SECONDS        # 0.18 s
# Jitter buffer between ffmpeg and the camera.  It has to be deep enough to
# ride out a slow pump iteration but shallow enough not to be heard: the queue
# IS latency.  24 frames = 480 ms declared, i.e. 240 ms of real audio, because
# the camera plays it at 2x.
TALK_QUEUE_FRAMES = 4 * TALK_FRAMES_PER_PKT
# The pump loop's cadence is set by the VIDEO side, not by talk, so one packet
# per iteration is not the same as one packet per 120 ms.  Allow the tick to
# send the packets it is behind by, but not more than this per call.
TALK_MAX_BURST = 3
# Speech bytes per AMR-NB mode, the ToC octet aside (RFC 4867 table 1).  We
# always encode 12.2 kbit/s (mode 7, 31 bytes), but a silent mic makes the
# encoder emit NO_DATA/SID frames, so the table has to be complete or the
# parser drifts out of sync with the stream.
AMR_PAYLOAD_BYTES = (12, 13, 15, 17, 19, 20, 26, 31, 5, 0, 0, 0, 0, 0, 0, 0)


def _ulaw_decode(u):
    """One G.711 mu-law byte -> signed 16-bit linear sample."""
    u = (~u) & 0xFF
    t = (((u & 0x0F) << 3) + 0x84) << ((u & 0x70) >> 4)
    return (0x84 - t) if (u & 0x80) else (t - 0x84)


_ULAW_TABLE = bytes().join(struct.pack("<h", _ulaw_decode(b)) for b in range(256))


def ulaw_to_pcm16(data, gain=1):
    """bytes of mu-law -> bytes of little-endian signed 16-bit PCM.

    `gain` multiplies before clipping.  The camera's mic idles around
    -76 dBFS (see JOURNAL Phase 15: per-second rms 2-4 of 32767, 85 % digital
    zero), so without gain the stream is technically correct but inaudible;
    the app has an AGC step we never found, this is ours.
    """
    if gain == 1:
        tbl = _ULAW_TABLE
        out = bytearray(len(data) * 2)
        mv = memoryview(out)
        for i, b in enumerate(data):
            mv[2 * i:2 * i + 2] = tbl[2 * b:2 * b + 2]
        return bytes(out)
    out = bytearray(len(data) * 2)
    mv = memoryview(out)
    for i, b in enumerate(data):
        v = _ulaw_decode(b) * gain
        if v > 32767:
            v = 32767
        elif v < -32768:
            v = -32768
        mv[2 * i:2 * i + 2] = struct.pack("<h", v)
    return bytes(out)


# --------------------------------------------------------------------------
# camera names -- read from the local cache, never fetched at runtime
# --------------------------------------------------------------------------
def load_devices_file():
    """Nicknames keyed by the "CAM-1_xxxxxxxxxxxx" id discovery reports."""
    if not os.path.exists(DEVICES_FILE):
        return {}
    try:
        raw = json.load(open(DEVICES_FILE, encoding="utf-8"))
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
        self.status_since = time.time()
        self.error = None
        # Live pipeline objects, so the Hub can break a wedged worker out of a
        # blocking pipe/socket call instead of waiting for a server restart.
        self._live_lock = threading.Lock()
        self._live_ff = None
        self._live_st = None
        self._forced_at = 0.0
        self.frame = b""
        self.seq = 0
        # Frames are buffered, not just "latest wins": ffmpeg hands JPEGs over
        # in bursts (the producer spends its time decrypting network packets,
        # so the pipe accumulates).  With a single `self.frame` slot a burst of
        # 7 collapsed into ONE delivery -- measured 19 frames served out of 132
        # published, because `seq = cur` jumped over the skipped ones.
        self.frames = collections.deque(maxlen=120)
        self.stats = {"h264": 0, "jpg": 0, "fps": 0.0, "last": 0.0}
        self.audio_stats = {"bytes": 0, "chunks": 0}
        self.audio_chunks = collections.deque(maxlen=200)
        self.audio_last_t = 0.0        # when the newest audio chunk was published
        self._audio_cond = threading.Condition()
        self._cond = threading.Condition()
        self._stop = threading.Event()
        self._on_status = on_status
        self._log = []
        # 2 = the camera's 1080p profile, 0 = its 640x360 sub-stream.  The
        # definition lives in the 108-byte v2 AvStreamCtl (kcpav.avstreamctl_v2).
        # If a camera refuses the HD request (no media at all) the worker drops
        # to SD and re-asks for HD a while later -- see SD_REPROBE.
        try:
            self.definition = int(os.environ.get("WYZE_DEFINITION", "2"))
        except ValueError:
            self.definition = 2
        self.hd_start = self.definition   # what to go back to after SD
        self.hd_fails = 0
        self.sd_since = 0.0               # when the SD fallback began; 0 = on HD
        self.sd_reprobe = SD_REPROBE      # current pause before re-asking
        self.stats["definition"] = self.definition   # so the page can see it
        # -- two-way audio (see talk_begin/talk_feed/talk_end) -------------
        self.talk_lock = threading.Lock()
        self.talk_on = False              # the page is holding its talk button
        self.talk_opened = False          # the opening frames have been sent
        self.talk_next = 0.0              # when the next packet may go out
        self.talk_frames = collections.deque(maxlen=TALK_QUEUE_FRAMES)  # payloads
        self.talk_ff = None               # the AMR encoder
        self.talk_stop = None
        self.talk_mic_hz = TALK_MIC_HZ     # rate the client reported (talk_begin)
        self.talk_dry = False              # counting only, nothing to a camera
        self.talk_first = 0.0              # first PCM of this session, for the rate
        self.talk_srcs = set()             # client connections that fed this session
        self.talk_text_said = False        # already complained about a text body
        self.talk_stats = {"pcm_bytes": 0, "frames": 0, "packets": 0,
                           "audio_ms": 0, "last_pcm": 0.0,
                           "posts": 0, "maxpost": 0}

    # -- helpers -----------------------------------------------------------
    def log(self, msg):
        self._log = (self._log + ["%s %s" % (time.strftime("%H:%M:%S"), msg)])[-40:]

    def set_status(self, s, err=None):
        if s != self.status:
            self.status_since = time.time()
        self.status, self.error = s, err
        if self._on_status:
            try:
                self._on_status()
            except Exception:
                pass

    def force_restart(self, why):
        """Break a wedged pipeline from outside the worker thread.

        The Hub calls this when a worker still claims "streaming" but has not
        published a JPEG for far longer than any in-worker timeout.  Killing
        ffmpeg and closing the UDP socket makes a blocked write/select return;
        _stop then makes the pump loop exit and the supervisor starts a fresh
        worker.  Without this the only recovery was restarting the server.
        """
        now = time.time()
        if now - self._forced_at < 10.0:      # one attempt per 10 s
            return False
        self._forced_at = now
        self.log("hub watchdog: %s -- forcing a restart" % why)
        self._stop.set()
        with self._live_lock:
            ff, st = self._live_ff, self._live_st
        for closer in (ff.kill if ff else None, st.close if st else None):
            if closer is None:
                continue
            try:
                closer()
            except Exception:
                pass
        return True

    def take(self, since_seq=0):
        """Return `([(jpeg, t_pub), ...], cursor)` for frames past `since_seq`.

        Nothing is consumed: several browsers (or a browser plus a test
        client) can watch the same camera at once.  A draining take() would
        hand each frame to exactly one viewer and split the stream between
        them.  Each caller keeps its own cursor; frames age out of the bounded
        deque once 120 have accumulated, so a viewer that falls that far behind
        skips ahead rather than growing without limit.

        The publish time rides along with each frame so a slow viewer can be
        BOUNDED rather than merely evicted: Handler._stream drops to the newest
        frame once the backlog is older than MAX_LAG.  Without that a browser
        reading marginally slower than we write accumulates a backlog, replays
        it, and then stays that far behind reality for the rest of the session
        -- which is exactly what "the cameras are delayed" looks like.
        """
        with self._cond:
            got = [(s, j, t) for s, j, t in self.frames if s > since_seq]
            return ([(j, t) for _, j, t in got],
                    (got[-1][0] if got else since_seq))

    def take_audio(self, since_seq=0):
        """Return `(chunks, cursor)` for every audio chunk newer than `since_seq`."""
        with self._audio_cond:
            got = [(s, c) for s, c in self.audio_chunks if s > since_seq]
            return [c for _, c in got], (got[-1][0] if got else since_seq)

    def audio_tail(self):
        """Newest audio sequence.

        A fresh listener starts here: starting at 0 would replay the whole
        200-chunk backlog (~2 s of stale audio) as one burst the moment the
        user presses SOUND.
        """
        with self._audio_cond:
            return self.audio_chunks[-1][0] if self.audio_chunks else 0

    def _publish(self, jpeg):
        with self._cond:
            self.seq += 1
            self.frames.append((self.seq, jpeg, time.time()))
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
                          local_port=0, timeout=12.0, on_log=self.log,
                          definition=self.definition)
        # The camera is now asked for its 1080p profile, so the frames that
        # arrive are 1920x1080.  Encoding four of those to JPEG every frame
        # pins the CPU (measured: ~10 % idle at native vs ~54 % at 960 and
        # ~66 % at 1280) and a saturated encoder IS user-visible delay, so the
        # default scales down to 1280 wide -- still 4x the pixels of the old
        # 640x360, at only ~2.5x the bytes.  WYZE_WIDTH=0 keeps the camera's
        # native 1920x1080 for maximum sharpness; any other width scales.
        width = int(os.environ.get("WYZE_WIDTH", "1280"))
        vf = ["-vf", "scale=%d:-2" % width] if width > 0 else []
        try:
            ff = subprocess.Popen(
                ["ffmpeg", "-loglevel", "error",
                 "-probesize", "32", "-analyzeduration", "0",
                 "-f", "h264", "-i", "pipe:0",
                 "-an"] + vf + [
                 "-f", "mjpeg", "-q:v", "5", "pipe:1"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        except Exception:
            st.close()                 # do not leak the bound UDP socket
            raise
        with self._live_lock:
            self._live_ff, self._live_st = ff, st
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

        # ffmpeg's stderr is a pipe too.  `-loglevel error` still prints one
        # line per corrupt frame, so a stream cut mid-GOP -- exactly what
        # happens when the official app takes the camera -- can fill the pipe
        # buffer.  ffmpeg then blocks writing stderr, stops reading stdin, and
        # the blocking ff.stdin.write() below wedges the worker forever.  That
        # was the "camera needs a server restart" failure.  Drain stderr and
        # keep only the tail for the worker's log ring.
        def _drain_err():
            tail = collections.deque(maxlen=6)
            while not stop_drain.is_set():
                try:
                    line = ff.stderr.readline()
                except (OSError, ValueError):
                    break
                if not line:
                    break
                text = line.decode("utf-8", "replace").strip()
                if text:
                    tail.append(text)
            for text in tail:
                self.log("ffmpeg: " + text)

        err_drain = threading.Thread(target=_drain_err, daemon=True,
                                     name="fferr-%s" % self.camera["tid"])
        err_drain.start()

        # Independent progress watchdog.  The 8 s input-stall check lives
        # inside the loop below, so it cannot fire while that loop is blocked
        # in ff.stdin.write().  If no iteration completes for PIPE_STALL
        # seconds, kill ffmpeg: the pending write raises, the loop exits, and
        # _cycle re-handshakes.  wd_fired then forces a fresh discovery too,
        # because the camera's P2P port may have changed while the app had it.
        hb = {"t": time.time()}
        wd_stop = threading.Event()
        wd_fired = threading.Event()

        def _watchdog():
            while not wd_stop.wait(1.0):
                idle = time.time() - hb["t"]
                if idle > PIPE_STALL:
                    self.log("watchdog: no pipeline progress for %.0fs -- "
                             "killing ffmpeg" % idle)
                    wd_fired.set()
                    try:
                        ff.kill()
                    except Exception:
                        pass
                    return

        watchdog = threading.Thread(target=_watchdog, daemon=True,
                                    name="wd-%s" % self.camera["tid"])
        watchdog.start()

        h264_before = self.stats["h264"]
        # Single pump loop: feed video AND audio from one CameraStream
        last_h264 = time.time()
        audio_cursor = 0
        jpg_mark = self.stats["jpg"]
        last_jpg_t = time.time()
        try:
            st.start()  # handshake + KCP up + AvStreamCtl
            for _ in range(1000000):  # effectively infinite
                hb["t"] = time.time()       # watchdog heartbeat
                if self._stop.is_set():
                    break
                st._pump(0.05, [(st.kcp_lo.conv, st.kcp_lo),
                                 (st.kcp_hi.conv, st.kcp_hi)])

                # Video: feed ffmpeg
                if st._buf:
                    chunk = bytes(st._buf)
                    del st._buf[:]
                    self.stats["h264"] += len(chunk)
                    last_h264 = time.time()
                    try:
                        ff.stdin.write(chunk)
                        ff.stdin.flush()
                    except (BrokenPipeError, ValueError, OSError):
                        break

                # Audio: queue chunks for the audio endpoint
                if st._abuf:
                    with self._audio_cond:
                        audio_cursor += 1
                        self.audio_chunks.append((audio_cursor, bytes(st._abuf)))
                        self.audio_last_t = time.time()
                        self.audio_stats["bytes"] += len(st._abuf)
                        self.audio_stats["chunks"] += 1
                        self._audio_cond.notify_all()
                    del st._abuf[:]

                # Talk: this camera's own voice, pushed on the same session.
                self._talk_tick(st, time.time())

                # Output stall: H.264 is still arriving (last_h264 was just
                # refreshed) but ffmpeg has published no JPEG.  That is a wedge
                # the input check below can never see, so recycle instead of
                # serving a frozen picture indefinitely.
                if self.stats["jpg"] != jpg_mark:
                    jpg_mark = self.stats["jpg"]
                    last_jpg_t = time.time()
                elif time.time() - last_jpg_t > DECODER_STALL:
                    raise RuntimeError(
                        "decoder stalled: H.264 in, no JPEG out")

                # stall check
                if time.time() - last_h264 > 8.0:
                    raise RuntimeError("stream stalled")

        finally:
            stop_drain.set()
            # A talk session outlives this stream's life: the camera holds one
            # session, so the encoder has to go with it or it keeps pushing.
            self.talk_end()
            # Kill ffmpeg BEFORE closing its stdin.  close() flushes, and that
            # flush is the same blocking pipe write the watchdog exists to
            # break; with the child gone it simply raises EPIPE and is caught.
            for closer in (ff.kill, lambda: ff.stdin.close(), st.close):
                try:
                    closer()
                except Exception:
                    pass
            wd_stop.set()
            for th in (drain, err_drain, watchdog):
                try:
                    th.join(timeout=2.0)
                except Exception:
                    pass
            with self._live_lock:
                self._live_ff = self._live_st = None
            # An AvStreamCtl the camera dislikes leaves us with NO media at
            # all, not the SD fallback -- so a run that produced zero bytes of
            # H.264 is the signal to retry, and only a few consecutive such
            # runs mean the camera is not doing HD *right now*.
            if self.stats["h264"] != h264_before:
                self.hd_fails = 0            # this session produced video
                # Serving SD successfully is the cue to try HD again: the
                # refusal was usually our own session not having timed out on
                # the camera yet, and that clears within a minute.  Backing off
                # keeps a genuinely SD-only camera cheap to live with -- one
                # short probe every few minutes rather than a permanent flap.
                if (self.definition != self.hd_start and self.sd_since
                        and time.time() - self.sd_since >= self.sd_reprobe):
                    self.log("served SD for %.0fs -- asking for definition=%d "
                             "again" % (time.time() - self.sd_since,
                                        self.hd_start))
                    self.definition = self.hd_start
                    self.sd_since = 0.0
                    self.sd_reprobe = min(self.sd_reprobe * 2, SD_REPROBE_MAX)
                    self.stats["definition"] = self.definition
            elif self.definition != 0:
                self.hd_fails += 1
                if self.hd_fails >= HD_RETRIES:
                    self.log("definition=%d gave no video %d times -- using "
                             "the SD sub-stream (640x360)"
                             % (self.definition, self.hd_fails))
                    self.definition = 0
                    self.sd_since = time.time()
                    self.stats["definition"] = self.definition
                else:
                    self.log("definition=%d gave no video (attempt %d/%d)"
                             % (self.definition, self.hd_fails, HD_RETRIES))
            self.set_status("reconnecting")

        # A watchdog kill means the pipeline stopped consuming input: restart
        # from discovery rather than trusting a session that may have been
        # taken over by the app.  Raising (instead of returning) makes run()
        # drop the cached P2P port and back off.
        if wd_fired.is_set():
            raise RuntimeError("pipeline watchdog restarted the session")

    # -- two-way audio (client -> camera) ----------------------------------
    def talk_begin(self, rate=None, dry=False):
        """Open a talk session.  Returns None on success, else an error string.

        The camera is only reachable through the worker's own CameraStream, so
        "begin" means: start an AMR encoder and mark the stream open.  The first
        actual bytes (the two opening frames, then 120 ms packets) go out from
        _talk_tick on the pump thread.

        `rate` is the sample rate the client really captured at (the page hands
        us its AudioContext's rate).  The page *asks* for 16 kHz but is not
        obliged to give us one -- a browser may hand back the hardware rate --
        and a mislabelled input is a pitch error we cannot hear from this end,
        so we trust the report and build the encoder around it.  asetrate is
        always half of the input rate, which keeps the 2x declared/real the
        camera wants true whatever that rate is.

        `dry` opens a session that accepts and counts the client's PCM but
        starts no encoder and sends nothing: the whole capture path can then be
        exercised from a browser without a camera hearing any of it.  See the
        ?drytalk=1 flag in PAGE.
        """
        with self.talk_lock:
            if self.talk_on:
                return None
            if not dry and self.status not in ("streaming",):
                return "camera is %s, not streaming" % self.status
            try:
                mic_hz = int(rate) if rate else TALK_MIC_HZ
            except (TypeError, ValueError):
                mic_hz = TALK_MIC_HZ
            if not TALK_MIC_MIN_HZ <= mic_hz <= TALK_MIC_MAX_HZ:
                return "client sample rate %s out of range" % rate
            content_hz = int(mic_hz * TALK_CAMERA_PLAYOUT)
            ff = None
            if not dry:
                cmd = ["ffmpeg", "-loglevel", "error", "-nostdin",
                       # Without these, ffmpeg fills an input buffer before it
                       # emits anything and the camera hears the first word of a
                       # sentence seconds late.  Same trap as the video pipe.
                       "-probesize", "32", "-analyzeduration", "0",
                       "-f", "s16le", "-ar", str(mic_hz), "-ac", "1",
                       "-i", "pipe:0",
                       # asetrate *relabels* the incoming samples at half the
                       # rate they were captured at: the same samples, twice the
                       # declared duration, half the pitch -- the content the
                       # camera's own 2x playout expects (see
                       # TALK_CAMERA_PLAYOUT).  aresample then guarantees the
                       # 8 kHz stream libopencore_amrnb insists on really is
                       # 8 kHz.
                       "-af", "asetrate=%d,aresample=8000" % content_hz,
                       "-ar", "8000", "-ac", "1",
                       "-c:a", "libopencore_amrnb", "-b:a", "12.2k",
                       "-f", "amr", "pipe:1"]
                try:
                    ff = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL)
                except OSError as e:
                    return "cannot start ffmpeg: %s" % e
            self.talk_ff = ff
            self.talk_mic_hz = mic_hz
            self.talk_dry = bool(dry)
            self.talk_stop = threading.Event()
            self.talk_frames = collections.deque(maxlen=TALK_QUEUE_FRAMES)
            self.talk_opened = False
            self.talk_next = 0.0
            self.talk_first = 0.0
            self.talk_srcs = set()
            self.talk_text_said = False
            self.talk_stats.update({"pcm_bytes": 0, "frames": 0,
                                    "packets": 0, "audio_ms": 0, "last_pcm": 0.0,
                                    "posts": 0, "maxpost": 0})
            self.talk_on = True
            if ff:
                threading.Thread(target=self._talk_reader, daemon=True,
                                 name="talk-%s" % self.camera["tid"]).start()
            self.log("talk: %s opened (client %d Hz -> %d Hz content)"
                     % ("dry run" if dry else "session", mic_hz, content_hz))
            return None

    def _talk_reader(self):
        """ffmpeg's AMR bytes -> talk_frames, as 31-byte payloads (no ToC).

        read1, not read: read(n) on a pipe BLOCKS until it has all n bytes, and
        the encoder only produces ~1.6 kB/s (12.2 kbit/s), so read(1024) sat
        there for ~640 ms and then handed up ~32 frames in one lump.  The queue
        is 24 frames deep, so two thirds of every lump was thrown away and the
        camera got fragmentary audio -- which is exactly what "the sound is
        awful" was.  read1 returns as soon as anything has arrived, the same
        lesson the video drain thread learned (see _drain above).
        """
        ff, stop = self.talk_ff, self.talk_stop
        buf = bytearray()
        hdr_done = False
        while not stop.is_set():
            try:
                b = ff.stdout.read1(4096)
            except (OSError, ValueError):
                break
            if not b:
                break                       # encoder exited
            buf += b
            if not hdr_done and len(buf) >= 6:
                if bytes(buf[:6]) == b"#!AMR\n":
                    del buf[:6]
                hdr_done = True
            while buf:
                size = AMR_PAYLOAD_BYTES[(buf[0] >> 3) & 0x0F]
                if len(buf) < size + 1:
                    break
                if size:
                    # deque(maxlen=TALK_QUEUE_FRAMES) drops the OLDEST frame if
                    # this ever overflows -- the right end to lose, because the
                    # newest audio is what the speaker is saying right now.
                    self.talk_frames.append(bytes(buf[1:1 + size]))
                del buf[:1 + size]

    def talk_feed(self, pcm, src=None):
        """Accept PCM16 from the page.  Returns False if it is dropped."""
        with self.talk_lock:
            if not self.talk_on or (not self.talk_ff and not self.talk_dry):
                return False
            if self.talk_ff:
                try:
                    self.talk_ff.stdin.write(pcm)
                    self.talk_ff.stdin.flush()
                except (BrokenPipeError, ValueError, OSError):
                    return False
            if not self.talk_stats["pcm_bytes"]:
                self.talk_first = time.time()
            if src is not None:
                self.talk_srcs.add(src)
            self.talk_stats["pcm_bytes"] += len(pcm)
            self.talk_stats["posts"] += 1
            if len(pcm) > self.talk_stats["maxpost"]:
                self.talk_stats["maxpost"] = len(pcm)
            self.talk_stats["last_pcm"] = time.time()
            return True

    def talk_end(self):
        with self.talk_lock:
            if not self.talk_on:
                return
            self.talk_on = False
            dry = self.talk_dry
            self.talk_dry = False
            self._talk_stop_encoder()
            n, first = self.talk_stats["pcm_bytes"], self.talk_first
            el = (time.time() - first) if first else 0.0
            srcs = len(self.talk_srcs)
            if n and el > 0.3:
                # Say how fast the page actually fed us, and from how many
                # connections.  A stream that arrives much faster than the rate
                # the page reported is the signature of more than one live
                # microphone, and it used to be invisible from here: the encoder
                # overran, the packet queue dropped most of it, and all anyone
                # saw was "garbage".
                arr, want = n / el, self.talk_mic_hz * 2
                extra = ""
                if arr > want * 1.4:
                    extra = ("  *** %.1fx the %.0f B/s it claimed from %d client "
                             "connection%s -- more than one microphone?"
                             % (arr / want, want, srcs,
                                "" if srcs == 1 else "s"))
                self.log("talk: %s closed, %.1f s of PCM at %.0f B/s in %d "
                         "POSTs (max %d B) from %d connection%s%s"
                         % ("dry run" if dry else "session", el, arr,
                            self.talk_stats["posts"], self.talk_stats["maxpost"],
                            srcs, "" if srcs == 1 else "s", extra))
            else:
                self.log("talk: %s closed"
                         % ("dry run" if dry else "session"))

    def talk_state(self):
        """A read-only snapshot of the talk session, for /api/state."""
        st = {"on": self.talk_on, "dry": self.talk_dry,
              "mic_hz": self.talk_mic_hz, **self.talk_stats}
        # Report what the page is really delivering against what it claimed.
        # The UI shows a worker's last log line, so a mismatch surfaces as a
        # warning on the tile instead of as unexplained garbage from a speaker.
        st["arrival"] = 0
        if self.talk_first and self.talk_stats["pcm_bytes"]:
            st["arrival"] = int(self.talk_stats["pcm_bytes"]
                                / max(0.25, time.time() - self.talk_first))
            if st["arrival"] > self.talk_mic_hz * 2 * 1.4:
                st["too_fast"] = True
        return st

    def _talk_stop_encoder(self):
        ff, self.talk_ff = self.talk_ff, None
        if self.talk_stop:
            self.talk_stop.set()
        if not ff:
            return
        # Kill first: closing stdin flushes, and a flush into a wedged encoder
        # blocks forever -- the same trap as the video pipe.
        for closer in (ff.kill, lambda: ff.stdin.close()):
            try:
                closer()
            except Exception:
                pass

    def _talk_tick(self, st, now):
        """Send the 120 ms packets that are due, if six frames are ready.

        Runs on the pump thread: CameraStream's socket has one owner and this is
        it.  A tiny job, which is why it is a tick and not a thread.
        """
        if not self.talk_on:
            return
        if self.talk_dry:
            # A dry run sends nothing, so there is nothing to pace and nothing
            # to open -- only the liveness check, so a forgotten dry session
            # closes itself the way a real one does.
            if (now - self.talk_stats["last_pcm"] > TALK_IDLE_TIMEOUT
                    and self.talk_stats["pcm_bytes"] > 0):
                self.log("talk: dry run idle, closing")
                self.talk_end()
            return
        # A dead browser must not leave an encoder running forever.
        if (now - self.talk_stats["last_pcm"] > TALK_IDLE_TIMEOUT
                and self.talk_stats["pcm_bytes"] > 0):
            self.log("talk: no audio for %.0f s, closing" % TALK_IDLE_TIMEOUT)
            self.talk_end()
            return
        if not self.talk_opened:
            st.open_talk()
            self.talk_opened = True
            # Prime the camera's buffer: pretend we are TALK_PREBUFFER behind,
            # so the loop below sends what it has (up to TALK_MAX_BURST) and the
            # camera starts with audio in hand instead of waiting on the first
            # packet.  Without this it underruns on our own jitter.
            self.talk_next = now - TALK_PREBUFFER
        # Pace at the rate the camera consumes: one 120 ms packet per 60 ms of
        # real time (TALK_PKT_REAL_SECONDS = 2.0 declared seconds per second).
        # A burst from the browser must not become a burst on the wire, or the
        # camera buffers it and the speaker hears their own voice come back late.
        #
        # Send every packet that is DUE, not one per call: this tick runs at
        # the pump loop's cadence, and that loop is paced by the video side (a
        # 50 ms select that overruns whenever ffmpeg applies back-pressure), so
        # one packet per call silently stretched the interval into whatever the
        # video happened to take.  If the loop was starved for longer than half
        # a second, forgive the debt instead of catching up -- replaying it
        # would only add latency, which is what the listener actually hears.
        if now - self.talk_next > 0.5:
            self.talk_next = now
        sent = 0
        while (sent < TALK_MAX_BURST
               and len(self.talk_frames) >= TALK_FRAMES_PER_PKT
               and now >= self.talk_next):
            batch = [self.talk_frames.popleft()
                     for _ in range(TALK_FRAMES_PER_PKT)]
            st.send_talk(batch)
            self.talk_stats["packets"] += 1
            self.talk_stats["frames"] += len(batch)
            self.talk_stats["audio_ms"] += TALK_PKT_SECONDS * 1000
            self.talk_next += TALK_PKT_REAL_SECONDS
            sent += 1

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
        self.talk_end()          # a dead worker has no session to talk on


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
        # No captured handshake on this machine yet: the server collects one
        # by itself (wiregrab.py -- the forge_call.py discovery-impersonation
        # scheme as a daemon).  While nothing is on file it shadows the
        # cameras; the first time the official app on any phone of this
        # Wi-Fi views ONE camera, the handshake bytes land here and the
        # catch file freezes.  Impersonation then stops and the grid
        # streams.  The UI banner reports the state meanwhile.
        if self.calling is None:
            self.grab = wiregrab.Grabber(ROOT, on_done=self.capture_landed)
            self.grab.start()
        else:
            self.grab = None
        # -- focus (see viewing / _supervise) -------------------------------
        # What the live viewer CONNECTIONS are asking for: id -> camera tid, or
        # None for "whatever is discoverable" (the grid's /feed).  A camera
        # loses its worker -- and the exclusive P2P session that goes with it
        # -- when nothing wants it, which is what makes focusing one camera
        # stop the others instead of streaming into tiles nobody can see.
        self._viewers = {}         # viewer-connection id -> tid | None
        self._next_cid = 0
        self.paused = set()        # tids currently stopped for lack of viewers
        self._unwanted_at = {}     # tid -> when it first had no viewer left
        self._supervise_stop = threading.Event()
        threading.Thread(target=self._supervise, daemon=True,
                         name="hub-supervisor").start()

    @staticmethod
    def _load_calling():
        """A captured CALLING -- any camera's will do (see module docstring).

        We deliberately bypass ``p2p_call.load_templates``'s preference for
        ``/tmp/forge_in_*.bin`` so a clean checkout behaves identically to a
        machine that happened to run the phone-side capture.
        """
        path = os.path.join(ROOT, "wire", "p2p_frames.json")
        try:
            doc = json.load(open(path, encoding="utf-8"))
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
    def refresh(self, progress=None, sweep=False):
        """Scan the LAN and reconcile it with the cached name list.

        ``sweep`` adds one unicast /24 pass on the final attempt.  Callers
        that retry on a timer leave it off (a broadcast storm every 2 s is
        rude); interactive/startup scans turn it on so a network that eats
        broadcasts still finds its cameras.
        """
        found = {}
        for attempt in range(1, DISCOVER_ATTEMPTS + 1):
            found = discover(DISCOVER_DURATION,
                             sweep=(sweep and attempt == DISCOVER_ATTEMPTS))
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

    def capture_landed(self, state):
        """wiregrab froze wire/p2p_frames.json: go live with it.

        Runs on the grabber thread.  The workers spawned so far were all
        parked on the missing-capture error, so replace them wholesale and
        rediscover; after that the regular viewer machinery owns the grid.
        """
        sys.stderr.write("[grab] handshake landed (tid ...%s): reloading\n"
                         % (state.get("complete_tid") or "?")[-4:])
        self.stop_all()
        self.calling = self._load_calling()
        self.grab = None
        self.refresh()

    # -- streaming ---------------------------------------------------------
    def ensure(self, tid):
        with self.lock:
            cam = self.cameras.get(int(tid))
            if not cam:
                return None, "unknown camera (run discovery first)"
            if not self.calling:
                return None, "waiting for the handshake grab (see the banner)"
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
        # Mute the supervisor while tearing everything down, or it would
        # re-ensure the workers this call is stopping out from under it.
        self._supervise_stop.set()
        try:
            with self.lock:
                ws = list(self.workers.values())
                self.workers.clear()
            for w in ws:
                w.stop()
            for w in ws:
                w.join(timeout=2.0)
        finally:
            self._supervise_stop.clear()

    # -- focus -------------------------------------------------------------
    @contextlib.contextmanager
    def viewing(self, tid=None):
        """Count one viewer connection for its whole lifetime.

        ``tid=None`` means "whatever is discoverable" (the grid's /feed); a
        tid is a focus-limited /feed, a direct /stream socket, or an /audio
        listener.  Handlers unwind their registration in a ``finally``, so a
        connection that goes away stops pulling the camera's resources the
        moment it does.
        """
        with self.lock:
            self._next_cid += 1
            cid = self._next_cid
            self._viewers[cid] = None if tid is None else int(tid)
        try:
            yield
        finally:
            with self.lock:
                self._viewers.pop(cid, None)

    def _wanted(self):
        """Camera tids at least one live viewer connection still wants.

        Returns ``None`` when someone is watching the undivided grid, which
        means every camera must keep running.
        """
        with self.lock:
            vals = list(self._viewers.values())
            cams = set(self.cameras)
        if None in vals:
            return None
        return {t for t in vals if t in cams}

    def _supervise(self):
        """Keep running exactly the camera workers that somebody wants.

        This is what makes focus actually free the server: a fullscreen view
        narrows its /feed to one camera and every OTHER worker -- its ffmpeg
        process, its P2P session, its memory -- is dropped after a short
        dwell.  Leaving fullscreen connects the whole grid again, cold.

        It also runs when nobody is connected at all (just the page open on
        this machine and nothing else): with no viewers left, the server soon
        stops decoding anything, instead of streaming every camera to nobody.

        The lock is never held across ensure()/stop(): both take it themselves.
        """
        while not self._supervise_stop.wait(PAUSE_TICK):
            want = self._wanted()
            with self.lock:
                tids = list(self.cameras)
            for tid in tids:
                needed = want is None or tid in want
                with self.lock:
                    w = self.workers.get(tid)
                if needed:
                    with self.lock:
                        self.paused.discard(tid)
                        self._unwanted_at.pop(tid, None)
                    # ensure() is a no-op while the worker is alive, but it
                    # replaces a dead one, which is why _wanted is not enough
                    # on its own -- a worker can die of its own failures.
                    if w is None or not w.is_alive():
                        try:
                            self.ensure(tid)
                        except Exception:
                            pass
                        with self.lock:
                            w = self.workers.get(tid)
                    # Last-resort watchdog: the in-worker one breaks blocking
                    # pipe writes, but if anything else wedges the thread it
                    # stays "streaming" forever and ensure() keeps returning
                    # the live-but-useless worker.  A stale pipeline is closed
                    # here; _stop makes the thread exit, and the next tick
                    # starts a fresh one.
                    if (w is not None and w.is_alive()
                            and w.status == "streaming"):
                        last = w.stats.get("last") or w.status_since
                        idle = time.time() - last
                        if idle > WORKER_STALL:
                            w.force_restart("no JPEG for %.0fs" % idle)
                    continue
                # Nobody wants it.  Unless it only just lost its last viewer
                # (a quick fullscreen toggle should not cost a cold handshake
                # on the way back), stop it and let go of the camera: the P2P
                # session is exclusive, so holding it would block any other
                # consumer of that camera too.
                with self.lock:
                    first = self._unwanted_at.setdefault(tid, time.time())
                    stale = (time.time() - first) >= PAUSE_DWELL
                    if stale:
                        self.workers.pop(tid, None)
                        self.paused.add(tid)
                if stale and w is not None:
                    w.stop()

    @staticmethod
    def _stats_copy(w):
        """Copy a worker's stats without tripping over a concurrent insert.

        The worker thread adds keys to this dict as it learns about them
        (``jpg``, then the per-connection ``served``/``lag_ms``/``dropped``...).
        ``json.dumps`` walking a dict that another thread is growing raises
        "dictionary changed size during iteration", which would surface as a
        random 500 on /api/state -- i.e. the page's poll silently failing.
        A retry is enough; this happens at most once per key.
        """
        if w is None:
            return {}
        while True:
            try:
                return dict(w.stats)
            except RuntimeError:
                time.sleep(0.005)

    def state(self):
        with self.lock:
            out = []
            for tid, cam in sorted(self.cameras.items()):
                w = self.workers.get(tid)
                out.append({
                    "tid": tid, "ip": cam.get("ip"), "name": cam.get("name"),
                    "mac": cam.get("mac"),
                    # no worker AND not wanted: focus (or an empty room)
                    # paused it on purpose -- not the same as "idle", which
                    # means no viewer has asked for it since discovery.
                    "status": w.status if w else
                        ("paused" if tid in self.paused else "idle"),
                    "error": w.error if w else None,
                    "seq": w.seq if w else 0,
                    "stats": self._stats_copy(w),
                    "talk": w.talk_state() if w else None,
                    "audio": None if not w else {
                        # How fast the server hands audio to whoever is
                        # listening, which is the part of the inbound delay
                        # that is OURS.  q is how many 20 ms chunks are waiting
                        # and age is how long the newest one has been waiting:
                        # both should sit near zero, because /audio drains in a
                        # tight loop and starts at the tail, not the backlog.
                        "q": len(w.audio_chunks),
                        "age": (time.time() - w.audio_last_t)
                               if w.audio_last_t else None,
                        "chunks": w.audio_stats["chunks"],
                    },
                    "log": list(w._log)[-6:] if w else [],
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
 .gainl { color:#8b949e; font-size:12px; display:flex; align-items:center;
          gap:7px; white-space:nowrap; }
 .gainl select { background:#21262d; color:#e6edf3; border:1px solid #30363d;
                 border-radius:6px; padding:5px 6px; font-size:12px;
                 font-variant-numeric:tabular-nums; cursor:pointer; }
 /* header icon buttons (icon only -- hover the glyph for its name) */
 .ibtn { display:inline-flex; align-items:center; padding:7px 9px; }
 .ibtn svg { display:block; }
 /* Square 2x2 grid (was: auto-fit fluid columns).  Two fixed columns on
    anything wide enough, one column on a phone, and every video box 1:1.
    The H.264 feed is 16:9, so it letterboxes inside the square with
    object-fit:contain -- the box shape is the layout choice, the stream
    itself is untouched. */
 #grid { display:grid; gap:14px; padding:18px;
         grid-template-columns:repeat(2,minmax(0,1fr));
         max-width:1440px; margin:0 auto; }
 @media (max-width:640px) { #grid { grid-template-columns:1fr; } }
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
 /* paused: the server dropped this camera's session because nobody was
    watching it (focus).  Dim gray on purpose -- quiet, not an error. */
 .dot.paused { background:#484f58; opacity:.55; }
 .name { font-weight:600; }
 .ip { color:#8b949e; font-size:12px; font-variant-numeric:tabular-nums; }
 .badge { margin-left:auto; font-size:11px; color:#8b949e; }
 .shot { position:relative; background:#000; aspect-ratio:1/1; }
 /* canvas, not <img>: all cameras now share ONE fetch() stream (see /feed),
    because a socket per camera exhausted the browser's six-connection
    per-origin pool and made every other request queue. */
 .shot canvas { width:100%; height:100%; object-fit:contain; display:block; }
 .shot .ph { position:absolute; inset:0; display:flex; align-items:center;
             justify-content:center; color:#484f58; font-size:13px;
             text-align:center; padding:10px; }
 .foot { padding:7px 12px; font-size:11px; color:#8b949e;
         border-top:1px solid #21262d; display:flex; gap:12px;
         font-variant-numeric:tabular-nums; min-height:30px; }
 .err { color:#f85149; }
 #banner { background:#9e6a03; color:#fff; padding:8px 20px; font-size:13px; }
 .hidden { display:none; }

 /* fullscreen: a tile's <canvas> is MOVED into this overlay, not duplicated, so
    it stays the element the /feed reader paints into (a second canvas would
    need its own decode path for the same picture). */
 /* Icon buttons.  Icons, not the emoji entities that
    were removed earlier and the SND/FS/JPG text that replaced them.  All
    inline SVG using currentColor, so the existing hover/active colours keep
    working with no per-icon CSS. */
 .fsbtn { background:none; border:0; color:#8b949e; cursor:pointer;
          line-height:1; padding:5px 6px; border-radius:4px;
          display:inline-flex; align-items:center; }
 .fsbtn svg { display:block; }
 .fsbtn:hover { background:#30363d; color:#e6edf3; }
 #overlay { position:fixed; inset:0; background:#000; z-index:100;
            display:none; }
 #overlay.open { display:block; }
 #ovslot { position:absolute; inset:0; display:flex; align-items:center;
           justify-content:center; }
 #ovslot canvas { width:100%; height:100%; object-fit:contain; }
 .obar { position:absolute; top:0; left:0; right:0; z-index:2;
         display:flex; align-items:center; gap:14px; padding:13px 18px;
         background:linear-gradient(rgba(0,0,0,.82), rgba(0,0,0,0));
         color:#fff; font-size:14px; opacity:0; transition:opacity .25s; }
 #overlay:hover .obar { opacity:1; }
 .obar .ostat { color:#8b949e; font-size:12px; }
 /* Wake Lock status in the fullscreen bar: green while the display is held
    awake, amber when this browser/origin refuses a lock. */
 .obar .owake { display:none; font-size:11px; letter-spacing:.02em;
                color:#3fb950; white-space:nowrap; }
 .obar .owake.show { display:inline-block; }
 .obar .owake.warn { color:#d29922; }
 .obar .x { background:rgba(255,255,255,.14); border:0; color:#fff;
            padding:7px 13px; border-radius:6px; cursor:pointer; }
 .obar .x:hover { background:rgba(255,255,255,.28); }
 /* the bar sits over video, so its speaker needs more contrast than the tiles */
 .obar .sndbtn { color:#c9d1d9; }
 .obar .sndbtn:hover { background:rgba(255,255,255,.16); color:#fff; }
 .obar .sndbtn.on { color:#3fb950; background:rgba(63,185,80,.18); }
  .sndbtn { background:none; border:0; color:#8b949e; cursor:pointer;
            line-height:1; padding:5px 6px; border-radius:4px;
            display:inline-flex; align-items:center; }
  .sndbtn svg { display:block; }
  .sndbtn:hover { background:#30363d; color:#e6edf3; }
  /* "on" is deliberately more than a colour change: the icon swaps to the
     un-muted speaker AND the button lights up, because otherwise there is no
     way to see whether audio is on short of hearing it. */
  .sndbtn.on { color:#3fb950; background:rgba(63,185,80,.14); }
  /* Hold-to-talk.  This is the page's only button that SENDS, so "on" is not
     the green the speaker uses -- a live microphone feeding a speaker in the
     room is better read as a live red, and it glows so it can be picked out
     from the back of the room.  touch-action:none stops the browser's
     press-and-hold gestures (text selection, context menu) from ending the
     press early. */
  .talkbtn { background:none; border:0; color:#8b949e; cursor:pointer;
             line-height:1; padding:5px 6px; border-radius:4px;
             display:inline-flex; align-items:center; touch-action:none;
             user-select:none; }
  .talkbtn svg { display:block; }
  .talkbtn:hover { background:#30363d; color:#e6edf3; }
  .talkbtn.on { color:#f85149; background:rgba(248,81,73,.14);
                box-shadow:0 0 0 2px rgba(248,81,73,.22); }
  .obar .talkbtn:hover { background:rgba(255,255,255,.16); }
  .obar .talkbtn.on { background:rgba(248,81,73,.3); box-shadow:none; }
</style>

<header>
  <h1><span>Wyze</span> cameras</h1>
  <span class="sub" id="cnt"></span>
  <div class="spacer"></div>
  <label class="gainl" title="The camera's mic idles at about -76 dBFS, which
    is correct but inaudible. Raise this until you hear the room -- if even
    64x is silent, the microphone is off in the camera's settings.">Audio gain
    <select id="gain">
      <option value="1">1x</option>
      <option value="2">2x</option>
      <option value="4">4x</option>
      <option value="8" selected>8x</option>
      <option value="16">16x</option>
      <option value="32">32x</option>
      <option value="64">64x</option>
    </select></label>
  <button id="fsall" class="ibtn" title="Fullscreen a camera (Esc exits)"><svg viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 2H2v4M10 2h4v4M10 14h4v-4M6 14H2v-4"/></svg></button>
  <button id="refresh" class="ibtn" title="Re-scan the LAN for cameras"><svg viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M13.4 8a5.4 5.4 0 1 1-1.6-3.8"/><path d="M13.4 2.2V5.4h-3.2"/></svg></button>
</header>
<div id="banner" class="hidden"></div>
<div id="grid"></div>

<div id="overlay">
  <div id="ovslot"></div>
  <div class="obar">
    <strong class="oname"></strong>
    <span class="ostat"></span>
    <span id="fswake" class="owake"></span>
    <div class="spacer"></div>
    <button id="fstalk" class="talkbtn" title="Hold to talk to this camera" aria-label="Talk to this camera"></button>
    <button id="fssound" class="sndbtn" title="Sound off (click to enable)" aria-label="Toggle sound"></button>
    <button class="x" title="Close fullscreen"><svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M4.2 4.2l7.6 7.6M11.8 4.2l-7.6 7.6"/></svg></button>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
// Inline SVG icons.  Deliberately not emoji (which render differently per
// platform and were removed once already) and not text labels.  Every path
// uses currentColor so the CSS hover/active colours apply unchanged, and the
// speaker pair is a real on/off state rather than a colour you have to squint
// at: ICON.mute has the cone struck through, ICON.snd has sound waves.
const ICON = {
  fs: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 2H2v4M10 2h4v4M10 14h4v-4M6 14H2v-4"/></svg>',
  cam: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><path d="M2 5.2h2.1l1-1.7h5.8l1 1.7H14V13H2z"/><circle cx="8" cy="9.1" r="2.4"/></svg>',
  snd: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h2.4L8.8 3.2v9.6L5.4 10H3z"/><path d="M11.2 5.7a3.3 3.3 0 0 1 0 4.6M13.2 3.7a6.1 6.1 0 0 1 0 8.6"/></svg>',
  mute: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h2.4L8.8 3.2v9.6L5.4 10H3z"/><path d="M11.1 6.2l3.7 3.6M14.8 6.2l-3.7 3.6"/></svg>',
  // the talk button: same house style, a mic instead of a speaker
  mic: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2.4a2.2 2.2 0 0 1 2.2 2.2v2.8a2.2 2.2 0 0 1-4.4 0V4.6A2.2 2.2 0 0 1 8 2.4z"/><path d="M4.6 8.8a3.4 3.4 0 0 0 6.8 0M8 12.4v2"/></svg>'
};

// -- audio -----------------------------------------------------------------
// The on/off state lives on the <audio> element (data-on), and BOTH the tile
// button and the fullscreen bar are driven from it.  The gap this design
// exists for: fullscreen had no audio control and no way to see whether sound
// was on except by hearing it.
//
// The element is still the state holder, but it no longer plays anything.
// Sound is scheduled on an AudioContext instead, for the reason the sound
// button used to feel broken: an <audio> element pointed at a live stream is a
// media player, and a media player fills a read-ahead buffer so it can ride
// out a stall it has no other defence against.  Measured on this Mac, that
// buffer sat at buffered.end() - currentTime = 2.47 s while the newest audio
// had reached the *server* 24-50 ms earlier: the entire 2.4 s inbound delay
// was the element, none of it was the camera.  A fetch() reader whose buffers
// we start ourselves on the context clock can be held to a fixed lead, so the
// camera's room arrives on the same timescale as its video.
const SND = new Map();       // tid -> session {ctx, gain, next, live[], ...}
const SND_LEAD = 0.15;       // seconds of audio scheduled ahead of the clock
const SND_MAX_AHEAD = 0.60;  // past this we are replaying history, not listening
const SND_MIN_BYTES = 320;   // one 20 ms frame of 16 kHz PCM16

function sndVisual(btn, on) {
  if (!btn) return;
  btn.classList.toggle('on', on);
  btn.innerHTML = on ? ICON.snd : ICON.mute;
  btn.title = on ? 'Sound on (click to mute)' : 'Sound off (click to enable)';
}

function syncAudioUi(tid) {
  const aud = document.getElementById('aud' + tid);
  const on = !!aud && aud.dataset.on === '1';
  sndVisual(document.querySelector('#c' + tid + ' .sndbtn'), on);
  if (FS.tid === tid) sndVisual($('#fssound'), on);
}

function sndStop(tid) {
  const st = SND.get(tid);
  if (!st) return;
  SND.delete(tid);
  for (const s of st.live) { try { s.stop(); } catch (_) {} }
  try { if (st.reader) st.reader.cancel(); } catch (_) {}
  try { st.gain.disconnect(); } catch (_) {}
  try { st.ctx.close(); } catch (_) {}
}

function sndSchedule(st, bytes) {
  const ctx = st.ctx, n = bytes.length >> 1;
  const buf = ctx.createBuffer(1, n, 16000);   // the node resamples to the device
  const ch = buf.getChannelData(0);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  for (let i = 0; i < n; i++) ch[i] = dv.getInt16(i * 2, true) / 32768;
  let at = st.next;
  if (at < ctx.currentTime + SND_LEAD) at = ctx.currentTime + SND_LEAD;
  if (at > ctx.currentTime + SND_MAX_AHEAD) {
    // Slower than real time somewhere upstream has turned into replaying old
    // audio.  Drop what is queued and jump to live -- the same decision the
    // video path makes with MAX_LAG, for the same reason: being behind is
    // worse than losing a moment.
    st.dropped++;
    for (const s of st.live) { try { s.stop(); } catch (_) {} }
    st.live = [];
    at = ctx.currentTime + SND_LEAD;
  }
  const src = ctx.createBufferSource();
  src.buffer = buf;
  src.connect(st.gain);
  src.onended = () => { const i = st.live.indexOf(src); if (i >= 0) st.live.splice(i, 1); };
  src.start(at);
  st.live.push(src);
  st.next = at + n / 16000;
  st.played += n;
}

async function sndRun(tid, st) {
  while (SND.get(tid) === st) {
    try {
      const r = await fetch('/pcm/' + tid + '?r=' + Date.now(),
                            {cache: 'no-store'});
      if (!r.ok || !r.body) throw new Error('HTTP ' + r.status);
      st.reader = r.body.getReader();
      st.recv = 0; st.since = performance.now();
      let pend = new Uint8Array(0);
      for (;;) {
        const step = await st.reader.read();
        if (step.done) break;
        if (SND.get(tid) !== st) return;
        st.recv += step.value.length;
        const merged = new Uint8Array(pend.length + step.value.length);
        merged.set(pend); merged.set(step.value, pend.length);
        pend = merged;
        const whole = (pend.length >> 1) << 1;       // complete int16 samples
        if (whole >= SND_MIN_BYTES) {
          sndSchedule(st, pend.subarray(0, whole));
          pend = pend.slice(whole);
        }
      }
    } catch (_) { /* server restarting, or the reader was cancelled */ }
    st.reader = null;
    if (SND.get(tid) !== st) return;
    await new Promise(r => setTimeout(r, 1000));     // then try again
  }
}

function setAudio(tid, on) {
  const aud = document.getElementById('aud' + tid);
  if (!aud) return;
  aud.dataset.on = on ? '1' : '';
  sndStop(tid);
  if (on) {
    // Reached straight from a click, which is the user gesture browsers
    // demand for an AudioContext -- nothing may be awaited before this.
    const AC = window.AudioContext || window.webkitAudioContext;
    const st = {ctx: new AC(), live: [], dropped: 0, recv: 0, played: 0,
                next: 0, since: performance.now()};
    st.gain = st.ctx.createGain();      // the boost is applied here, in float,
    st.gain.gain.value = GAIN;          // so the slider no longer restarts the
    st.gain.connect(st.ctx.destination); // stream -- see syncGain()
    st.next = st.ctx.currentTime + SND_LEAD;
    SND.set(tid, st);
    sndRun(tid, st);
  }
  syncAudioUi(tid);
}
// -- talking to a camera ----------------------------------------------------
// The page sends exactly one thing: this camera's own voice.  The camera holds
// ONE session, so the server does not open a second connection to the camera --
// it pushes our audio down the socket the video worker is already pumping, and
// all this side has to do is hand over 16 kHz PCM in order.
//
// HOLD the button.  getUserMedia wants a user gesture, so the request goes out
// on the first press, never at page load.  ScriptProcessor (deprecated, but
// present in every browser and needing no build step) captures it.
const TALK = {tid: null, ctx: null, src: null, node: null, stream: null,
              pending: new Uint8Array(0), busy: false, err: null,
              sess: 0, starting: false, dry: false};
// ?drytalk=1 runs the whole capture path against a server that counts the PCM
// and hands it to no camera.  That is how the capture side gets tested without
// pointing a speaker at anyone -- see the dry branch in CameraStreamThread.
const TALK_DRY = /(^|[?&])drytalk=1/.test(location.search);
const TALK_BUF = 512, TALK_BUF_BYTES = TALK_BUF * 2;   // 512 samples = 32 ms

function talkReq(path, body) {
  // Separate from j() because it carries the HTTP status, which is the whole
  // difference between "busy" and "gone" here.
  const h = {};
  if (body !== null) {
    if (body instanceof Uint8Array || body instanceof ArrayBuffer) {
      // Raw bytes on the wire.  This is not a detail: JSON.stringify() of a
      // Uint8Array is an OBJECT of indices -- {"0":12,"1":7,...} -- which is
      // about nine times the length AND is not PCM at all, so the camera plays
      // the braces, quotes and decimal digits as audio.  That was the entire
      // difference between the file-driven path (raw bytes from Python, clean)
      // and the browser path (always garbage), and it is why the arrival rate
      // measured 9x the rate the page claimed to send.
      h['Content-Type'] = 'application/octet-stream';
    } else {
      h['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }
  }
  return fetch(path, {method: 'POST', headers: h, body: body})
    .then(r => r.json().then(d => ({status: r.status, d: d}))
      .catch(() => ({status: r.status, d: {}})));
}

function syncTalkUi(tid) {
  const on = TALK.tid === tid && !TALK.err;
  const tip = TALK.err ? 'Talk: ' + TALK.err
          : on ? (TALK.dry ? 'Talk test (no camera) -- release to stop'
                           : 'Talking -- release to stop')
          : 'Hold to talk to this camera';
  for (const b of document.querySelectorAll('#c' + tid + ' .talkbtn')) {
    b.classList.toggle('on', on);
    b.title = tip;
  }
  if (FS.tid === tid) {
    const f = $('#fstalk');
    f.classList.toggle('on', on);
    f.title = tip;
  }
}

function talkStart(tid) {
  TALK.err = null;
  syncTalkUi(tid);
  if (!window.isSecureContext || !(navigator.mediaDevices
                                   && navigator.mediaDevices.getUserMedia)) {
    TALK.err = 'microphone needs this page on http://localhost (secure context)';
    syncTalkUi(tid);
    return;
  }
  if (TALK.tid === tid) return;
  if (TALK.tid !== null || TALK.starting) talkStop(true);
  // Claim the slot BEFORE the async work and stamp the session.  getUserMedia
  // plus the start POST take 100-300 ms, and a tap inside that window used to
  // be unstoppable: the release found TALK.tid still null and did nothing, and
  // the session it left behind kept the microphone open with its own
  // onaudioprocess for the rest of the page's life.  A handful of taps is a
  // handful of live microphones feeding one queue at a multiple of real time --
  // the encoder overflows, and the camera plays a sliced hiss that never stops,
  // even when nobody is speaking.  Claiming the slot first means the release
  // always has something to stop.
  const sess = ++TALK.sess;
  TALK.tid = tid;            // now, so a release can stop a start in flight
  TALK.starting = true;
  TALK.dry = TALK_DRY;
  syncTalkUi(tid);
  navigator.mediaDevices.getUserMedia(
      {audio: {channelCount: 1, echoCancellation: true,
               noiseSuppression: true, autoGainControl: true}})
    .then(stream => {
      if (sess !== TALK.sess) {              // released while we waited
        stream.getAudioTracks().forEach(t => t.stop());
        return null;
      }
      TALK.stream = stream;
      const AC = window.AudioContext || window.webkitAudioContext;
      TALK.ctx = new AC({sampleRate: 16000});
      // We *ask* for 16 kHz and then report whatever we actually got: a browser
      // may hand back the hardware rate instead, and the server sizes the
      // encoder around this number, so a wrong guess here cannot reach the
      // camera as a wrong pitch.
      return talkReq('/api/talk/start',
                     {tid: tid, rate: TALK.ctx.sampleRate, dry: TALK.dry});
    })
    .then(r => {
      if (r === null) return;                // already torn down above
      if (sess !== TALK.sess) {              // released while the start was out
        talkReq('/api/talk/stop', {tid: tid}).catch(() => {});
        return;
      }
      if (r.status !== 200 || r.d.error) {
        TALK.err = r.d.error || ('server refused, HTTP ' + r.status);
        talkStop(true);
        return;
      }
      TALK.starting = false;
      TALK.micHz = TALK.ctx.sampleRate;
      // What this capture actually delivers, counted from inside the page.  A
      // rate far above micHz means something else is contributing samples --
      // another microphone the page leaked, or a second tab -- and the server
      // compares this against what it receives.
      TALK.m = {t0: performance.now(), cb: 0, samples: 0, maxlen: 0,
                others: 0, ctxRate: TALK.ctx.sampleRate, posted: 0, posts: 0};
      TALK.src = TALK.ctx.createMediaStreamSource(TALK.stream);
      TALK.node = TALK.ctx.createScriptProcessor(TALK_BUF, 1, 1);
      TALK.pending = new Uint8Array(0);
      TALK.src.connect(TALK.node);
      // zero gain, not the speakers: this is a microphone aimed at a speaker
      // that is already in the room, not a monitor.
      const mute = TALK.ctx.createGain();
      mute.gain.value = 0;
      TALK.node.connect(mute);
      mute.connect(TALK.ctx.destination);
      // Bound to its own session, so a node that outlives its session cannot
      // write into the next one's buffer.
      TALK.node.onaudioprocess = e => talkPcm(e, sess);
      syncTalkUi(tid);
    })
    .catch(e => {
      if (sess !== TALK.sess) return;
      TALK.err = (e && e.name) || 'microphone refused';
      talkStop(true);
    });
}

function talkPcm(e, sess) {
  // Count before the guard: a callback from a node that is no longer the
  // current one is exactly the thing worth reporting.
  const m = TALK.m;
  if (m) {
    const n = e.inputBuffer.length;
    m.cb++;
    m.samples += n;
    if (n > m.maxlen) m.maxlen = n;
    if (e.target !== TALK.node) m.others++;
  }
  if (sess !== TALK.sess) return;   // a node from a session we have left behind
  const f = e.inputBuffer.getChannelData(0);
  const bytes = new Uint8Array(f.length * 2);
  const dv = new DataView(bytes.buffer);
  for (let i = 0; i < f.length; i++) {
    let s = f[i];
    if (s > 1) s = 1; else if (s < -1) s = -1;
    dv.setInt16(i * 2, s < 0 ? s * 0x8000 : s * 0x7fff, true);
  }
  const merged = new Uint8Array(TALK.pending.length + bytes.length);
  merged.set(TALK.pending);
  merged.set(bytes, TALK.pending.length);
  TALK.pending = merged;
  talkFlush();
}

function talkFlush() {
  // Await each POST before the next: the camera plays what it receives in the
  // order it arrives, and a second request in flight is a second chance to
  // reorder it.
  while (TALK.pending.length >= TALK_BUF_BYTES && !TALK.busy) {
    const out = TALK.pending.slice(0, TALK_BUF_BYTES);
    TALK.pending = TALK.pending.slice(TALK_BUF_BYTES);
    if (TALK.m) { TALK.m.posted += TALK_BUF_BYTES; TALK.m.posts++; }
    TALK.busy = true;
    talkReq('/api/talk/pcm/' + TALK.tid, out).then(r => {
      TALK.busy = false;
      if (r.status !== 200 || r.d.ok === false) {
        // The worker restarted or the camera closed the session.  Say so: a
        // button that lights up and transmits nothing is worse than a dead
        // one.
        TALK.err = r.d.error || "lost the camera\'s session -- press again";
        talkStop(true);
      } else if (TALK.pending.length >= TALK_BUF_BYTES) {
        talkFlush();
      }
    }).catch(() => { TALK.busy = false; talkStop(true); });
  }
  // Late audio is worse than missing audio: a stalled browser sheds its tail
  // instead of having it come out minutes later.
  if (TALK.pending.length > TALK_BUF_BYTES * 32) {
    TALK.pending = TALK.pending.slice(-TALK_BUF_BYTES * 8);
  }
}

function talkReport() {
  // The page's own account of what it captured: samples per second into the
  // buffer, how many callbacks that took, and whether any of them came from a
  // node that is not the current one.  Sent at the end of every session, so a
  // session that misbehaves leaves a record rather than only an anecdote.
  const m = TALK.m;
  TALK.m = null;
  if (!m || !m.cb || !m.t0) return;
  const wall = (performance.now() - m.t0) / 1000;
  if (wall < 0.3) return;
  talkReq('/api/micprobe', {main: {
    mic_hz: TALK.micHz, ctxRate: m.ctxRate, rate: Math.round(m.samples / wall),
    samples: m.samples, wall: wall, callbacks: m.cb,
    per_sec: Math.round(m.cb / wall), maxlen: m.maxlen, others: m.others,
    posted: m.posted, posts: m.posts,
    post_rate: Math.round(m.posted / wall), dry: TALK.dry}}).catch(() => {});
}

function talkCleanup() {
  talkReport();
  const n = TALK.node, s = TALK.src, t = TALK.stream, c = TALK.ctx;
  TALK.node = TALK.src = TALK.stream = TALK.ctx = null;
  TALK.pending = new Uint8Array(0);
  TALK.busy = false;
  TALK.starting = false;
  if (n) { n.onaudioprocess = null; try { n.disconnect(); } catch (_) {} }
  if (s) { try { s.disconnect(); } catch (_) {} }
  if (t) { try { t.getAudioTracks().forEach(tr => tr.stop()); } catch (_) {} }
  if (c) { try { c.close(); } catch (_) {} }
}

function talkStop(silent) {
  const tid = TALK.tid;
  // Invalidate whatever start might still be in flight before doing anything
  // else: its .then must not come back and install a microphone that nobody is
  // holding.  That is the whole fix -- a release now always cancels a start,
  // even one that has not finished yet.
  TALK.sess++;
  talkCleanup();
  TALK.tid = null;
  if (tid == null) return;
  if (!silent) talkReq('/api/talk/stop', {tid: tid}).catch(() => {});
  syncTalkUi(tid);
  syncTalkUi(FS.tid);
}
// -- one connection for all video ------------------------------------------
// Every camera's JPEGs arrive on a single fetch stream (Handler._feed), framed
// as <Q tid><Q publish-ms><I length> followed by the JPEG bytes.  Sockets are
// now 1 feed + one <audio> per camera you switch on, instead of one socket per
// camera -- which is what exhausted the browser's six-per-origin HTTP/1.1 pool
// and left /api/state and the snapshot button queued forever.
const FEED_HDR = 20;
const slot = new Map();      // tid -> {bytes, ms}  newest frame, never a queue
const decoding = new Set();  // tid -> a decode is in flight
const LAT = {};              // tid -> ms from publish to painted, this browser
const AGO = {};              // tid -> Date.now() when this browser last painted

function feedFrame(tid, ms, bytes) {
  // Overwrite rather than queue.  If this browser cannot decode as fast as the
  // cameras produce, showing the newest frame is the entire point; queueing
  // here would rebuild exactly the backlog MAX_LAG exists to prevent.
  slot.set(tid, {bytes: bytes, ms: ms});
}

async function paint() {
  for (const kv of slot) {
    const tid = kv[0], f = kv[1];
    if (decoding.has(tid)) continue;
    slot.delete(tid);
    decoding.add(tid);
    try {
      const bmp = await createImageBitmap(
        new Blob([f.bytes], {type: 'image/jpeg'}));
      const cv = document.getElementById('view' + tid);
      if (cv) {
        if (cv.width !== bmp.width || cv.height !== bmp.height) {
          cv.width = bmp.width; cv.height = bmp.height;
        }
        cv.getContext('2d').drawImage(bmp, 0, 0);
        LAT[tid] = Date.now() - f.ms;      // end-to-end: publish -> painted
        AGO[tid] = Date.now();
      }
      if (bmp.close) bmp.close();
    } catch (_) { /* torn or non-JPEG frame -- skip it */ }
    decoding.delete(tid);
  }
  requestAnimationFrame(paint);
}

// Pure framing step (no sockets, no DOM) so the wire format can be tested
// outside a browser -- see feedtest.js.  Returns [frames, leftover].
function parseFeed(buf) {
  const out = [];
  let off = 0;
  while (buf.length - off >= FEED_HDR) {
    const dv = new DataView(buf.buffer, buf.byteOffset + off, FEED_HDR);
    const tid = Number(dv.getBigUint64(0, true));
    const ms = Number(dv.getBigUint64(8, true));
    const len = dv.getUint32(16, true);
    if (len > (4 << 20)) { off = buf.length; break; }   // desync: resync empty
    if (buf.length - off < FEED_HDR + len) break;       // need the rest yet
    out.push({tid: tid, ms: ms,
              bytes: buf.slice(off + FEED_HDR, off + FEED_HDR + len)});
    off += FEED_HDR + len;
  }
  return [out, off ? buf.slice(off) : buf];
}

/* Focus: the ONE /feed connection is narrowed to a single camera.  openFs and
   closeFs call setFocus(); an abort cuts the connection short and feedLoop
   reconnects quickly with ?focus=<tid> on the URL.  With nothing else holding
   viewers, the server then STOPS the other cameras' workers -- ffmpeg, the
   P2P session, all of it -- so fullscreen really does unclog the server, and
   the grid reconnects everything (cold, ~1-2 s) when fullscreen closes. */
let FOCUS = null;         // camera the feed is narrowed to, null = whole grid
let FEED_AC = null;       // AbortController of the connection in flight
let FEED_KICK = false;    // a self-initiated abort: reconnect fast, not 1 s

function setFocus(tid) {
  if (FOCUS === tid) return;
  FOCUS = tid;
  FEED_KICK = true;
  if (FEED_AC) { try { FEED_AC.abort(); } catch (_) {} }
}

async function readFeed() {
  FEED_AC = new AbortController();
  const r = await fetch('/feed?r=' + Date.now()
    + (FOCUS !== null ? '&focus=' + FOCUS : ''),
    {cache: 'no-store', signal: FEED_AC.signal});
  if (!r.ok || !r.body) throw new Error('HTTP ' + r.status);
  const rd = r.body.getReader();
  let buf = new Uint8Array(0);
  for (;;) {
    const step = await rd.read();
    if (step.done) break;
    // Append, then pull off every complete frame.  A chunk boundary falls
    // anywhere, so a partial frame simply stays in buf for the next read.
    const merged = new Uint8Array(buf.length + step.value.length);
    merged.set(buf);
    merged.set(step.value, buf.length);
    const parsed = parseFeed(merged);
    buf = parsed[1];
    for (const f of parsed[0]) feedFrame(f.tid, f.ms, f.bytes);
  }
}

async function feedLoop() {
  for (;;) {
    try { await readFeed(); } catch (_) { /* server restarting */ }
    await new Promise(r => setTimeout(r, FEED_KICK ? 150 : 1000));
    FEED_KICK = false;                                   // reconnect
  }
}

let LAST = [];            // latest /api/state snapshot, for fullscreen helpers
let GAIN = 1;             // audio boost, see #gain; applied in the gain node
const gainEl = document.getElementById('gain');
function syncGain() {
  GAIN = Number(gainEl.value) || 1;
  // Sound is mixed here, in float, not multiplied into 16-bit samples on the
  // server -- so a change takes effect at once and far more gracefully than
  // the old "re-point the <audio> src at ?gain=N" did.
  SND.forEach(st => { try { st.gain.gain.value = GAIN; } catch (_) {} });
}
if (gainEl) {
  gainEl.value = '8';     // the mic idles at -76 dBFS, unity is inaudible
  syncGain();
  gainEl.addEventListener('change', syncGain);
}

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
      '<div class="ip"></div><div class="badge"></div>' +
      '<button class="talkbtn" title="Hold to talk to this camera"' +
      ' aria-label="Talk to this camera">' + ICON.mic + '</button>' +
      '<button class="fsbtn" title="Fullscreen (or double-click the video)"' +
      ' aria-label="Fullscreen">' + ICON.fs + '</button>' +
      '<button class="sndbtn" title="Sound off (click to enable)"' +
      ' aria-label="Toggle sound">' + ICON.mute + '</button>' +
      '<button class="fsbtn" title="Save a still JPEG (snapshot)"' +
      ' aria-label="Save a snapshot">' + ICON.cam + '</button></div>' +
      '<div class="shot"><div class="ph">connecting&hellip;</div>' +
      '<canvas id="view' + c.tid + '" width="0" height="0" class="hidden">' +
      '</canvas></div>' +
      '<audio id="aud' + c.tid + '" class="hidden" preload="none" crossorigin="anonymous"></audio>' +
      '<div class="foot"><span class="f1"></span>' +
      '<span class="f2 err"></span></div>';
    $('#grid').appendChild(el);
    const [fsb, snapb] = el.querySelectorAll('.head .fsbtn');
    fsb.addEventListener('click', e => {
      e.stopPropagation(); openFs(c.tid);
    });
    // Snapshot is taken from the canvas, NOT from the server.
    //
    // It used to be an <a download href="/snapshot/<tid>.jpg">, which is a
    // fresh HTTP request.  Chrome allows only six connections per origin, and
    // with a socket per camera every slot was already taken, so the request sat
    // in "pending" until a stream ended -- which is why the button appeared to
    // hang for minutes.  The decoded frame is already in this canvas, so
    // re-encoding it here costs nothing and needs no connection at all.
    snapb.addEventListener('click', e => {
      e.stopPropagation();
      const cv = document.getElementById('view' + c.tid);
      if (!cv || !cv.width) return;
      cv.toBlob(blob => {
        if (!blob) return;
        const t = new Date(), p = n => (n < 10 ? '0' + n : '' + n);
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'wyze-' + c.tid + '-' + t.getFullYear()
          + p(t.getMonth() + 1) + p(t.getDate()) + '-'
          + p(t.getHours()) + p(t.getMinutes()) + p(t.getSeconds()) + '.jpg';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 10000);
      }, 'image/jpeg', 0.92);
    });
    el.addEventListener('dblclick', () => openFs(c.tid));
  }
  // Sound button.  The <audio> streams /audio/<tid>.wav (16 kHz PCM16), so
  // the browser does the mixing and the tile's MJPEG socket is untouched.
  // The real work lives in setAudio()/syncAudioUi() so the fullscreen bar can
  // drive the same state.
  //
  // The listeners are wired exactly once per tile.  tile() is called from
  // every /api/state poll, and this block used to sit outside the
  // create-once `if (!el)` above -- so a fresh click handler was appended
  // every 2 s.  Ten minutes in, one click on SND ran 300 handlers against 300
  // separate `audioOn` closures that all read false, which is exactly the
  // "I cannot tell whether sound is on" symptom.
  const sndb = el.querySelector('.head .sndbtn'),
        aud = document.getElementById('aud' + c.tid);
  if (sndb && aud) {
    sndVisual(sndb, aud.dataset.on === '1');
    if (!sndb.dataset.wired) {
      sndb.dataset.wired = '1';
      sndb.addEventListener('click', e => {
        e.stopPropagation();
        setAudio(c.tid, aud.dataset.on !== '1');
      });
      // No 'error' listener on the element any more: the Web Audio reader owns
      // the stream now and reconnects itself (see sndRun), so a camera going
      // away leaves the button lit and simply resumes -- switching it
      // off silently was its own small lie about what is happening.
    }
  }
  // Hold-to-talk.  Pointer events, not click: the press IS the transmit switch.
  // Wired once per tile -- tile() runs on every /api/state poll, so without the
  // dataset.wired guard each poll would stack another handler on it, exactly
  // the bug the comment above the sound button records.
  const tb = el.querySelector('.talkbtn');
  if (tb && !tb.dataset.wired) {
    tb.dataset.wired = '1';
    const down = e => { e.preventDefault(); e.stopPropagation();
                        talkStart(c.tid); };
    const up = e => { e.preventDefault(); e.stopPropagation();
                      if (TALK.tid === c.tid) talkStop(); };
    tb.addEventListener('pointerdown', down);
    tb.addEventListener('pointerup', up);
    tb.addEventListener('pointercancel', up);
    // A finger that slides off the button has released it.  Without this the
    // camera keeps "hearing" a silent room after the user let go.
    tb.addEventListener('pointerleave', up);
    tb.addEventListener('contextmenu', up);
  }
  el.querySelector('.name').textContent = c.name || ('Camera ' + c.tid);
  el.querySelector('.ip').textContent = c.ip || '\\u2014';
  // The badge must describe the PICTURE, not repeat the worker's opinion.
  //
  // Two different failures were being conflated:
  //
  //   * the worker has lost the camera -- it says connecting / reconnecting /
  //     offline, and there genuinely is no stream;
  //   * the picture stopped updating while the worker still believes it is
  //     fine.  CameraStreamThread only gives up on a silent camera after 8 s
  //     (the stall check in run()), so for that entire window it reports
  //     "streaming" over a frozen frame -- and printing the raw status there
  //     is exactly the "it says connecting/streaming while the camera is
  //     streaming" report.  The badge was naming the worker's opinion while
  //     the viewer was looking at the picture.
  //
  // So the worker's words now appear only when the worker really has lost the
  // camera, and a picture that stopped updating says so in its own word.
  // 2.5 s is far above the ~50 ms frame interval and above ffmpeg's bursts,
  // so a healthy camera never trips it.
  const st = c.stats || {};
  const age = (AGO[c.tid] != null) ? Date.now() - AGO[c.tid] : null;
  const live = age != null && age < 2500;
  let state, cls;
  if (c.status === 'offline') {
    state = 'offline'; cls = 'offline';
  } else if (c.status === 'error') {
    state = 'error'; cls = 'error';
  } else if (c.status === 'paused') {
    // The server dropped this camera's session: nobody is watching it (focus).
    // Not an error and not 'offline' -- the frame below is the last one it
    // painted, and it comes back by itself when fullscreen closes.
    state = 'paused'; cls = 'paused';
  } else if (live) {
    state = 'live'; cls = 'streaming';
  } else if (age == null) {
    // The worker has a stream but this browser has never painted a frame:
    // either the handshake is still finishing, or /feed is not delivering.
    state = c.status === 'streaming' ? 'no video' : (c.status || 'starting');
    cls = c.status || 'starting';
  } else {
    state = 'stalled'; cls = 'connecting';
  }
  el.querySelector('.dot').className = 'dot ' + cls;
  const badge = el.querySelector('.badge');
  badge.textContent = state;
  badge.title =
    'picture: ' + (age == null ? 'no frame painted yet in this browser'
      : live ? 'updating, ' + age + ' ms behind'
             : 'frozen for ' + (age / 1000).toFixed(1) + ' s')
    + '\\nserver: ' + (c.status || 'unknown')
    + '\\nframes decoded on the server: ' + (st.jpg || 0)
    + (st.fps ? ' (' + st.fps.toFixed(1) + ' fps)' : '');

  // Look the <canvas> up by id, NOT with el.querySelector('canvas'): while a
  // camera is fullscreen its canvas lives inside the overlay, so it is no
  // longer a descendant of the tile.
  //
  // Nothing is attached here any more.  Every camera's video arrives on the
  // single /feed fetch stream opened once at page load (see readFeed), and the
  // server creates a worker for each discovered camera as soon as /feed
  // connects -- so a tile only has to choose between its last painted frame and
  // the placeholder.  The frame deliberately stays up through a stall (the old
  // <img> behaved the same way); the badge above is what reports staleness.
  //
  // A brand-new <canvas> reports width 300 (the HTML default), so the markup
  // pins width="0" height="0" and "have we painted?" is tracked explicitly by
  // LAT -- otherwise the placeholder would vanish over a blank canvas at load.
  const cv = document.getElementById('view' + c.tid),
        ph = el.querySelector('.ph');
  if (cv && age != null && c.status !== 'offline') {
    cv.classList.remove('hidden');
    ph.classList.add('hidden');
  } else {
    if (cv) cv.classList.add('hidden');
    ph.classList.remove('hidden');
    // "streaming" here would read as a contradiction -- the placeholder is
    // only visible when nothing is being painted, so name that instead.
    ph.textContent = c.error ? c.error
      : (c.status === 'offline' ? 'camera offline (powered off?)'
        : (c.status === 'streaming' || age != null)
          ? 'waiting for video\\u2026'
          : (c.status || 'starting') + '\\u2026');
  }

  const s = c.stats || {};
  // s.jpg counts frames this SERVER WORKER has decoded since the camera
  // started streaming -- it deliberately survives page reloads (the worker
  // keeps running so you do not pay an 8-10s discovery+handshake on refresh).
  // Label it as a worker total so it does not look like a viewer counter.
  //
  // lag_ms/dropped come from the stream handler and are the two numbers that
  // matter when the picture feels behind: lag is how stale the oldest frame
  // was when this connection last wrote it, and dropped counts frames we
  // skipped rather than replay (replaying would leave the view permanently
  // that far behind reality).  Low lag with dropped climbing means the
  // browser cannot keep up; high lag would have meant our queue did it.
  const lag = (s.lag_ms != null) ? Math.round(s.lag_ms) : null;
  // LAT is measured HERE: publish time on the server -> painted in this canvas.
  // That is the full end-to-end delay a viewer experiences -- server queue,
  // socket, JPEG decode and composite -- and it is the only number that can
  // settle whether the remaining delay is ours.  Until the first frame is
  // painted, fall back to the server's own lag figure.
  const delay = (LAT[c.tid] != null) ? Math.round(LAT[c.tid]) : lag;
  el.querySelector('.f1').textContent =
    s.jpg ? ((s.fps || 0).toFixed(1) + ' fps \\u00b7 ' + s.jpg + ' total'
             + (delay != null ? ' \\u00b7 ' + delay + ' ms' : '')
             + (s.dropped ? ' \\u00b7 -' + s.dropped : ''))
          : (c.status === 'streaming' ? 'starting\\u2026' : '');
  el.querySelector('.f1').title =
    'frames decoded since this camera\\'s stream started on the server'
    + '\\n<ms>: from the frame being published on the server to it being'
    + ' painted in this browser (measured end-to-end here; lower is better)'
    + '\\ndropped: stale frames skipped so the view stays live';
  // A talk error outranks the camera's own: it is the one a viewer can act on
  // (press again) and the one that cannot be seen on the picture.  While a
  // session is live the same line says how much has actually gone out, so a
  // button that looks alive can be checked against the wire.
  el.querySelector('.f2').textContent =
    (TALK.tid === c.tid && TALK.err) ? TALK.err
    : (TALK.tid === c.tid && c.talk && c.talk.on && c.talk.audio_ms)
      ? 'talking \\u00b7 ' + (c.talk.audio_ms / 1000).toFixed(1) + ' s'
      : (c.error || '');
  if (c.log && c.log.length) el.querySelector('.foot').title = c.log.join('\\n');

  // Keep the overlay bar in sync if this camera is the one fullscreened.
  if (FS.tid === c.tid) {
    $('.oname').textContent = c.name || ('Camera ' + c.tid);
    $('.ostat').textContent =
      state + (delay != null ? ' \\u00b7 ' + delay + ' ms' : '');
  }
}

/* ---- keep the screen awake -------------------------------------------
   The Screen Wake Lock API is the standard way to stop the display from
   sleeping while a camera is fullscreen.  It needs a *secure context*:
   http://127.0.0.1 and http://localhost qualify, a plain http://LAN-IP does
   not, so a phone pointed at 192.168.x.x gets the honest "screen may sleep"
   note instead of a silent failure.  The browser releases the lock whenever
   the tab is hidden; visibilitychange takes it back. */
const WAKE = (() => {
  const el = $('#fswake');
  let sentinel = null, wanted = false, pending = false;
  function paint(state) {
    if (!el) return;
    el.classList.toggle('show', state !== 'off');
    el.classList.toggle('warn', state === 'warn');
    el.textContent = state === 'on' ? 'screen on'
                   : state === 'warn' ? 'screen may sleep' : '';
    el.title = state === 'on'
      ? 'Wake Lock active: the display will not turn off while this view is open.'
      : state === 'warn'
        ? 'This browser/origin refused a screen Wake Lock. A secure origin is '
          + 'required: use http://127.0.0.1:8080 on the server PC, or HTTPS '
          + 'elsewhere (a phone on http://192.168.x.x cannot keep the display '
          + 'awake).'
        : '';
  }
  async function acquire() {
    if (!wanted || sentinel || pending) return;
    if (!navigator.wakeLock) { paint('warn'); return; }
    pending = true;
    try {
      const s = await navigator.wakeLock.request('screen');
      if (!wanted) { Promise.resolve(s.release()).catch(() => {}); return; }
      sentinel = s;
      // Released by the browser on tab hide, battery saver, etc.  Do not
      // fight it: the visibility handler below re-asks when we come back.
      s.addEventListener('release', () => {
        if (sentinel === s) sentinel = null;
        if (wanted) paint(document.visibilityState === 'visible'
                          ? 'warn' : 'off');
      });
      paint('on');
    } catch (_) {
      paint('warn');       // NotAllowedError: battery saver or site policy
    } finally {
      pending = false;
    }
  }
  function on()  { wanted = true; acquire(); }
  function off() {
    wanted = false;
    if (sentinel) {
      Promise.resolve(sentinel.release()).catch(() => {});
      sentinel = null;
    }
    paint('off');
  }
  document.addEventListener('visibilitychange', () => {
    if (wanted && document.visibilityState === 'visible') acquire();
  });
  return {on, off};
})();

/* ---- fullscreen ------------------------------------------------------
   The tile's existing <canvas> is MOVED into the overlay and moved back on
   close.  Moving keeps the element, so it stays the same thing the /feed
   reader is painting into; a second canvas would need its own decoder. */
const FS = {tid: null, home: null};

function openFs(tid) {
  if (FS.tid === tid) { WAKE.on(); return; }   // same camera: just re-arm
  if (FS.tid !== null) closeFs();
  const cv = document.getElementById('view' + tid),
        aud = document.getElementById('aud' + tid),
        tileEl = document.getElementById('c' + tid);
  if (!cv || !tileEl) return;
  FS.tid = tid;
  FS.home = cv.parentNode;                  // the tile's .shot, before moving
  FS.audHome = aud.parentNode;
  $('.oname').textContent = tileEl.querySelector('.name').textContent;
  $('.ostat').textContent = tileEl.querySelector('.badge').textContent;
  $('#ovslot').appendChild(cv);             // MOVE, not clone
  $('#ovslot').appendChild(aud);            // move audio too
  cv.classList.remove('hidden');
  tileEl.querySelector('.ph').classList.remove('hidden');
  $('#overlay').classList.add('open');
  WAKE.on();                                // display must not sleep now
  syncAudioUi(tid);                         // show the bar's speaker state
  // Focus: narrow the single /feed to this camera.  The server drops the
  // other workers (see Hub._supervise) -- that is the point of fullscreen.
  setFocus(tid);
}

function closeFs() {
  if (FS.tid === null) return;
  // Back to the grid before any teardown: unfocus makes the server bring the
  // other cameras' workers back (cold, so tiles reconnect over the next 1-2 s).
  setFocus(null);
  const cv = document.getElementById('view' + FS.tid),
        aud = document.getElementById('aud' + FS.tid),
        home = FS.home,
        audHome = FS.audHome;
  $('#overlay').classList.remove('open');
  WAKE.off();                               // back to normal sleep policy
  if (cv && home) {
    home.appendChild(cv);                   // move it back into the tile
  }
  if (aud && audHome) {
    audHome.appendChild(aud);               // move audio back into the tile
    // Deliberately NOT paused.  Sound keeps playing when you leave fullscreen,
    // and the tile's speaker icon stays truthful because it is driven from the
    // same element.  It used to be killed here, so closing a fullscreen view
    // silently muted that camera.
    syncAudioUi(FS.tid);
  }
  // Re-run tile() so the canvas's hidden/visible state is recalculated for
  // its home slot instead of inheriting whatever fullscreen left behind.
  const d = LAST && LAST.find(c => c.tid === FS.tid);
  if (d) tile(d);
  FS.tid = null;
  FS.home = null;
  FS.audHome = null;
}

$('#overlay .x').addEventListener('click', closeFs);
// Sound toggle in the fullscreen bar.  Same underlying <audio> element and the
// same data-on state as the tile's button, so the two never disagree.
$('#fssound').addEventListener('click', e => {
  e.stopPropagation();
  if (FS.tid == null) return;
  const aud = document.getElementById('aud' + FS.tid);
  if (!aud) return;
  setAudio(FS.tid, aud.dataset.on !== '1');
});
// Hold-to-talk in the fullscreen bar.  Same session as the tile's button -- the
// overlay is the same video, and the mic goes to the same camera either way.
let fsTalk = false;
$('#fstalk').addEventListener('pointerdown', e => {
  if (FS.tid == null) return;
  e.preventDefault();
  e.stopPropagation();
  fsTalk = true;
  talkStart(FS.tid);
});
const fsTalkUp = e => {
  if (!fsTalk) return;
  fsTalk = false;
  if (FS.tid != null) talkStop();
};
$('#fstalk').addEventListener('pointerup', fsTalkUp);
$('#fstalk').addEventListener('pointercancel', fsTalkUp);
$('#fstalk').addEventListener('pointerleave', fsTalkUp);
$('#fstalk').addEventListener('contextmenu', fsTalkUp);
// Click the black surround (but not the picture, not the bar) to dismiss.
$('#ovslot').addEventListener('click', e => { if (e.target.id === 'ovslot') closeFs(); });
$('#overlay').addEventListener('dblclick', closeFs);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeFs(); if (document.fullscreenElement) document.exitFullscreen(); }
});
// Header button: browser fullscreen on whichever camera is showing, else
// fullscreen the first one so the button is never a dead end.
$('#fsall').addEventListener('click', () => {
  const tid = FS.tid !== null ? FS.tid : (LAST[0] && LAST[0].tid);
  if (tid != null) openFs(tid);
});

async function tick() {
  try {
    // Tell the server how far behind live this browser's speakers are.  For a
    // live WAV that the browser has no end for, buffered.end() is the newest
    // audio it has downloaded and currentTime is what is reaching the speaker
    // now -- so the difference is the delay that is neither the camera's nor
    // the server's, it is the media element's own read-ahead.  Sent on the
    // poll that already happens rather than as another request.
    const lag = [];
    SND.forEach((st, tid) => {
      // Scheduled-ahead is exactly the delay: audio already queued against the
      // context clock but not yet at the speakers, plus at most one 20 ms frame
      // the reader has not unpacked.  Same meaning as the <audio> element's
      // buffered.end() - currentTime, which is what this replaces.
      let b = -1;
      try { b = st.next - st.ctx.currentTime; } catch (_) {}
      lag.push(tid + ':' + (b < 0 ? -1 : b.toFixed(2)) + ':' + st.dropped);
    });
    // The same trip: what this browser measured publish -> painted for video,
    // so the two directions can be compared with no stopwatch involved.
    const vid = Object.keys(LAT).map(t => t + ':' + Math.round(LAT[t]));
    const qs = [];
    if (lag.length) qs.push('aud=' + lag.join(','));
    if (vid.length) qs.push('vid=' + vid.join(','));
    const d = await j('/api/state' + (qs.length ? '?' + qs.join('&') : ''));
    const cams = d.cameras || [];
    LAST = cams;
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

// The single video connection and the paint loop.  Both start immediately and
// keep themselves alive; tick() only describes what the server is doing.
feedLoop();
requestAnimationFrame(paint);

tick();
// 2.5 s rather than 2 s: the state poll is a separate request, and with the
// feed on one socket plus one <audio> per camera you listen to, leaving a
// spare slot in the browser's six-per-origin pool keeps snapshots instant.
setInterval(tick, 2500);
</script>
"""


# -- microphone self-test ---------------------------------------------------
# The talk path's one unverifiable step is the browser's own capture: the page
# asks for a 16 kHz AudioContext and reports TALK.ctx.sampleRate, but a rate
# that is merely *claimed* cannot be trusted -- if the capture really runs at
# another rate, the server sizes the encoder wrongly, produces audio far faster
# than the camera consumes it, and the playout becomes a sliced, hissing
# garble that the pacing hides.  This page measures what the browser actually
# delivers instead of asking it: open /probe, press once, read the numbers.
# It touches no camera and plays no sound.
PROBE_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Wyze microphone self-test</title>
<style>
 body { font: 14px/1.55 -apple-system, system-ui, sans-serif; background:#0d1117;
        color:#e6edf3; margin:0; padding:28px; max-width:720px; }
 h1 { font-size:17px; margin:0 0 6px; }
 p { color:#8b949e; margin:8px 0; }
 button { font:inherit; padding:10px 16px; border-radius:8px;
          border:1px solid #30363d; background:#21262d; color:#e6edf3;
          cursor:pointer; }
 button:hover { background:#30363d; }
 table { border-collapse:collapse; margin-top:18px; }
 th, td { padding:6px 18px 6px 0; text-align:left; vertical-align:top; }
 th { color:#8b949e; font-weight:500; }
 .big { font-size:20px; font-weight:600; color:#3fb950; }
 .bad { color:#f85149; }
 code { color:#58a6ff; }
</style></head><body>
<h1>Microphone self-test</h1>
<p>Measures what this browser really hands the talk feature. Silent: nothing is
sent to a camera and nothing is played. It does open the microphone, so the
browser will ask permission.</p>
<p><button id="go">Run the self-test (about 6 s)</button></p>
<div id="out"></div>
<script>
const CONSTRAINTS = {audio: {channelCount: 1, echoCancellation: true,
                             noiseSuppression: true, autoGainControl: true}};

function one(label, makeCtx) {
  return navigator.mediaDevices.getUserMedia(CONSTRAINTS).then(stream => {
    const track = stream.getAudioTracks()[0];
    const set = track.getSettings ? track.getSettings() : {};
    const ctx = makeCtx();
    const src = ctx.createMediaStreamSource(stream);
    const node = ctx.createScriptProcessor(512, 1, 1);
    const mute = ctx.createGain();
    mute.gain.value = 0;
    src.connect(node); node.connect(mute); mute.connect(ctx.destination);
    let samples = 0, calls = 0, peak = 0, sum = 0, n = 0;
    node.onaudioprocess = e => {
      const f = e.inputBuffer.getChannelData(0);
      samples += f.length; calls++;
      for (let i = 0; i < f.length; i++) {
        const a = Math.abs(f[i]);
        if (a > peak) peak = a;
        sum += f[i] * f[i]; n++;
      }
    };
    const t0 = performance.now();
    return new Promise(res => setTimeout(res, 3000)).then(() => {
      const r = {
        label: label, ctxRate: ctx.sampleRate, ctxState: ctx.state,
        trackRate: set.sampleRate || null,
        trackChannels: set.channelCount || null,
        device: track.label || '',
        seconds: (performance.now() - t0) / 1000,
        samples: samples, callbacks: calls, peak: peak,
        rms: Math.sqrt(sum / Math.max(1, n)),
      };
      node.onaudioprocess = null;
      try { src.disconnect(); node.disconnect(); } catch (_) {}
      stream.getAudioTracks().forEach(t => t.stop());
      try { ctx.close(); } catch (_) {}
      return r;
    });
  });
}

document.getElementById('go').onclick = () => {
  const AC = window.AudioContext || window.webkitAudioContext;
  const out = document.getElementById('out');
  out.innerHTML = '<p>measuring &mdash; stay quiet or talk normally, either is '
                + 'fine&hellip;</p>';
  const asked = () => one('asked for 16000 Hz', () => new AC({sampleRate: 16000}));
  const plain = () => one('browser default', () => new AC());
  asked().then(a => plain().then(b => {
    let rows = '';
    for (const r of [a, b]) {
      const rate = r.samples / r.seconds;
      const ok = Math.abs(rate - r.ctxRate) < r.ctxRate * 0.05;
      rows += '<tr><th>' + r.label + '</th>'
            + '<td class="' + (ok ? 'big' : 'big bad') + '">'
            + Math.round(rate).toLocaleString() + ' samples/s</td>'
            + '<td>' + r.samples.toLocaleString() + ' samples in '
            + r.seconds.toFixed(2) + ' s (' + r.callbacks + ' callbacks)</td></tr>'
            + '<tr><th></th><td colspan="2">context says <code>'
            + r.ctxRate + ' Hz</code> (' + r.ctxState + ') &middot; mic track '
            + r.trackRate + ' Hz / ' + r.trackChannels + ' ch<br>device: '
            + r.device + '<br>peak ' + r.peak.toFixed(3) + ' &middot; rms '
            + r.rms.toFixed(4) + '</td></tr>';
    }
    out.innerHTML = '<table>' + rows + '</table>'
      + '<p>The first column is the truth; the context&rsquo;s own figure is '
      + 'only a claim. Green means they agree within 5%.<br>'
      + '<span id="sent">reporting&hellip;</span></p>';
    // Three channels to the same endpoint.  A browser that quietly drops one
    // of them still tells the server what it measured -- and the "reporting:"
    // line says which one got through, which is itself worth knowing.
    const payload = JSON.stringify({asked: a, plain: b});
    const sent = [];
    fetch('/api/micprobe', {method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: payload})
      .then(r => sent.push('fetch HTTP ' + r.status))
      .catch(e => sent.push('fetch failed (' + ((e && e.name) || e) + ')'))
      .then(() => {
        const el = document.getElementById('sent');
        if (el) el.textContent = 'reporting: ' + sent.join(', ');
      });
    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon('/api/micprobe',
                             new Blob([payload], {type: 'application/json'}));
      }
    } catch (_) {}
    try {
      new Image().src = '/api/micprobe?d=' + encodeURIComponent(payload);
    } catch (_) {}
  })).catch(e => {
    out.innerHTML = '<p class="bad">' + ((e && e.name) || e) + ': '
                  + ((e && e.message) || 'getUserMedia failed') + '</p>';
  });
};
</script></body></html>
"""

LAST_PROBE = {}

# What the page's own <audio> element says it is playing behind live, per
# camera: buffered.end() - currentTime is, by definition, the audio that the
# browser has already downloaded but has not reached the speaker yet.  That is
# the whole inbound delay if our server is handing chunks over promptly, so the
# page reports it on every state poll and the server just records it.
AUD_LAG = {}

# PCM that arrived when no session could accept it.  A page whose microphone
# outlived its session -- the leak the session stamp in PAGE fixes -- goes on
# POSTing forever, so this counter is the fingerprint of a stray capture, and
# its rate divided by the ~32 kB/s one 16 kHz microphone delivers is roughly
# how many of them are still out there.  Exposed through /api/state.
TALK_JUNK = {"bytes": 0, "srcs": set(), "first": 0.0, "last": 0.0}


def note_talk_junk(n, src=None):
    if not n:
        return
    if not TALK_JUNK["first"]:
        TALK_JUNK["first"] = time.time()
    if src is not None:
        TALK_JUNK["srcs"].add(src)
    TALK_JUNK["bytes"] += n
    TALK_JUNK["last"] = time.time()


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
        except ConnectionError:
            pass

    def handle_one_request(self):
        # Windows reports a browser that vanished mid-request as
        # ConnectionAbortedError (WSAECONNABORTED).  socketserver would print a
        # whole traceback for what is just a closed tab or a phone leaving
        # Wi-Fi; treat it as the end of this connection instead.
        try:
            super().handle_one_request()
        except ConnectionError:
            self.close_connection = True

    def _json(self, code, **kw):
        self._send(code, kw)

    def _raw_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return b""
        try:
            return self.rfile.read(n)
        except ConnectionError:
            return b""       # client vanished mid-upload; not a server error

    def _body(self):
        try:
            return json.loads(self._raw_body().decode("utf-8", "replace"))
        except Exception:
            return {}

    def _micprobe(self, d):
        """Record what the browser measured about its own capture.

        Kept in a module global rather than a worker because it is a property
        of the browser, not of any camera, and exposed through /api/state so
        it can be read back without hunting through a log.  It is also the
        only honest answer to "what rate is the page really giving us": the
        page *claims* an AudioContext rate, and a claim cannot be trusted.
        """
        if not isinstance(d, dict):
            d = {"raw": str(d)[:300]}
        LAST_PROBE.clear()
        LAST_PROBE.update(d)
        r = d.get("main")
        if isinstance(r, dict):
            print("micprobe main: the talk page measured %.0f samples/s captured "
                  "over %.2f s (%d callbacks, %.0f/s, longest %s samples), and "
                  "POSTed %s B (%.0f B/s in %d POSTs); claimed %s Hz, %s "
                  "callbacks from another node"
                  % (r.get("rate", 0), r.get("wall", 0), r.get("callbacks", 0),
                     r.get("per_sec", 0), r.get("maxlen"), r.get("posted"),
                     r.get("post_rate", 0), r.get("posts"), r.get("ctxRate"),
                     r.get("others")), flush=True)
        for k in ("asked", "plain"):
            r = d.get(k)
            if isinstance(r, dict):
                print("micprobe %s: %.0f samples/s delivered, context says "
                      "%s Hz, track %s Hz/%s ch, peak %.3f rms %.4f"
                      % (k, r.get("samples", 0)
                         / max(0.001, r.get("seconds", 1) or 1),
                         r.get("ctxRate"), r.get("trackRate"),
                         r.get("trackChannels"), r.get("peak", 0),
                         r.get("rms", 0)), flush=True)
        return {"ok": True}

    # -- stills ------------------------------------------------------------
    def _snapshot(self, tid):
        """Serve the newest decoded JPEG as a downloadable still.

        Deliberately NOT a frame consumed off the stream: CameraStreamThread
        keeps `self.frame` as the newest decoded JPEG alongside the bounded
        deque that feeds the MJPEG viewers, so grabbing a still can never
        steal a frame from a live viewer.
        """
        try:
            tid = int(tid)
        except ValueError:
            self._json(404, error="bad camera id")
            return
        w, err = HUB.ensure(tid)
        if err:
            self._json(503, error=err)
            return
        # The worker starts on demand and needs a handshake before the first
        # frame decodes, so wait briefly instead of 503-ing on first click.
        deadline = time.time() + 8.0
        while time.time() < deadline and not w.frame and w.is_alive():
            time.sleep(0.25)
        if not w.frame:
            self._json(503, error=w.error or "no frame decoded yet")
            return
        body = w.frame
        name = "wyze-%s-%s.jpg" % (tid, time.strftime("%Y%m%d-%H%M%S"))
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition",
                         'attachment; filename="%s"' % name)
        self.end_headers()
        try:
            self.wfile.write(body)
        except ConnectionError:
            pass

    # -- one connection for every camera -----------------------------------
    _FEED_HDR = struct.Struct("<QQI")      # tid, publish ms, jpeg length

    def _feed(self):
        """Multiplex every camera's MJPEG onto a SINGLE connection.

        The page used to open one MJPEG socket per camera.  With four cameras
        that is four of the browser's six HTTP/1.1 connections to one origin,
        and switching audio on used the rest -- so /api/state polls and the
        snapshot button had nothing left to run on and simply queued.  That is
        precisely the "everything stacks in pending" and "JPG took minutes"
        report.  One connection for all video empties the pool instead.

        It also makes the browser able to time a frame against its own clock,
        which is the only way to see the last hop's contribution to the delay
        that Phase 16 measured at every earlier stage.  Server and browser are
        the same machine here, so time.time() and Date.now() agree.

        Framing, per frame::

            <Q  tid      u64   camera id
            <Q  t_ms     u64   publish time, epoch milliseconds
            <I  length   u32   JPEG size
            length bytes of JPEG

        Binary rather than multipart so the client slices frames with a
        DataView and never has to scan for a boundary.

        ``?focus=<tid>`` narrows this ONE connection to a single camera: the
        page sends it when a tile goes fullscreen (see setFocus in the page's
        JS).  With focus set, no other camera is even begun -- and because the
        connection then counts as a viewer of only that camera, Hub._supervise
        stops the other workers and frees their sessions for real.
        """
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            focus = int((q.get("focus") or [""])[0])
        except ValueError:
            focus = None
        with HUB.lock:
            if focus is None:
                tids = sorted(HUB.cameras)
            else:                     # focused: one camera or nothing
                tids = [focus] if focus in HUB.cameras else []
        workers = []
        for tid in tids:
            w, _err = HUB.ensure(tid)
            if w:
                workers.append(w)

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        # Count this connection as a viewer from here until the finally at the
        # bottom of the loop (a vanished client must not keep demand forever --
        # that is what holds every camera "running" in the supervisor).
        view = HUB.viewing(focus)     # None here means "the whole grid"
        view.__enter__()

        cursors = {w.camera["tid"]: w.seq for w in workers}
        # Per-connection diagnostics, mirroring _stream so /api/state keeps
        # reporting the same per-camera keys now that the page watches /feed.
        for w in workers:
            for k in ("served", "loops", "first_frame_at", "lag_ms", "dropped"):
                w.stats.pop(k, None)
            w.stats["t0"] = time.time()
            w.stats["nconn"] = w.stats.get("nconn", 0) + 1
            w.stats["base_jpg"] = w.stats.get("jpg", 0)
        served = collections.defaultdict(int)
        dropped = collections.defaultdict(int)
        roster_at = time.time()
        try:
            while True:
                # Discovery can find a camera (or lose one) while the page is
                # already watching, so re-read the roster periodically.
                if time.time() - roster_at > 5.0:
                    roster_at = time.time()
                    # A focused connection re-ensures only its own camera, so
                    # discovery finding a new camera elsewhere never drags
                    # workers onto a server that is deliberately not streaming
                    # them.
                    with HUB.lock:
                        if focus is None:
                            tids = sorted(HUB.cameras)
                        else:
                            tids = [focus] if focus in HUB.cameras else []
                    # Re-ensure EVERY wanted camera, not just newly discovered
                    # ones.  A worker can be replaced while this connection is
                    # open -- the recovery watchdog forces a fresh one -- and
                    # holding the dead object would freeze that tile until the
                    # page reconnected (i.e. until the server restarted).
                    by_tid = {w.camera["tid"]: w for w in workers}
                    for tid in tids:
                        w, _err = HUB.ensure(tid)
                        if not w:
                            continue
                        old = by_tid.get(tid)
                        if old is w:
                            continue
                        by_tid[tid] = w
                        # The replacement starts its own sequence at 0, so a
                        # cursor from the old worker would skip every new
                        # frame.  Start live and reset its per-connection stats.
                        cursors[tid] = w.seq
                        served[tid] = 0
                        dropped[tid] = 0
                        w.stats["t0"] = time.time()
                        w.stats["base_jpg"] = w.stats.get("jpg", 0)
                        w.stats["nconn"] = w.stats.get("nconn", 0) + 1
                    workers = list(by_tid.values())

                out = bytearray()
                for w in workers:
                    tid = w.camera["tid"]
                    frames, cursor = w.take(cursors.get(tid, w.seq))
                    cursors[tid] = cursor
                    w.stats["pub"] = (w.stats.get("jpg", 0)
                                      - w.stats.get("base_jpg", 0))
                    if not frames:
                        continue
                    # Same delay bound as the single-camera stream: replaying a
                    # backlog is what turns a small lag into a permanent one.
                    lag = time.time() - frames[0][1]
                    if lag > MAX_LAG and len(frames) > 1:
                        dropped[tid] += len(frames) - 1
                        frames = frames[-1:]
                    w.stats["lag_ms"] = round(lag * 1000.0, 1)
                    w.stats["dropped"] = dropped[tid]
                    if served[tid] == 0:
                        w.stats["first_frame_at"] = round(
                            time.time() - w.stats["t0"], 1)
                    served[tid] += len(frames)
                    w.stats["served"] = served[tid]
                    for j, t in frames:
                        out += self._FEED_HDR.pack(tid, int(t * 1000), len(j))
                        out += j
                if out:
                    self.wfile.write(out)
                    self.wfile.flush()
                else:
                    time.sleep(0.01)
                    for w in workers:
                        w.stats["loops"] = w.stats.get("loops", 0) + 1
        except ConnectionError:
            pass
        except Exception as e:
            sys.stderr.write("feed stopped: %r\n" % (e,))
        finally:
            view.__exit__(None, None, None)

    # -- routes ------------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
        elif path == "/api/state":
            # The page reports what its <audio> elements are actually playing
            # behind live (?aud=tid:seconds,tid:seconds).  See AUD_LAG.
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            now = time.time()
            for pair in (q.get("aud", [""])[0] or "").split(","):
                if ":" in pair:
                    parts = pair.split(":")
                    try:
                        tid_i = int(parts[0])
                        AUD_LAG.setdefault(tid_i, {})
                        AUD_LAG[tid_i].update(behind=float(parts[1]), t=now)
                        if len(parts) > 2:
                            AUD_LAG[tid_i]["drop"] = int(parts[2])
                    except ValueError:
                        pass
            for pair in (q.get("vid", [""])[0] or "").split(","):
                if ":" in pair:
                    tid_s, ms_s = pair.split(":", 1)
                    try:
                        AUD_LAG.setdefault(int(tid_s), {})
                        AUD_LAG[int(tid_s)].update(vid_ms=float(ms_s), t=now)
                    except ValueError:
                        pass
            names = load_devices_file()
            grab = HUB.grab.state() if getattr(HUB, "grab", None) else None
            if HUB.calling is None:
                warn = ("no handshake on file yet, so there is no video: "
                        "on any phone of this Wi-Fi open the official Wyze "
                        "app and view ONE camera once; the server takes "
                        "care of the rest by itself.")
                if grab and grab.get("genuine"):
                    warn += (" (the grabber is shadowing %d camera(s), "
                             "waiting for the app's handshake)" % grab["genuine"])
            else:
                warn = None if names else \
                    "wyze_devices.json not found \\u2014 camera names are generic."
            self._json(200, cameras=HUB.state(),
                       capture=grab,
                       micprobe=LAST_PROBE,
                       audio_lag=AUD_LAG,
                       talk_junk={"bytes": TALK_JUNK["bytes"],
                                  "srcs": len(TALK_JUNK["srcs"]),
                                  "first": TALK_JUNK["first"],
                                  "last": TALK_JUNK["last"]},
                       warning=warn)
        elif path == "/feed":
            self._feed()
        elif path == "/probe":
            self._send(200, PROBE_PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/api/micprobe":
            # The probe page's fallback channel: an image GET carries the
            # measurement in the query string, in case fetch is the thing that
            # is not working.
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                d = json.loads(q.get("d", ["{}"])[0])
            except Exception:
                d = {"raw": q.get("d", [""])[0][:300]}
            self._json(200, **self._micprobe(d))
        elif path.startswith("/stream/") and path.endswith(".mjpg"):
            self._stream(path.split("/")[2].split(".")[0])
        elif path.startswith("/audio/") and path.endswith(".wav"):
            self._audio(path.split("/")[2].split(".")[0])
        elif path.startswith("/pcm/"):
            # Same audio, no WAV header: what the page's Web Audio reader wants.
            self._audio(path.split("/")[2], wav=False)
        elif path.startswith("/snapshot/") and path.endswith(".jpg"):
            self._snapshot(path.split("/")[2].split(".")[0])
        else:
            self._json(404, error="not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/discover":
            self._body()
            notes = []
            found = HUB.refresh(progress=lambda m: notes.append(m), sweep=True)
            if not found:
                notes.append("nothing answered %d broadcast attempts"
                             % DISCOVER_ATTEMPTS)
            self._json(200, found=len(found), ips=sorted(found),
                       note="; ".join(notes))
        elif path.startswith("/api/talk/"):
            self._talk(path[len("/api/talk/"):].split("/"), self._raw_body())
        elif path == "/api/micprobe":
            self._json(200, **self._micprobe(self._body()))
        else:
            self._json(404, error="not found")

    # -- two-way audio --------------------------------------------------------
    def _talk(self, parts, body):
        """Client -> camera audio, in three tiny endpoints::

            POST /api/talk/start     {"tid": N, "rate": Hz}
            POST /api/talk/stop      {"tid": N}
            POST /api/talk/pcm/<tid>   16 kHz mono PCM16 in the body

        The PCM arrives as fixed-size POSTs because BaseHTTPRequestHandler cannot
        read a chunked request body, and a chunked fetch POST (a ReadableStream
        request body) is not supported by every browser either.
        """
        verb, rest = (parts + [""])[:2]
        if verb == "pcm":
            # parts is ["pcm", "<tid>"], so the id is parts[1].
            try:
                tid = int(parts[1])
            except (ValueError, IndexError):
                note_talk_junk(len(body), self.client_address)
                self._json(404, error="bad camera id")
                return
            w, err = HUB.ensure(tid)
            if err:
                note_talk_junk(len(body), self.client_address)
                self._json(503, error=err)
                return
            # A body that is entirely printable ASCII is not PCM16: real
            # samples use all 256 byte values, and even pure silence is zeros.
            # Text here means a client JSON-encoded its samples -- an object of
            # indices, nine characters per byte -- which the camera would play
            # as braces and decimal digits.  Refuse it and say why, so the page
            # shows the reason on the button instead of anyone hearing garbage.
            if body[:1] in (b"{", b"[") and all(0x20 <= c <= 0x7e for c in body):
                if not w.talk_text_said:
                    w.talk_text_said = True
                    w.log("talk: refusing text bodies from the page (%d B "
                          "starting %r) -- PCM must be raw samples"
                          % (len(body), bytes(body[:16])))
                self._json(400, error="the page is sending text, not PCM "
                                      "samples -- reload it")
                return
            # Any length is accepted: a dropped or short chunk must not end the
            # session, only make this one answer say "nothing to send".
            # The client's address is recorded so a session can report how many
            # separate connections fed it: a page that leaked microphones, or a
            # second tab, shows up here as more than one.
            ok = bool(body) and w.talk_feed(bytes(body), src=self.client_address)
            if body and not ok:
                note_talk_junk(len(body), self.client_address)
            self._json(200, ok=ok)
            return
        if verb in ("start", "stop"):
            # _raw_body() gives bytes here: this is a real body, not _body().
            try:
                d = json.loads(body.decode("utf-8", "replace"))
            except Exception:
                d = {}
            try:
                tid = int(d.get("tid"))
            except (TypeError, ValueError):
                self._json(404, error="bad camera id")
                return
            w, err = HUB.ensure(tid)
            if err:
                self._json(503, error=err)
                return
            if verb == "start":
                err = w.talk_begin(rate=d.get("rate"), dry=bool(d.get("dry")))
                self._json(200 if not err else 503,
                           **({"error": err} if err else {"ok": True}))
            else:
                w.talk_end()
                self._json(200, ok=True)
            return
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
        # A direct MJPEG viewer counts as demand exactly like a /feed
        # connection: the supervisor keeps this camera running while the
        # socket lives, and drops it again after the socket is gone.
        view = HUB.viewing(tid)
        view.__enter__()
        served, dead = 0, 0
        dropped = 0
        # Start at the current head: a new viewer should get LIVE frames, not
        # a burst of up-to-120 stale ones buffered for earlier viewers.
        cursor = w.seq
        t_write = 0.0
        # Per-connection diagnostics.  Only touch keys THIS handler writes --
        # popping a producer-owned key (jpg/h264/fps) races with the worker's
        # `self.stats["h264"] += n` and raises KeyError, which tears down the
        # stream.  Baselines let us report per-connection totals instead.
        for k in ("served", "loops", "t_write", "first_frame_at",
                  "lag_ms", "dropped"):
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
                    # Bound the viewer's lag.  take() returns everything newer
                    # than the cursor, so a browser reading slightly slower
                    # than we write accumulates a backlog, replays it, and then
                    # stays that far behind reality for the rest of the session
                    # -- a permanent, invisible delay.  The publish timestamps
                    # make it measurable: when the OLDEST pending frame is
                    # older than MAX_LAG we are queueing, not streaming, so
                    # jump to the newest frame and count the loss.
                    lag = time.time() - frames[0][1]
                    if lag > MAX_LAG and len(frames) > 1:
                        dropped += len(frames) - 1
                        frames = frames[-1:]
                    w.stats["lag_ms"] = round(lag * 1000.0, 1)
                    w.stats["dropped"] = dropped
                    if served == 0:
                        w.stats["first_frame_at"] = round(
                            time.time() - w.stats["t0"], 1)
                    served += len(frames)
                    w.stats["served"] = served
                    try:
                        t0 = time.time()
                        # one write carrying every frame that accumulated --
                        # a burst must not collapse into a single image.
                        # X-Time is the wall-clock publish time in ms; a client
                        # on this host can subtract it from Date.now() to read
                        # the true end-to-end delay of the frame it is showing.
                        self.wfile.write(b"".join(
                            (b"--frame\r\nContent-Type: image/jpeg\r\n"
                             b"X-Time: %d\r\nContent-Length: %d\r\n\r\n"
                             % (int(t * 1000), len(j)))
                            + j + b"\r\n" for j, t in frames))
                        self.wfile.flush()
                        t_write += time.time() - t0
                        w.stats["t_write"] = round(t_write, 2)
                    except ConnectionError:
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
            view.__exit__(None, None, None)
            w.log("mjpeg served %d frames (write %.1fs)"
                  % (served, t_write))

    # -- audio -------------------------------------------------------------
    def _audio(self, tid, wav=True):
        """Stream 16 kHz mono PCM16 built from the camera's mu-law audio.

        Two shapes, same audio.  `/audio/<tid>.wav` is a streaming WAV for an
        <audio> element or a shell tool; `/pcm/<tid>` is the same PCM with no
        header, for the page, which reads it with fetch() and schedules it on
        an AudioContext.  The page stopped using <audio> because a media
        element insists on buffering ~2.5 s of a live stream (measured:
        buffered.end() - currentTime) to protect itself against stalls it
        cannot otherwise survive -- a delay our own reader can simply decline.

        The camera emits audio interleaved with video on the same linktype/conv,
        and CameraStream._abuf holds gap-filled mu-law (see
        CameraStream._take_audio_frames, which pads every 40000 us hole with
        mu-law zero so the timeline stays at 50 frames/s).  CameraStreamThread
        collects it in a bounded deque; this endpoint decodes each chunk to
        linear PCM.

        `?gain=N` (1..64) multiplies before clipping -- the camera's mic idles
        at about -76 dBFS, correct but inaudible.
        """
        try:
            tid = int(tid)
        except ValueError:
            self._json(404, error="bad camera id")
            return
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            gain = int(q.get("gain", ["1"])[0])
        except ValueError:
            gain = 1
        gain = max(1, min(gain, 64))
        w, err = HUB.ensure(tid)
        if err:
            self._json(503, error=err)
            return

        self.send_response(200)
        self.send_header("Content-Type",
                         "audio/wav" if wav else "application/octet-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()

        # Streaming WAV header: RIFF with 0xFFFFFFFF size (unknown length).
        # fmt=1 (PCM), 1 ch, 16 kHz, 32000 B/s, 2 B/block, 16 bits.
        riff = struct.pack(
            "<4sI4s4sIHHIIHH4sI",
            b"RIFF", 0xFFFFFFFF, b"WAVE", b"fmt ", 16,
            1, 1, SAMPLE_RATE, SAMPLE_RATE * 2, 2, 16,
            b"data", 0xFFFFFFFF)
        try:
            if wav:
                self.wfile.write(riff)
                self.wfile.flush()
        except ConnectionError:
            return

        # An audio listener counts as demand just like a video viewer: while
        # someone is listening, the supervisor must not drop this camera's
        # session out from under them (sound deliberately keeps playing after
        # fullscreen closes -- see the tile's speaker button).
        view = HUB.viewing(tid)
        view.__enter__()
        cursor = w.audio_tail()      # start live, not with the 200-chunk backlog
        dead = 0
        try:
            while True:
                chunks, cursor = w.take_audio(cursor)
                if chunks:
                    try:
                        self.wfile.write(ulaw_to_pcm16(b"".join(chunks), gain))
                        self.wfile.flush()
                        dead = 0
                    except ConnectionError:
                        break
                else:
                    time.sleep(0.02)
                    if not w.is_alive():
                        dead += 1
                        if dead > 100:
                            break
        finally:
            view.__exit__(None, None, None)


def platform_report():
    """One screen of facts that decide whether discovery can work at all."""
    print("Python %s on %s" % (sys.version.split()[0], sys.platform))
    ips = local_ipv4()
    print("local IPv4 : %s" % (", ".join(ips) or "(none -- no LAN address?)"))
    print("broadcast  : %s" % (", ".join(broadcast_addrs()) or "(none)"))
    ff = shutil.which("ffmpeg")
    print("ffmpeg     : %s" % (ff or "NOT FOUND on PATH -- video will not decode"))
    if sys.platform.startswith("win"):
        # The inbound direction is the one Windows blocks by default, and it
        # is the answer's direction: we send the probe, the camera answers to
        # our ephemeral port.  No amount of broadcast tuning survives that.
        print("windows    : if the probe leaves but no camera answers, allow "
              "%s" % sys.executable)
        print("             through Windows Defender Firewall (Private "
              "networks), not just outbound.")


def no_camera_help():
    """What to check when three probes produced nothing."""
    print("")
    print("No camera answered. Check these in order:")
    print("  1. This PC and the cameras are on the same subnet.  Compare the")
    print("     local IPv4 above with the IP the phone shows for a camera")
    print("     (official app -> camera -> Device Info).  Different third")
    print("     octet means a second router/guest VLAN: broadcasts cannot")
    print("     cross it.")
    print("  2. Windows Firewall must allow INBOUND UDP for %s."
          % sys.executable)
    if sys.platform.startswith("win"):
        print("     Run once in an elevated PowerShell:")
        print('       New-NetFirewallRule -DisplayName "wyze-cam-stream" '
              '-Direction Inbound')
        print('         -Program "%s" -Protocol UDP -Action Allow '
              '-Profile Private' % sys.executable)
        print("     Also make sure the Wi-Fi/Ethernet profile is Private:")
        print("       Get-NetConnectionProfile")
        print('       Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" '
              '-NetworkCategory Private')
    print("  3. Ping a camera's IP.  A reply proves routing; a timeout with")
    print("     the same subnet usually means the firewall or AP isolation.")
    print("     If the Wyze app shows a camera IP, probe it directly")
    print("     (from the wyze-cam-stream directory):")
    print("       python ../discover.py 192.168.1.23")
    print("  4. Some routers/APs enable 'client isolation' (guest Wi-Fi),")
    print("     which blocks PC <-> camera traffic entirely.")
    print("  5. A VPN, Hyper-V, WSL or VirtualBox adapter can take the")
    print("     broadcast route.  Disconnect the VPN and retry.")


def main():
    # Windows consoles/redirected stdout use a legacy code page; camera
    # nicknames are user data and may not fit it.  Never let a print() kill
    # the scan -- degrade the glyph instead.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(description="Wyze camera web viewer (LAN only)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default: localhost only)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--discover", action="store_true",
                    help="scan the LAN once and exit")
    args = ap.parse_args()

    if args.discover:
        platform_report()
        found = {}
        for attempt in range(1, DISCOVER_ATTEMPTS + 1):
            print("discovery attempt %d/%d..." % (attempt, DISCOVER_ATTEMPTS),
                  flush=True)
            # Last chance: unicast the local /24 as well, so a blocked
            # broadcast does not look like an absent camera.
            found = discover(DISCOVER_DURATION, verbose=True,
                             sweep=(attempt == DISCOVER_ATTEMPTS))
            if found:
                break
        devs = load_devices_file()
        for ip, d in sorted(found.items()):
            mac = d.get("wyze_id") or ""
            print("%-16s tid=%s port=%-6s %-12s %s"
                  % (ip, d.get("tid"), d.get("p2p_port"),
                     (devs.get(mac) or {}).get("nickname") or "?", mac))
        if not found:
            no_camera_help()
        return 0

    if not shutil.which("ffmpeg"):
        print("WARNING: ffmpeg is not on PATH.  Discovery will work but the")
        print("         video pipeline cannot decode; install ffmpeg and")
        print("         reopen this terminal before streaming.")

    if not HUB.calling:
        print("No handshake on file yet: the grabber is armed and shadows "
              "the cameras.")
        print("The first time the official app on any phone of this Wi-Fi "
              "views ONE")
        print("camera, the handshake lands by itself and the grid streams.")

    devs = load_devices_file()
    print("Scanning the LAN for cameras...")
    found = HUB.refresh(progress=lambda m: print("  " + m), sweep=True)
    if not found:
        print("  no cameras answered (they may be off) "
              "-- the UI retries every 2 s.")
        print("  Run 'python server.py --discover' for a full LAN/firewall "
              "diagnostic.")
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
