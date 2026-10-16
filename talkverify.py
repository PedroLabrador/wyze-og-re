#!/usr/bin/env python3
"""END-TO-END ACOUSTIC CHECK of the talk path, with a real microphone.

This is the tool that settled the talk rate in Phase 22.  It is the only check
that measures what the camera's speaker actually does, rather than asking the
user what a clip sounded like -- and it is why the answer is now a number.

It needs a person and a microphone, so it is interactive by design.  One
sitting, three phases:

  A  a normal voice take over the microphone; the loudest 7 s is trimmed,
     peak-normalised and becomes the test clip (and gives its natural pitch)
  B  silence while the microphone is moved to the camera's speaker
  C  the camera plays 1.5 s of 1 kHz tone, a pause, then that voice, through
     the real product path, while the microphone records the speaker

Then everything is measured offline with stdlib only (Goertzel, no numpy):

  * where the beep lands in frequency.  We hand the camera content that is
    deliberately 2x slow, so 1 kHz travels as 500 Hz; the camera's own 2x
    playout must put it back at ~1000 Hz.
  * the beep's duty cycle at 2/5/10 ms resolution.  A starved camera idles
    between packets and shows it here (51 % when fed at 1x, 90-100 % at 2x).
  * the pitch of the voice that comes back, against the pitch recorded in A.

ALWAYS take the silent-room control first: record 2 s with nothing played and
confirm it is digital silence with no tone in any band.  Without that
control a room hum or a fan is indistinguishable from a camera.

Make sure the camera is streaming and that the Wyze app is force-stopped --
the camera holds ONE session.

Usage:
    python3 talkverify.py [--port 8080] [--tid 429728658691722]
                          [--mic 1] [--skip-voice]
"""

import json
import math
import os
import struct
import subprocess
import sys
import time
import urllib.request
import wave

FF = "/opt/homebrew/bin/ffmpeg"
BASE = "http://127.0.0.1:8080"
TID = 429728658691722              # Camera 1; overridden by --tid
SR = 16000
MIC_DEV = "1"                      # AVFoundation audio device: External Microphone
VOICE_WAV = "/tmp/user_voice.wav"
VOICE_PCM = "/tmp/user_voice.pcm"
REC = "/tmp/mic_cam2.wav"
PLAY = "/tmp/probe2.pcm"
TONE_HZ = 1000.0
TONE_S = 1.5
GAP_S = 0.8
REC_S = 14.0
VOICE_MAX_S = 7.0


def post(path, body, ctype):
    r = urllib.request.Request(BASE + path, data=body, method="POST")
    r.add_header("Content-Type", ctype)
    with urllib.request.urlopen(r, timeout=30) as f:
        return f.read().decode()


def wait_streaming(timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(BASE + "/api/state", timeout=20) as f:
                s = json.loads(f.read())
            c = [x for x in s["cameras"] if x["tid"] == TID][0]
        except Exception:
            time.sleep(1)
            continue
        if c["status"] == "streaming" and c["stats"]["fps"] > 8:
            return c
        print("   waiting: cam1=%s fps=%.1f"
              % (c["status"], c["stats"]["fps"]), flush=True)
        time.sleep(2)
    return None


def record(path, secs):
    subprocess.run([FF, "-y", "-hide_banner", "-loglevel", "error",
                    "-f", "avfoundation", "-i", ":%s" % MIC_DEV,
                    "-t", str(secs), "-ar", str(SR), "-ac", "1", path],
                   stdin=subprocess.DEVNULL)


def read_wav(path):
    with wave.open(path) as w:
        sr = w.getframerate()
        raw = w.readframes(w.getnframes())
    return sr, list(struct.unpack("<%dh" % (len(raw) // 2), raw))


def rms(x):
    return math.sqrt(sum(float(v) * v for v in x) / len(x)) if x else 0.0


def band(s, f):
    w = 2 * math.pi * f / SR
    c = 2 * math.cos(w)
    q1 = q2 = 0.0
    for v in s:
        q0 = c * q1 - q2 + v / 32768.0
        q2, q1 = q1, q0
    return math.sqrt(max(0.0, q1 * q1 + q2 * q2 - c * q1 * q2)) / len(s)


def f0_autocorr(x, fmin=50, fmax=500):
    N = int(0.040 * SR)
    hop = N // 2
    lo, hi = int(SR / fmax), int(SR / fmin)
    out = []
    for i in range(0, len(x) - N, hop):
        fr = [v / 32768.0 for v in x[i:i + N]]
        if rms(fr) < 0.02:
            continue
        m = sum(fr) / N
        fr = [v - m for v in fr]
        e0 = sum(v * v for v in fr)
        if e0 <= 0:
            continue
        best = (0, 0)
        for lag in range(lo, hi):
            s = sum(fr[j] * fr[j + lag] for j in range(N - lag))
            if s > best[0]:
                best = (s, lag)
        if best[1] and best[0] / e0 > 0.35:
            out.append(SR / best[1])
    out.sort()
    return out


def phase_a():
    print(">>> PHASE A: SPEAK NOW -- normal voice, right up close to the "
          "microphone, keep talking for 18 s", flush=True)
    record(VOICE_WAV, 18)
    sr, x = read_wav(VOICE_WAV)
    if sr != SR:
        raise SystemExit("mic gave %d Hz, expected %d" % (sr, SR))
    hop = 1600
    env = [rms(x[i:i + hop]) for i in range(0, len(x) - hop, hop)]
    if not env:
        print("   PHASE A captured no samples")
        return None
    floor = sorted(env)[len(env) // 5]
    thr = max(30.0, 4.0 * floor)
    loud = [i for i, e in enumerate(env) if e > thr]
    print("   phase A: floor %.1f, threshold %.1f, %d/%d windows above, peak "
          "window %.1f" % (floor, thr, len(loud), len(env), max(env)))
    if not loud:
        print("   PHASE A was silent")
        return None
    a = loud[0] * hop
    b = min(len(x), (loud[-1] + 1) * hop)
    if (b - a) / SR > VOICE_MAX_S:
        # Keep the loudest VOICE_MAX_S inside the span rather than its head,
        # in case speech starts late.
        step = hop
        best, bs = a, -1.0
        while best + int(VOICE_MAX_S * SR) <= b:
            s = sum(env[best // hop:(best + int(VOICE_MAX_S * SR)) // hop])
            if s > bs:
                bs, ba = s, best
            best += step
        a = ba if bs > 0 else a
        b = a + int(VOICE_MAX_S * SR)
    clip = x[a:b]
    peak = max(abs(v) for v in clip)
    if peak:
        gain = 0.6 * 32767.0 / peak
        clip = [max(-32768, min(32767, int(v * gain))) for v in clip]
    with open(VOICE_PCM, "wb") as f:
        f.write(struct.pack("<%dh" % len(clip), *clip))
    f0 = f0_autocorr(clip)
    print("   voice: %.2f s (from %.2f s of recording), raw peak %d, "
          "%.1f dBFS" % (len(clip) / SR, len(x) / SR, peak,
                         20 * math.log10(max(1e-9, peak) / 32768.0)))
    if f0:
        print("   voice F0 (median autocorrelation): %.1f Hz  [n=%d, "
              "%.0f-%.0f]" % (f0[len(f0) // 2], len(f0), f0[0], f0[-1]))
    return clip


def phase_c():
    voice = open(VOICE_PCM, "rb").read()
    n = int(SR * TONE_S)
    tone = b"".join(struct.pack("<h", int(0.35 * 32767
                                          * math.sin(2 * math.pi * TONE_HZ * i / SR)))
                    for i in range(n))
    data = tone + b"\x00" * int(SR * GAP_S * 2) + voice
    open(PLAY, "wb").write(data)
    print(">>> PHASE B: move the microphone to the camera's speaker now, 8 s",
          flush=True)
    time.sleep(8)
    print(">>> PHASE C: recording %d s; the camera will beep then speak"
          % REC_S, flush=True)
    rec = subprocess.Popen([FF, "-y", "-hide_banner", "-loglevel", "error",
                            "-f", "avfoundation", "-i", ":%s" % MIC_DEV,
                            "-t", str(REC_S), "-ar", str(SR), "-ac", "1", REC],
                           stdin=subprocess.DEVNULL)
    time.sleep(3.0)
    for attempt in (1, 2, 3):
        try:
            post("/api/talk/start", b'{"tid":%d}' % TID, "application/json")
            break
        except Exception as e:
            print("   start attempt %d failed: %s" % (attempt, e), flush=True)
            time.sleep(2)
    t0 = time.time()
    k = 0
    for i in range(0, len(data), 1024):
        post("/api/talk/pcm/%d" % TID, data[i:i + 1024], "application/octet-stream")
        k += 1
        nxt = t0 + k * 0.032
        if nxt > time.time():
            time.sleep(nxt - time.time())
    post("/api/talk/stop", b'{"tid":%d}' % TID, "application/json")
    print("   playback: %.2f s of signal in %.2f s wall"
          % (len(data) / 2 / SR, time.time() - t0), flush=True)
    rec.wait()

    sr, x = read_wav(REC)
    print("\nrecording: %.2f s @ %d Hz" % (len(x) / sr, sr))
    w = int(sr * 0.1)
    env = [rms(x[i:i + w]) for i in range(0, len(x) - w, w)]
    peak = max(env) if env else 0
    line = ""
    for v in env:
        r = v / peak if peak else 0
        line += "L" if r > 0.5 else ("s" if r > 0.15 else ("." if r > 0.03 else " "))
    print("100 ms profile ('L' loud/'s' voice/'.' weak/' ' silent):")
    for i in range(0, len(line), 100):
        print("  %5.1fs %s" % (i * 0.1, line[i:i + 100]))

    loud = [i for i, v in enumerate(env) if v > 0.3 * peak]
    if not loud:
        raise SystemExit("nothing above 30%% of peak in the recording")
    t_start = loud[0] * 0.1
    print("\nfirst loud window at %.1f s (playback began ~3.0 s in)" % t_start)

    seg = x[int((t_start + 0.25) * sr):int((t_start + 1.3) * sr)]
    print("tone segment %.2f-%.2f s:" % (t_start + 0.25, t_start + 1.3))
    bands = {f: band(seg, f) for f in (250, 500, 1000, 2000, 3000)}
    tot = sum(bands.values()) or 1.0
    for f, e in sorted(bands.items(), key=lambda kv: -kv[1]):
        print("   %5d Hz %8.5f (%5.1f %%)" % (f, e, 100 * e / tot))
    best = max(bands, key=bands.get)
    print("=> dominant %d Hz  (shipped as 500 Hz content -> camera 2x would "
          "give 1000 Hz)" % best)

    tw = sr // 500
    tenv = [rms(seg[i:i + tw]) for i in range(0, len(seg) - tw, tw)]
    if tenv:
        mx = max(tenv)
        on = sum(1 for v in tenv if v > 0.5 * mx)
        print("tone duty (2 ms windows): %.0f%%  (was 51%% when we fed at 1x)"
              % (100.0 * on / len(tenv)))

    tail = x[int((t_start + TONE_S + GAP_S) * sr):]
    f0 = f0_autocorr(tail, fmin=60, fmax=900)
    print("played-back voice F0: %s"
          % ("%.1f Hz [n=%d]" % (f0[len(f0) // 2], len(f0)) if f0 else "none"))


def main():
    global BASE, TID, MIC_DEV
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--tid", type=int, default=TID,
                    help="camera TID (default: Camera 1)")
    ap.add_argument("--mic", default=MIC_DEV,
                    help="AVFoundation audio device index (default 1)")
    ap.add_argument("--skip-voice", action="store_true",
                    help="skip phase A and reuse /tmp/user_voice.pcm")
    args = ap.parse_args()
    BASE = "http://127.0.0.1:%d" % args.port
    TID = args.tid
    MIC_DEV = args.mic
    if args.skip_voice and not os.path.exists(VOICE_PCM):
        raise SystemExit("--skip-voice needs %s; run without it once" % VOICE_PCM)
    c = wait_streaming()
    if not c:
        raise SystemExit("camera %d never reached streaming" % TID)
    print("cam1 streaming fps=%.1f" % c["stats"]["fps"], flush=True)
    clip = None if args.skip_voice else phase_a()
    if clip is None and args.skip_voice:
        print("phase A skipped; reusing %s" % VOICE_PCM, flush=True)
    elif clip is None:
        print("no usable voice captured -- falling back to the app's captured "
              "audio (first %.0f s)" % VOICE_MAX_S, flush=True)
        raw = open("/tmp/ab16.pcm", "rb").read()[:int(VOICE_MAX_S * SR) * 2]
        with open(VOICE_PCM, "wb") as f:
            f.write(raw)
    phase_c()


if __name__ == "__main__":
    main()
