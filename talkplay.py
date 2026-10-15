#!/usr/bin/env python3
"""Play an AMR-NB file into a Wyze OG camera's speaker.

This is the proof step for two-way audio: it drives a normal CameraStream
session and pushes client->camera media the way the app does -- linktype 4 on
the low conv, RC5 with the session AV key, six AMR-NB (12.2 kbit/s) frames per
120 ms packet.

The default source is the app's own captured talk audio, so if the camera
speaks that voice back then the framing, the cipher, the conv and the
codec are all right at once.

The camera holds ONE session; force-stop the Wyze app before running this.

Usage:
    python3 talkplay.py <tid> [--capture] [--amr FILE] [--secs N] [--loop]
                        [--gain D] [--quiet]
"""
import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                        # noqa: E402
from mtp_frame import unwrap                             # noqa: E402
from listreq import rc5_setup, rc5_decrypt_block         # noqa: E402
from appcalling import mode1                             # noqa: E402

TALK_CONV = 0x00F82BBF
FFMPEG = "/opt/homebrew/bin/ffmpeg"
FRAMES = "~/Downloads/wyze-re/wire/p2p_frames.json"


def load_records(path):
    out = []
    with open(path, "rb") as f:
        while True:
            b = f.read(4)
            if len(b) < 4:
                return out
            out.append(f.read(struct.unpack("<I", b)[0]))


def captured_amr():
    """The app's talk audio as a list of 31-byte AMR-NB payloads."""
    buf = bytearray()
    for d in load_records("/tmp/applan_a2c.bin"):
        if d[:2] != b"\xc0\x10":
            continue
        u = unwrap(d)
        if not u:
            continue
        s = u[0]
        if len(s) < 24 or (s[4] & 0x0F) != 1:
            continue
        if struct.unpack_from("<I", s, 0)[0] != TALK_CONV:
            continue
        buf += s[24:24 + struct.unpack_from("<I", s, 20)[0]]
    key = None
    for d in load_records("/tmp/applan_a2c.bin"):
        if d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4" and len(d) > 100:
            pt = mode1(d)
            if (struct.unpack_from("<I", pt, 28)[0] | 0x80000000) == TALK_CONV | 0x80000000:
                key = pt[120:128]
    S = rc5_setup(key)
    payloads, i = [], 0
    while i + 4 <= len(buf):
        ln = struct.unpack_from("<H", buf, i + 2)[0]
        if ln < 4 or i + ln > len(buf):
            break
        b = bytes(buf[i + 4:i + ln])
        p = b"".join(rc5_decrypt_block(S, b[o:o + 8], "little")
                     for o in range(0, len(b) // 8 * 8, 8)) + b[len(b) // 8 * 8:]
        if len(p) == p2p_client.TALK_PKT_BYTES:
            for k in range(p2p_client.TALK_FRAMES_PER_PKT):
                off = 34 + k * p2p_client.TALK_AMR_FRAME
                payloads.append(p[off + 1:off + p2p_client.TALK_AMR_FRAME])
        i += ln
    return payloads


def amr_file_payloads(path):
    """Payloads (without ToC) from an AMR-NB file, re-encoded at 12.2 kbit/s."""
    d = open(path, "rb").read()
    if d[:6] != b"#!AMR\n":
        raise SystemExit("%s is not an AMR-NB file" % path)
    d = d[6:]
    out, i = [], 0
    while i < len(d):
        ft = (d[i] >> 3) & 0x0F
        if ft != 7:                      # only 12.2 kbit/s frames fit our pkt
            break
        out.append(d[i + 1:i + 32])
        i += 32
    return out


def main():
    args = [a for a in sys.argv[1:]]
    tid = None
    for a in list(args):
        if not a.startswith("-"):
            tid = a
            args.remove(a)
            break
    tid = tid or "429728659223864"
    secs = 30.0
    if "--secs" in args:
        secs = float(args[args.index("--secs") + 1])
    loop = "--loop" in args
    quiet = "--quiet" in args
    amr_file = None
    if "--amr" in args:
        amr_file = args[args.index("--amr") + 1]
    gain = 1.0
    if "--gain" in args:
        gain = float(args[args.index("--gain") + 1])
    speed = 1.0
    if "--speed" in args:
        speed = float(args[args.index("--speed") + 1])

    if amr_file or not os.path.exists("/tmp/applan_a2c.bin"):
        if not amr_file:
            raise SystemExit("no --amr file and no captured dialogue in /tmp")
        payloads = amr_file_payloads(amr_file)
        print("source: %s (%d AMR frames)" % (amr_file, len(payloads)))
    else:
        payloads = captured_amr()
        print("source: captured app talk audio (%d AMR frames = %.1f s)"
              % (len(payloads), len(payloads) * 0.02))

    if gain != 1.0 or speed != 1.0:
        payloads = _reencode(payloads, gain=gain, speed=speed)
        print("applied gain=%s speed=%s -> %d AMR frames = %.1f s"
              % (gain, speed, len(payloads), len(payloads) * 0.02))

    got = p2p_client.discover(duration=5.0, want_tid=tid)
    if not got:
        raise SystemExit("camera %s not found" % tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("camera %s:%s" % (ip, port), flush=True)

    import json
    j = json.load(open(FRAMES))
    ent = (j.get("devices", {}) or {}).get(tid) or {}
    hexs = (ent.get("frames") or {}).get("calling")
    if not hexs:
        raise SystemExit("no CALLING for %s in %s" % (tid, FRAMES))
    calling = bytes.fromhex(hexs)
    print("using our %d B CALLING for %s" % (len(calling), tid))

    st = p2p_client.CameraStream(
        ip, port, tid, calling, timeout=secs + 5.0,
        on_log=(lambda m: None) if quiet else (lambda m: print("   [log] %s" % m, flush=True)))

    try:
        st.open_talk()
        print("talk stream open; sending %d frames of 120 ms" % len(payloads), flush=True)
        t0 = time.time()
        n = 0
        idx = 0
        nxt = t0
        while time.time() - t0 < secs and idx < len(payloads):
            batch = payloads[idx:idx + p2p_client.TALK_FRAMES_PER_PKT]
            idx += len(batch)
            if len(batch) < p2p_client.TALK_FRAMES_PER_PKT:
                if loop:
                    idx = 0
                    continue
                break
            st.send_talk(batch)
            n += 1
            nxt += 0.120
            st._pump(max(0.0, nxt - time.time()),
                     [(st.kcp_lo.conv, st.kcp_lo), (st.kcp_hi.conv, st.kcp_hi)])
            if n % 25 == 0:
                print("  %5.1f s  sent %d packets (%.1f s of audio)"
                      % (time.time() - t0, n, n * 0.12), flush=True)
        print("sent %d packets in %.1f s" % (n, time.time() - t0))
    finally:
        st.close()


def _apply_gain(payloads, gain):
    """Decode, scale and re-encode the AMR payloads (needs ffmpeg)."""
    return _reencode(payloads, gain=gain)


def _reencode(payloads, gain=1.0, speed=1.0):
    """Decode, optionally rescale/respeed, and re-encode to AMR-NB 12.2k.

    `speed` > 1 makes the clip play faster by resampling rather than by
    time-stretching, so the pitch moves with the rate -- that is what tells a
    playback-rate problem apart from a codec problem.
    """
    blob = b"#!AMR\n" + b"".join(bytes([0x3C]) + p for p in payloads)
    open("/tmp/talkgain_in.amr", "wb").write(blob)
    chain = []
    if speed != 1.0:
        chain.append("asetrate=%d" % int(8000 * speed))
        chain.append("aresample=8000")
    if gain != 1.0:
        chain.append("volume=%f" % gain)
    cmd = [FFMPEG, "-y", "-v", "error", "-i", "/tmp/talkgain_in.amr"]
    if chain:
        cmd += ["-af", ",".join(chain)]
    cmd += ["-ar", "8000", "-ac", "1", "-c:a", "libopencore_amrnb",
            "-b:a", "12.2k", "/tmp/talkgain_out.amr"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("re-encode failed: %s" % r.stderr.strip())
    return amr_file_payloads("/tmp/talkgain_out.amr")


if __name__ == "__main__":
    main()
