#!/usr/bin/env python3
"""Decode the app's mic audio: test the AMR hypothesis.

Each 32-byte block in the 226-byte talk frame starts with a constant 0x3c and is
followed by 31 bytes.  AMR-NB mode 7 (12.2 kbit/s) is 244 bits == 31 bytes per
20 ms frame, and six of those is 120 ms -- which matches both the observed byte
rate and the observed send interval.  0x3c = 0b0_0111_100 is then a plausible
RFC 4867 Table-of-Contents octet with FT=7.

If that is right, concatenating the blocks with an AMR header must decode to
speech with ffmpeg.

Usage: python3 talkamr.py
"""
import os
import struct
import subprocess
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
from mtp_frame import unwrap                              # noqa: E402
from listreq import rc5_setup, rc5_decrypt_block          # noqa: E402
from appcalling import mode1                              # noqa: E402

CONV = 0x00F82BBF
FFMPEG = "/opt/homebrew/bin/ffmpeg"


def load(path):
    out = []
    with open(path, "rb") as f:
        while True:
            b = f.read(4)
            if len(b) < 4:
                return out
            out.append(f.read(struct.unpack("<I", b)[0]))


def key_for(conv_hi):
    for d in load("/tmp/applan_a2c.bin"):
        if d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4" and len(d) > 100:
            pt = mode1(d)
            if (struct.unpack_from("<I", pt, 28)[0] | 0x80000000) == conv_hi:
                return pt[120:128]


def frames():
    buf = bytearray()
    for d in load("/tmp/applan_a2c.bin"):
        if d[:2] != b"\xc0\x10":
            continue
        u = unwrap(d)
        if not u:
            continue
        s = u[0]
        if len(s) < 24 or (s[4] & 0x0F) != 1:
            continue
        if struct.unpack_from("<I", s, 0)[0] != CONV:
            continue
        ln = struct.unpack_from("<I", s, 20)[0]
        buf += s[24:24 + ln]
    key = key_for(CONV | 0x80000000)
    S = rc5_setup(key)
    out, i = [], 0
    while i + 4 <= len(buf):
        ln = struct.unpack_from("<H", buf, i + 2)[0]
        if ln < 4 or i + ln > len(buf):
            break
        b = bytes(buf[i + 4:i + ln])
        out.append(b"".join(rc5_decrypt_block(S, b[o:o + 8], "little")
                            for o in range(0, len(b) // 8 * 8, 8)) + b[len(b) // 8 * 8:])
        i += ln
    return [p for p in out if len(p) == 226]


def main():
    fr = frames()
    print("%d talk frames of 226 B" % len(fr))

    # blocks start at 34, then every 32 bytes
    subs = []
    for p in fr:
        for k in range(6):
            off = 34 + 32 * k
            subs.append(p[off:off + 32])
    print("%d sub-blocks of 32 B" % len(subs))

    for name, blob in (("AMR_NB", b"#!AMR\n" + b"".join(subs)),
                       ("AMR_WB", b"#!AMR-WB\n" + b"".join(subs))):
        path = "/tmp/talk_%s.amr" % name
        with open(path, "wb") as f:
            f.write(blob)
        print("\n=== %s (%d bytes) ===" % (name, len(blob)))
        r = subprocess.run([FFMPEG, "-hide_banner", "-v", "warning", "-i", path,
                            "-f", "s16le", "-ac", "1", "-ar", "8000",
                            "/tmp/talk_%s.raw" % name],
                           capture_output=True, text=True)
        err = (r.stderr or "").strip()
        print("  ffmpeg: %s" % (err if err else "(no warnings)"))
        raw = "/tmp/talk_%s.raw" % name
        if os.path.exists(raw):
            d = open(raw, "rb").read()
            n = len(d) // 2
            print("  decoded %d samples = %.2f s" % (n, n / 8000.0))
            if n:
                s = struct.unpack("<%dh" % n, d[:n * 2])
                peak = max(abs(x) for x in s)
                rms = (sum(x * x for x in s) / n) ** 0.5
                nz = sum(1 for x in s if x)
                print("  peak %d  rms %.1f  nonzero %.1f%%"
                      % (peak, rms, 100.0 * nz / n))
                print("  first 24 samples: %s" % (s[:24],))


if __name__ == "__main__":
    main()
