#!/usr/bin/env python3
"""Round-trip test for the talk audio codec.

Captured sub-block -> decode -> re-encode -> compare.  If ffmpeg's AMR-NB
encoder at 12.2 kbit/s reproduces the captured silence bytes, then the codec and
the bitrate are both pinned and we can generate our own talk audio.

Usage: python3 talkrt.py
"""
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
        buf += s[24:24 + struct.unpack_from("<I", s, 20)[0]]
    key = next(mode1(d)[120:128] for d in load("/tmp/applan_a2c.bin")
               if d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4"
               and len(d) > 100
               and (struct.unpack_from("<I", mode1(d), 28)[0] | 0x80000000)
               == CONV | 0x80000000)
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


def amr_frames(path):
    """Frames from an AMR-NB file as (toc, payload)."""
    d = open(path, "rb").read()
    assert d[:6] == b"#!AMR\n", d[:8]
    d = d[6:]
    sizes = {0: 13, 1: 14, 2: 16, 3: 18, 4: 20, 5: 21, 6: 27, 7: 32,
             8: 6, 15: 1}          # ToC byte including the ToC octet
    out, i = [], 0
    while i < len(d):
        toc = d[i]
        ft = (toc >> 3) & 0x0F
        n = sizes.get(ft)
        if n is None or i + n > len(d):
            break
        out.append((toc, d[i + 1:i + n]))
        i += n
    return out


def main():
    fr = frames()
    sub = [fr[2][34 + 32 * k:34 + 32 * k + 32] for k in range(6)]
    print("captured silence sub-block 0: %s" % sub[0].hex())
    print("captured toc=%02x payload=%s" % (sub[0][0], sub[0][1:].hex()))

    blob = b"#!AMR\n" + b"".join(sub)
    open("/tmp/rt_in.amr", "wb").write(blob)

    # decode to raw PCM
    r = subprocess.run([FFMPEG, "-y", "-v", "error", "-i", "/tmp/rt_in.amr",
                        "-f", "s16le", "-ac", "1", "-ar", "8000", "/tmp/rt.pcm"],
                       capture_output=True, text=True)
    print("decode:", r.stderr.strip() or "ok")
    pcm = open("/tmp/rt.pcm", "rb").read()
    print("pcm %d bytes = %.3f s" % (len(pcm), len(pcm) / 2 / 8000))

    for br in ("12.2k", "12.2", "12200"):
        r = subprocess.run([FFMPEG, "-y", "-v", "error", "-f", "s16le",
                            "-ar", "8000", "-ac", "1", "-i", "/tmp/rt.pcm",
                            "-c:a", "libopencore_amrnb", "-b:a", br,
                            "/tmp/rt_out.amr"], capture_output=True, text=True)
        if r.returncode != 0:
            print("encode %s: %s" % (br, r.stderr.strip().splitlines()[-1:]))
            continue
        got = amr_frames("/tmp/rt_out.amr")
        print("\nencode %s -> %d frames" % (br, len(got)))
        for k in range(min(6, len(got))):
            toc, pay = got[k]
            match = "MATCH" if (bytes([toc]) + pay) == sub[k] else "differs"
            print("  frame %d  ours %02x %s  ffmpeg %02x %s  %s"
                  % (k, sub[k][0], sub[k][1:9].hex(), toc, pay[:8].hex(), match))
        break


if __name__ == "__main__":
    main()
