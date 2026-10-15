#!/usr/bin/env python3
"""Read the session word a camera puts in its own `c0 90` hello.

The 74-byte hellos the camera emits at ~1 Hz are MTP frames in the clear, and
their payload[4:8] is a session word.  Comparing that against the conv we are
forging with answers the question that has been blocking phase E:

    does the camera actually hold a session whose +0x10 is OUR word?

If the hello word != our conv, iv_find_mtp_session misses for both the forged
7e a3 (0x4bb44) and every KCP WASK (0x6315c), which would explain a clean ack
followed by silence perfectly.

    python3 decode_hello.py /tmp/p2p_mtpres3.log
"""
import re
import struct
import sys

sys.path.insert(0, ".")
from mtp_frame import unwrap                       # noqa: E402

REPLY = re.compile(r"REPLY from (\d+\.\d+\.\d+\.\d+):(\d+) len=(\d+)")
SENT = re.compile(r"\[\s*([\d.]+)s\] mtp_res conv=0x([0-9a-f]{8}) "
                  r"fl=([0-9a-f]{8}) :(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)")


def main(path):
    lines = open(path, errors="replace").read().splitlines()

    # what conv we sent, per camera
    sent = {}
    for i, ln in enumerate(lines):
        m = SENT.search(ln)
        if m:
            sent.setdefault(m.group(5), set()).add(int(m.group(2), 16))

    # every 74-byte reply and its hex
    words = {}
    i = 0
    while i < len(lines):
        m = REPLY.search(lines[i])
        if m and int(m.group(3)) == 74:
            hexbytes = []
            for j in range(i + 1, min(i + 8, len(lines))):
                mm = re.match(r"^\s*\d+\s+((?:[0-9a-f]{2} ){1,16})", lines[j])
                if mm:
                    hexbytes.extend(mm.group(1).split())
                elif hexbytes:
                    break
            raw = bytes(int(b, 16) for b in hexbytes)
            if len(raw) == 74:
                r = unwrap(raw)
                if r and len(r[0]) >= 8:
                    w = struct.unpack_from("<I", r[0], 4)[0]
                    words.setdefault(m.group(1), set()).add(w)
        i += 1

    print("%-16s %-24s %s" % ("camera", "hello word(s)", "our conv(s)"))
    print("-" * 78)
    ok = True
    for ip in sorted(set(sent) | set(words)):
        hw = sorted(words.get(ip, ()))
        sw = sorted(sent.get(ip, ()))
        match = bool(set(hw) & set(sw))
        ok = ok and match and len(hw) == 1
        print("%-16s %-24s %s   %s"
              % (ip,
                 " ".join("0x%08x" % w for w in hw) or "-",
                 " ".join("0x%08x" % w for w in sw) or "-",
                 "MATCH" if match else "*** MISMATCH ***"))
    print()
    if not words:
        print("no 74-byte hellos parsed")
        return 1
    print("verdict:", "hello word == our conv on every camera"
          if ok else "MISMATCH -> the session does not hold our word")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
