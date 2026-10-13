#!/usr/bin/env python3
"""Freeze the captured P2P frames into wire/p2p_frames.json.

`p2p_call.py` normally reads `/tmp/forge_in_*.bin`, which only exists after a
`forge_call.py` run against the patched app. That is a temp file, so the repo
would not be reproducible from a clean checkout. This script harvests whatever
is in /tmp right now and writes one JSON file the repo can be committed with.

IMPORTANT: the per-session word (`session+0x10`, see P2P_PROTOCOL.md 5e) is
random per session, and the *hello* and the *CALLING* we replay **must carry the
same word** or the camera's `iv_find_mtp_session` lookup drops one of them. So
frames are grouped by (tid, word) and only whole groups are kept.
"""
import glob
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyze_calls import decrypt          # noqa: E402
from mtp_frame import unwrap               # noqa: E402
from p2p_call import extract_tid           # noqa: E402

SIMPLE_HELLO, CALLING_LEN, TRANSFER_LEN = 74, 128, 76
KIND = {SIMPLE_HELLO: "hello", CALLING_LEN: "calling", TRANSFER_LEN: "avstreamctl"}


def word_of(tid, d):
    """The session word embedded in this frame, or None if unreadable."""
    if len(d) == SIMPLE_HELLO:
        r = unwrap(d)
        return struct.unpack_from("<I", r[0], 4)[0] if r else None
    if len(d) == CALLING_LEN:
        return struct.unpack_from("<I", decrypt(d), 28)[0]
    if len(d) == TRANSFER_LEN:
        return struct.unpack_from("<I", decrypt(d), 56)[0]
    return None


def main():
    # group every capture by (tid, word) so a group is internally consistent
    groups = {}
    for fn in sorted(glob.glob("/tmp/forge_in_*.bin")):
        d = open(fn, "rb").read()
        tid = extract_tid(d)
        if tid is None or len(d) not in KIND:
            continue
        w = word_of(tid, d)
        if w is None:
            continue
        groups.setdefault((tid, w), {})[KIND[len(d)]] = d.hex()

    # for each tid prefer a group holding all three frames, else the largest
    best = {}
    for (tid, w), slot in groups.items():
        cur = best.get(tid)
        if cur is None or (len(slot), w) > (len(cur[1]), cur[0]):
            best[tid] = (w, slot)

    out = {
        "_comment": (
            "Captured Wyze OG (CAM-1) P2P frames, frozen from forge_call.py. "
            "word = session+0x10; hello and calling MUST share one word "
            "(P2P_PROTOCOL.md 5e)."
        ),
        "devices": {},
    }
    for tid in sorted(best):
        w, slot = best[tid]
        out["devices"][str(tid)] = {
            "word": "0x%08x" % w,
            "frames": slot,
            "complete": sorted(slot) == ["avstreamctl", "calling", "hello"],
        }

    dst = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "wire", "p2p_frames.json")
    with open(dst, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print("wrote %s" % dst)
    for tid in sorted(best):
        w, slot = best[tid]
        print("  tid=%-20s word=0x%08x  %s%s"
              % (tid, w, ",".join(sorted(slot)),
                 "" if sorted(slot) == ["avstreamctl", "calling", "hello"]
                 else "   <-- INCOMPLETE"))


if __name__ == "__main__":
    main()
