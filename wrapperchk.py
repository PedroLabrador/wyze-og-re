#!/usr/bin/env python3
"""Is the app's 164-byte `7f 0c a4 00` frame a wrapper around our CALLING?

The relay capture shows the app sending, right after TOPEN and BEFORE the
`7e a6` / `7e a7` / `7e aa` dialogue, a `0x7f` frame of 164 bytes whose
first payload bytes contain "a4".  Our client never sends anything like it:
we go straight to the 128-byte `7e a4 80 00` CALLING.

Two readings, and they lead opposite ways:

  (a) it is relay *encapsulation* -- the app hands the relay a GUTES frame
      to forward, and the relay strips the `7f 0c` wrapper before it ever
      reaches the camera.  Then it is plumbing we correctly ignore.
  (b) it is camera-facing protocol we have skipped entirely, and a client
      that never sends the preamble may be judged incomplete and handed the
      640x360 sub-stream instead of the 1920x1080 encoder.

(a) is checkable for free: if the app's own 128-byte CALLING appears as a
byte-for-byte substring of the 164-byte frame, it is a wrapper.
"""
import json
import re
import struct

LOG = "/tmp/cap_relay.log"
P2P = "~/Downloads/wyze-re/wire/p2p_frames.json"


def records(path=LOG):
    """Yield (direction, hexline) pairs from the relay capture."""
    cur = None
    for line in open(path, errors="replace"):
        m = re.match(r"\s*\[\s*[\d.]+s\]\s+(T->R|T<-R)\s+\S+\s+len=(\d+)", line)
        if m:
            cur = m.group(1)
            continue
        if line.startswith("  HEX") and cur:
            d, cur = cur, None
            h = line[5:].strip()
            if h:
                yield d, bytes.fromhex(h)


def frames():
    """Walk GUTES frames out of every record using [2:4] as total length."""
    out = []
    for d, data in records():
        i = 0
        while i + 4 <= len(data):
            if data[i] not in (0x7E, 0x7F):
                break
            ln = struct.unpack_from("<H", data, i + 2)[0]
            if ln < 4 or i + ln > len(data):
                ln = len(data) - i
            out.append((d, data[i:i + ln]))
            i += ln
    return out


def main():
    fs = frames()
    print("== all relay frames, in capture order ==")
    for i, (d, f) in enumerate(fs):
        tag = "app->relay" if d == "T->R" else "relay->app"
        print("  %3d  %-10s  %02x %02x  len=%-5d  %s"
              % (i, tag, f[0], f[1], len(f), f[:16].hex()))

    big = [f for (d, f) in fs if d == "T->R" and f[0] == 0x7F and len(f) == 164]
    print("\n== 0x7f/164-byte app->relay frames: %d ==" % len(big))
    if not big:
        print("   none found")
        return
    b = big[0]
    print("   full hex:\n     %s" % b.hex())

    doc = json.load(open(P2P))
    print("\n== is our 128-byte CALLING a substring of it? ==")
    for tid, dev in doc["devices"].items():
        c = dev["frames"]["calling"]
        calling = bytes.fromhex(c if isinstance(c, str)
                                else "".join("%02x" % x for x in c))
        pos = b.find(calling)
        print("   tid %s  calling %d B  ->  %s"
              % (tid, len(calling),
                 "FOUND at offset %d" % pos if pos >= 0 else "not present"))

    print("\n== shorter markers: which of these appear inside the 164-B frame? ==")
    for name, off, ln in (("calling[0:16]", 0, 16), ("calling[16:48]", 16, 32),
                          ("calling[48:80]", 48, 32), ("calling[80:112]", 80, 32),
                          ("calling[96:112]", 96, 16), ("calling[112:128]", 112, 16)):
        for tid, dev in doc["devices"].items():
            c = dev["frames"]["calling"]
            calling = bytes.fromhex(c if isinstance(c, str)
                                    else "".join("%02x" % x for x in c))
            pos = b.find(calling[off:off + ln])
            if pos >= 0:
                print("   %s of tid %s -> offset %d in the 164-B frame"
                      % (name, tid, pos))

    print("\n== does the 164-B frame start with a 128-B CALLING + 32 B extra? ==")
    print("   frame[4:132]   = %s" % b[4:132].hex())
    print("   frame[132:164] = %s   <-- the 32 B tail, if it is a wrapper"
          % b[132:164].hex())


if __name__ == "__main__":
    main()
