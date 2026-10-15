#!/usr/bin/env python3
"""Compare the AvStreamCtl we send against ones captured from the real app.

We build the 76-byte frame with blob=\\x00*32 and w160=0; if the app fills
those from its session config (memcpy(buf+24, obj+0x1ec, 32);
buf[62:64]=(u16)obj->0x160) a zero blob may be why the camera's audio sits
at the mu-law quantiser floor.
"""
import json
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
import kcpav                                          # noqa: E402
import p2p_client                                     # noqa: E402

doc = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))

ours = p2p_client.build_avstreamctl()
print("we send   : %s" % ours.hex())
print("            [0]=%02x [1]=%02x len=%d action=%d blob[24:56]=%s [62:64]=%d"
      % (ours[0], ours[1], len(ours),
         int.from_bytes(ours[8:12], "little"), ours[24:56].hex(),
         int.from_bytes(ours[62:64], "little")))

print()
for tid, rec in doc.get("devices", {}).items():
    frames = rec.get("frames", {})
    for name in ("avstreamctl", "avstream_ctl", "ctl", "av_ctl"):
        v = frames.get(name)
        if not v:
            continue
        raw = bytes.fromhex(v) if isinstance(v, str) else bytes(v)
        print("tid %s  %s  (%d B)" % (tid, name, len(raw)))
        print("  app     : %s" % raw.hex())
        if len(raw) == len(ours):
            diffs = [i for i in range(len(raw)) if raw[i] != ours[i]]
            print("  differs from ours at byte offsets: %s" % diffs)
            if diffs:
                lo, hi = min(diffs), max(diffs)
                print("  app [24:56]=%s" % raw[24:56].hex())
                print("  app [62:64]=%d" % int.from_bytes(raw[62:64], "little"))
                print("  first diff @%d: app=%02x ours=%02x"
                      % (lo, raw[lo], ours[lo]))
                print("  last  diff @%d: app=%02x ours=%02x"
                      % (hi, raw[hi], ours[hi]))
        print()

# also show every distinct field the captured frames use
print("--- summary of captured frames ---")
for tid, rec in doc.get("devices", {}).items():
    for k, v in (rec.get("frames") or {}).items():
        raw = bytes.fromhex(v) if isinstance(v, str) else bytes(v or b"")
        if len(raw) == 76 and raw[0] == 3:
            print("  tid %s %-14s [0]=%02x action=%d blob=%s w160=%d"
                  % (tid, k, raw[0],
                     int.from_bytes(raw[8:12], "little"),
                     raw[24:56].hex(),
                     int.from_bytes(raw[62:64], "little")))
