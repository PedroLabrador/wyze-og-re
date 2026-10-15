#!/usr/bin/env python3
"""Why do we only extract ~39 of the camera's 50 audio frames/s?

Reads the saved body stream /tmp/vf.h264 and, for every audio AV frame it
can find, reports:

  * whether the frame was complete inside its body (or truncated at a TLV
    boundary -- i.e. would be missed by _take_audio_frames)
  * the u32 microsecond timestamp at [20:24], and the histogram of deltas
    between successive frames

A delta of 20000 = one 20 ms frame.  40000/60000/... = the camera did send
the frame but we failed to extract it (or KCP lost the TLV).
"""
import collections
import struct

SYNC = b"\xff\xff\xff\x88"
HDR = SYNC + b"\x00\x00\x01\x00"
ZEROS = b"\x00" * 12

path = "/tmp/vf.h264"
d = open(path, "rb").read()

found = []          # (offset, complete?, payload_len, timestamp)
truncated = []
i = 0
while True:
    i = d.find(SYNC, i)
    if i < 0:
        break
    if d[i:i + 8] == HDR and d[i + 8:i + 20] == ZEROS:
        ln = struct.unpack_from("<H", d, i + 28)[0]
        ts = struct.unpack_from("<I", d, i + 20)[0]
        if 64 <= ln <= 4096 and i + 30 + ln <= len(d):
            found.append((i, True, ln, ts))
            i += 30 + ln
            continue
        else:
            truncated.append((i, ln, len(d) - i - 30))
    i += 1

print("%s  (%d B)" % (path, len(d)))
print("audio frames complete : %d" % len(found))
print("audio frames TRUNCATED at body end: %d" % len(truncated))
for off, ln, avail in truncated[:8]:
    print("    @%-7d want=%d have=%d" % (off, ln, avail))

print("\npayload lengths: %s"
      % collections.Counter(l for _, _, l, _ in found).most_common())

# timestamp deltas (u32 microseconds, wraps)
tss = [t for _, _, _, t in found]
deltas = collections.Counter()
for a, b in zip(tss, tss[1:]):
    dd = (b - a) & 0xFFFFFFFF
    deltas[dd] += 1
print("\ndelta histogram (us): %s" % deltas.most_common(10))
n20 = deltas.get(20000, 0)
print("frames at exactly 20000 us : %d" % n20)
print("frames with a gap (>20000) : %d"
      % sum(v for k, v in deltas.items() if k > 20000))

gapsum = sum(((b - a) & 0xFFFFFFFF) for a, b in zip(tss, tss[1:]))
if gapsum:
    print("span covered by timestamps : %.2f s" % (gapsum / 1e6))
    print("=> ideal 20 ms frames in that span : %d" % round(gapsum / 20000))
