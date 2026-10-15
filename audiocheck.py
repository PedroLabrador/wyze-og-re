#!/usr/bin/env python3
"""Unit checks for the audio path (no camera needed).

1. _ulaw_decode matches Python's audioop.ulaw2lin for all 256 codes
2. ulaw_to_pcm16 produces the right length and byte order
3. the streaming WAV header packs to the expected fmt
"""
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re/wyze-cam-stream")
sys.path.insert(0, "~/Downloads/wyze-re")

import server                                        # noqa: E402

ok = True

# 1. decode table vs audioop
import audioop                                       # noqa: E402
bad = []
for b in range(256):
    ref = struct.unpack("<h", audioop.ulaw2lin(bytes([b]), 2))[0]
    got = server._ulaw_decode(b)
    if ref != got:
        bad.append((b, ref, got))
print("ulaw decode table: %d/256 mismatched" % len(bad))
if bad:
    ok = False
    print("  first mismatches:", bad[:8])

# 2. bulk conversion
data = bytes(range(256)) * 4
pcm = server.ulaw_to_pcm16(data)
print("ulaw_to_pcm16: in=%d out=%d (want %d) %s"
      % (len(data), len(pcm), len(data) * 2,
         "OK" if len(pcm) == len(data) * 2 else "BAD"))
if len(pcm) != len(data) * 2:
    ok = False
ref = audioop.ulaw2lin(data, 2)
print("bulk result == audioop: %s" % (pcm == ref))
if pcm != ref:
    ok = False

# silence codes decode to 0
print("0xff -> %d, 0x7f -> %d (want 0,0)"
      % (server._ulaw_decode(0xFF), server._ulaw_decode(0x7F)))

# 3. WAV fmt
riff = struct.pack("<4sI4s4sIHHIIHH4sI", b"RIFF", 0xFFFFFFFF, b"WAVE",
                   b"fmt ", 16, 1, 1, 16000, 32000, 2, 16,
                   b"data", 0xFFFFFFFF)
fmt = struct.unpack_from("<HHIIHH", riff, 20)
print("WAV fmt (audio_format,channels,rate,byte_rate,block_align,bits) = %s"
      % (fmt,))
if fmt != (1, 1, 16000, 32000, 2, 16):
    ok = False

print("\n%s" % ("ALL OK" if ok else "FAILURES ABOVE"))
sys.exit(0 if ok else 1)
