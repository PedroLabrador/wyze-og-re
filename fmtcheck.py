#!/usr/bin/env python3
"""Which coding is the audio payload really -- mu-law, PCM16, or A-law?

Reads /tmp/vf.ulaw (the extracted 320-byte payloads) and checks:

  1. even-position vs odd-position byte histograms
       mu-law -> identical (byte oriented)
       PCM16  -> bimodal, high byte stuck at 00/ff
  2. does data[2i] == data[2i+1] more often than chance?  (sample duplication
       would mean the camera upsamples 8 kHz to 16 kHz)
  3. decoded level under each candidate coding
  4. the mu-law codes present, decoded -> they should pair as (-16,+16),
     (-8,+8), (0,0)
"""
import collections
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re/wyze-cam-stream")
import server                                        # noqa: E402

path = "/tmp/vf.ulaw"
d = open(path, "rb").read()
print("%s  %d B (%.2f s of 16 kHz audio)\n" % (path, len(d), len(d) / 16000.0))


def top(counter, n=8):
    tot = sum(counter.values())
    return " ".join("%02x:%.1f%%" % (k, 100.0 * v / tot)
                    for k, v in counter.most_common(n))


ev = collections.Counter(d[0::2])
od = collections.Counter(d[1::2])
print("1. even bytes : %s" % top(ev))
print("   odd bytes  : %s" % top(od))
print("   -> identical? %s\n"
      % ("yes (byte oriented: mu-law)" if top(ev, 4).split()[0][:2] == top(od, 4).split()[0][:2]
         else "NO (PCM16-like)"))

# 2. sample duplication
n = len(d) // 2
dup = sum(1 for i in range(n) if d[2 * i] == d[2 * i + 1])
c = collections.Counter(zip(d[0::2], d[1::2]))
best_pair, best_c = c.most_common(1)[0]
print("2. even==odd byte: %.1f%% (n=%d)  most common pair %02x%02x = %.1f%%"
      % (100.0 * dup / n, n, best_pair[0], best_pair[1], 100.0 * best_c / n))
print("   -> near 100%% would mean duplicated (upsampled) samples\n")

# 3. decoded level per candidate coding
def stats(pcm, label):
    if len(pcm) < 4:
        return
    n = len(pcm) // 2
    sm = struct.unpack_from("<%dh" % n, pcm)
    rms = (sum(x * x for x in sm) / n) ** 0.5
    zero = sum(1 for x in sm if x == 0) / n
    per = []
    for k in range(0, n, 16000):
        ch = sm[k:k + 16000]
        per.append(int((sum(x * x for x in ch) / max(1, len(ch))) ** 0.5))
    print("   %-10s rms=%-7d zero=%.2f  peak=%-6d  per-second rms=%s"
          % (label, int(rms), zero, max(abs(x) for x in sm), per))


print("3. decoded level under each coding:")
stats(server.ulaw_to_pcm16(d), "mu-law")
stats(struct.pack("<%dH" % (len(d) // 2),
                  *[struct.unpack_from("<H", d, 2 * i)[0]
                    for i in range(len(d) // 2)]), "PCM16 le")
stats(struct.pack("<%dH" % (len(d) // 2),
                  *[struct.unpack_from(">H", d, 2 * i)[0]
                    for i in range(len(d) // 2)]), "PCM16 be")

# 4. mu-law code -> sample, showing the symmetry
print("\n4. mu-law codes present and what they decode to:")
c = collections.Counter(d)
for code, k in c.most_common(10):
    print("   %02x  %5.1f%%  -> %+6d" % (code, 100.0 * k / len(d),
                                          server._ulaw_decode(code)))
