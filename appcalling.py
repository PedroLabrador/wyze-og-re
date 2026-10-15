#!/usr/bin/env python3
"""Decrypt the 3.23.1 app's 213-byte CALLING and compare it with our 128-byte.

The app's LAN dialogue (captured with PCAPdroid through the VPN, no root) is
the same dialect our client speaks -- 7ea4 CALLING, c090 meter, c010 KCP --
except its CALLING is 213 B where ours (from the 2.50.7 app) is 128 B.  The
extra 85 bytes are the prime suspect for the per-session encoder selection.

Uses the frame-derived mode-1 key rule: key = f[0:4] || f[20:23] || 00,
RC5 over [12:20] and [24:] in 8-byte blocks (listreq / analyze_calls).
"""
import json
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
from listreq import rc5_setup, rc5_decrypt_block   # noqa: E402


def load(path):
    out = []
    with open(path, "rb") as f:
        while True:
            b = f.read(4)
            if len(b) < 4:
                return out
            n = struct.unpack("<I", b)[0]
            out.append(f.read(n))


def mode1(buf):
    key = bytes([buf[0], buf[1], buf[2], buf[3], buf[20], buf[21], buf[22], 0])
    S = rc5_setup(key)
    out = bytearray(buf)
    out[12:20] = rc5_decrypt_block(S, bytes(out[12:20]), "little")
    for off in range(24, len(out) - 7, 8):
        out[off:off + 8] = rc5_decrypt_block(S, bytes(out[off:off + 8]), "little")
    return bytes(out)


def ascii_of(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def dump(tag, b, base=0):
    print("--- %s (%d B) ---" % (tag, len(b)))
    for off in range(0, len(b), 16):
        c = b[off:off + 16]
        print("  %4d  %-47s |%s|"
              % (base + off, " ".join("%02x" % x for x in c), ascii_of(c)))


def main():
    frs = load("/tmp/applan_a2c.bin")
    calling = next(f for f in frs if f[:2] in (b"\x7e\xa4", b"\x7f\xa4"))
    print("app CALLING: %d B, first16 %s"
          % (len(calling), calling[:16].hex()))

    d = mode1(calling)
    dump("app CALLING decrypted", d)

    print("\n-- scans in the decrypted frame --")
    for pat, name in ((b"\xc0\xa8\x00\xf0", "192.168.77.14 (app IP)"),
                      (b"\xc0\xa8\x00\xec", "192.168.77.13 (Mac IP)"),
                      (b"\xbb\xa3", "port 48035 (app port)")):
        i = d.find(pat)
        print("  %-28s at %s" % (name, i), d[i:i + 20].hex() if i >= 0 else "")

    # compare against our 128-byte CALLING for this camera
    try:
        j = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
    except Exception as e:
        print("p2p_frames.json:", e)
        j = None
    if j:
        ent = (j.get("devices", {}).get("429728659223864")
               or j.get("429728659223864") or j.get("192.168.77.10"))
        if isinstance(ent, dict) and "frames" in ent:
            ent = ent["frames"]
        if isinstance(ent, dict) and "calling" in ent:
            ours = bytes.fromhex(ent["calling"])
            print("\nours: %d B, first16 %s" % (len(ours), ours[:16].hex()))
            dump("our CALLING decrypted", mode1(ours))
        else:
            print("\n(no entry for this camera in p2p_frames.json)")


if __name__ == "__main__":
    main()
