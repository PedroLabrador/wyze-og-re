#!/usr/bin/env python3
"""Decode the 3.23.1 app's captured CALLING and compare it with ours.

The CALLING payload is RC5-ECB with a key derived from the frame itself
(key = frame[0:4] + frame[20:23] + 0x00), the same rule as the list frames.
Decrypting the app's CALLING shows what the new SDK puts in the handshake --
and whether a quality/definition field lives there.
"""
import re
import sys

from analyze_calls import decrypt
from listreq import rc5_setup, rc5_decrypt_block

LOG = "/tmp/cap_relay_323.log"

# first app->cam 7ea6 frame (the CALLING)
blob = open(LOG).read()
frames = re.findall(r"HEX (7ea6[0-9a-f]+)", blob)
calling = bytes.fromhex(frames[0])
print("app CALLING frame (%d B): %s" % (len(calling), calling.hex()))

pt = decrypt(calling)
print("\nplaintext (%d B):" % len(pt))
print("  full: %s" % pt.hex())
for off in range(0, len(pt), 8):
    chunk = pt[off:off + 8]
    print("  [%3d] %s   %s" % (off, chunk.hex(),
                               " ".join("%02x" % b for b in chunk)))

# ours, for comparison (camera 1 from wire/p2p_frames.json)
import json
try:
    dev = json.load(open("wire/p2p_frames.json"))
    k = list(dev)[0]
    ours = bytes.fromhex(dev[k]["calling"])
    print("\nour CALLING frame (%d B, device %s): %s" % (len(ours), k, ours[:24].hex()))
    opt = decrypt(ours)
    print("our plaintext tail [112:128]: %s" % opt[112:128].hex())
except Exception as e:
    print("(no wire capture: %r)" % e)
