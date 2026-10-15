#!/usr/bin/env python3
"""
Extract every 7e a3 MTP_RES_RESPONSE out of /tmp/cap_relay.log and decrypt it.

Why this exists
---------------
P2P_PROTOCOL.md 5h established that GUTES type 163 (0xa3) -> gat_on_rcvpkt_MTP_RES_RESPONSE,
the ONLY caller of iv_mtp_session_add_udp_relay -> the only producer of the type-135
channels that the camera's kcb->output gate requires.

The open question was the *direction*: 5g assumed we would SEND a 7f a2 to the camera.
Wrong - type 162 has no handler at all. What the camera wants is a 7e a3, and
giot_on_rcvpkt is reached from the ordinary LAN receive path (non-0xc0 frames fall through
to it at the router on 0x340c4).

So if we can forge a 7e a3 that names the camera's own LAN address and send it straight at
the camera, the camera runs the same code path the relay would have triggered - and the
relay is bypassed entirely.

This script decrypts the real ones we captured so we can learn the layout and forge one.

RC5 rule (verified 30/30 on LIST, CALLING and 0xb9):
    key = frame[0:4] || frame[0x14:0x17] || 0x00        (8 bytes)
    ECB over [12:20] and [24:...], little-endian block words

Usage:
    python3 show_mtp_res.py                 # decrypt every 7e a3 in the capture
    python3 show_mtp_res.py --hex <hex>     # decrypt one frame you supply
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_calls import decrypt, hexdump          # noqa: E402  (the verified RC5 rule)

CAP = "/tmp/cap_relay.log"


def frames_from_capture():
    """Pull raw hex records out of the MITM log, keeping direction + timestamp."""
    out = []
    cur = None
    for line in open(CAP, errors="replace"):
        m = re.match(r"\[\s*([\d.]+)s\]\s+(\S+)\s+\S+\s+len=(\d+)\s+(.*)", line)
        if m:
            cur = {"t": float(m.group(1)), "dir": m.group(2),
                   "n": int(m.group(3)), "note": m.group(4).strip(), "hex": ""}
            out.append(cur)
        elif cur is not None and line.startswith("  HEX "):
            cur["hex"] = line[6:].strip()
    return out


def carve(blob):
    """Walk a GUTES stream splitting it into records using the [2:4] u16LE total length."""
    recs = []
    i = 0
    while i + 4 <= len(blob):
        ln = blob[i + 2] | (blob[i + 3] << 8)
        if ln < 4 or i + ln > len(blob):
            break
        recs.append(blob[i:i + ln])
        i += ln
    return recs, blob[i:]


def main():
    argv = sys.argv[1:]

    if "--hex" in argv:
        raw = bytes.fromhex(argv[argv.index("--hex") + 1].replace(" ", ""))
        recs, _ = carve(raw)
        for r in recs or [raw]:
            print("=== type %#x  len %d ===" % (r[1], len(r)))
            print("-- ciphertext --")
            print(hexdump(r))
            print("-- plaintext --")
            print(hexdump(decrypt(r)))
        return

    if not os.path.exists(CAP):
        print("capture not found: %s" % CAP)
        return

    hits = 0
    for e in frames_from_capture():
        if not e["hex"] or "7ea3" not in e["hex"]:
            continue
        raw = bytes.fromhex(e["hex"])
        recs, _ = carve(raw)
        for r in recs:
            if r[1] != 0xa3:
                continue
            hits += 1
            print("=" * 78)
            print("7e a3  t=%.2fs  dir=%s  len=%d   %s"
                  % (e["t"], e["dir"], len(r), e["note"]))
            print("=" * 78)
            print("-- ciphertext --")
            print(hexdump(r))
            print("-- plaintext (RC5, key = hdr[0:4]||hdr[0x14:0x17]||00) --")
            print(hexdump(decrypt(r)))
            print()
    print("# %d MTP_RES_RESPONSE frames" % hits)


if __name__ == "__main__":
    main()
