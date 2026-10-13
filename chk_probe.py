#!/usr/bin/env python3
"""
chk_probe.py -- use the running app as an ORACLE for the LIST_RESP checksum.

WHY
---
iv_gute_frm_verity_chkval (0x2ab3c) and iv_gute_frm_init_chkval (0x2aa38) are
the same XOR fold:

    acc  = flags & 0x00FFFFFF          # word at 0x14
    acc ^= W0 ^ W4 ^ W8 ^ W12
    for i in range(get_encrypt_data_len(buf) >> 2):
        acc ^= W[(i + 6) * 4]                  # offsets 24, 28, ...
    return acc                                  # compared with word at 0x10

Offset 0x10 (the stored checksum itself) is NOT folded in.

That formula is PROVEN for requests (our builder reproduces the app's
LIST_REQUEST byte-for-byte) yet it does NOT reproduce the checksum the app
computes on a LIST_RESPONSE.  Since the app's answer is deterministic
(identical frames -> identical chk_val) the only remaining explanation is
that the app's *plaintext* differs from ours at some folded offset.

EXPERIMENT
----------
PROVEN: taking a genuine response G, decrypting it, fixing the stored checksum
word (0x10) to 0 and XORing DELTA into any one of the 38 payload words
(24..172) makes the app answer

    chk(probe) ^ chk(base) == 0x01010101 == DELTA

for EVERY offset.  That proves (a) our plaintext is right there, (b) all 38
payload words are folded in, (c) nwords == 38, and (d) the fold structure.

REMAINING: a constant offset of 0x1c04b5de between our checksum and the
app's.  Since bytes 0..11 and byte 20 (flags) are not RC5-encrypted, only
W12 (bytes 12..15) is an encrypted folded term -- so this burst perturbs each
of the four folded header terms individually to find which one the app folds
differently (candidates: iv_gute_frm_decrypt_id at 0x2ac40 may rewrite
bytes 4..11 before the checksum runs).

Probes are identified by ORDER (logged ~70 ms apart, sent 60 ms apart).

EXPECTED OUTPUT -> P2P_PROTOCOL.md (response checksum section)
"""
import select
import socket
import struct
import sys
import time

from cap_relay import rc5_apply
from listreq import checksum, payload_len

REAL_LIST = ("18.118.90.161", 51701)
LIST_PORT = 51701
DELAY = 0.06            # spacing between probe datagrams
DELTA = 0x01010101      # the single word perturbation we apply


def forward(req):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    try:
        s.sendto(req, REAL_LIST)
        return s.recvfrom(65535)[0]
    except OSError as e:
        print("[!] list server: %r" % e, flush=True)
        return None
    finally:
        s.close()


def build_probes(genuine):
    """Fix marker=0 for every frame (so block [12:20] is identical across the
    burst) and perturb exactly one payload word per probe.

    init_chkval folds offsets 0,4,8,12 and 24,28,... -- NOT offset 16 -- so
    with a constant marker any change in the app's answer must come from the
    one word we touched.  Identifying probes by ORDER (they are logged in
    order at ~70 ms spacing), the difference

        chk(probe_i) ^ chk(base) == DELTA

    proves both that the offset is folded in AND that our plaintext there
    equals the app's.  Any other value means our decrypt disagrees with the
    app's at that offset.
    """
    plain = bytearray(rc5_apply(genuine, decrypt=True))
    with open("/tmp/genuine_plain.hex", "w") as fh:
        fh.write(bytes(plain).hex() + "\n")
    ours = checksum(plain)
    theirs = struct.unpack_from("<I", plain, 16)[0]
    print("[model] our checksum(plain)      = 0x%08x" % (ours & 0xFFFFFFFF),
          flush=True)
    print("[model] stored in genuine frame  = 0x%08x" % (theirs & 0xFFFFFFFF),
          flush=True)
    print("[model] MATCH: %s" % (ours == theirs), flush=True)

    def enc(off=None, xorv=DELTA, flags=None):
        p = bytearray(plain)
        if off is not None:
            w = struct.unpack_from("<I", p, off)[0]
            struct.pack_into("<I", p, off, w ^ xorv)
        if flags is not None:
            struct.pack_into("<I", p, 20, flags)
        struct.pack_into("<I", p, 16, 0)          # marker always 0
        return rc5_apply(bytes(p), decrypt=False)

    fl = struct.unpack_from("<I", plain, 20)[0]
    # Payload offsets are PROVEN (chk(probe)^chk(base) == DELTA for all 38),
    # so probe the four folded header terms one at a time:
    seq = [
        ("BASE (no change)",              enc()),
        ("W4  (off4)  ^= DELTA",          enc(4)),
        ("W8  (off8)  ^= DELTA",          enc(8)),
        ("W12 (off12) ^= DELTA",          enc(12)),
        ("flags(off20) ^= 0x1",           enc(20, 0x1, fl ^ 0x1)),
        ("CTRL payload off100 ^= DELTA",  enc(100)),
        ("CTRL payload off24  ^= DELTA",  enc(24)),
    ]
    return seq, plain


def main():
    lsn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsn.bind(("0.0.0.0", LIST_PORT))
    print("[probe] list udp 0.0.0.0:%d" % LIST_PORT, flush=True)

    t0 = time.time()
    dur = float(sys.argv[1]) if len(sys.argv) > 1 else 90.0
    sent_burst = False
    genuine = None
    table = {}

    while time.time() - t0 < dur:
        try:
            r, _, _ = select.select([lsn], [], [], 0.5)
        except OSError:
            continue
        if not r:
            continue
        data, addr = lsn.recvfrom(65535)
        if not data:
            continue
        print("[%.1fs] REQ %s:%d len=%d"
              % (time.time() - t0, addr[0], addr[1], len(data)), flush=True)

        resp = forward(data)
        if resp is None:
            continue

        if not sent_burst:
            genuine = resp
            seq, _ = build_probes(resp)
            base_chk = struct.unpack_from(
                "<I", rc5_apply(resp, decrypt=True), 16)[0]
            print("[%.1fs] genuine LIST_RESP (%d B), genuine chk=0x%08x; "
                  "burst of %d" % (time.time() - t0, len(resp),
                                   base_chk, len(seq)), flush=True)
            for i, (label, wire) in enumerate(seq):
                lsn.sendto(wire, addr)
                print("     #%02d %-40s" % (i, label), flush=True)
                time.sleep(DELAY)
            sent_burst = True
            print("[%.1fs] burst done" % (time.time() - t0), flush=True)
        else:
            # keep the app's query alive with an honest response
            lsn.sendto(resp, addr)

    print("[probe] finished; %s" % ("burst sent" if sent_burst else "NO BURST"),
          flush=True)


if __name__ == "__main__":
    main()
