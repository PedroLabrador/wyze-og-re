#!/usr/bin/env python3
"""Forge a GUTES CALLING (`7e a4`, 128 B) for any camera.

Why this exists
---------------
The captures in ``wire/p2p_frames.json`` only cover cameras 1, 2 and 3.  Camera
4 answers LAN discovery but has no captured CALLING, so replaying the frozen
frames skips it.  Rather than collect a fresh capture (which needs the phone
running the patched app), we rewrite an existing CALLING: the frame turns out
to be almost entirely *client*-chosen state, with exactly one camera-bound
field.

CALLING layout (plaintext, recovered from ``iv_init_frm_CALLING`` @0x542c0 and
confirmed against a decrypted capture)::

    [ 0: 4]  7e a4 80 00          magic, type 164, total length 128
    [ 4:12]  id8                  session connection id (ctx->0x240/0x244)
    [12:16]  (encrypted region A)
    [16:20]  checksum             iv_gute_frm_init_chkval
    [20:24]  flags                plaintext -- key mode, bit25, ack
    [24:28]  03 00 00 00
    [28:32]  conv                 u32 LE -- the session word both sides adopt
    [32:40]  d_log 0x840186d6001260a3     shared constant, NOT camera-bound
    [40:48]  tid                  u64 LE -- *** THE ONLY CAMERA-BOUND FIELD ***
    [48:54]  00 00 01 00 00 00
    [54:56]  local port           u16 LE (the app advertises 48171)
    [64:68]  local IP             4 bytes, the *sender's* address
    [72:76]  00 00 00 00
    [120:128] AV RC5 key          8 B -- the key the peer will decrypt video with

Crypto (same rule as LIST frames, P2P_PROTOCOL.md 4a/9)::

    key       = frame[0:4] || frame[20:23] || 0x00      (8 B, "mode 1")
    block     = 8 B, RC5, ECB, 6 rounds, little-endian words
    regions   = [12:20] and [24:]  -- everything except the header
    checksum  = iv_gute_frm_init_chkval, computed over PLAINTEXT, stored at [16:20]

``build_list_request`` in ``listreq.py`` establishes the ordering: checksum is
written *before* encryption, and neither [16:20] (the slot) nor the flags at
[20:24] are inside an encrypted region, so the key derivation and the checksum
both see plaintext.

Round-trip is verified byte-for-byte against a real capture in ``selftest`` --
if ``encrypt(decrypt(calling)) != calling`` the constants are wrong.

Usage::

    from calling_forge import forge_calling
    raw = forge_calling(template, tid=429728658756018)     # camera 4
"""
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from listreq import rc5_setup, rc5_encrypt_block, rc5_decrypt_block, checksum  # noqa: E402

AV_KEY_OFF = 120
TID_OFF = 40
CONV_OFF = 28
IP_OFF = 64
PORT_OFF = 54
ID8_OFF = 4
LEN = 128


def decrypt(frame):
    """Inverse of :func:`encrypt`; same rule as analyze_calls.decrypt."""
    key = bytes(frame[0:4]) + bytes(frame[20:23]) + b"\x00"
    st = rc5_setup(key)
    out = bytearray(frame)
    for off in list(range(12, 20, 8)) + list(range(24, len(frame), 8)):
        if off + 8 > len(out):
            break
        out[off:off + 8] = rc5_decrypt_block(st, bytes(frame[off:off + 8]),
                                             "little")
    return bytes(out)


def _payload_len(buf):
    """gute_get_encrypt_data_len: total_len - 24, minus optional extensions."""
    n = struct.unpack_from("<H", buf, 2)[0] - 24
    flags = struct.unpack_from("<I", buf, 0x14)[0]
    if (flags >> 22) & 1:
        n -= 80
    if (flags >> 24) & 1:
        n -= 16
    return n


def encrypt(pt):
    """Plaintext -> wire bytes.  Mirror of build_list_request's tail.

    Order matters: the checksum covers [0:16] and the payload as *plaintext*,
    so it must be written before any RC5 block is replaced.
    """
    if len(pt) != LEN:
        raise ValueError("CALLING must be %d bytes, got %d" % (LEN, len(pt)))
    buf = bytearray(pt)
    struct.pack_into("<I", buf, 16, checksum(buf))
    key = bytes([buf[0], buf[1], buf[2], buf[3],
                 buf[0x14], buf[0x15], buf[0x16], 0x00])
    st = rc5_setup(key)
    buf[12:20] = rc5_encrypt_block(st, bytes(buf[12:20]), "little")
    for i in range(_payload_len(buf) >> 3):
        off = 24 + i * 8
        buf[off:off + 8] = rc5_encrypt_block(st, bytes(buf[off:off + 8]),
                                             "little")
    return bytes(buf)


def local_ip_toward(host):
    """The source address the kernel will use to reach `host`.

    The CALLING advertises the sender's address at [64:68]; the app wrote its
    own phone IP there.  We must write ours, or a camera that honours the
    advertised address (NAT traversal) would reply to the wrong place.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 9))          # no packets sent for a UDP connect
        return s.getsockname()[0]
    finally:
        s.close()


def forge_calling(template, tid=None, ip=None, port=None, avkey=None,
                  conv=None, id8=None):
    """Rewrite a captured CALLING for another camera.

    Only `tid` is strictly camera-bound.  Everything else is client state we
    are free to regenerate -- but by default we keep the template's values so
    a first attempt changes as few variables as possible.
    """
    pt = bytearray(decrypt(template))
    if len(pt) != LEN:
        raise ValueError("template is %d bytes, expected %d"
                         % (len(template), LEN))
    if tid is not None:
        struct.pack_into("<Q", pt, TID_OFF, tid)
    if conv is not None:
        struct.pack_into("<I", pt, CONV_OFF, conv)
    if id8 is not None:
        pt[ID8_OFF:ID8_OFF + 8] = id8
    if port is not None:
        struct.pack_into("<H", pt, PORT_OFF, port)
    if ip is not None:
        pt[IP_OFF:IP_OFF + 4] = socket.inet_aton(ip)
    if avkey is not None:
        if len(avkey) != 8:
            raise ValueError("AV key must be 8 bytes")
        pt[AV_KEY_OFF:AV_KEY_OFF + 8] = avkey
    return encrypt(bytes(pt))


def selftest():
    """encrypt(decrypt(x)) == x on a real capture, field-by-field."""
    import json
    here = os.path.dirname(os.path.abspath(__file__))
    doc = json.load(open(os.path.join(here, "wire", "p2p_frames.json")))
    tid = "429728659223864"
    rec = doc["devices"][tid]["frames"]["calling"]
    raw = bytes.fromhex(rec) if isinstance(rec, str) else bytes(rec)

    back = encrypt(decrypt(raw))
    assert back == raw, "round-trip FAILED:\n  orig %s\n  back %s" % (
        raw.hex(), back.hex())
    print("[ok] encrypt(decrypt(calling)) == calling  (%d bytes)" % len(raw))

    # identity re-forge (no changes) must be byte-identical too
    assert forge_calling(raw) == raw, "identity forge changed the frame"
    print("[ok] forge_calling(template) is byte-identical (no changes)")

    # changing ONLY the TID must leave every other field alone
    pt0 = decrypt(raw)
    other = forge_calling(raw, tid=429728658756018)
    pt1 = decrypt(other)
    assert struct.unpack_from("<Q", pt1, TID_OFF)[0] == 429728658756018
    for off in (ID8_OFF, CONV_OFF, IP_OFF, PORT_OFF, AV_KEY_OFF):
        n = 8 if off in (ID8_OFF, AV_KEY_OFF) else 4
        assert pt0[off:off + n] == pt1[off:off + n], \
            "field at %d changed unexpectedly" % off
    print("[ok] swapping TID leaves id8/conv/ip/port/avkey untouched")

    # the stored checksum must be recomputed over the *new* plaintext
    pt2 = decrypt(other)
    assert struct.unpack_from("<I", pt2, 16)[0] == checksum(pt2), \
        "checksum not recomputed for the edited frame"
    print("[ok] checksum recomputed over the new plaintext")
    print("ALL OK")
    return True


if __name__ == "__main__":
    sys.exit(0 if selftest() else 1)
