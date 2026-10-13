#!/usr/bin/env python3
"""
Craft a Gwell/Kalay ListFrmRequest and probe the Wyze mars list server.

Everything here is recovered from libiotp2pav.so (armeabi-v7a) disassembly
and cross-checked against live logcat. See wyze-cam-stream/P2P_PROTOCOL.md.

    iv_init_frm_listsrv        0x36544   frame layout
    iv_gute_frm_init_chkval    0x2aa38   XOR checksum
    iv_gute_frm_rc5_encrypt    0x2b2ac   RC5, header-derived key
    rc5_ctx_new(8, 6)                      -> RC5-32, 6 rounds
    gute_get_encrypt_data_len  0x2a9b4   len(buf) - 24  (+ flag adjustments)

Usage:
    python3 listreq.py            # probe all list servers
"""
import socket
import struct
import sys
import time

MASK = 0xFFFFFFFF
P, Q = 0xB7E15163, 0x9E3779B9
ROUNDS = 6
W = 32

# wyze-mars-asrv.wyzecam.com (observed in logcat) on UDP 51701
LIST_SERVERS = [
    "18.118.90.161",
    "34.215.36.59",
    "35.85.21.174",
    "3.19.80.22",
]
LIST_PORT = 51701

# this install's terminal ID; logcat prints devID=-8934711932044025693
# which as uint64 is 9512032141665525923 (== the srcID in AV stats)
DEVID_SIGNED = -8934711932044025693
DEVID = DEVID_SIGNED & 0xFFFFFFFFFFFFFFFF


def _rotl32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK


def rc5_setup(key: bytes):
    """RC5 key schedule for w=32, r=6 (14 subkeys)."""
    b = len(key)
    c = max(1, b // 4)
    L = [0] * c
    # fill L with the key bytes, high index down (per Rivest's spec)
    for i in range(b - 1, -1, -1):
        L[i // 4] = ((L[i // 4] << 8) + key[i]) & MASK

    t = 2 * (ROUNDS + 1)
    S = [0] * t
    S[0] = P
    for i in range(1, t):
        S[i] = (S[i - 1] + Q) & MASK

    A = B = i = j = 0
    for _ in range(3 * max(t, c)):
        A = S[i] = _rotl32((S[i] + A + B) & MASK, 3)
        B = L[j] = _rotl32((L[j] + A + B) & MASK, A + B)
        i = (i + 1) % t
        j = (j + 1) % c
    return S


def rc5_encrypt_block(S, blk: bytes, byteorder: str = "little") -> bytes:
    A = int.from_bytes(blk[0:4], byteorder)
    B = int.from_bytes(blk[4:8], byteorder)
    A = (A + S[0]) & MASK
    B = (B + S[1]) & MASK
    for i in range(1, ROUNDS + 1):
        A = (_rotl32(A ^ B, B) + S[2 * i]) & MASK
        B = (_rotl32(B ^ A, A) + S[2 * i + 1]) & MASK
    return A.to_bytes(4, byteorder) + B.to_bytes(4, byteorder)


def rc5_decrypt_block(S, blk: bytes, byteorder: str = "little") -> bytes:
    """Inverse of rc5_encrypt_block (the Feistel run backwards)."""
    A = int.from_bytes(blk[0:4], byteorder)
    B = int.from_bytes(blk[4:8], byteorder)
    for i in range(ROUNDS, 0, -1):
        B = (_rotl32((B - S[2 * i + 1]) & MASK, 32 - (A & 31)) ^ A) & MASK
        A = (_rotl32((A - S[2 * i]) & MASK, 32 - (B & 31)) ^ B) & MASK
    B = (B - S[1]) & MASK
    A = (A - S[0]) & MASK
    return A.to_bytes(4, byteorder) + B.to_bytes(4, byteorder)


def payload_len(buf) -> int:
    """gute_get_encrypt_data_len: total_len - 24, minus optional extensions."""
    n = struct.unpack_from("<H", buf, 2)[0] - 24
    flags = struct.unpack_from("<I", buf, 0x14)[0]
    if (flags >> 22) & 1:
        n -= 80
    if (flags >> 24) & 1:
        n -= 16
    return n


def checksum(buf) -> int:
    """iv_gute_frm_init_chkval -- 32-bit XOR fold, masked with 0x00FFFFFF."""
    nwords = payload_len(buf) >> 2
    chk = struct.unpack_from("<I", buf, 0x14)[0] & 0x00FFFFFF
    for off in (0x00, 0x04, 0x08, 0x0C):
        chk ^= struct.unpack_from("<I", buf, off)[0]
    for i in range(nwords):
        chk ^= struct.unpack_from("<I", buf, (i + 6) * 4)[0]
    return chk & MASK


def build_list_request(seq: int = 0, devid: int = DEVID, byteorder: str = "little") -> bytes:
    """Reimplements iv_init_frm_listsrv + chkval + rc5_encrypt exactly."""
    buf = bytearray(40)
    buf[0] = 0x7F                     # magic
    buf[1] = 0x15                     # type 21 = LIST_REQUEST
    struct.pack_into("<H", buf, 2, 40)          # total length
    struct.pack_into("<Q", buf, 4, devid)       # 64-bit terminal ID
    struct.pack_into("<I", buf, 12, seq)        # sequence
    struct.pack_into("<I", buf, 20, 0x00010000) # flags: (>>16)&3 == 1 -> header-derived key
    struct.pack_into("<H", buf, 24, 1)          # offset 24 |= 1

    struct.pack_into("<I", buf, 16, checksum(buf))

    # key = buf[0..3] || buf[0x14..0x16] || 0x00
    key = bytes([buf[0], buf[1], buf[2], buf[3], buf[0x14], buf[0x15], buf[0x16], 0x00])
    S = rc5_setup(key)

    buf[12:20] = rc5_encrypt_block(S, bytes(buf[12:20]), byteorder)
    nblocks = payload_len(buf) >> 3
    for i in range(nblocks):
        off = 24 + i * 8
        buf[off:off + 8] = rc5_encrypt_block(S, bytes(buf[off:off + 8]), byteorder)
    return bytes(buf)


def probe(ip: str, byteorder: str, seq: int, timeout: float = 2.0):
    pkt = build_list_request(seq=seq, byteorder=byteorder)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, LIST_PORT))
        data, addr = s.recvfrom(65535)
        print(f"  [+] RESPONSE from {addr[0]}:{addr[1]} len={len(data)}")
        print(f"      HEX {data.hex()}")
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        print(f"      ASC {asc}")
        return data
    except socket.timeout:
        return None
    except OSError as e:
        print(f"  [!] {ip}: {e}")
        return None
    finally:
        s.close()


def main():
    print(f"devid u64 = {DEVID}")
    pkt = build_list_request(seq=0)
    print(f"frame (40B): {pkt.hex()}")
    print()

    hits = []
    for byteorder in ("little", "big"):
        for seq in (0, 1):
            print(f"== byteorder={byteorder} seq={seq} ==")
            for ip in LIST_SERVERS:
                r = probe(ip, byteorder, seq, timeout=1.5)
                if r:
                    hits.append((byteorder, seq, ip, r))
            if hits:
                break
        if hits:
            break

    print()
    if hits:
        print(f"HIT: {len(hits)} response(s)")
    else:
        print("no response (silent) -- frame likely wrong, or server ignores us")


if __name__ == "__main__":
    main()
