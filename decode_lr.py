#!/usr/bin/env python3
"""
Decode a decrypted LIST_RESP frame.

    python3 decode_lr.py wire/list_resp_decrypted.hex

Layout recovered from gat_on_rcvpkt_LIST_RESP (0x4ad64) and
iv_addRmtP2pSrv (0x410d0) in lib/armeabi-v7a/libiotp2pav.so:

  frame
  +0   u8   magic          0x7f
  +1   u8   type           0x16 = 22 = LIST_RESP
  +2   u16  total_len      LE
  +4   u32  ?              (responses carry 0x000185f4...)
  +8   u32  ?
  +16  ?      16 bytes, see probe
  +24  u16  flags          bit0 = the same |=1 the request builder sets
  +26  ?      6 bytes
  +32  records[], 36 bytes each, count = (total_len - 32) // 36

  record
  +0   u32  ipv4           network byte order
  +4   u16x8 ipv6          16 bytes, may be zero
  +20  u8   kind           bit0/bit3 vary; bits1-2 -> entry+92 (2 bits)
  +21  u8   (pad/part of +20 as u16)
  +22  u16  srv_id         LE -> entry+94
  +24  u16  port1          network order -> sockaddr at entry+12
  +26  u16  port2          network order -> sockaddr at entry+112
  +28  u16  port3          network order -> sockaddr at entry+132
  +30  u16  port4          network order -> sockaddr at entry+148
  +32  u32  ?              never read by iv_addRmtP2pSrv (zeros in capture)

Cross-checks that MUST hold against live logcat:
  iv_addRmtP2pSrv: add udp_addr 3.13.212.24:28800 srv_id=49
"""
import re
import sys


def ip4(b):
    return ".".join(str(x) for x in b)


def ip6(b):
    if not any(b):
        return "-"
    h = [b[i] << 8 | b[i + 1] for i in range(0, 16, 2)]
    return ":".join("%x" % x for x in h)


def main():
    if len(sys.argv) > 1:
        raw = open(sys.argv[1]).read()
    else:
        raw = open("wire/list_resp_decrypted.hex").read()
    data = bytes(int(x, 16) for x in re.findall(r"[0-9a-fA-F]{2}", raw))

    print("frame %d bytes" % len(data))
    print("  magic      0x%02x" % data[0])
    print("  type       %d (0x%02x)" % (data[1], data[1]))
    total = data[2] | data[3] << 8
    print("  total_len  %d%s" % (total, "  OK" if total == len(data) else "  MISMATCH"))
    print("  +4  u32    0x%08x" % int.from_bytes(data[4:8], "little"))
    print("  +8  u32    0x%08x" % int.from_bytes(data[8:12], "little"))
    print("  +12 u32    0x%08x" % int.from_bytes(data[12:16], "little"))
    print("  +16 16B    %s" % data[16:32].hex())
    print("  +24 u16    0x%04x  (&1 = %d)" % (
        int.from_bytes(data[24:26], "little"), data[24] & 1))
    print("  +26 6B     %s" % data[26:32].hex())

    body = data[32:total]
    n = len(body) // 36
    print("  payload    %d bytes -> %d records of 36 (remainder %d)"
          % (len(body), n, len(body) % 36))

    print()
    hdr = "%-4s %-6s %-16s %-39s %-5s %s" % (
        "rec", "srv_id", "ipv4", "ipv6", "kind", "ports (+24/+26/+28/+30)")
    print(hdr)
    print("-" * len(hdr))
    for i in range(n):
        r = body[i * 36:(i + 1) * 36]
        srv = int.from_bytes(r[22:24], "little")
        ports = [int.from_bytes(r[o:o + 2], "big") for o in (24, 26, 28, 30)]
        print("%-4d %-6d %-16s %-39s %-5d %s" % (
            i, srv, ip4(r[0:4]), ip6(r[4:20]), r[20],
            "/".join(str(p) for p in ports)))
        print("     raw +%02d..+35: %s" % (i * 36, r[20:].hex()))

    # --- cross-check against the logcat line captured on the phone ---
    print()
    expect = [("3.13.212.24", 28800, 49)]
    for ip, port, srv in expect:
        hit = [i for i in range(n)
               if ip4(body[i * 36:i * 36 + 4]) == ip
               and int.from_bytes(body[i * 36 + 24:i * 36 + 26], "big") == port
               and int.from_bytes(body[i * 36 + 22:i * 36 + 24], "little") == srv]
        print("logcat 'add udp_addr %s:%d srv_id=%d' -> %s" % (
            ip, port, srv, "MATCH rec %d" % hit[0] if hit else "*** NO MATCH ***"))


if __name__ == "__main__":
    main()
