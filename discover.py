#!/usr/bin/env python3
"""Standalone LAN discovery for Wyze/Gwell cameras -- no phone, no app.

This is the piece that was missing: how the client learns each camera's P2P
port.  Reverse-engineered from send_loop (0x7d778) and confirmed by sniffing
the real exchange with lansniff.py (P2P_PROTOCOL.md 5d).

    us  --UDP 28 B-->  broadcast 192.168.77.18:8899   (also ff02::1%if:8899)
    cam --UDP 138 B->  <our port>                      (from <cam>:8899)

Request, 28 bytes, NOT encrypted (the payload counter is visible in the clear
even though the flags word advertises RC5; the checksum word is left zero):

    [0]      0x70            magic
    [1]      0x02            type 2 = discovery request
    [2:4]    u16 LE  = 28    total length
    [4:12]   8 x 00          terminal-id slot, empty on the wire
    [12:16]  u32 LE          monotonically increasing probe counter
    [16:20]  4 x 00          checksum slot -- NOT computed here
    [20:24]  u32 LE  = 0x02010000   flags (>>16 & 3 == 1 -> "RC5")
    [24:26]  u16 = 0
    [26:28]  u16 LE  = our port     the camera replies HERE

Reply, 138 bytes, cleartext:

    [0]      0x70
    [1]      0x03            type 3 = discovery reply
    [2:4]    u16 LE  = 138   total length
    [4:12]   8 x 00
    [12:20]  8 random bytes
    [20:24]  0
    [24:28]  u32 = 1
    [28:32]  u32 (constant 0x000e11b2 across all four cams)
    [32:36]  u32 (constant 0x000186d6 across all four cams)
    [36:40]  0
    [40:44]  0x02000054      u16@40 = 84
    [44:48]  u32 LE = P2P PORT   <-- the whole point of this file
    [48:58]  0
    [58:64]  MAC, 6 bytes
    [64:66]  u16 = 8
    [66:102] 0
    [102:126] ASCII wyze_id, NUL padded ("CAM-1_D03F27747BB0")

The camera's IPv4 is simply the SOURCE address of the reply.

Verified: 192.168.77.12 -> 59239 and 192.168.77.17 -> 63011 are exactly the
endpoints the app logged in iv_mtp_session_add_lan_or_nat.

Usage:
    python3 discover.py             # broadcast + multicast, 3 s
    python3 discover.py 192.168.77.12 192.168.77.17   # unicast to given cams
"""
import select
import socket
import struct
import sys
import time

BROADCAST_PORT = 8899
FLAGS = 0x02010000
BROADCAST = "192.168.77.18"
MULTICAST6 = ("ff02::1", BROADCAST_PORT)
REPLY_LEN = 138


def build_probe(reply_port, counter=0x10000000):
    return struct.pack(
        "<BBH 8s I 4s I H H",
        0x70,              # magic
        0x02,              # type
        28,                # total length
        b"\x00" * 8,       # terminal id slot
        counter,           # probe counter
        b"\x00" * 4,       # checksum slot (not computed)
        FLAGS,             # flags
        0,                 # padding
        reply_port,        # where the camera must answer
    )


def parse_reply(data, addr):
    if len(data) < 128 or data[0] != 0x70 or data[1] != 0x03:
        return None
    total = struct.unpack_from("<H", data, 2)[0]
    p2p_port = struct.unpack_from("<I", data, 44)[0]
    mac = ":".join("%02x" % b for b in data[58:64])
    wyze_id = data[102:126].split(b"\x00", 1)[0].decode("ascii", "replace")
    return {
        "ip": addr[0],
        "p2p_port": p2p_port,
        "mac": mac,
        "wyze_id": wyze_id,
        # [28:36] u64 LE = the device / TID that every P2P frame addresses.
        # (Earlier notes called [28:32] a constant; only the high dword is
        # shared -- the whole qword is the per-device TID.)
        "tid": struct.unpack_from("<Q", data, 28)[0],
        "wire_len": total,
        "raw": data.hex(),
    }


def main():
    targets = sys.argv[1:] or []
    duration = 3.0

    # Bind an ephemeral reply port (the app uses 8900; anything works because
    # we announce it in the probe).
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("0.0.0.0", 0))
    rx.setblocking(False)
    reply_port = rx.getsockname()[1]

    tx4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx4.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    socks = [rx]
    destinations = []
    if targets:
        destinations = [(ip, BROADCAST_PORT) for ip in targets]
    else:
        destinations = [(BROADCAST, BROADCAST_PORT)]
        try:
            tx6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            tx6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            socks.append(tx6)
            destinations.append(("ff02::1%en0", BROADCAST_PORT))
        except OSError as e:
            print("[!] no ipv6: %r" % e)

    print("[probe] reply port %d -> %s" % (reply_port, destinations), flush=True)
    for i, dest in enumerate(destinations):
        probe = build_probe(reply_port, 0x10000000 + i)
        try:
            if ":" in dest[0]:
                tx6.sendto(probe, dest)
            else:
                tx4.sendto(probe, dest)
        except OSError as e:
            print("[!] send %s: %r" % (dest, e), flush=True)

    found, seen_addrs = {}, set()
    deadline = time.time() + duration
    while time.time() < deadline:
        r, _, _ = select.select(socks, [], [], max(0.0, deadline - time.time()))
        for s in r:
            try:
                data, addr = s.recvfrom(4096)
            except OSError:
                continue
            if s is rx:
                dev = parse_reply(data, addr)
                if not dev:
                    print("[?] junk from %s: %s" % (addr[:2], data[:16].hex()))
                    continue
                key = dev["ip"]
                if key in seen_addrs:
                    continue
                seen_addrs.add(key)
                found[key] = dev
                print("  %-16s p2p_port=%-6d mac=%s  %s"
                      % (dev["ip"], dev["p2p_port"], dev["mac"], dev["wyze_id"]),
                      flush=True)
            else:
                # our own probe looping back is not a reply
                pass

    print("[done] %d camera(s)" % len(found), flush=True)
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
