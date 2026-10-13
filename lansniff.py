#!/usr/bin/env python3
"""Sniff the Gwell LAN discovery on UDP/8900 and probe the cameras.

The app does:
    broadcast_init / broadcast_fd_init      -> binds :8900 to receive
    send_loop addr_len=28 multicast=ff02::1 -> discovery probe

ff02::1 is the all-nodes link-local group, so every host on the segment --
including this Mac -- receives those probes.  Binding UDP/8900 on both IPv4
and IPv6 should therefore show us the exact probe bytes AND any camera
reply, without needing root/tcpdump.
"""
import select
import socket
import sys
import time

PORT = 8900
DUR = float(sys.argv[1]) if len(sys.argv) > 1 else 45.0
CAMS = ["192.168.77.12", "192.168.77.10", "192.168.77.17", "192.168.77.11"]

socks = []
for fam, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if fam == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind((addr, PORT))
        s.setblocking(False)
        socks.append(s)
        print("[listen] %s:%d" % (addr, PORT), flush=True)
    except OSError as e:
        print("[!] bind %s:%d: %r" % (addr, PORT, e), flush=True)

# probe every camera on 8900 so we learn whether *it* is what answers
probe = bytes(range(32))
for c in CAMS:
    for s in socks:
        fam = s.family
        if fam == socket.AF_INET and ":" not in c:
            try:
                s.sendto(probe, (c, PORT))
            except OSError as e:
                print("[!] probe %s: %r" % (c, e), flush=True)

t0 = time.time()
seen = 0
while time.time() - t0 < DUR:
    r, _, _ = select.select(socks, [], [], 1.0)
    for s in r:
        try:
            data, addr = s.recvfrom(65535)
        except OSError:
            continue
        seen += 1
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        print("[%6.2fs] <- %-30s len=%-4d %s\n            %s"
              % (time.time() - t0, "%s:%d" % addr[:2], len(data), data.hex(), asc),
              flush=True)

print("[done] %d packet(s)" % seen, flush=True)
