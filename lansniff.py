#!/usr/bin/env python3
"""Sniff the Gwell LAN discovery probes and optionally replay them.

Why port 8899 and not 8900
--------------------------
P2P_PROTOCOL.md 5c first sniffed 0.0.0.0:8900 and saw nothing. The disassembly
of send_loop (0x7d778) settles it: it passes the constant

    movw r2, #0x22c3          ; 8899
    strh r2, [sp, #198]
    ...
    ldrh r3, [sp, #198]       -> send_msg(buf, len=28, ip, port=8899, fd)

and an empirical probe of the cameras confirms it: 8900/32300/4456 answer with
ICMP port-unreachable (closed) while **8899 is silent on all four cameras**
(open).  The app binds its *receive* socket on :8900 (broadcast_fd_init) but
sends the probe *to* :8899, so listening on 8900 was never going to see it.

Usage:
    python3 lansniff.py 55                 # listen on 8899 (and 8900) for 55 s
    python3 lansniff.py 55 replay          # also replay every probe to the cams
"""
import select
import socket
import sys
import time

PORTS = (8899, 8900)
DUR = float(sys.argv[1]) if len(sys.argv) > 1 else 45.0
REPLAY = len(sys.argv) > 2 and sys.argv[2] == "replay"
CAMS = ["192.168.77.12", "192.168.77.10", "192.168.77.17", "192.168.77.11"]

socks = []
for port in PORTS:
    for fam, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        try:
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if fam == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.bind((addr, port))
            s.setblocking(False)
            socks.append(s)
            print("[listen] %s:%d" % (addr, port), flush=True)
        except OSError as e:
            print("[!] bind %s:%d: %r" % (addr, port, e), flush=True)

t0 = time.time()
seen = []
while time.time() - t0 < DUR:
    r, _, _ = select.select(socks, [], [], 1.0)
    for s in r:
        try:
            data, addr = s.recvfrom(65535)
        except OSError:
            continue
        seen.append((s, data, addr))
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        print("[%6.2fs] <- port %-5d %-30s len=%-4d %s\n            %s"
              % (time.time() - t0, s.getsockname()[1], "%s:%d" % addr[:2],
                 len(data), data.hex(), asc), flush=True)

        if REPLAY:
            # Forward the app's own probe to every camera on 8899 and print
            # whatever comes back -- this is how we learn the reply format
            # without having to guess it.
            for c in CAMS:
                if s.family == socket.AF_INET and ":" not in c:
                    try:
                        s.sendto(data, (c, 8899))
                    except OSError as e:
                        print("[!] replay to %s: %r" % (c, e), flush=True)

if REPLAY and seen:
    print("--- waiting 3 s for replay replies ---", flush=True)
    end = time.time() + 3
    while time.time() < end:
        r, _, _ = select.select(socks, [], [], 1.0)
        for s in r:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            print("[REPLY]  <- port %-5d %-30s len=%-4d %s\n            %s"
                  % (s.getsockname()[1], "%s:%d" % addr[:2], len(data),
                     data.hex(), asc), flush=True)

print("[done] %d packet(s)" % len(seen), flush=True)
