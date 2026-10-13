#!/usr/bin/env python3
"""
UDP + TCP listener impersonating the Wyze/Gwell list server.

GWApi.GWellP2PUrl is patched to "|192.168.77.13", so the app resolves its
list-server host to this Mac. Ground truth for iv_init_frm_listsrv.

Live logcat shows it alternates:
    iv_send_list_request mode=0 -> UDP ListFrmRequest  (the wire format I reversed)
    iv_send_list_request mode=1 -> evhttp_connection   (HTTP fallback, same port)

    python3 cap_listsrv2.py [port] [seconds]
"""
import select
import socket
import sys
import time

OUT = "/tmp/cap_listsrv.log"
port = int(sys.argv[1]) if len(sys.argv) > 1 else 51701
dur = float(sys.argv[2]) if len(sys.argv) > 2 else 100.0

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp.bind(("0.0.0.0", port))

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("0.0.0.0", port))
tcp.listen(16)
tcp.setblocking(False)

f = open(OUT, "w")
f.write("# udp+tcp on 0.0.0.0:%d for %.0fs\n" % (port, dur))
f.flush()
print("[listen] udp+tcp 0.0.0.0:%d" % port, flush=True)

t0 = time.time()
n = 0
conns = {}


def emit(kind, addr, data):
    global n
    n += 1
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    block = "[%6.2fs] %-3s %s:%d len=%d\n  HEX %s\n  ASC %s\n" % (
        time.time() - t0, kind, addr[0], addr[1], len(data), data.hex(), asc,
    )
    print(block, end="", flush=True)
    f.write(block)
    f.flush()


while time.time() - t0 < dur:
    rl = [udp, tcp] + list(conns.keys())
    try:
        r, _, _ = select.select(rl, [], [], 0.5)
    except (ValueError, OSError):
        conns = {}
        continue
    for s in r:
        if s is udp:
            try:
                data, addr = udp.recvfrom(65535)
            except OSError:
                continue
            if data:
                emit("UDP", addr, data)
        elif s is tcp:
            try:
                c, addr = tcp.accept()
            except OSError:
                continue
            conns[c] = addr
            c.setblocking(False)
            print("[beat] TCP accept from %s:%d" % addr, flush=True)
        else:
            addr = conns[s]
            try:
                data = s.recv(65535)
            except OSError:
                data = b""
            if data:
                emit("TCP", addr, data)
            else:
                try:
                    s.close()
                except OSError:
                    pass
                conns.pop(s, None)

f.write("# total %d chunk(s)\n" % n)
f.close()
print("[done] %d chunk(s)" % n, flush=True)
