#!/usr/bin/env python3
"""Answer the patched app's list exchange for real, by proxying it upstream.

The October list-server recipe repoints the app's Gwell list host at the
capture machine (`GWApi.GWellP2PUrl` -> "|<capture-host>") and runs a listener
that records the request and never answers (`cap_listsrv2.py`).  When that
address only exists as an IP alias on the capture machine -- because the app's
baked-in host belongs to a subnet the LAN no longer uses -- the app retries
the exchange every 60 s and never completes it.

This makes the exchange succeed instead: forward every request to the genuine
service and hand the genuine answer back.  Both transports the app alternates
are handled -- UDP datagrams on 51701, and the HTTP/1.1 POST fallback on the
same port (`Content-Length` body, answered `HTTP/1.1 200 OK` with a 176-byte
binary body).

    python3 listsrv.py 300                     # run for 300 s
    python3 listsrv.py 300 wyze-mars-asrv.wyzecam.com 51701

Only lengths and source addresses are printed; the bodies are the app's own
account traffic and are never logged.
"""
import select
import socket
import sys
import threading
import time

PORT = 51701
UP_HOST = "wyze-mars-asrv.wyzecam.com"
UP_PORT = 51701


def resolve(host, port):
    return sorted({ai[4][0] for ai in socket.getaddrinfo(host, port,
                                                         socket.AF_INET)})


def should_stop(t0, dur):
    return dur and time.time() - t0 >= dur


def udp_loop(t0, dur, up_ips, log):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.setblocking(False)
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while not should_stop(t0, dur):
        r, _, _ = select.select([s], [], [], 0.5)
        if not r:
            continue
        data, addr = s.recvfrom(65535)
        log("[udp] %s:%d -> upstream  req len=%d" % (addr[0], addr[1], len(data)))
        reply = None
        for ip in up_ips:
            try:
                up.settimeout(2.0)
                up.sendto(data, (ip, UP_PORT))
                reply, _ = up.recvfrom(65535)
                break
            except (socket.timeout, OSError):
                continue
        if reply is None:
            log("[udp] %s:%d  no upstream answer" % (addr[0], addr[1]))
            continue
        try:
            s.sendto(reply, addr)
            log("[udp] %s:%d <- answer  len=%d" % (addr[0], addr[1], len(reply)))
        except OSError as e:
            log("[udp] reply failed: %r" % e)
    s.close()
    up.close()


def read_http_request(conn):
    """Read one header+body request.  Returns None on a clean close."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 65536:
            return None
    head, _, rest = buf.partition(b"\r\n\r\n")
    need = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            need = int(line.split(b":", 1)[1].strip())
    while len(rest) < need:
        chunk = conn.recv(4096)
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest


def read_http_response(sock):
    """Read one HTTP response; honour Content-Length, else read to close."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return buf
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    need = None
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            need = int(line.split(b":", 1)[1].strip())
    if need is None:
        return head + b"\r\n\r\n" + rest
    while len(rest) < need:
        chunk = sock.recv(4096)
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest


def handle_tcp(conn, addr, up_ips, log):
    up = None
    # macOS accept() hands back a socket that inherits O_NONBLOCK from the
    # listening socket, so the second request on a keep-alive connection would
    # die with EAGAIN; the app reuses its connection, so make it blocking.
    conn.setblocking(True)
    try:
        for ip in up_ips:
            try:
                up = socket.create_connection((ip, UP_PORT), timeout=3)
                break
            except OSError:
                continue
        if up is None:
            log("[tcp] %s:%d  no upstream" % addr[:2])
            return
        while True:
            req = read_http_request(conn)
            if not req:
                break
            log("[tcp] %s:%d -> upstream  req len=%d" % (addr[0], addr[1], len(req)))
            up.sendall(req)
            up.settimeout(4.0)
            resp = read_http_response(up)
            if not resp:
                log("[tcp] %s:%d  upstream closed" % (addr[0], addr[1]))
                break
            conn.sendall(resp)
            first = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            log("[tcp] %s:%d <- answer  len=%d  %s"
                % (addr[0], addr[1], len(resp), first))
    except (OSError, ValueError) as e:
        log("[tcp] %s:%d  %r" % (addr[0], addr[1], e))
    finally:
        try:
            conn.close()
        except OSError:
            pass
        if up:
            try:
                up.close()
            except OSError:
                pass


def main():
    args = [a for a in sys.argv[1:]]
    dur = float(args[0]) if args and not args[0].startswith("-") else 0.0
    host = args[1] if len(args) > 1 else UP_HOST
    up_ips = resolve(host, UP_PORT)
    t0 = time.time()

    def log(msg):
        print("[%6.2fs] %s" % (time.time() - t0, msg), flush=True)

    log("list proxy on 0.0.0.0:%d -> %s %s  for %s"
        % (PORT, host, up_ips, "%.0f s" % dur if dur else "ever"))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("0.0.0.0", PORT))
    tcp.listen(8)
    tcp.setblocking(False)

    threading.Thread(target=udp_loop, args=(t0, dur, up_ips, log),
                     daemon=True).start()

    while not should_stop(t0, dur):
        r, _, _ = select.select([tcp], [], [], 0.5)
        if not r:
            continue
        conn, addr = tcp.accept()
        log("[tcp] accept from %s:%d" % addr)
        threading.Thread(target=handle_tcp, args=(conn, addr, up_ips, log),
                         daemon=True).start()
    tcp.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
