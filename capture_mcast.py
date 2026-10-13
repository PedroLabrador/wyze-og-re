#!/usr/bin/env python3
"""Capture the Wyze/Gwell LAN discovery channel.

libiotp2pav.so does LAN device discovery over IPv6 multicast ff02::1 (see
send_loop log: 'send_loop addr_len=28 multicast=ff02::1'), which is why a
plain IPv4 listener on UDP/8900 sees nothing.

This binds IPv6 wildcard on the app's local port (8900) and the list-request
port (51701) on every interface, joins ff02::1, and dumps everything.
"""
import socket, struct, threading, time, binascii, datetime, sys, os

PORTS = [8900, 51701]
MCAST = "ff02::1"
stop = False

def ts():
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log(tag, msg):
    print(f"[{ts()}] {tag:5s} {msg}", flush=True)

def ifaces():
    out = []
    try:
        import ifaddrs  # not stdlib
    except Exception:
        pass
    # macOS: use getifaddrs via socket won't give index; use if_nametoindex over known ifaces
    for name in ["en0", "en5", "en1", "en2", "en3", "en4", "lo0", "utun0", "utun1", "utun2"]:
        try:
            idx = socket.if_nametoindex(name)
            out.append((name, idx))
        except Exception:
            pass
    return out

def listener(port, iface_name, iface_idx):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except Exception as e:
        log("UDP6", f"socket fail {e}")
        return
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass
    try:
        s.bind(("::", port))
    except OSError as e:
        log("UDP6", f"[{iface_name}] bind ::{port} failed: {e}")
        s.close()
        return
    # join ff02::1 on this interface
    # macOS Python exposes IPV6_JOIN_GROUP; Linux exposes IPV6_ADD_MEMBERSHIP.
    join_opt = getattr(socket, "IPV6_ADD_MEMBERSHIP",
                       getattr(socket, "IPV6_JOIN_GROUP", 12))
    try:
        group_bin = socket.inet_pton(socket.AF_INET6, MCAST)
        mreq = group_bin + struct.pack("@I", iface_idx)
        s.setsockopt(socket.IPPROTO_IPV6, join_opt, mreq)
        joined = True
    except Exception as e:
        joined = False
        log("UDP6", f"[{iface_name}] join {MCAST}%{iface_name} failed: {e}")
    try:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                     struct.pack("@I", iface_idx))
    except Exception:
        pass
    s.settimeout(0.3)
    log("UDP6", f"[{iface_name}#{iface_idx}] bound ::{port} joined={joined}")
    while not stop:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception as e:
            log("UDP6", f"[{iface_name}] recv err {e}")
            break
        src = addr[0]
        # skip pure loopback chatter noise
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        log("UDP6", f"[{iface_name}] myport={port} FROM {src}%{addr[3]}:{addr[1]} len={len(data)}")
        log("UDP6", f"  HEX {binascii.hexlify(data).decode()}")
        log("UDP6", f"  ASC {asc}")
    try:
        s.close()
    except Exception:
        pass

def main():
    global stop
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 30
    ifs = ifaces()
    log("MAIN", f"interfaces: {ifs}")
    threads = []
    for name, idx in ifs:
        if name == "lo0":
            continue
        for p in PORTS:
            t = threading.Thread(target=listener, args=(p, name, idx), daemon=True)
            t.start()
            threads.append(t)
    time.sleep(1)
    log("MAIN", f"listening {duration}s")
    t0 = time.time()
    beat = 0.0
    while time.time() - t0 < duration:
        el = time.time() - t0
        if el - beat >= 5:
            beat = el
            log("MAIN", f"t+{el:.0f}s ...")
        time.sleep(0.3)
    stop = True
    time.sleep(1)
    log("MAIN", "done")

main()
