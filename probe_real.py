#!/usr/bin/env python3
"""
Probe the REAL Wyze list server with (a) the app's captured packet and
(b) our own reconstructions, to find which one gets a LIST_RESP back.

Ground truth captured 2026-10-12 by patching GWApi.GWellP2PUrl to point
at this Mac and running cap_listsrv2.py:

    phone 192.168.77.19 -> udp/51701, 40 bytes:
    7f152800 4b64b35d7f2dddab 94d93411 e3835696 00000100
             000102030405060708090a0b0c0d0e0f

Decrypted with key 7f15280000000100 (header-derived, RC5-32/6/8, LE):
    [4:12]  4b64b35d7f2dddab  -> plaintext 0xabdd2d7f5db3644b (NOT the
                                 terminal ID; see note below)
    [12:20] -> seq=0, chk=0x843af30b
    [24:40] -> 0100000000000000   (u16 1 at offset 24, rest zero)

chk=0x843af30b equals iv_gute_frm_init_chkval computed over the *plaintext*
terminal ID 0x840186d6001260a3 (the logcat devID), i.e. the checksum is
taken BEFORE the [4:12] field is finalised. My builder therefore emits
byte-identical output to the app except at [4:12].

Also discovered: the client falls back to HTTP on the same port:
    POST /iotvideo/service/ListService/GetServiceList HTTP/1.1
    Content-Type: application/octet-stream
    Content-Length: 40
    <same 40 raw bytes>
"""
import socket
import struct
import sys
import time

HOST = "wyze-mars-asrv.wyzecam.com"
PORT = 51701

APP_PACKET = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f1011121314151617"
    "000102030405060708090a0b0c0d0e0f"
)

sys.path.insert(0, ".")
from listreq import build_list_request  # noqa: E402

DEVID_LOGCAT = 9512032141665525923
DEVID_IN_PKT = int.from_bytes(APP_PACKET[4:12], "little")


def resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, PORT,
                                                            socket.AF_INET)})
    except OSError as e:
        print("  resolve failed: %s" % e)
        return []


def udp_probe(ip, pkt, label, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, PORT))
        data, addr = s.recvfrom(65535)
        print("  [+] %-28s %-16s RESP len=%d" % (label, ip, len(data)))
        print("      HEX %s" % data.hex())
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        print("      ASC %s" % asc)
        return data
    except socket.timeout:
        print("  [.] %-28s %-16s timeout" % (label, ip))
        return None
    except OSError as e:
        print("  [!] %-28s %-16s %s" % (label, ip, e))
        return None
    finally:
        s.close()


def http_probe(ip, pkt, timeout=3.0):
    body = pkt
    req = (
        b"POST /iotvideo/service/ListService/GetServiceList HTTP/1.1\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: %d\r\n\r\n" % len(body)
    ) + body
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, PORT))
        s.sendall(req)
        data = s.recv(65535)
        print("  [+] %-28s %-16s HTTP resp len=%d" % ("http", ip, len(data)))
        print("      %r" % data[:400])
        return data
    except socket.timeout:
        print("  [.] %-28s %-16s timeout" % ("http", ip))
        return None
    except OSError as e:
        print("  [!] %-28s %-16s %s" % ("http", ip, e))
        return None
    finally:
        s.close()


def main():
    print("devID in app packet : %d  (%s)" % (DEVID_IN_PKT, hex(DEVID_IN_PKT)))
    print("logcat terminal ID  : %d  (%s)" % (DEVID_LOGCAT, hex(DEVID_LOGCAT)))
    print()

    ips = resolve(HOST)
    print("resolved %s -> %s" % (HOST, ips))
    if not ips:
        return 1
    print()

    variants = [
        ("app packet (verbatim)", APP_PACKET),
        ("ours, terminal ID", build_list_request(seq=0, devid=DEVID_LOGCAT)),
        ("ours, pkt field as ID", build_list_request(seq=0, devid=DEVID_IN_PKT)),
        ("ours, seq=1", build_list_request(seq=1, devid=DEVID_LOGCAT)),
    ]

    for ip in ips:
        print("=== UDP %s:%d ===" % (ip, PORT))
        for label, pkt in variants:
            if udp_probe(ip, pkt, label):
                return 0
        print()

    print("=== HTTP fallback ===")
    ip = ips[0]
    http_probe(ip, APP_PACKET)

    print("\nno UDP response from any server/variant")
    return 0


if __name__ == "__main__":
    sys.exit(main())
