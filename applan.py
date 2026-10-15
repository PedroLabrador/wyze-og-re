#!/usr/bin/env python3
"""Extract the app<->camera LAN P2P dialogue from a PCAPdroid capture.

This is the channel Phase 12 declared unobservable: the Wyze app's live view
runs direct LAN UDP to the camera (192.168.77.10:55013 here), and PCAPdroid
captures it through the VPN without root.

Writes /tmp/applan_<dir>.bin as <u32 len><payload> records (datagram
boundaries preserved) and prints a per-direction type histogram.

Usage: python3 applan.py file.pcap [camera_ip] [camera_port] [app_port]
"""
import struct
import sys
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import pcapparse                                        # noqa: E402
import ipaddress                                        # noqa: E402


def main():
    path = sys.argv[1]
    cam_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.77.10"
    cam_port = int(sys.argv[3]) if len(sys.argv) > 3 else 55013
    app_port = int(sys.argv[4]) if len(sys.argv) > 4 else 0

    a2c, c2a = [], []
    for data in pcapparse.read_pcap(path):
        r = pcapparse.parse_eth(data)
        if not r:
            continue
        etype, off = r
        if etype != 0x0800:
            continue
        ip = pcapparse.parse_ip4(data, off)
        if not ip or ip["proto"] != 17:
            continue
        if len(data) < ip["off"] + 8:
            continue
        sp, dp = struct.unpack_from(">HH", data, ip["off"])
        ulen = struct.unpack_from(">H", data, ip["off"] + 4)[0]
        payload = data[ip["off"] + 8:ip["off"] + 8 + max(0, ulen - 8)]
        if dp == cam_port and ip["dst"] == cam_ip:
            a2c.append(payload)
        elif sp == cam_port and ip["src"] == cam_ip:
            c2a.append(payload)

    print("app->camera: %d datagrams, %d bytes"
          % (len(a2c), sum(len(p) for p in a2c)))
    print("camera->app: %d datagrams, %d bytes"
          % (len(c2a), sum(len(p) for p in c2a)))

    for name, seq in (("a2c", a2c), ("c2a", c2a)):
        with open("/tmp/applan_%s.bin" % name, "wb") as f:
            for p in seq:
                f.write(struct.pack("<I", len(p)))
                f.write(p)
        hist = Counter(p[:2].hex() for p in seq)
        print("\n%s prefixes: %s" % (name, hist.most_common(12)))
        print("  first 8 datagrams:")
        for p in seq[:8]:
            print("    len=%-5d %s" % (len(p), p[:40].hex()))


if __name__ == "__main__":
    main()
