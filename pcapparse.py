#!/usr/bin/env python3
"""Summarise a PCAPdroid capture: flows, and dump LAN-UDP payloads.

Pure Python (no scapy): reads the classic pcap record format and walks
Ethernet -> IPv4 -> UDP/TCP.  The point is to find the Wyze app's
direct-LAN P2P dialogue with the camera, which has never been observed.

Usage:
    python3 pcapparse.py file.pcap [--dumplan out.bin] [--only IP]
"""
import ipaddress
import struct
import sys
from collections import Counter, defaultdict


LINKTYPE = [None]          # DLT of the file, set by read_pcap


def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            end = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            end = ">"
        else:
            raise SystemExit("not a pcap: %s" % magic.hex())
        LINKTYPE[0] = struct.unpack_from(end + "I", gh, 20)[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            _, _, incl, _ = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield data


def parse_eth(data):
    """Locate the IPv4 header for this record's link type.

    Returns (ethertype, payload_offset) with ethertype 0x0800 meaning "IPv4
    here", so the caller's existing branch logic still works.
    """
    dlt = LINKTYPE[0]
    if dlt == 101:                       # DLT_RAW: the record IS the IP packet
        if len(data) < 20:
            return None
        return 0x0800, 0
    if dlt == 113:                       # DLT_LINUX_SLL: 16-byte cooked hdr
        if len(data) < 16:
            return None
        return struct.unpack_from(">H", data, 14)[0], 16
    if dlt == 0:                         # DLT_NULL: 4-byte family
        if len(data) < 4:
            return None
        return 0x0800 if data[:4] in (b"\x02\x00\x00\x00",) else 0, 4
    if len(data) < 14:                   # assume Ethernet
        return None
    ethertype = struct.unpack_from(">H", data, 12)[0]
    off = 14
    while ethertype in (0x8100, 0x88A8) and len(data) >= off + 4:
        ethertype = struct.unpack_from(">H", data, off + 2)[0]
        off += 4
    return ethertype, off


def parse_ip4(data, off):
    if len(data) < off + 20:
        return None
    vihl = data[off]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0xF) * 4
    proto = data[off + 9]
    src = str(ipaddress.IPv4Address(data[off + 12:off + 16]))
    dst = str(ipaddress.IPv4Address(data[off + 16:off + 20]))
    tot = struct.unpack_from(">H", data, off + 2)[0]
    # account for fragmentation: only the first fragment carries L4
    frag = struct.unpack_from(">H", data, off + 6)[0]
    return dict(proto=proto, src=src, dst=dst, off=off + ihl,
                tot=tot, firstfrag=(frag & 0x1FFF) == 0)


def main():
    path = sys.argv[1]
    dump = None
    only = None
    for i, a in enumerate(sys.argv):
        if a == "--dumplan":
            dump = sys.argv[i + 1]
        if a == "--only":
            only = sys.argv[i + 1]

    flows = Counter()
    pkts_per_flow = defaultdict(int)
    bytes_per_flow = defaultdict(int)
    lan_tuples = Counter()
    ip_pairs = Counter()
    n = 0
    lan_records = []

    for data in read_pcap(path):
        n += 1
        r = parse_eth(data)
        if not r:
            continue
        ethertype, off = r
        if ethertype == 0x0806:
            flows[("ARP", "", "")] += 1
            continue
        if ethertype != 0x0800:
            flows[("eth-%04x" % ethertype, "", "")] += 1
            continue
        ip = parse_ip4(data, off)
        if not ip:
            continue
        if ip["proto"] == 17:                       # UDP
            if len(data) < ip["off"] + 8:
                continue
            sp, dp = struct.unpack_from(">HH", data, ip["off"])
            ulen = struct.unpack_from(">H", data, ip["off"] + 4)[0]
            payload = data[ip["off"] + 8:ip["off"] + 8 + max(0, ulen - 8)]
            key = (ip["src"], sp, ip["dst"], dp)
            flows[key] += 1
            bytes_per_flow[key] += len(payload)
            ip_pairs["%s -> %s" % (ip["src"], ip["dst"])] += 1
            if (ip["src"].startswith("192.168.") or ip["dst"].startswith("192.168.")):
                lan_tuples[key] += 1
                if dump:
                    is_udp = True
                    lan_records.append((ip, sp, dp, payload))
        elif ip["proto"] == 6:                      # TCP
            if len(data) < ip["off"] + 20:
                continue
            sp, dp = struct.unpack_from(">HH", data, ip["off"])
            doff = (data[ip["off"] + 12] >> 4) * 4
            payload = data[ip["off"] + doff:ip["off"] + ip["tot"]]
            key = ("TCP", "%s:%d" % (ip["src"], sp), "%s:%d" % (ip["dst"], dp))
            flows[key] += 1
            bytes_per_flow[key] += len(payload)
            ip_pairs["%s -> %s" % (ip["src"], ip["dst"])] += 1
        else:
            key = ("ip-proto-%d" % ip["proto"], ip["src"], ip["dst"])
            flows[key] += 1
            ip_pairs["%s -> %s" % (ip["src"], ip["dst"])] += 1

    print("packets: %d" % n)
    print("\n== top flows (pkts, payload bytes) ==")
    for k, v in flows.most_common(25):
        print("  %-4s %-24s -> %-24s  %6d pkts  %9d B"
              % (k[0], k[1], k[2], v, bytes_per_flow[k]))

    print("\n== IP pairs ==")
    for k, v in ip_pairs.most_common(20):
        print("  %-40s %6d" % (k, v))

    print("\n== LAN tuples (192.168.x) ==")
    if not lan_tuples:
        print("  (none -- the app's LAN traffic did not go through the VPN)")
    for k, v in lan_tuples.most_common(30):
        print("  %s:%d -> %s:%d   %d pkts  %d B"
              % (k[0], k[1], k[2], k[3], v, bytes_per_flow[k]))

    if dump and lan_records:
        with open(dump, "wb") as f:
            for ip, sp, dp, payload in lan_records:
                if only and ip["dst"] != only and ip["src"] != only:
                    continue
                f.write(struct.pack(">4s4sHH", ip["src"].encode(), b"",
                                   0, len(payload)))
                f.write(bytes(ipaddress.IPv4Address(ip["dst"])))
                f.write(struct.pack(">HH", sp, dp))
                f.write(payload)
        print("\nwrote %d LAN UDP payloads to %s" % (len(lan_records), dump))


if __name__ == "__main__":
    main()
