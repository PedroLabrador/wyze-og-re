#!/usr/bin/env python3
"""
Locate the address lists inside a decrypted MTP_RES_RESPONSE (GUTES type 0xa3).

gat_on_rcvpkt_MTP_RES_RESPONSE @ 0x4bafc does, in order:

    conv   = *(frame + 0x1c)                    # session lookup, same slot CALLING uses
    p      = frame + 120
    if (*p     >= 32) *p     = 32               # count A, clamped
    if (p[1] >= 16) p[1] = 16                   # count B, clamped
    memcpy(array,  p + 2,              nA * 16) # 16-byte entries -> add_udp_relay  (type 135)
    memcpy(scratch, p + 2 + nA * 16,   nB * 28) # 28-byte entries -> lan/nat        (type 1/2)

and the 16-byte entry is read as:

    entry+8  -> passed straight to iv_mtp_session_add_udp_relay  (the address struct)
    ldrh [entry+10]  -> port
    ldr  [entry+12]  -> ip

which is exactly a sockaddr_in laid out at entry+8:
    +8  u16 family   +10 u16 port   +12 u32 ip

This script prints the lists out of every captured frame so the layout can be
confirmed against addresses we already know (our Mac, the cameras, AWS relays).

Usage:  python3 find_addrs.py [--hex <framehex>]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_calls import decrypt, hexdump        # noqa: E402
from show_mtp_res import frames_from_capture, carve   # noqa: E402

# things we can recognise on sight
KNOWN = {
    "192.168.77.13": bytes([192, 168, 0, 236]),   # Mac en0 / Wi-Fi
    "192.168.77.20": bytes([192, 168, 0, 132]),   # Mac en5 / USB LAN
    "192.168.77.19": bytes([192, 168, 0, 242]),   # the phone
    "192.168.77.12": bytes([192, 168, 0, 217]),   # cam1
    "192.168.77.10": bytes([192, 168, 0, 224]),   # cam2
    "192.168.77.17": bytes([192, 168, 0, 169]),   # cam3
    "192.168.77.11": bytes([192, 168, 0, 117]),   # cam4
    "3.13.212.24": bytes([3, 13, 212, 24]),       # relay srv49
    "3.131.23.11": bytes([3, 131, 23, 11]),       # relay srv48
    "52.40.221.253": bytes([52, 40, 221, 253]),   # relay srv28
    "44.238.104.252": bytes([44, 238, 104, 252]),  # relay srv18
}


def scan(frame, label):
    print("=" * 78)
    print("%s   len=%d   conv(frame[28:32]) = %08x"
          % (label, len(frame), int.from_bytes(frame[28:32], "little")))
    print("=" * 78)

    # 1. brute-force every offset for a known IPv4 address
    print("\n  -- known IPv4 found at these offsets --")
    hits = 0
    for name, pat in KNOWN.items():
        start = 0
        while True:
            i = frame.find(pat, start)
            if i < 0:
                break
            port = int.from_bytes(frame[i - 2:i], "little") if i >= 2 else 0
            portn = int.from_bytes(frame[i - 2:i], "big") if i >= 2 else 0
            print("      %-16s @%-4d   (u16LE-2=%-5d u16BE-2=%d)"
                  % (name, i, port, portn))
            hits += 1
            start = i + 1
    if not hits:
        print("      (none)")

    # 2. the frame+120 header the function actually reads
    if len(frame) > 122:
        nA, nB = frame[120], frame[121]
        print("\n  -- frame[120:] as the function parses it --")
        print("      raw   nA=%d  nB=%d   -> clamped nA=%d nB=%d"
              % (nA, nB, min(nA, 32), min(nB, 16)))
        print("      A (16 B entries) would span [%d:%d]"
              % (122, 122 + min(nA, 32) * 16))
        print("      B (28 B entries) would span [%d:%d]"
              % (122 + min(nA, 32) * 16, 122 + min(nA, 32) * 16 + min(nB, 16) * 28))

    # 3. walk every plausible 16-byte entry start and show family/port/ip
    print("\n  -- candidate 16-byte entry tables (family@+8 port@+10 ip@+12) --")
    shown = 0
    for base in (122, 120, 124, 116, 128, 104, 96):
        if base + 16 > len(frame):
            continue
        n = 0
        rows = []
        off = base
        while off + 16 <= len(frame) and n < 8:
            fam = int.from_bytes(frame[off + 8:off + 10], "little")
            prt = int.from_bytes(frame[off + 10:off + 12], "little")
            ipb = frame[off + 12:off + 16]
            ip = ".".join(str(c) for c in ipb)
            if fam in (2, 23, 10) or ipb.count(0) <= 2:
                rows.append("        [%2d] base+%-3d fam=%-4d port=%-5d %s"
                            % (n, off, fam, prt, ip))
            off += 16
            n += 1
        if rows:
            print("      base=%d" % base)
            for r in rows:
                print(r)
            shown += 1
    if not shown:
        print("      (nothing recognisable)")


def main():
    if "--hex" in sys.argv:
        h = sys.argv[sys.argv.index("--hex") + 1]
        scan(decrypt(bytes.fromhex(h.replace(" ", ""))), "supplied")
        return
    seen = 0
    for e in frames_from_capture():
        if not e["hex"] or "7ea3" not in e["hex"]:
            continue
        for r in carve(bytes.fromhex(e["hex"]))[0]:
            if r[1] != 0xa3 or len(r) < 100:
                continue
            seen += 1
            scan(decrypt(r), "7e a3  t=%.2fs %s" % (e["t"], e["dir"]))
            print()
            if seen >= 3:
                return


if __name__ == "__main__":
    main()
