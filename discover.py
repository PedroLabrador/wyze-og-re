#!/usr/bin/env python3
"""Standalone LAN discovery for Wyze/Gwell cameras -- no phone, no app.

This is the piece that was missing: how the client learns each camera's P2P
port.  Reverse-engineered from send_loop (0x7d778) and confirmed by sniffing
the real exchange with lansniff.py (P2P_PROTOCOL.md 5d).

    us  --UDP 28 B-->  <subnet broadcast>:8899     (also ff02::1%if:8899)
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
import re
import select
import socket
import struct
import subprocess
import sys
import time

BROADCAST_PORT = 8899
FLAGS = 0x02010000
# limited-broadcast fallback (routers never forward it, but it reaches every
# host on the same link, which is all a camera needs); per-interface subnet
# broadcasts are derived at runtime in broadcast_addrs().
BROADCAST = "255.255.255.255"
MULTICAST6 = ("ff02::1", BROADCAST_PORT)
REPLY_LEN = 138


IS_WINDOWS = sys.platform.startswith("win")
_QUAD_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _mask_bits(mask):
    """Prefix length of a dotted-quad netmask, or None if not contiguous."""
    try:
        n = int.from_bytes(socket.inet_aton(mask), "big")
    except OSError:
        return None
    if n == 0:
        return None              # 0.0.0.0 is "no mask", not a /0 netmask
    inv = (~n) & 0xFFFFFFFF
    if inv & (inv + 1):
        return None              # 255.0.255.0 and friends are not netmasks
    return bin(n).count("1")


def _broadcast_of(ip, mask):
    """Directed broadcast for one address/netmask pair, or None for /31, /32."""
    bits = _mask_bits(mask)
    if bits is None or bits >= 31:
        return None
    try:
        i = int.from_bytes(socket.inet_aton(ip), "big")
        m = int.from_bytes(socket.inet_aton(mask), "big")
    except OSError:
        return None
    return socket.inet_ntoa(((i & m) | ((~m) & 0xFFFFFFFF)).to_bytes(4, "big"))


def windows_ifaces():
    """[(ip, netmask)] for every IPv4 adapter, from `ipconfig`.

    Windows has no equivalent of `ip -4 addr`, and its text output is
    localised.  The *values* are always plain dotted quads, though, so pair
    each netmask with the address printed immediately above it instead of
    matching English labels.  (Order in `ipconfig` is Address then Mask.)
    """
    if not IS_WINDOWS:
        return []
    try:
        run = subprocess.run(
            ["ipconfig"], capture_output=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return []
    # Digits and dots are ASCII in every OEM/ANSI code page; high bytes only
    # appear in adapter names, which we do not parse.
    txt = run.stdout.decode("ascii", "replace")
    pairs, last = [], None
    for line in txt.splitlines():
        mo = _QUAD_RE.search(line)
        if not mo:
            continue
        value = mo.group(1)
        bits = _mask_bits(value)
        if bits is not None:
            if last and bits < 31:
                pairs.append((last, value))
            last = None
        else:
            last = value
    return pairs


def resolver_ipv4():
    """IPv4 addresses the resolver knows about (last-resort enumeration)."""
    try:
        return [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
                if not ip.startswith("127.")]
    except OSError:
        return []


def local_ipv4():
    """Every non-loopback IPv4 address on this host, best effort.

    Used by the grabber's self-gate (wiregrab.own_ips) as well as discovery's
    sweep fallback.  On Windows this is the only enumeration that works
    without running an external tool per call, so the two share it.
    """
    ips = []
    if IS_WINDOWS:
        ips = [ip for ip, _ in windows_ifaces()]
    else:
        try:
            if sys.platform == "darwin":
                txt = subprocess.run(["ifconfig"], capture_output=True,
                                     timeout=3).stdout.decode("utf-8", "replace")
            else:
                txt = subprocess.run(["ip", "-4", "-o", "addr"],
                                     capture_output=True, timeout=3
                                     ).stdout.decode("utf-8", "replace")
                if "inet" not in txt:
                    txt = subprocess.run(["ifconfig"], capture_output=True,
                                         timeout=3
                                         ).stdout.decode("utf-8", "replace")
            ips = re.findall(r"\binet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", txt)
        except Exception:
            pass
    if not ips:
        ips = resolver_ipv4()
    seen, res = set(), []
    for ip in ips:
        if ip in seen or ip == "0.0.0.0" or ip.startswith("127."):
            continue
        seen.add(ip)
        res.append(ip)
    return res


def slash24_hosts(exclude=()):
    """Every usable host on each local subnet (one /24 at most per adapter).

    A unicast probe is a fallback for networks where the broadcast is dropped
    before it reaches the camera (VPN/virtual adapters on Windows are the
    usual culprits).  The camera answers unicast probes just like broadcast
    ones -- discover.py's command line has always supported that.

    On Windows the real netmask is used, which also keeps the sweep out of
    /32 VPN adapters (a /32 has no broadcast and no neighbours) and small
    point-to-point links.  Wide subnets are capped at the local /24 so a /16
    does not turn into 65k packets.
    """
    skip = set(exclude) | {"0.0.0.0", "127.0.0.1"}
    nets = (windows_ifaces() if IS_WINDOWS else
            [(ip, "255.255.255.0") for ip in local_ipv4()])
    out, seen = [], set()
    for ip, mask in nets:
        if ip.startswith(("127.", "169.254.")):
            continue
        bits = _mask_bits(mask)
        if bits is None or bits >= 31:      # /32 VPN, /31 point-to-point
            continue
        if bits < 24:
            base = ip.rsplit(".", 1)[0]
            cands = ["%s.%d" % (base, host) for host in range(1, 255)]
        else:
            m = int.from_bytes(socket.inet_aton(mask), "big")
            net = int.from_bytes(socket.inet_aton(ip), "big") & m
            size = 1 << (32 - bits)
            cands = [socket.inet_ntoa((net + k).to_bytes(4, "big"))
                     for k in range(1, size - 1)]
        for cand in cands:
            if cand in skip or cand in seen:
                continue
            seen.add(cand)
            out.append(cand)
    return out


def broadcast_addrs():
    """The broadcast address of every local IPv4 interface, best first.

    macOS `ifconfig`, Linux `ip -4 addr` and Windows `ipconfig` all expose the
    addresses; parsing them means the code works on any home subnet -- from a
    fresh checkout, with no relay to hand-edit and no netmask guessing.  If
    nothing parses (unusual OS), fall back to limited broadcast
    255.255.255.255.

    Windows used to fall into the Linux branch: `ip` does not exist there, the
    exception was swallowed, and discovery silently went out as a single
    255.255.255.255 packet.  On a machine with a VPN or Hyper-V/WSL adapter
    that limited broadcast is often routed out the wrong interface, so no
    camera ever answered.  Use the per-adapter subnet broadcast instead.
    """
    out = []
    try:
        if IS_WINDOWS:
            for ip, mask in windows_ifaces():
                b = _broadcast_of(ip, mask)
                if b:
                    out.append(b)
            if not out:
                # ipconfig missing/unparseable: assume the home default /24.
                for ip in resolver_ipv4():
                    out.append("%s.255" % ip.rsplit(".", 1)[0])
        elif sys.platform == "darwin":
            txt = subprocess.run(["ifconfig"], capture_output=True,
                                 timeout=3).stdout.decode("utf-8", "replace")
            # macOS puts everything on one line:
            #   inet 192.168.0.132 netmask 0xffffff00 broadcast 192.168.0.255
            # (the old code looked for a line *starting* with "broadcast ",
            # which never matches, so it always fell back to 255.255.255.255).
            for ln in txt.splitlines():
                if "inet " not in ln:
                    continue
                mo = re.search(r"\bbroadcast\s+(\d+\.\d+\.\d+\.\d+)", ln)
                if mo:
                    out.append(mo.group(1))
                    continue
                mip = re.search(r"\binet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", ln)
                mmo = re.search(r"\bnetmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)",
                                ln)
                if mip and mmo:
                    mask = mmo.group(1)
                    if mask.startswith("0x"):
                        mask = socket.inet_ntoa(
                            int(mask, 16).to_bytes(4, "big"))
                    b = _broadcast_of(mip.group(1), mask)
                    if b:
                        out.append(b)
        else:
            try:
                txt = subprocess.run(["ip", "-4", "-o", "addr"],
                                     capture_output=True, timeout=3
                                     ).stdout.decode("utf-8", "replace")
            except Exception:
                txt = ""
            for mo in re.finditer(r"\bbrd\s+(\d+\.\d+\.\d+\.\d+)\b", txt):
                out.append(mo.group(1))
            if not out:
                # Linux without brd left out, or a BSD: try `ifconfig`.
                try:
                    txt = subprocess.run(["ifconfig"], capture_output=True,
                                         timeout=3
                                         ).stdout.decode("utf-8", "replace")
                except Exception:
                    txt = ""
                for mo in re.finditer(r"broadcast\s+(\d+\.\d+\.\d+\.\d+)", txt):
                    out.append(mo.group(1))
            if not out:
                for mo in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\b", txt):
                    ip_s, pre = mo.group(1), int(mo.group(2))
                    mask = None
                    if pre == 24:
                        mask = "255.255.255.0"
                    elif pre == 16:
                        mask = "255.255.0.0"
                    elif pre == 8:
                        mask = "255.0.0.0"
                    if mask:
                        b = _broadcast_of(ip_s, mask)
                        if b:
                            out.append(b)
    except Exception:
        pass
    out = [b for b in out if b and not b.startswith("127.")]
    # Always keep the limited broadcast as a last target: it costs one packet
    # and is the one address no adapter/netmask parsing can get wrong.  On
    # Windows it can leave via the wrong interface (hence the directed
    # broadcasts above), but when it leaves via the right one it just works.
    out.append(BROADCAST)
    seen, res = set(out), []
    for b in out:
        if b not in seen:
            continue
        seen.discard(b)      # dedupe in order
        res.append(b)
    return res or [BROADCAST]


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
        destinations = [(b, BROADCAST_PORT) for b in broadcast_addrs()]
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
