#!/usr/bin/env python3
"""Forge a LAN-discovery reply so the app calls US instead of the camera.

Why this exists
---------------
We need the bytes of the client's `CALLING` frame (iv_init_frm_CALLING, type
0xa4, 128 B - P2P_PROTOCOL.md 5e) but the phone->camera UDP leg is not
sniffable from the Mac (no raw sockets without root).

Discovery (5d) gives us a much friendlier lever: the camera's endpoint is
whatever IP:PORT the *reply* claims, where the IP is simply the reply's source
address.  So if WE answer the phone's probe - from the Mac's own IP, with a
real camera's MAC and wyze_id but our own P2P port - the app's
`find_dst_id_inlan` resolves the camera to 192.168.77.13:<our port> and dials
the Mac.  Whatever it sends is then ours to read.

This is read-mostly and reversible: we only send UDP packets.  Stop the
script and the app goes back to calling the real cameras on its next start.

Layout of the forged 138-byte reply (all fields copied verbatim from a genuine
capture; only offset 44 and the checksum word change):
    [0]    0x70
    [1]    0x03
    [2:4]  u16 LE = 138
    [16:20] checksum (XOR-rebalanced when the port changes)
    [28:36] u64 LE = dev_id / TID  <-- the key find_dst_id_inlan matches on,
                                       e.g. 429728658756018 for D03F277576D8
    [44:48] u32 LE = P2P PORT      <-- the edit
    [58:64] MAC                    <-- genuine, so the app matches the device
    [102:126] wyze_id              <-- genuine

Usage:
    python3 forge_call.py            # run for 120 s, print anything received
    python3 forge_call.py 180
    python3 forge_call.py 180 --identical
    python3 forge_call.py 180 --listen=60407

Takeover mode -- the one that still works with current app builds
-----------------------------------------------------------------
A running app already knows each camera's LAN endpoint and dials it, so it
ignores a forged discovery reply while the real camera is answering the same
probe.  Remove the competitor instead:

    1. with the camera ON, run this once and note the printed
           [clone] <camera-ip>  port <p2p-port>
    2. power that camera off
    3. give this host the camera's address:
           sudo ifconfig <iface> alias <camera-ip> 255.255.255.0
    4. python3 forge_call.py 600 --listen=<p2p-port>
    5. open that camera in the app; it dials <camera-ip>:<p2p-port>, which
       is now this host, and every frame lands in /tmp/forge_in_*.bin
    6. undo: sudo ifconfig <iface> -alias <camera-ip>

`--listen` binds a P2P port even when no camera could be cloned, which is
what makes step 4 possible with the camera switched off.
"""
import select
import socket
import struct
import sys
import time

sys.path.insert(0, ".")
from discover import build_probe, BROADCAST_PORT, broadcast_addrs

DISC_PORT = 8899          # source port the app expects a reply from
FAKE_P2P_PORT = 29000     # where we want the app to send its CALLING frame
PHONE_PORT = 8900         # the port broadcast_fd_init binds on the phone
_args = [a for a in sys.argv[1:] if not a.startswith("--")]
# --identical: send the genuine reply byte-for-byte (only the source IP differs).
# This isolates "is the payload edit being rejected?" from "is the source IP
# being rejected?"  see P2P_PROTOCOL.md 5d / 5e.
IDENTICAL = "--identical" in sys.argv
# --listen=60407[,60599]  extra P2P ports to bind even when the camera that
# owns them is powered off (the takeover recipe: the app already knows the
# candidate camera's port from its own earlier discovery, so the only thing
# missing on this side is a listener there).
LISTEN = set()
for _a in sys.argv[1:]:
    if _a.startswith("--listen="):
        LISTEN |= {int(x) for x in _a.split("=", 1)[1].split(",") if x.strip()}
DUR = float(_args[0]) if _args else 120.0


def hexdump(data, base=0):
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("  %4d  %-47s  |%s|" % (base + off,
                                             " ".join("%02x" % b for b in chunk), asc))
    return "\n".join(lines)


def capture_genuine_replies():
    """Ask the real cameras for their adverts so we can clone them exactly."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("0.0.0.0", 0))
    rx.setblocking(False)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    probe = build_probe(rx.getsockname()[1])
    for bc in broadcast_addrs():
        try:
            tx.sendto(probe, (bc, BROADCAST_PORT))
        except OSError:
            pass

    replies = {}
    end = time.time() + 3.0
    while time.time() < end and len(replies) < 4:
        r, _, _ = select.select([rx], [], [], 0.3)
        if not r:
            continue
        data, addr = rx.recvfrom(4096)
        if len(data) == 138 and data[0] == 0x70 and data[1] == 0x03:
            replies.setdefault(addr[0], data)
    rx.close()
    tx.close()
    return replies


def main():
    genuine = capture_genuine_replies()
    if not genuine and not LISTEN:
        print("[!] captured no genuine replies - nothing to clone", flush=True)
        return 1

    forges = {}
    for ip, data in sorted(genuine.items()):
        wid = data[102:126].split(b"\x00")[0].decode()
        if IDENTICAL:
            forges[ip] = data
            print("[clone] %-16s IDENTICAL (no edits)  port %d  id=%s"
                  % (ip, struct.unpack_from("<I", data, 44)[0], wid), flush=True)
            continue
        forged = bytearray(data)
        # The reply header follows the usual layout:
        #   [0] magic 70  [1] type 03  [2:4] len  [12:16] seq
        #   [16:20] checksum  [20:24] flags (0 -> payload is NOT RC5'd)
        # so [16:20] must be rebalanced when we touch [44:48], exactly like
        # LIST_RESP (P2P_PROTOCOL.md 4a): chk = g(header) ^ fold(payload),
        # and folding is XOR, so XOR the same delta back into the checksum.
        delta = struct.unpack_from("<I", data, 44)[0] ^ FAKE_P2P_PORT
        chk = struct.unpack_from("<I", data, 16)[0]
        struct.pack_into("<I", forged, 44, FAKE_P2P_PORT)
        struct.pack_into("<I", forged, 16, chk ^ delta)
        forges[ip] = bytes(forged)
        print("[clone] %-16s port %-6d -> %d  chk 0x%08x^0x%08x=0x%08x  mac=%s id=%s"
              % (ip, struct.unpack_from("<I", data, 44)[0], FAKE_P2P_PORT,
                 chk, delta, chk ^ delta,
                 ":".join("%02x" % b for b in data[58:64]),
                 data[102:126].split(b"\x00")[0].decode()), flush=True)

    # socket A: impersonate the camera's discovery port (8899)
    disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    disc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    disc.bind(("0.0.0.0", DISC_PORT))
    disc.setblocking(False)

    # socket B: the fake P2P endpoint - anything arriving here is the
    # app's CALLING / KCP / AV traffic, captured in the clear.
    p2p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    p2p.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    p2p.bind(("0.0.0.0", FAKE_P2P_PORT))
    p2p.setblocking(False)

    # Sockets C: bind the cameras' REAL p2p ports on this host.
    # The app dials the endpoint it already knows: the reply's source IP with
    # the port the camera advertised.  Listening there is what captures the
    # handshake -- and during a takeover it is the ONLY thing that matters,
    # because the camera that owned the address is powered off.
    real_ports = {}
    ports_to_bind = {struct.unpack_from("<I", data, 44)[0]
                     for data in genuine.values()}   # REAL ports: read from
    ports_to_bind |= LISTEN                          # the genuine reply,
    for p in sorted(ports_to_bind):                  # never the edited clone
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", p))
            s.setblocking(False)
            real_ports[p] = s
        except OSError as e:
            print("[!] cannot bind camera port %d: %s" % (p, e), flush=True)

    socks = [disc, p2p] + list(real_ports.values())
    port_name = {p: "camport:%d" % p for p in real_ports}
    port_name[FAKE_P2P_PORT] = "fakep2p:%d" % FAKE_P2P_PORT
    phone = None
    forged_sent = 0
    t0 = time.time()
    last_send = 0.0
    n = 0
    seq = 0

    print("[listen] discovery :%d   fake p2p :%d   camera ports %s   for %.0f s"
          % (DISC_PORT, FAKE_P2P_PORT, sorted(real_ports), DUR), flush=True)

    def blast():
        for forged in forges.values():
            for dest in ({phone} if phone else set(broadcast_addrs())):
                for port in phone_ports:
                    try:
                        disc.sendto(forged, (dest, port))
                    except OSError:
                        pass

    phone_ports = {PHONE_PORT}

    while time.time() - t0 < DUR:
        now = time.time()
        # First-wins? Unknown, so be safe on both counts: send far more often
        # than the camera does (it only answers a probe, ~1 Hz) AND answer a
        # probe with zero delay so we are never the late one.
        if now - last_send >= 0.002:
            last_send = now
            before = forged_sent
            blast()
            forged_sent += (1 if phone else 0) * len(forges)
            n += 1
            del before

        r, _, _ = select.select(socks, [], [], 0.2)
        for s in r:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            if s is disc:
                if len(data) == 28 and data[0] == 0x70 and data[1] == 0x02:
                    if phone != addr[0]:
                        phone = addr[0]
                    want = struct.unpack_from("<H", data, 26)[0] or PHONE_PORT
                    # The probe says who it hunts and where it waits:
                    #   [4:12]  8-byte slot the app fills when targeting one
                    #           camera (zero on a blanket sweep)
                    #   [12:16] probe counter
                    #   [26:28] reply port the cameras must answer (the app
                    #           listens for replies there)
                    slot = data[4:12]
                    tgt = ("zero (sweep)" if not any(slot)
                           else "..." + slot.hex()[-4:])
                    print("[%6.2fs] PROBE %s:%d -> answered :%d  target %s "
                          "counter 0x%08x%s"
                          % (now - t0, phone, addr[1], want, tgt,
                             struct.unpack_from("<I", data, 12)[0],
                             "" if want == PHONE_PORT
                             else "  (declared %d)" % want),
                          flush=True)
                    if want not in phone_ports:
                        phone_ports.add(want)
                    for port in ({want, PHONE_PORT}):
                        for forged in forges.values():
                            try:
                                disc.sendto(forged, (phone, port))
                            except OSError:
                                pass
                    last_send = time.time()
                else:
                    print("[%6.2fs] disc <- %s:%d %d B"
                          % (now - t0, addr[0], addr[1], len(data)), flush=True)
                continue

            # ---- this is the payoff: raw bytes from the app ----
            local = s.getsockname()[1]
            print("\n[%6.2fs] *** INBOUND [%s] from %s:%d  len=%d ***"
                  % (now - t0, port_name.get(local, str(local)),
                     addr[0], addr[1], len(data)), flush=True)
            print(hexdump(data), flush=True)
            print("ascii: %r" % data[:128], flush=True)
            # NB: several packets can land in the same wall-clock second, so a
            # time-only name silently overwrites the earlier captures.
            seq += 1
            fn = "/tmp/forge_in_%d_%d_%03d.bin" % (local, int(time.time()), seq)
            open(fn, "wb").write(data)
            print("saved -> %s\n" % fn, flush=True)

    print("[done] forged replies sent=%d" % forged_sent, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
