#!/usr/bin/env python3
"""
List-server impersonator + relay MITM.

The app's GWApi.GWellP2PUrl is patched to "|192.168.77.13", so it already dials this
Mac on UDP 51701 (see P2P_PROTOCOL.md §3a). This script goes one step further than
cap_listsrv2.py: instead of just *logging* the LIST_REQUEST, it

  1. forwards the request to the genuine list server,
  2. takes the real LIST_RESP, RC5-decrypts it,
  3. rewrites every relay record's IPv4 (record+0) and port (record+24) to THIS Mac,
  4. re-checksums, re-encrypts, and hands the modified response back to the app,
  5. then listens on the relay port and forwards the app's UDP traffic to the real
     relay (3.13.212.24:28800), capturing certify / init_info / GDM in the clear
     on both legs.

Frame rules (P2P_PROTOCOL.md §3a, §4, §5):
    key   = frame[0:4] || frame[0x14:0x17] || 0x00
    chk   = XOR fold over the plaintext, masked 0x00FFFFFF, stored at [16:20]
    RC5   = 32-bit words, 6 rounds, 8-byte blocks, LITTLE-endian, over [12:20] and [24:]
    records at frame+32, stride 36:  +0 IPv4(BE)  +22 srv_id(LE)  +24 port(BE)

    python3 cap_relay.py [list_port] [relay_port] [seconds]
"""
import select
import socket
import struct
import sys
import time

from listreq import MASK, rc5_setup, rc5_encrypt_block, rc5_decrypt_block, payload_len, checksum

LIST_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 51701
RELAY_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 28800
DUR = float(sys.argv[3]) if len(sys.argv) > 3 else 180.0

MAC_IP = "192.168.77.13"
REAL_LIST = ("18.118.90.161", 51701)
REAL_RELAY = ("3.13.212.24", 28800)   # srv_id 49, from record 0 of the LIST_RESP

OUT = "/tmp/cap_relay.log"
t0 = time.time()
f = None
n = [0]
app_addr = None


def emit(kind, addr, data, note=""):
    n[0] += 1
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    block = ("[%7.2fs] %-6s %-21s len=%-5d %s\n  HEX %s\n  ASC %s\n"
             % (time.time() - t0, kind, "%s:%d" % addr, len(data), note,
                data.hex(), asc))
    print(block, end="", flush=True)
    if f:
        f.write(block)
        f.flush()


def key_of(buf):
    """key = frame[0:4] || frame[0x14:0x17] || 0x00  (listreq.py rule)."""
    return bytes([buf[0], buf[1], buf[2], buf[3],
                  buf[0x14], buf[0x15], buf[0x16], 0x00])


def rc5_apply(buf, decrypt=False):
    """RC5 [12:20] and [24:] in place. decrypt=False encrypts, True decrypts."""
    S = rc5_setup(key_of(buf))
    fn = rc5_decrypt_block if decrypt else rc5_encrypt_block
    buf = bytearray(buf)
    buf[12:20] = fn(S, bytes(buf[12:20]), "little")
    nblocks = payload_len(buf) >> 3
    for i in range(nblocks):
        off = 24 + i * 8
        if off + 8 <= len(buf):
            buf[off:off + 8] = fn(S, bytes(buf[off:off + 8]), "little")
    return bytes(buf)


def rewrite_relays(resp, mac_ip, relay_port):
    """Point every LIST_RESP record at us, XOR-FOLD-NEUTRAL.

    WHY THE BALANCING ACT
    ---------------------
    iv_gute_frm_init_chkval/verity_chkval is a pure XOR fold over the header
    words 0,4,8,12 plus payload words 24,28,...,172.  Proven by experiment:
    XORing DELTA into ANY payload word makes the app answer chk(base)^DELTA,
    and the offset-16 word is not folded at all.

    The app's answer nevertheless differs from our own fold by a constant
    g(header)-^-h(header) that depends only on bytes 0..23 (the app folds
    values produced by iv_gute_frm_decrypt_id, which we do not model).  Two
    controls with an identical header but different payloads both returned
    exactly the same constant, so:

        app_chk(payload') = g(H) ^ fold(payload')

    i.e. IF THE PAYLOAD FOLD IS UNCHANGED THE APP RECOMPUTES THE ORIGINAL
    CHECKSUM, and we can leave offset 16 (the stored checksum) exactly as the
    genuine server wrote it -- no oracle round-trip needed.

    We therefore XOR the total delta of every field we rewrite back out
    through one sacrificial word, keeping the fold identical.
    """
    plain = bytearray(resp)
    total = struct.unpack_from("<H", plain, 2)[0]
    nrec = (total - 32) // 36
    notes = []
    ipb = socket.inet_aton(mac_ip)          # network byte order == wire order
    new_ip = struct.unpack(">I", ipb)[0]
    port12 = struct.pack(">HH", relay_port, relay_port)   # ports are big-endian
    delta = 0

    def flip(off, new):
        nonlocal delta
        delta ^= struct.unpack(">I", plain[off:off + 4])[0]
        plain[off:off + 4] = new
        delta ^= struct.unpack(">I", new)[0]

    for i in range(nrec):
        off = 32 + i * 36
        old_ip = socket.inet_ntoa(plain[off:off + 4])
        old_p = struct.unpack_from(">H", plain, off + 24)[0]
        srv = struct.unpack_from("<H", plain, off + 22)[0]
        flip(off, ipb)                              # +0  IPv4
        flip(off + 24, port12)                      # +24/+26 ports 1,2
        flip(off + 28, struct.pack(">H", relay_port) + plain[off + 30:off + 32])
        notes.append("rec%d srv=%d %s:%d -> %s:%d"
                     % (i, srv, old_ip, old_p, mac_ip, relay_port))

    if delta:
        # Sacrificial word: rec3's trailing 4 bytes (offset 172), last word of
        # the payload and zero in every record we have seen.
        # NOTE: `delta` was accumulated with big-endian reads (IPv4 and the
        # port fields are big-endian on the wire), so it must be applied with
        # the same endianness -- XOR is byte-wise, and packing with "<I" here
        # would XOR the bytes with the reversed sequence (a rotate-right-8),
        # which is exactly how the first attempt failed to balance.
        sacr = 172
        if sacr + 4 <= len(plain):
            struct.pack_into(">I", plain, sacr,
                             struct.unpack_from(">I", plain, sacr)[0] ^ delta)
            notes.append("fold-balanced: xor 0x%08x into payload word @%d "
                         "(chk word @16 left untouched)" % (delta, sacr))
        else:
            notes.append("WARNING: could not balance delta 0x%08x" % delta)
    return bytes(plain), notes


def transform_list_resp(resp):
    """Decrypt the genuine LIST_RESP, repoint the relays at us, re-encrypt.

    The stored checksum (offset 16) and the flags word are left byte-for-byte
    as the genuine server sent them: rewrite_relays() keeps the payload's XOR
    fold identical, so the app recomputes exactly that checksum.
    """
    try:
        plain = rc5_apply(resp, decrypt=True)
    except Exception as e:                  # noqa: BLE001
        emit("LIST", ("?", 0), resp, "decrypt failed: %r" % e)
        return None, []
    magic, typ = plain[0], plain[1]
    if magic != 0x7F or typ != 0x16:
        emit("LIST", ("?", 0), plain, "not a LIST_RESP (magic=%02x type=%02x)" % (magic, typ))
        return None, []
    stored = struct.unpack_from("<I", plain, 16)[0]
    plain, notes = rewrite_relays(plain, MAC_IP, RELAY_PORT)
    plain = bytearray(plain)
    now = struct.unpack_from("<I", plain, 16)[0]
    assert now == stored, "checksum word was disturbed: %08x != %08x" % (now, stored)
    notes.append("chk @16 kept = 0x%08x (fold-neutral edit)" % stored)
    return rc5_apply(bytes(plain), decrypt=False), notes


# ---------------------------------------------------------------- list server
def probe_list_server(req):
    """Forward the app's own LIST_REQUEST to the genuine server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    try:
        s.sendto(req, REAL_LIST)
        data, addr = s.recvfrom(65535)
        return data
    except (socket.timeout, OSError) as e:
        print("[!] list server: %r" % e, flush=True)
        return None
    finally:
        s.close()


# --------------------------------------------------------------------- sockets
def main():
    global f, app_addr
    lsn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsn.bind(("0.0.0.0", LIST_PORT))

    rl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rl.bind(("0.0.0.0", RELAY_PORT))

    f = open(OUT, "w")
    f.write("# list udp 0.0.0.0:%d, relay udp 0.0.0.0:%d -> %s:%d, %.0fs\n"
            % (LIST_PORT, RELAY_PORT, REAL_RELAY[0], REAL_RELAY[1], DUR))
    print("[listen] list:%d  relay:%d -> real %s:%d  (%.0fs)"
          % (LIST_PORT, RELAY_PORT, REAL_RELAY[0], REAL_RELAY[1], DUR), flush=True)

    cache = {}
    while time.time() - t0 < DUR:
        try:
            r, _, _ = select.select([lsn, rl], [], [], 0.5)
        except OSError:
            continue
        for s in r:
            data, addr = s.recvfrom(65535)
            if not data:
                continue

            if s is lsn:
                emit("REQ", addr, data, "list request from app")
                resp = probe_list_server(data) or cache.get("raw")
                if resp is None:
                    continue
                if resp is cache.get("raw"):
                    emit("REPLAY", REAL_LIST, resp, "cached genuine LIST_RESP")
                cache["raw"] = resp
                emit("RESP", REAL_LIST, resp, "genuine LIST_RESP")
                out, notes = transform_list_resp(resp)
                if out is None:
                    continue
                for nt in notes:
                    print("       * %s" % nt, flush=True)
                    f.write("       * %s\n" % nt)
                emit("MOD", addr, out,
                     "LIST_RESP repointed at %s:%d" % (MAC_IP, RELAY_PORT))
                lsn.sendto(out, addr)
            elif addr[0] == REAL_RELAY[0]:
                emit("<-AWS", addr, data, "relay response")
                if app_addr:
                    rl.sendto(data, app_addr)
            else:
                app_addr = addr
                emit("APP->", addr, data, "relay leg")
                rl.sendto(data, REAL_RELAY)

    f.write("# total %d chunk(s)\n" % n[0])
    f.close()
    print("[done] %d chunk(s)" % n[0], flush=True)


if __name__ == "__main__":
    main()
