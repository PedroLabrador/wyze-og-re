#!/usr/bin/env python3
"""Talk to a Wyze GC1's P2P port OURSELVES - replay the app's own handshake.

Why this exists
---------------
forge_call.py proved we can make the app dial us, which bought us the bytes of
the frames the app sends.  But the app never gets a camera back, so we still
have never seen the camera's reply.  This tool removes the phone entirely:

    discover  ->  camera_ip:port          (discover.py, ~3 s, no app needed)
    send      ->  the app's own frames    (captured by forge_call.py)
    receive   ->  whatever the camera says

[!]  LIMIT, PROVEN 2026-10-13 - DO NOT KEEP DEBUGGING THIS PATH FOR VIDEO
-----------------------------------------------------------------------
The control plane here is COMPLETE and correct: the camera acks the CALLING and
the AvStreamCtl, and its session+0x10 provably matches ours.  But **KCP will
never start over plain LAN**, on either side.  kcb->output (a static at
0x5c1d8 that objdump mislabels iv_create_kcb+0x16c) round-robins the session's
channel pool and only accepts channel **type 135** - and type-135 channels are
created by exactly one function, gat_on_rcvpkt_MTP_RES_RESPONSE, i.e. by the
**relay rendezvous**.  LAN calling only adds types 1/2.  So the camera eats our
WASK, wants to answer WINS, and then throws the answer away.

`--kcp` is therefore kept as a *negative* control, not a path to video.  The
video route goes through the relay (see P2P_PROTOCOL.md 5f and STATUS.md).
Keep this tool: it is the byte-exact proof of everything above, and the
discovery + frame-replay machinery is reusable.

The three frames the app sends, in order (P2P_PROTOCOL.md 5e):

    74 B  c0 90 02 09   cleartext session hello: d_log + TID + tick
   128 B  7e a4 80 00   CALLING   type 0xa4   (iv_init_frm_CALLING)
    76 B  7e b9 4c 00   type 0xb9, GUTES-encrypted, TID + d_log

Two ways to send them:

    (default)   byte-for-byte replay of the captured frame.  The embedded
                local IP/port still point at the phone (192.168.77.19:48171),
                so we bind local port 48171 to match [54:56].  Nothing to
                recompute - the checksum is genuine.

    --rewrite   patch [64:68] to OUR IP and rebalance the checksum.

Checksum rebalancing (this is the same fold-neutral trick as LIST_RESP):

    chk is constant across retransmits while only byte 23 (the retransmit
    counter, stamped after the checksum) changes, so byte 23 is not covered
    and g() is a fixed value for a given header.  Therefore:

        chk_new = chk_tmpl ^ fold_tmpl[24:] ^ fold_new[24:]

    i.e. XOR the delta of every 4-byte word we touch (big-endian words, as in
    P2P_PROTOCOL.md 4a) straight into the checksum word at [16:20].

Changing the IP does not disturb the RC5 key, which is
    key = frame[0:4] || frame[0x14:0x17] || 0x00
i.e. magic/len plus the low 3 bytes of the flags word.

Usage:
    python3 p2p_call.py                 # replay, 30 s
    python3 p2p_call.py 60
    python3 p2p_call.py 60 --rewrite    # patch our IP in, rebalance chk
    python3 p2p_call.py 60 --kcp        # + probe type 0x25 (create_kcp_session)
"""
import glob
import json
import os
import select
import socket
import struct
import sys
import time

sys.path.insert(0, ".")
from analyze_calls import decrypt, hexdump
from discover import build_probe, parse_reply, BROADCAST, BROADCAST_PORT
from listreq import rc5_decrypt_block, rc5_encrypt_block, rc5_setup
from mtp_frame import wrap as mtp_wrap, unwrap as mtp_unwrap
import mtp_res
import portstat_resp

CALLING_PORT = 48171        # the port embedded at [54:56] of the CALLING
SIMPLE_HELLO = 74           # the c0900209 frame
CALLING_LEN = 128
TRANSFER_LEN = 76
KCP25_LEN = 28              # inner length of giot_send_create_kcp_session_msg

D_LOG = 0x840186d6001260a3  # the phone's own id, as embedded in hello/CALLING

_args = [a for a in sys.argv[1:] if not a.startswith("--")]
REWRITE = "--rewrite" in sys.argv
KCP = "--kcp" in sys.argv
MTPRES = "--mtpres" in sys.argv
DUR = float(_args[0]) if _args else 30.0


# ---------------------------------------------------------------- templates
def extract_tid(frame):
    """TID lives at a different offset in each frame type."""
    if len(frame) == SIMPLE_HELLO and frame[:4] == b"\xc0\x90\x02\x09":
        return struct.unpack_from("<Q", frame, 26)[0]
    if frame[0] == 0x7e:
        pt = decrypt(frame)
        if len(frame) == CALLING_LEN:
            return struct.unpack_from("<Q", pt, 40)[0]
        if len(frame) == TRANSFER_LEN:
            return struct.unpack_from("<Q", pt, 28)[0]
    return None


def load_templates():
    """tid -> {74: frame, 128: frame, 76: frame} from the forge captures.

    Prefers the live `/tmp/forge_in_*.bin` captures (freshest), and falls back to
    the frozen `wire/p2p_frames.json` so a clean checkout still works. The JSON
    keeps one whole (hello, calling, avstreamctl) group per TID so all three
    carry the *same* `session+0x10` word -- see P2P_PROTOCOL.md 5e.
    """
    out = {}
    for fn in sorted(glob.glob("/tmp/forge_in_*.bin")):
        d = open(fn, "rb").read()
        tid = extract_tid(d)
        if tid is None:
            continue
        slot = out.setdefault(tid, {})
        key = {74: SIMPLE_HELLO, 128: CALLING_LEN, 76: TRANSFER_LEN}.get(len(d))
        if key and key not in slot:
            slot[key] = d
    if out:
        return out

    frozen = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "wire", "p2p_frames.json")
    if not os.path.exists(frozen):
        return out
    with open(frozen) as f:
        doc = json.load(f)
    print("[templates] using frozen wire/p2p_frames.json (no /tmp captures)")
    for tid, rec in doc.get("devices", {}).items():
        slot = {}
        for kind, hx in rec.get("frames", {}).items():
            key = {"hello": SIMPLE_HELLO, "calling": CALLING_LEN,
                   "avstreamctl": TRANSFER_LEN}[kind]
            slot[key] = bytes.fromhex(hx)
        if slot:
            out[int(tid)] = slot
    return out


def fold_words(buf, start=24):
    """XOR of the 4-byte big-endian words in buf[start:] (P2P_PROTOCOL 4a)."""
    v = 0
    for off in range(start, len(buf) - 3, 4):
        v ^= struct.unpack_from(">I", buf, off)[0]
    return v


def rewrite_ip(frame, new_ip_bytes):
    """Patch [64:68] into a CALLING frame and rebalance [16:20]."""
    pt = bytearray(decrypt(frame))
    old_ip = bytes(pt[64:68])
    if old_ip == new_ip_bytes:
        return bytes(frame)
    chk = struct.unpack_from(">I", pt, 16)[0]
    old_word = struct.unpack_from(">I", pt, 64)[0]
    new_word = struct.unpack(">I", new_ip_bytes)[0]
    # fold covers [24:]; only the word at [64:68] moves
    struct.pack_into(">I", pt, 16, chk ^ old_word ^ new_word)
    pt[64:68] = new_ip_bytes

    # re-encrypt [12:20] and [24:] with the (unchanged) key
    key = frame[0:4] + frame[20:23] + b"\x00"
    st = rc5_setup(key)
    out = bytearray(pt)
    for off in list(range(12, 20, 8)) + list(range(24, len(frame), 8)):
        if off + 8 > len(out):
            break
        out[off:off + 8] = rc5_encrypt_block(st, bytes(pt[off:off + 8]), "little")
    return bytes(out)


# ---------------------------------------------------------------- type 0x25
def build_kcp25(word, l1, l2, flag=1):
    """Build `giot_send_create_kcp_session_msg` (libiotp2pav.so @ 0x53394).

    flag MUST be 1 (`C0 90`): this is an MTP control command, and bit7 of the
    MTP header byte [1] is the packet-class bit the receive router (0x340c4)
    tests.  flag=0 sends it as `C0 10`, which lands in iv_on_rcv_kcpdata_pkt
    and is parsed as a KCP segment (first 4 bytes taken as a conv id), so it
    is dropped.  That was the bug in the first probe run.

    The function writes a 28-byte INNER frame and hands it to
    iv_mtp_chnnel_send_mtp_frm (0x5b148), which prepends the 6-byte MTP header
    (0xc0 + length + chval).  So what actually goes on the wire is 34 bytes.

    Inner frame, exactly as the disassembly writes it:

        [0]     0x00        (memset; never written with a magic)
        [1]     0x25        movw r1, #37
        [2:4]   u16LE 28    strh r1, [r2, #2]   <-- also read back as the length
        [4:8]   session+0x10  = the per-cam word (same word at CALLING +28 and
                               hello payload +4)
        [8:12]  0             str r2, [r1, #0x8]  with r2 = 0
        [12:16] session+0x1c  <-- UNKNOWN
        [16:20] session+0x20  <-- UNKNOWN
        [20:24] session+0x24  <-- UNKNOWN
        [24:28] session+0x28  <-- UNKNOWN

    The receiver (iv_rcv_kcp_create_msg @ 0x619f8) only checks
    `session->0x10 == payload[4]` and then returns -- it sends NO reply, so
    silence after this frame is the expected behaviour, not a rejection.
    It never looks at [12:28], so those four words can stay zero.
    """
    inner = bytearray(KCP25_LEN)
    inner[1] = 0x25
    struct.pack_into("<H", inner, 2, KCP25_LEN)
    struct.pack_into("<I", inner, 4, word)
    # [8:12] stays zero
    inner[12:20] = l1
    inner[20:28] = l2
    return mtp_wrap(bytes(inner), flag=flag)


def kcp25_variants(dev, myip, word):
    """Candidate type-0x25 frames for one camera, labelled for the log."""
    tid = struct.pack("<Q", dev["tid"])
    me = struct.pack("<Q", D_LOG)
    cam_ip = socket.inet_aton(dev["ip"])
    cam_port = struct.pack("<I", dev["p2p_port"])
    my_ip = socket.inet_aton(myip)
    my_port = struct.pack("<I", CALLING_PORT)

    return [
        ("kcp25:ids-fwd",      build_kcp25(word, me, tid)),
        ("kcp25:ids-rev",      build_kcp25(word, tid, me)),
        ("kcp25:zero",         build_kcp25(word, b"\x00" * 8, b"\x00" * 8)),
        ("kcp25:addr",         build_kcp25(word, my_port + my_ip,
                                           cam_port + cam_ip)),
        ("kcp25:addr-rev",     build_kcp25(word, my_ip + my_port,
                                           cam_ip + cam_port)),
    ]


# ---------------------------------------------------------------- real KCP
KCP_CMD_PUSH, KCP_CMD_ACK, KCP_CMD_WASK, KCP_CMD_WINS = 81, 82, 83, 84
KCP_CMD_NAMES = {81: "PUSH", 82: "ACK", 83: "WASK", 84: "WINS"}


def kcp_seg(conv, cmd, frg=0, wnd=128, ts=0, sn=0, una=0, data=b""):
    """One raw KCP segment (standard ikcp -- ivkcp_* is ikcp renamed).

    24-byte header, all little-endian (confirmed by ivkcp_input @ 0x79ca0,
    which rejects anything whose remaining length is not >= 24, and by
    ivkcp_flush @ 0x7ab38 which emits cmds 81/82/83/84):
        u32 conv | u8 cmd | u8 frg | u16 wnd | u32 ts | u32 sn | u32 una
        | u32 len
    """
    return (struct.pack("<I", conv & 0xFFFFFFFF)
            + bytes([cmd & 0xFF, frg & 0xFF])
            + struct.pack("<HIII", wnd & 0xFFFF, ts & 0xFFFFFFFF,
                          sn & 0xFFFFFFFF, una & 0xFFFFFFFF)
            + struct.pack("<I", len(data)) + bytes(data))


def kcp_wrap(conv, cmd, **kw):
    """A KCP segment inside the MTP header with class bit 0 -> `C0 10`.

    iv_on_rcv_kcpdata_pkt (0x630c0) strips the 6-byte header, looks the
    session up by conv, picks session+0x334 if conv bit31 is set and
    session+0x330 if it is clear, and calls ivkcp_input.  iv_find_mtp_session
    matches BOTH `W|0x80000000` and `W&0x7fffffff`, so both convs are valid.
    """
    return mtp_wrap(kcp_seg(conv, cmd, **kw), flag=0)


def kcp_variants(word):
    """Both conv forms of a WASK probe, labelled for the log."""
    lo, hi = word & 0x7FFFFFFF, word | 0x80000000
    return [
        ("kcp:wask-conv-lo", kcp_wrap(lo, KCP_CMD_WASK)),
        ("kcp:wask-conv-hi", kcp_wrap(hi, KCP_CMD_WASK)),
        ("kcp:ack-conv-lo",  kcp_wrap(lo, KCP_CMD_ACK)),
    ]


# ---------------------------------------------------------------- discovery
def discover(duration=3.0):
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("0.0.0.0", 0))
    rx.setblocking(False)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    tx.sendto(build_probe(rx.getsockname()[1]), (BROADCAST, BROADCAST_PORT))

    found = {}
    end = time.time() + duration
    while time.time() < end and len(found) < 4:
        r, _, _ = select.select([rx], [], [], 0.25)
        if not r:
            continue
        data, addr = rx.recvfrom(4096)
        dev = parse_reply(data, addr)
        if dev and dev["ip"] not in found:
            found[dev["ip"]] = dev
            print("  %-16s port=%-6d tid=%-20d %s"
                  % (dev["ip"], dev["p2p_port"], dev["tid"], dev["wyze_id"]),
                  flush=True)
    rx.close()
    tx.close()
    return found


def local_ip_for(peer):
    """Which source address the kernel will use to reach the camera."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer, 1))
        return s.getsockname()[0]
    finally:
        s.close()


# ---------------------------------------------------------------- main
def main():
    print("[discover] ...", flush=True)
    cams = discover(3.0)
    if not cams:
        print("[!] no cameras found", flush=True)
        return 1

    tpl = load_templates()
    print("[templates] captured frames for %d TIDs" % len(tpl), flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", CALLING_PORT))
    sock.setblocking(False)
    print("[listen] local port %d (matches CALLING [54:56])" % CALLING_PORT,
          flush=True)

    # what we will send, per camera
    plan = []
    for ip, dev in sorted(cams.items()):
        frames = tpl.get(dev["tid"])
        if not frames:
            print("  %-16s no captured frames for tid %d - skipped"
                  % (ip, dev["tid"]), flush=True)
            continue
        myip = local_ip_for(ip)
        seq = []
        if SIMPLE_HELLO in frames:
            seq.append(("hello", "hello74", frames[SIMPLE_HELLO]))
        if CALLING_LEN in frames:
            raw = frames[CALLING_LEN]
            if REWRITE:
                seq.append(("calling", "calling128(rewritten -> %s)" % myip,
                            rewrite_ip(raw, socket.inet_aton(myip))))
            else:
                seq.append(("calling", "calling128(replay)", raw))
        if TRANSFER_LEN in frames:
            seq.append(("xfer", "xfer76", frames[TRANSFER_LEN]))
        if KCP and CALLING_LEN in frames:
            word = struct.unpack_from("<I", decrypt(frames[CALLING_LEN]), 28)[0]
            for lbl, frm in kcp25_variants(dev, myip, word):
                seq.append(("kcp", "%-40s" % lbl, frm))
            for lbl, frm in kcp_variants(word):
                seq.append(("kcpw", "%-40s" % lbl, frm))
        if MTPRES:
            # conv: prefer the hello (an MTP `c0` frame -- no RC5, so inner[4:8]
            # is the session word whatever the key mode).  Cameras with no
            # captured hello instead take it from their CALLING, which stores it
            # at [0x1c] -- that is the very field iv_mtp_session_new copies into
            # session+0x10.  Only readable for mode-1 CALLINGs, and the app's
            # own are always mode 1.
            # The CALLING's 8 B id at [4:12] is likewise outside the cipher.
            word = None
            if SIMPLE_HELLO in frames:
                r = mtp_unwrap(frames[SIMPLE_HELLO])
                if r:
                    word = struct.unpack_from("<I", r[0], 4)[0]
            if word is None and CALLING_LEN in frames:
                cl = frames[CALLING_LEN]
                if (struct.unpack_from("<I", cl, 20)[0] >> 16) & 3 == 1:
                    word = struct.unpack_from("<I", decrypt(cl), 28)[0]
            id8 = frames[CALLING_LEN][4:12] if CALLING_LEN in frames else b"\x00" * 8
            if word is None:
                print("  %-16s no hello and no mode-1 CALLING -> no conv, "
                      "skipped" % ip, flush=True)
            else:
                # iv_gutes_pkt_isDuplicate (0x30180) keys its receive cache on
                # (frame[4:12], frame[12:16]) -- id8 and seq -- with NO expiry
                # (iv_gutes_find_rcvpkt walks the whole list, no time test), and
                # switch case 1 drops a hit at 0x2c5b8 *before* dispatching it.
                # We deliberately reuse the CALLING's id8, so every forged frame
                # needs its own seq or only the first conv variant is ever
                # looked at.  Real seqs are millisecond ticks (the three
                # captured CALLINGs carry 0x2df83644/46/48, +2 per camera), so
                # seed from the CALLING's own seq: a value this camera already
                # accepted in this very session.
                base = struct.unpack_from("<I", decrypt(frames[CALLING_LEN]),
                                          12)[0]
                combos = []
                for conv in dict.fromkeys(
                        [word, word | 0x80000000, word & 0x7FFFFFFF]):
                    combos.append((conv, mtp_res.FLAGS1))
                    combos.append((conv, 0xD2050000))  # observed high byte
                for n, (conv, fl) in enumerate(combos):
                    seq.append(("mtpres",
                                "mtp_res conv=0x%08x fl=%08x" % (conv, fl),
                                mtp_res.build(conv, myip, CALLING_PORT, id8,
                                              seq=base + n, flags=fl)))
                # Phase E2 (KCP unblock): the 7e a3 adds the relay + arms the
                # send_rcv_map_port watchdog, but that timer re-arms forever
                # until obj+0x4ec is set, and the ONLY writer of that byte is
                # PortStatResp (7f cb).  Send it for every conv variant, right
                # after the 7e a3 that created the session it must key on.
                for n, conv in enumerate(dict.fromkeys(
                        [word, word | 0x80000000, word & 0x7FFFFFFF])):
                    seq.append(("portstat",
                                "portstat_resp conv=0x%08x" % conv,
                                portstat_resp.build(conv, seq=base + n,
                                                    id8=id8)))
        plan.append((ip, dev, seq))
        print("  %-16s -> %s   local_ip=%s"
              % (ip, " ".join(lbl for _, lbl, _ in seq), myip), flush=True)

    if not plan:
        print("[!] nothing to send", flush=True)
        return 1

    t0 = time.time()
    n_sent = 0
    seen = set()

    def show(data, addr, rep):
        print("\n[%6.2fs] *** REPLY from %s:%d len=%d%s ***"
              % (time.time() - t0, addr[0], addr[1], len(data), rep), flush=True)
        print(hexdump(data), flush=True)
        if data and data[0] == 0x7e:
            print("--- decrypted ---", flush=True)
            print(hexdump(decrypt(data)), flush=True)
        elif data and data[0] == 0xc0:
            r = mtp_unwrap(data)
            if r:
                payload, total, flag, ok = r
                if flag == 0 and len(payload) >= 24:
                    # class `C0 10` == KCP data (receive router @ 0x340c4)
                    (conv, cmd, frg, wnd, ts, sn, una,
                     ln) = struct.unpack("<IBBHIIII", payload[:24])
                    print("--- KCP  conv=0x%08x cmd=%d(%s) frg=%d wnd=%d "
                          "ts=%u sn=%u una=%u len=%d chval_ok=%s ---"
                          % (conv, cmd, KCP_CMD_NAMES.get(cmd, "?"), frg, wnd,
                             ts, sn, una, ln, ok), flush=True)
                    if ln and payload[24:24 + ln]:
                        print(hexdump(payload[24:24 + ln], 30), flush=True)
                else:
                    print("--- MTP: inner type=0x%02x inner_len=%d "
                          "chval_ok=%s ---"
                          % (payload[1], struct.unpack_from("<H", payload, 2)[0]
                             if len(payload) > 3 else -1, ok), flush=True)
                    print(hexdump(payload, 6), flush=True)
        # KCP segments do NOT start with 0x7e - flag them explicitly.
        elif data:
            print("--- NOT a GUTES/MTP frame: possible KCP / AV payload ---",
                  flush=True)
        fn = "/tmp/p2p_reply_%d_%03d.bin" % (int(time.time()), len(seen))
        open(fn, "wb").write(data)
        print("saved -> %s" % fn, flush=True)

    def drain(seconds):
        got = 0
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([sock], [], [],
                                    max(0.0, end - time.time()))
            if not r:
                continue
            try:
                data, addr = sock.recvfrom(65535)
            except OSError:
                continue
            got += 1
            sig = (addr[0], data)
            rep = " (dup)" if sig in seen else ""
            seen.add(sig)
            show(data, addr, rep)
        return got

    def send_step(which, quiet=False, match=None):
        sent = 0
        for ip, dev, seq in plan:
            for k, lbl, frame in seq:
                if k != which or (match is not None and lbl != match):
                    continue
                try:
                    sock.sendto(frame, (ip, dev["p2p_port"]))
                    sent += 1
                    if not quiet:
                        print("  [%6.2fs] %-32s :%d -> %s:%d (%d B)"
                              % (time.time() - t0, lbl, sock.getsockname()[1],
                                 ip, dev["p2p_port"], len(frame)), flush=True)
                except OSError as e:
                    print("  [!] send to %s: %r" % (ip, e), flush=True)
                time.sleep(0.1)
        return sent

    # Blasting the whole handshake once a second restarts the state machine on
    # every tick, so the camera never gets past the first ACK.  Send each frame
    # ONCE, in order, letting the camera answer between steps.
    #
    # The order comes from a real session in logcat (/tmp/wyze_live.txt):
    #   gutes_on_ackfrm_Lan_Calling -> iv_on_ackfrm_Calling
    #     -> giot_send_create_kcp_session_msg      <-- type 0x25
    #     -> iv_rcvpkt_AVSTREAMCTL_ACCEPT
    #     -> iv_notify_p2pconnReady -> start_av_enc_dec -> video_decode_proc
    print("\n[phase A] ordered handshake", flush=True)
    n_sent += send_step("hello")
    n_sent += drain(2.0)
    n_sent += send_step("calling")
    n_sent += drain(2.0)

    # The camera only has a session to look up once it has processed our
    # CALLING, so the forged MTP_RES has to go strictly after phase A.  If the
    # field map is right this gives the camera a type-135 channel pointing at
    # us, which is the one thing its kcb->output gate requires before it will
    # emit a single `C0 10` KCP packet.
    if MTPRES:
        print("\n[phase E] forge 7e a3 MTP_RES_RESPONSE -> type-135 channel",
              flush=True)
        n_sent += send_step("mtpres")
        n_sent += drain(3.0)
        # Phase E2 (KCP unblock): 7e a3 adds the relay + arms the
        # send_rcv_map_port watchdog, but that timer re-arms forever until
        # obj+0x4ec is set, and the ONLY writer of that byte is PortStatResp
        # (7f cb).  Without this the camera never starts KCP.
        print("[phase E2] forge 7f cb PortStatResp -> set obj+0x4ec (KCP gate)",
              flush=True)
        n_sent += send_step("portstat")
        n_sent += drain(3.0)
    if KCP:
        tags = list(dict.fromkeys(lbl for k, lbl, _ in plan[0][2]
                                  if k == "kcp"))
        for rnd in range(2):
            print("[phase C] round %d: %d type-0x25 candidates"
                  % (rnd, len(tags)), flush=True)
            for vname in tags:
                n_sent += send_step("kcp", match=vname)
                n_sent += drain(1.5)
    n_sent += send_step("xfer")
    n_sent += drain(2.0)

    # Now speak actual KCP.  Receiving a WASK makes the peer set
    # `kcp->probe |= 2` (ivkcp_input @ 0x7a24c) and answer with a WINS
    # window update on its next flush (ivkcp_flush @ 0x7ae7c), so a WASK is a
    # zero-payload round trip that needs no guessed fields beyond `conv`.
    # Both conv forms are sent because iv_on_rcv_kcpdata_pkt routes on bit31.
    if KCP:
        print("\n[phase D] KCP WASK probe (both conv forms), 12 s", flush=True)
        end = time.time() + 12
        tick = 0
        while time.time() < end:
            n_sent += send_step("kcpw", quiet=(tick > 0))
            n_sent += drain(1.0)
            tick += 1

    # The camera then floods its own hello at ~1 Hz forever.  Two readings are
    # possible: it is a keepalive we must mirror, or it is waiting on a frame
    # we have not identified.  Mirror it (plus the transfer request) and watch
    # for anything that is not one of the three known types.
    print("\n[phase B] %.0f s: mirror the camera's hello at 1 Hz" % DUR,
          flush=True)
    end = time.time() + DUR
    beat = 0
    while time.time() < end:
        n_sent += drain(1.0)
        beat += 1
        quiet = beat > 2
        n_sent += send_step("hello", quiet=quiet)
        n_sent += send_step("xfer", quiet=quiet)

    print("\n[done] sent=%d  distinct replies=%d" % (n_sent, len(seen)),
          flush=True)
    sock.close()
    return 0 if seen else 2


if __name__ == "__main__":
    sys.exit(main())
