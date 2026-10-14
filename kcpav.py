#!/usr/bin/env python3
"""KCP transport + the real AvStreamCtl frame -- the thing that starts video.

Why this module exists
----------------------
P2P_PROTOCOL.md 5i: the client does NOT send the AvStreamCtl as a raw GUTES
`7e b9` frame.  `iv_send_av_stream_ctl_frm` (0x541a8) calls `ivkcp_send`
TWICE and never `iv_mtp_chnnel_send_mtp_frm`:

    0x541e4 bl -> 0x13a40  iv_init_frm_AvStreamCtl
    0x54264 bl -> 0x13a4c  ivkcp_send
    0x54288 bl -> 0x13a4c  ivkcp_send

So the AvStreamCtl is a plain 76-byte payload INSIDE KCP -- no GUTES header,
no RC5, no checksum.  It rides as `C0 10` + 6-byte MTP header + ikcp segment.

Receive side (`iv_on_rcv_kcpdata_pkt`, 0x630c0) takes the segment at
MTP-header+6 and feeds `ivkcp_input`, so our segment must be a genuine
ikcp segment.

Wire layout (standard ikcp, 24-byte header):

    [0:4]   conv        (u32 LE)
    [4]     cmd         81=PUSH 82=ACK 83=WASK 84=WINS
    [5]     frg
    [6:8]   wnd         (u16 LE)
    [8:12]  ts          (u32 LE, ms tick)
    [12:16] sn          (u32 LE)
    [16:20] una         (u32 LE)
    [20:24] len         (u32 LE, payload bytes that follow)

Verified against our own captured WASK: `cb02e2f7 53 00 8000 0*20` is
conv=0xf7e202cb cmd=83(=0x53, WASK) frg=0 wnd=128 ts=sn=una=len=0.

The AvStreamCtl payload, exactly as `iv_init_frm_AvStreamCtl` (0x53274)
plus its wrapper (`buf[0xc] = arg2` at 0x541f4) write it:

    memset(buf, 0, 0x4c)                  # 76 bytes
    [0]     = 3                           # <-- NOT 0x7e. KCP-ctrl msg type.
    [1]    |= 2                           # only when action == 1
    [2:4]   = 0x4c                        # length field, 76
    [4:8]   = obj->0x164
    [8:12]  = action
    [0xc]   = action                      # set by the wrapper, not init
    [0x10:0x14] = obj->0xac               # action == 1
    [0x14:0x18] = obj->0xb0               # action == 1
    [0x14:0x18] = obj->0x1e4              # action == 2 (overrides)
    [24:56] = 32 B from obj->0x1ec        # action == 1
    [24:56] = 32 B from obj->0x20c        # action == 2
    [62:64] = (u16) obj->0x160            # action == 1

A GUTES frame would have [0]=0x7e/0x7f, checksum at [16:20] and flags at
[20:24].  Here [0x10]/[0x14] are DATA and [0]=3 -- proof this is not GUTES.

The obj->0x164 / 0xac / 0xb0 / 0x160 / 0x1ec fields are AV-channel state we
cannot read from a capture (we never captured a KCP packet).  They are
therefore parameterised here; `FIELDS` holds the variants we try.
"""
import struct
import time

# ---- ikcp commands -------------------------------------------------------
CMD_PUSH = 81
CMD_ACK = 82
CMD_WASK = 83
CMD_WINS = 84

CMDNAME = {81: "PUSH", 82: "ACK", 83: "WASK", 84: "WINS"}

# ---- actions (the `arg2` of iv_send_av_stream_ctl_frm) -------------------
ACT_START = 1          # sets bit1 of [1], fills [0x10]/[0x14]/[24:56]/[62:64]
ACT_ALT = 2            # fills [0x14] from obj->0x1e4, [24:56] from obj->0x20c
ACT_STOP = 6           # wrapper routes this to kcp_b (the lo-conv object)

MTU = 1032             # gute_recv_fragment_init mtu=1032, from the live log


def _tick_ms():
    """A millisecond tick.  ikcp wants a monotonic ms clock, not wall time."""
    return int(time.monotonic() * 1000) & 0xFFFFFFFF


def seg(conv, cmd, data=b"", wnd=128, ts=None, sn=0, una=0, frg=0):
    """Build one ikcp segment (24-byte header + data)."""
    if ts is None:
        ts = _tick_ms()
    hdr = struct.pack("<IBBHIIII", conv & 0xFFFFFFFF, cmd & 0xFF,
                      frg & 0xFF, wnd & 0xFFFF, ts & 0xFFFFFFFF,
                      sn & 0xFFFFFFFF, una & 0xFFFFFFFF, len(data))
    return hdr + bytes(data)


def parse_seg(buf):
    """Parse a single ikcp segment -> dict, or None if too short/malformed."""
    if len(buf) < 24:
        return None
    conv, cmd, frg, wnd, ts, sn, una, ln = struct.unpack_from("<IBBHIIII", buf)
    if 24 + ln > len(buf):
        return None
    return {"conv": conv, "cmd": cmd, "frg": frg, "wnd": wnd, "ts": ts,
            "sn": sn, "una": una, "len": ln, "data": bytes(buf[24:24 + ln]),
            "raw": bytes(buf[:24 + ln])}


def parse_all(buf):
    """Walk a buffer that may hold several back-to-back ikcp segments."""
    out, off = [], 0
    while off + 24 <= len(buf):
        s = parse_seg(buf[off:])
        if s is None:
            break
        out.append(s)
        off += 24 + s["len"]
    return out


# ---- the AvStreamCtl payload --------------------------------------------
FIELDS = {
    # (id164, ac, b0, w160) -- filled per camera by the caller where known.
    "zero": {"id164": 0, "ac": 0, "b0": 0, "w160": 0, "blob": b"\x00" * 32},
}


def avstreamctl(action=ACT_START, id164=0, ac=0, b0=0, w160=0,
                blob=None, alt=0):
    """The 76-byte frame `iv_init_frm_AvStreamCtl` builds (0x53274).

    Returns bytes of length 76.  See the module docstring for the exact
    field-by-field provenance.
    """
    buf = bytearray(0x4c)
    buf[0] = 3
    buf[2:4] = struct.pack("<H", 0x4c)
    buf[4:8] = struct.pack("<I", id164 & 0xFFFFFFFF)
    buf[8:12] = struct.pack("<I", action & 0xFFFFFFFF)
    buf[0xC] = action & 0xFF                     # wrapper: str r2,[r3,#0xc]

    if action == ACT_START:
        buf[1] |= 2
        buf[0x10:0x14] = struct.pack("<I", ac & 0xFFFFFFFF)
        buf[0x14:0x18] = struct.pack("<I", b0 & 0xFFFFFFFF)
        buf[62:64] = struct.pack("<H", w160 & 0xFFFF)
        buf[24:56] = (blob or b"\x00" * 32)[:32].ljust(32, b"\x00")
    elif action == ACT_ALT:
        buf[0x14:0x18] = struct.pack("<I", alt & 0xFFFFFFFF)
        buf[24:56] = (blob or b"\x00" * 32)[:32].ljust(32, b"\x00")
    return bytes(buf)


class KCP(object):
    """Minimal ikcp: enough to PUSH one message and read what comes back.

    Deliberately NOT a full retransmission engine.  The LAN path has ~0 loss
    (the live log showed `lost_ratio=0.000000`), so a single well-formed PUSH
    plus ACK handling is what we need to prove the transport and harvest the
    AVSTREAMCTL_ACCEPT.
    """

    def __init__(self, conv, wnd=128, mtu=MTU):
        self.conv = conv & 0xFFFFFFFF
        self.wnd = wnd
        self.mtu = mtu
        self.snd_nxt = 0        # next sn to send
        self.rcv_nxt = 0        # next sn expected
        self.snd_una = 0        # oldest un-acked
        self.dead_link = 20
        self.packets = []       # raw ikcp segments to transmit
        self.received = []      # reassembled PUSH payloads (data, sn)

    # -- sending -----------------------------------------------------------
    def push(self, data):
        """Queue `data`, fragmenting to MTU.  Returns the segments built."""
        data = bytes(data)
        if not data:
            return []
        segs = []
        # fragment exactly as ikcp does: count full chunks, +1 if a remainder
        n = (len(data) + self.mtu - 1) // self.mtu
        off = 0
        for i in range(n):
            chunk = data[off:off + self.mtu]
            off += len(chunk)
            # frg counts DOWN from (n-1) to 0 on the last fragment
            frg = (n - 1) - i
            s = seg(self.conv, CMD_PUSH, chunk, wnd=self.wnd,
                    sn=self.snd_nxt, una=self.snd_una, frg=frg)
            self.packets.append(s)
            segs.append(s)
            self.snd_nxt = (self.snd_nxt + 1) & 0xFFFFFFFF
        return segs

    def wask(self):
        """A window probe -- asks the peer to report its window."""
        s = seg(self.conv, CMD_WASK, b"", wnd=self.wnd,
                sn=self.snd_nxt, una=self.snd_una)
        self.packets.append(s)
        self.snd_nxt = (self.snd_nxt + 1) & 0xFFFFFFFF
        return s

    def take_packets(self):
        out, self.packets = self.packets, []
        return out

    # -- receiving ---------------------------------------------------------
    def input(self, buf):
        """Feed raw ikcp bytes from the wire.  Returns parsed segments."""
        got = []
        for s in parse_all(buf):
            got.append(s)
            cmd = s["cmd"]
            if cmd == CMD_PUSH:
                # ack it (the camera expects an ACK for its sn)
                self.packets.append(
                    seg(self.conv, CMD_ACK, b"", wnd=self.wnd,
                        sn=0, una=s["sn"]))
                self.received.append((s["data"], s["sn"]))
                self._advance(s["sn"])
            elif cmd == CMD_ACK:
                self.snd_una = max(self.snd_una, s["una"])
            # WASK/WINS need no action for our purposes
        return got

    def _advance(self, sn):
        if self.rcv_nxt == 0 and sn == 0:
            self.rcv_nxt = 1
            return
        if sn == self.rcv_nxt:
            self.rcv_nxt = (self.rcv_nxt + 1) & 0xFFFFFFFF

    def take_received(self):
        out, self.received = self.received, []
        return out


def describe(segdict):
    """One-line label for a parsed segment, for the run log."""
    c = CMDNAME.get(segdict["cmd"], str(segdict["cmd"]))
    return ("conv=0x%08x cmd=%-4s wnd=%d ts=%d sn=%d una=%d len=%d"
            % (segdict["conv"], c, segdict["wnd"], segdict["ts"],
               segdict["sn"], segdict["una"], segdict["len"]))


def selftest():
    """Structural checks -- no network."""
    ok = True

    # 1. our historical WASK parses back exactly as documented
    w = bytes.fromhex("cb02e2f7" "53" "00" "8000" + "00" * 16)
    s = parse_seg(w)
    assert s and s["conv"] == 0xF7E202CB, s
    assert s["cmd"] == CMD_WASK and s["wnd"] == 128 and s["len"] == 0
    print("[ok] historical WASK parses: conv=0x%08x cmd=%d wnd=%d"
          % (s["conv"], s["cmd"], s["wnd"]))

    # 2. round-trip a PUSH with payload
    k = KCP(0xF7E202CB)
    frame = avstreamctl(ACT_START)
    assert len(frame) == 0x4C, len(frame)
    segs = k.push(frame)
    assert len(segs) == 1, "76 bytes must fit one MTU segment"
    p = parse_seg(segs[0])
    assert p["cmd"] == CMD_PUSH and p["len"] == 0x4C, p
    assert p["data"] == frame
    print("[ok] AvStreamCtl PUSH: %d B payload, %d B segment, frg=%d"
          % (p["len"], len(segs[0]), p["frg"]))

    # 3. the frame shape matches iv_init_frm_AvStreamCtl
    assert frame[0] == 3 and frame[2:4] == b"\x4c\x00"
    assert frame[1] & 2, "action==1 must set bit1 of [1]"
    assert frame[8:12] == struct.pack("<I", ACT_START)
    assert frame[0xC] == ACT_START
    print("[ok] frame[0]=%d frame[1]=0x%02x frame[2:4]=%s action@8=%s"
          % (frame[0], frame[1], frame[2:4].hex(), frame[8:12].hex()))

    # 4. MTP wrap routes to the KCP handler
    from mtp_frame import wrap, unwrap
    wire = wrap(segs[0], 0)
    assert wire[0] == 0xC0 and wire[1] == 0x10, wire[:2].hex()
    pl, tot, flag, chk = unwrap(wire)
    assert chk and pl == segs[0], "chval must verify"
    assert (wire[1] >> 7) & 1 == 0 and (wire[1] >> 4) & 1 == 1
    print("[ok] MTP wrap -> %s (bit7=0 bit4=1 -> iv_on_rcv_kcpdata_pkt), "
          "chval ok, total=%d" % (wire[:6].hex(), tot))

    # 5. ACK handling advances una
    k2 = KCP(0x1234)
    k2.push(b"\x01" * 10)
    ack = seg(0x1234, CMD_ACK, b"", una=3)
    k2.input(ack)
    assert k2.snd_una == 3, k2.snd_una
    print("[ok] ACK advances snd_una -> %d" % k2.snd_una)

    # 6. fragmenting a >MTU message yields >1 segment with descending frg
    k3 = KCP(0x1, mtu=1032)
    segs3 = k3.push(b"\xAA" * 2500)
    assert len(segs3) == 3, len(segs3)
    frgs = [parse_seg(x)["frg"] for x in segs3]
    assert frgs == [2, 1, 0], frgs
    print("[ok] 2500 B fragments into %d segs, frg=%s (mtu=%d)"
          % (len(segs3), frgs, k3.mtu))

    print("\nALL OK")
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if selftest() else 1)
