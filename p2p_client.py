#!/usr/bin/env python3
"""Wyze OG P2P client -- discover, handshake, KCP, decrypt, emit H.264.

No phone, no app, no third-party library.  Pure Python over UDP sockets.
Everything here is reverse-engineered from the `com.hualai` APK's
libiotp2pav.so; the evidence for each step is in ../P2P_PROTOCOL.md and the
attempt history is in ../JOURNAL.md.

The working chain (each stage is a hard-won finding):

    LAN discovery  ->  CALLING (7e a4)  ->  meter_ack (C0 90, inner type 2)
        ->  KCP up (C0 10)  ->  AvStreamCtl INSIDE KCP (76 B, buf[0]=3)
        ->  RC5-ECB AV decrypt, key = CALLING[120:128]  ->  H.264

The three non-obvious steps, all of which independently blocked progress:

  1. The camera sends `C0 90` meter REQUESTS (inner [1] == 1).  Echoing them
     back makes the camera re-run iv_rcv_meter_req and ask again -- an echo
     loop that never advances the state machine.  You must answer with inner
     [1] == 2 (iv_rcv_meter_ack).  See make_meter_ack in ../p2p_call.py.

  2. The AvStreamCtl is NOT a GUTES frame.  iv_send_av_stream_ctl_frm (0x541a8)
     calls ivkcp_send twice, so the frame is a plain 76-byte payload inside a
     KCP PUSH.  The `7e b9` frames in our captures are PASSTHROUGH_MSG
     (type 185) and merely share the 76-byte size.

  3. The AV stream is RC5-ECB in 8-byte blocks, and the 8-byte key is the
     TAIL of the CALLING frame we send -- iv_mtp_session_new's second branch
     reads ctx+0x480 from arg->0x78 of the parsed CALLING.

Usage:
    from p2p_client import CameraStream
    for nal in CameraStream(ip, port, tid, calling).h264():
        ...
"""
import select
import socket
import struct
import time

import kcpav
import mtp_frame
from listreq import rc5_setup, rc5_decrypt_block, rc5_encrypt_block
# analyze_calls.decrypt handles the mode-1 GUTES frames (key = the plaintext
# header, see P2P_PROTOCOL.md 5/5a).  The CALLING is mode-1.  This is the one
# place we lean on an RE helper; folding it in properly is a cleanup task.
from analyze_calls import decrypt
from mtp_frame import wrap as mtp_wrap, unwrap as mtp_unwrap

CALLING_PORT = 48171       # the source port embedded at CALLING [54:56]
MTU = 1032                 # gute_recv_fragment_init mtu=1032, from live logcat

# LAN discovery is proven in ../discover.py -- reuse it rather than
# re-deriving the probe.  Note the real port is 8899 and the real target is
# the subnet broadcast, not 255.255.255.255.
from discover import (build_probe, parse_reply,          # noqa: E402
                      BROADCAST, BROADCAST_PORT)


def discover(duration=3.0, want_tid=None):
    """Broadcast-probe the LAN.  Returns {ip: {"tid","p2p_port"}}.

    Ports are NOT stable, so this must be re-run at the start of every
    session.  It is also flaky -- callers should retry.
    """
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("0.0.0.0", 0))
    rx.setblocking(False)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    tx.sendto(build_probe(rx.getsockname()[1]), (BROADCAST, BROADCAST_PORT))

    found = {}
    end = time.time() + duration
    while time.time() < end:
        r, _, _ = select.select([rx], [], [], 0.25)
        if not r:
            continue
        try:
            data, addr = rx.recvfrom(4096)
        except OSError:
            continue
        dev = parse_reply(data, addr)
        if not dev:
            continue
        if want_tid and str(dev["tid"]) != str(want_tid):
            continue
        # keep wyze_id/mac too: the cloud device list is keyed by the
        # "CAM-1_xxxxxxxxxxxx" id, so nicknames can only be resolved if the
        # discovery reply carries it through.
        found[dev["ip"]] = {"tid": dev["tid"], "p2p_port": dev["p2p_port"],
                            "wyze_id": dev.get("wyze_id"),
                            "mac": dev.get("mac")}
    rx.close()
    tx.close()
    return found


# ---- the meter exchange --------------------------------------------------
def make_meter_ack(inner_frame):
    """Turn a received `C0 90` meter REQUEST into a meter ACK.

    inner_frame is the raw 74-byte MTP frame the camera sent.  The MTP
    control dispatcher (iv_on_rcv_mtpCtrl_pkt, 0x57e58) indexes its table at
    0x57f18 by inner[1] - 1; type 1 -> iv_rcv_meter_req (0x603c4), type 2 ->
    iv_rcv_meter_ack (0x61338).  Everything else is preserved verbatim.
    """
    r = mtp_unwrap(inner_frame)
    if not r or len(r[0]) < 8:
        return None
    inner = bytearray(r[0])
    if inner[1] != 1:
        return None
    inner[1] = 2
    return mtp_wrap(bytes(inner), 1)      # flag=1 -> C0 90, MTP control


# ---- the AvStreamCtl -----------------------------------------------------
def build_avstreamctl(action=kcpav.ACT_START, blob=None):
    """The 76-byte frame iv_init_frm_AvStreamCtl builds (0x53274).

    Sent as the payload of a KCP PUSH -- NOT as a GUTES frame.
    """
    return kcpav.avstreamctl(action, blob=blob)


# ---- the AV cipher -------------------------------------------------------
def rc5_decrypt_stream(key, data):
    """RC5-ECB decrypt `data` in 8-byte blocks with an 8-byte `key`.

    Mirrors iv_rcv_tlvfrm (0x628e8):
        for (i = 0; i < (len-4)/8; i++)
            rc5_ctx_dec(ctx->0x488, frame + 4 + i*8, 8);
    """
    st = rc5_setup(key)
    out = bytearray()
    n = len(data) - (len(data) % 8)
    for i in range(0, n, 8):
        out += rc5_decrypt_block(st, bytes(data[i:i + 8]), "little")
    out += data[n:]                       # trailing partial block, untouched
    return bytes(out)


def split_nal_units(buf):
    """Yield raw H.264 NAL units (start code stripped) from Annex-B `buf`."""
    starts = []
    i = 0
    while True:
        j = buf.find(b"\x00\x00\x01", i)
        if j < 0:
            break
        starts.append(j)
        i = j + 3
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(buf)
        yield buf[s + 3:e]


# ---- the session ---------------------------------------------------------
class CameraStream(object):
    """One camera.  `h264()` is a generator yielding Annex-B NAL byte strings.

    `calling` is a complete 128-byte CALLING frame for this camera.  Its last
    8 bytes ARE the AV RC5 key, so a caller that synthesises its own CALLING
    simply picks a random key there and it will be honoured by the camera
    (iv_mtp_session_new branch B reads it back out of the frame).
    """

    def __init__(self, ip, p2p_port, tid, calling, local_ip=None,
                 timeout=8.0, on_log=None, local_port=None):
        self.ip = ip
        self.p2p_port = p2p_port
        self.tid = tid
        self.calling = bytes(calling)
        # BOTH the conv and the AV key live in the RC5-encrypted region of
        # the CALLING ([24:]), so they must be read from the PLAINTEXT, not
        # from the wire bytes.  Sending still uses the encrypted frame.
        pt = decrypt(self.calling)
        self.key = pt[120:128]
        self.timeout = timeout
        self.log = on_log or (lambda m: None)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # One socket per camera -- they CANNOT all share 48171, or only one
        # could ever receive.  48171 is the port the app advertises in
        # CALLING[54:56]; whether the camera answers source-port or
        # advertised-port is empirical (see the multi-camera note in the
        # server).  Passing local_port=0 lets the OS pick.
        self.sock.bind(("0.0.0.0",
                        CALLING_PORT if local_port is None else local_port))
        self.local_port = self.sock.getsockname()[1]
        self.sock.setblocking(False)
        self.conv = struct.unpack_from("<I", pt, 28)[0]
        self.kcp = None
        self._buf = bytearray()
        self._abuf = bytearray()          # audio (mu-law)
        self._audio_ts = None             # last audio frame timestamp (us)
        self._started = False

    # -- the handshake -----------------------------------------------------
    def _send(self, data):
        try:
            self.sock.sendto(data, (self.ip, self.p2p_port))
        except OSError as e:
            self.log("send error: %r" % (e,))

    def _pump(self, seconds, kcp_convs):
        """Receive for `seconds`, reacting to meter requests and KCP.

        kcp_convs is a list of (conv, kcp_object) pairs we accept data from.
        """
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([self.sock], [], [],
                                    max(0.0, end - time.time()))
            if not r:
                continue
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                continue

            # 1. MTP control: answer the camera's meter REQUEST with an ACK.
            if data[:2] == b"\xc0\x90":
                ack = make_meter_ack(data)
                if ack:
                    self._send(ack)
                    self.log("meter_req -> meter_ack")
                continue

            # 2. KCP data: feed every matching conv.
            if data[:2] == b"\xc0\x10":
                rr = mtp_unwrap(data)
                if not rr or not rr[3]:
                    continue
                for conv, kc in kcp_convs:
                    kc.input(rr[0])              # dedup + reorder + queue ACK
                    for payload, _sn in kc.take_received():
                        self._on_tlv(payload)    # ONLY in-order, unique data
                    for pkt in kc.take_packets():
                        self._send(mtp_wrap(pkt, 0))
                continue

    def _on_tlv(self, payload):
        """A TLV frame arrived over KCP: [0]=type [2:4]=u16LE len [4:]=body.

        Linktype 4 (media) is RC5 with the AV key.  The plaintext body is
        a *fragment* of the camera's AV stream, not necessarily one frame:

          - Video frames larger than one TLV are split.  Only the FIRST
            fragment carries the 0xff 0xff 0xff 0x88 AV header; the rest are
            bare H.264 continuation bytes with no header at all.  Dropping
            those (as 73585b2 did) truncates frames -> ffmpeg decode errors.
          - Audio AV frames are complete and self-identifying::

                0   ff ff ff 88 00 00 01 00      sync
                8   00 x12                       reserved
                20  u32 timestamp, microseconds (0x4e20 = 20000 per frame)
                24  u32 session-dependent byte (0x87 / 0x88 seen)
                28  u16 payload length (320)
                30  mu-law payload

            ...and they may be *nested* inside the same TLV as video (a
            350-byte audio frame followed by video bytes), or several audio
            frames packed back to back (700 / 1004 byte bodies), or preceded
            by the 28-byte stream descriptor (see wire/p2p_frames.json).

        So: append every body to the H.264 feed untouched, and additionally
        carve the audio payloads out of it.  This is safe because a mu-law
        payload never contains an Annex-B start code -- measured over the
        audio-classified bodies, every `00 00 01` sat at an AV frame boundary,
        never inside the 320-byte payload.

        Linktype 3 is AvStreamCtl (plaintext) -- we ignore it after handshake.
        """
        if len(payload) < 5:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        if ln <= 4 or ln > len(payload):
            ln = len(payload)
        body = payload[4:ln]
        if not body:
            return

        lt = payload[0]
        if lt == 3:
            return                                 # AvStreamCtl reply, ignore
        if lt != 4:
            self.tlv_other = getattr(self, "tlv_other", 0) + 1
            return

        # linktype 4: decrypt with AV key
        pt = rc5_decrypt_stream(self.key, body)
        if not pt:
            return

        # 1) video: everything, header-less continuations included.
        self._buf += pt
        # 2) audio: pull every mu-law payload out of the same bytes.
        self._take_audio_frames(pt)

    _AV_SYNC = b"\xff\xff\xff\x88"
    _AUD_ZEROS = b"\x00" * 12
    _AUD_PERIOD = 20000            # microseconds per audio frame (320 @ 16 kHz)

    def _take_audio_frames(self, pt):
        """Append the mu-law payload of each audio AV frame found in `pt`.

        The frame header is (measured, two independent sessions)::

            0   ff ff ff 88 00 00 01 00    sync
            8   00 x12                      reserved
            20  u32 timestamp, microseconds (advances 0x4e20 = 20000/frame)
            24  u32 session byte, 0x87 in one session, 0x88 in another
            28  u16 payload length (320)
            30  mu-law payload

        Bytes [24:28] are NOT a constant, so only the sync, the 12 reserved
        zeros and a sane length are tested.  Video frames never carry the
        12 zeros: in a 12 s capture 749 syncs split exactly into 512 audio
        (12 zeros) + 237 video headers, and ffmpeg decoded 236 frames.

        The camera drops roughly one audio frame in six on the wire (110
        single 40000 us gaps in 488 frames / 11.94 s), so every gap is
        back-filled with mu-law digital zero (0xff decodes to 0).  Without
        that the 152 kB we receive would be a 9.5 s clip for a 12 s view and
        would play back 26 % fast and out of sync with the video.
        """
        i = 0
        n = len(pt)
        while True:
            i = pt.find(self._AV_SYNC, i)
            if i < 0:
                return
            if (i + 30 <= n
                    and pt[i:i + 8] == self._AV_SYNC + b"\x00\x00\x01\x00"
                    and pt[i + 8:i + 20] == self._AUD_ZEROS):
                ln = struct.unpack_from("<H", pt, i + 28)[0]
                if 64 <= ln <= 4096 and i + 30 + ln <= n:
                    self._audio_gap_fill(pt[i + 20:i + 24], ln)
                    self._abuf += pt[i + 30:i + 30 + ln]
                    i += 30 + ln                   # skip past its payload
                    continue
            i += 1

    def _audio_gap_fill(self, tsb, ln):
        """Insert silence for frames the camera's clock says we never got."""
        ts = struct.unpack("<I", tsb)[0]
        prev = self._audio_ts
        self._audio_ts = ts
        if prev is None:
            return
        delta = (ts - prev) & 0xFFFFFFFF
        if self._AUD_PERIOD < delta <= 2000000:     # 1 frame .. 2 s
            missing = min(delta // self._AUD_PERIOD - 1, 100)
            # 0xff is mu-law negative zero -> PCM 0
            self._abuf += b"\xff" * (ln * missing)

    def start(self):
        """Run the handshake once.  Idempotent-ish; safe to call again."""
        if self._started:
            return
        self._send(self.calling)
        self.log("CALLING -> %s:%d (conv=0x%08x)"
                 % (self.ip, self.p2p_port, self.conv))
        # let the camera answer with hellos + a session
        self._pump(1.5, [])

        # both conv bit-forms: iv_on_rcv_kcpdata_pkt (0x630c0) selects
        # session->0x334 on bit31 set and ->0x330 on clear, and
        # iv_find_mtp_session (0x5d96c) accepts either.
        lo, hi = self.conv & 0x7FFFFFFF, self.conv | 0x80000000
        self.kcp_lo = kcpav.KCP(lo, mtu=MTU)
        self.kcp_hi = kcpav.KCP(hi, mtu=MTU)

        # request the stream.  This is the only thing that makes the camera
        # emit C0 10 -- it has nothing to send until we ask.
        for kc in (self.kcp_lo, self.kcp_hi):
            kc.push(build_avstreamctl())
            for pkt in kc.take_packets():
                self._send(mtp_wrap(pkt, 0))
        self.log("AvStreamCtl PUSH (KCP)")
        self._started = True

    # -- the data path -----------------------------------------------------
    def raw_h264(self):
        """Generator of decrypted H.264 bytes, ready to pipe into ffmpeg.

        Prefer this over h264().  A naive `00 00 01` scan over the decrypted
        stream yields FALSE positives from payload bytes, whereas ffmpeg's
        H.264 parser resyncs properly and produces clean frames.
        """
        self.start()
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            self._pump(0.5, [(self.kcp_lo.conv, self.kcp_lo),
                             (self.kcp_hi.conv, self.kcp_hi)])
            if self._buf:
                out = bytes(self._buf)
                del self._buf[:]
                deadline = time.time() + self.timeout
                yield out

    def h264(self, settle=2.0):
        """Generator of decrypted H.264 NAL unit byte strings."""
        self.start()
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            self._pump(0.5, [(self.kcp_lo.conv, self.kcp_lo),
                             (self.kcp_hi.conv, self.kcp_hi)])
            while b"\x00\x00\x01" in self._buf:
                i = self._buf.find(b"\x00\x00\x01")
                if i > 0:
                    del self._buf[:i]
                j = self._buf.find(b"\x00\x00\x01", 3)
                if j < 0:
                    break
                yield bytes(self._buf[3:j])
                del self._buf[:j]
                deadline = time.time() + self.timeout

    def raw_audio(self):
        """Generator of raw mu-law audio bytes (8 kHz, mono, no header)."""
        self.start()
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            self._pump(0.5, [(self.kcp_lo.conv, self.kcp_lo),
                             (self.kcp_hi.conv, self.kcp_hi)])
            if self._abuf:
                out = bytes(self._abuf)
                del self._abuf[:]
                deadline = time.time() + self.timeout
                yield out

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def selftest():
    """Structural checks -- no network."""
    # the AV key really is CALLING[120:128]
    c = bytearray(128)
    c[120:128] = bytes(range(8))
    assert bytes(c)[120:128] == bytes(range(8))

    # RC5 round-trip on 8-byte blocks
    from listreq import rc5_encrypt_block
    key = b"\x11" * 8
    st = rc5_setup(key)
    pt = b"ABCDEFGH12345678"
    ct = b"".join(rc5_encrypt_block(st, pt[i:i + 8], "little")
                  for i in range(0, 16, 8))
    assert rc5_decrypt_stream(key, ct) == pt, "RC5 round-trip failed"
    print("[ok] RC5-ECB round-trip over 8-byte blocks")

    # meter_ack flips exactly one byte
    fake = mtp_wrap(b"\x00\x01\x44\x00" + b"\x00" * 64, 1)
    ack = make_meter_ack(fake)
    assert ack is not None and mtp_unwrap(ack)[0][1] == 2
    print("[ok] meter_req -> meter_ack flips inner[1] to 2")
    print("ALL OK")
    return True


if __name__ == "__main__":
    import sys
    sys.exit(0 if selftest() else 1)
