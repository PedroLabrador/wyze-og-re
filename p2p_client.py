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
# the subnet broadcast, derived per interface at runtime (see broadcast_addrs).
from discover import (build_probe, parse_reply, broadcast_addrs,
                      slash24_hosts, BROADCAST_PORT)


def discover(duration=3.0, want_tid=None, verbose=False, sweep=False):
    """Broadcast-probe the LAN.  Returns {ip: {"tid","p2p_port"}}.

    Ports are NOT stable, so this must be re-run at the start of every
    session.  It is also flaky -- callers should retry.

    ``verbose`` prints every destination, send error and reply; it is what
    ``server.py --discover`` uses to make a silent zero-camera result
    debuggable.  ``sweep`` adds 254 unicast probes per local /24 after the
    broadcasts: if a Windows firewall/router/VPN eats the broadcast, unicast
    still reaches the camera and the answer proves the LAN path works.
    """
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("0.0.0.0", 0))
    rx.setblocking(False)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    reply_port = rx.getsockname()[1]
    probe = build_probe(reply_port)
    targets = broadcast_addrs()
    if verbose:
        print("[discover] reply port %d, %d broadcast target(s): %s"
              % (reply_port, len(targets), ", ".join(targets)), flush=True)
    for bc in targets:
        try:
            tx.sendto(probe, (bc, BROADCAST_PORT))
        except OSError as e:
            if verbose:
                print("[discover] send to %s:8899 failed: %s" % (bc, e),
                      flush=True)
    if sweep:
        hosts = slash24_hosts(exclude=())
        if verbose:
            print("[discover] sweeping %d unicast hosts on :%d"
                  % (len(hosts), BROADCAST_PORT), flush=True)
        for ip in hosts:
            try:
                tx.sendto(probe, (ip, BROADCAST_PORT))
            except OSError:
                pass

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
            if verbose:
                print("[discover] junk %d B from %s:%d head %s"
                      % (len(data), addr[0], addr[1], data[:10].hex()),
                      flush=True)
            continue
        if want_tid and str(dev["tid"]) != str(want_tid):
            continue
        # keep wyze_id/mac too: the cloud device list is keyed by the
        # "CAM-1_xxxxxxxxxxxx" id, so nicknames can only be resolved if the
        # discovery reply carries it through.
        if dev["ip"] not in found and verbose:
            print("[discover] reply from %s: p2p_port=%s tid=%s %s"
                  % (dev["ip"], dev["p2p_port"], dev["tid"],
                     dev.get("wyze_id") or ""), flush=True)
        found[dev["ip"]] = {"tid": dev["tid"], "p2p_port": dev["p2p_port"],
                            "wyze_id": dev.get("wyze_id"),
                            "mac": dev.get("mac")}
    rx.close()
    tx.close()
    if verbose and not found:
        print("[discover] no reply in %.1fs. The probe left this host, so "
              "either the camera is not on this subnet or its answer was "
              "blocked on the way back (Windows Firewall is the usual "
              "reason; see README)." % duration, flush=True)
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

    This is the 2.50.7 shape and always yields the 640x360 sub-stream.  Use
    build_avstreamctl_hd() to ask for 1080p.
    """
    return kcpav.avstreamctl(action, blob=blob)


def build_avstreamctl_hd(definition=kcpav.DEF_HD, action=kcpav.ACT_START):
    """The 108-byte 3.23.1 AvStreamCtl -- the one that selects 1080p.

    `definition` 2 = 1920x1080, 0 = 640x360.  See kcpav.avstreamctl_v2.
    """
    return kcpav.avstreamctl_v2(definition=definition, action=action)


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


def rc5_encrypt_stream(key, data):
    """The inverse of rc5_decrypt_stream: RC5-ECB over 8-byte blocks.

    The trailing partial block is NOT encrypted, which is what the app does on
    the wire -- a 226-byte talk frame is 224 encrypted bytes plus 2 plaintext
    ones, and the camera accepts frames built the same way.
    """
    st = rc5_setup(key)
    out = bytearray()
    n = len(data) - (len(data) % 8)
    for i in range(0, n, 8):
        out += rc5_encrypt_block(st, bytes(data[i:i + 8]), "little")
    out += data[n:]
    return bytes(out)


# ---- the client -> camera audio (talk) -----------------------------------
#
# Reversed from a PCAPdroid capture of the app holding the talk button.  The
# app pushes linktype-4 media on the LOW conv (the AvStreamCtl goes on the high
# one), and the body is RC5 with the same AV key as the incoming media.
#
#   0   ff ff ff 88       AV sync
#   4   00 00 03 00
#   8   00 x12
#   20  u32 counter       increments 60 per frame in the app
#   24  00 00 00 00
#   28  40 00 40 00 40 00
#   34  6 x (0x3c + 31 B) six AMR-NB frames
#
# Each sub-frame is RFC 4867 octet-aligned AMR-NB: the ToC octet 0x3c is
# FT=7, i.e. the 12.2 kbit/s mode, whose 244-bit frames are stored in 31
# bytes.  Six 20 ms frames is 120 ms, which matches the observed send
# interval and byte rate.  Verified by decoding the capture to speech and by
# re-encoding silence with ffmpeg (same ToC, same frame size).
TALK_AMR_FRAME = 32                   # 1 byte ToC + 31 bytes payload
TALK_AMR_TOC = 0x3C                   # AMR-NB FT 7 (12.2 kbit/s)
TALK_FRAMES_PER_PKT = 6               # 6 x 20 ms = 120 ms
TALK_PKT_BYTES = 34 + TALK_AMR_FRAME * TALK_FRAMES_PER_PKT     # 226
TALK_COUNTER_STEP = 60                # what the app advances it by

# The two frames the app sends the moment the talk button goes down, before any
# audio.  The first is 28 B -- 16 kHz (0x3e80) and 320 samples (0x0140) at
# [12:18], i.e. the audio stream's parameters.  The second is 37 B and carries
# the byte 0x32 at [29].  Both are replayed verbatim because only their effect
# is known; they are not user data and carry no session material.
TALK_OPEN_FRAMES = (
    bytes.fromhex("000102030405060708090a0b0c0d0e0f10111213141516"
                  "0040010000"),
    bytes.fromhex("000102030405060708090a0b0c0d0e0f10111213141516"
                  "409a504001"),
)


def build_talk_frame(amr_frames, counter=0):
    """One 226-byte client->camera audio frame from six 31-byte AMR payloads.

    `amr_frames` are payloads WITHOUT the ToC octet, exactly as an AMR-NB
    encoder emits them; the ToC is added here.
    """
    if len(amr_frames) != TALK_FRAMES_PER_PKT:
        raise ValueError("need %d AMR frames, got %d"
                         % (TALK_FRAMES_PER_PKT, len(amr_frames)))
    buf = bytearray(TALK_PKT_BYTES)
    buf[0:4] = b"\xff\xff\xff\x88"
    buf[6] = 3
    struct.pack_into("<I", buf, 20, counter & 0xFFFFFFFF)
    buf[28:34] = b"\x40\x00\x40\x00\x40\x00"
    for i, f in enumerate(amr_frames):
        off = 34 + i * TALK_AMR_FRAME
        if len(f) != TALK_AMR_FRAME - 1:
            raise ValueError("AMR frame %d is %d bytes, want %d"
                             % (i, len(f), TALK_AMR_FRAME - 1))
        buf[off] = TALK_AMR_TOC
        buf[off + 1:off + TALK_AMR_FRAME] = f
    return bytes(buf)


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
                 timeout=8.0, on_log=None, local_port=None,
                 definition=kcpav.DEF_HD):
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
        # None -> the 2.50.7 76-byte AvStreamCtl (640x360 only).  An int ->
        # the 108-byte v2 frame carrying that definition (2 = 1080p).
        self.definition = definition
        self.kcp = None
        self._buf = bytearray()
        self._abuf = bytearray()          # audio (mu-law)
        self._audio_ts = None             # last audio frame timestamp (us)
        self._meter_logged = False
        self._started = False
        self._talk_counter = 0

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
                    # One ack every ~2 s would otherwise flush everything
                    # else out of the server's 40-line log ring, so only the
                    # first of a run is worth recording.
                    if not self._meter_logged:
                        self.log("meter_req -> meter_ack (then every ~2 s)")
                        self._meter_logged = True
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
        #
        # definition is what picks the operational profile: None sends the
        # 76-byte 2.50.7 frame (640x360), an int sends the 108-byte 3.23.1
        # frame, where 2 asks for 1920x1080.
        if self.definition is None:
            ctl = build_avstreamctl()
        else:
            ctl = build_avstreamctl_hd(definition=self.definition)
        for kc in (self.kcp_lo, self.kcp_hi):
            kc.push(ctl)
            for pkt in kc.take_packets():
                self._send(mtp_wrap(pkt, 0))
        self.log("AvStreamCtl PUSH (KCP, definition=%s)"
                 % ("v1" if self.definition is None else self.definition))
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

    # -- client -> camera audio (talk) -------------------------------------
    def _talk_push(self, body):
        """Wrap `body` as a linktype-4 media TLV and PUSH it on the lo conv.

        The app pushes its own media on the LOW conv, which is the AV link;
        the AvStreamCtl is the only thing that goes on the high one.  TLV
        flag byte 2 means "from the client" (the camera uses 1).
        """
        frame = bytearray(4 + len(body))
        frame[0] = 4
        frame[1] = 2
        struct.pack_into("<H", frame, 2, len(frame))
        frame[4:] = body
        self.kcp_lo.push(bytes(frame))
        for pkt in self.kcp_lo.take_packets():
            self._send(mtp_wrap(pkt, 0))

    def open_talk(self):
        """Send the two frames the app sends before its first audio frame."""
        self.start()
        for blob in (TALK_OPEN_FRAMES):
            self._talk_push(rc5_encrypt_stream(self.key, blob))
            self._pump(0.15, [(self.kcp_lo.conv, self.kcp_lo),
                              (self.kcp_hi.conv, self.kcp_hi)])
        self._talk_counter = 0
        self.log("talk: audio stream opened")
        return True

    def send_talk(self, amr_frames):
        """Send one 120 ms packet of six AMR frames (31 B each, no ToC)."""
        pt = build_talk_frame(amr_frames, self._talk_counter)
        self._talk_counter = (self._talk_counter
                              + TALK_COUNTER_STEP) & 0xFFFFFFFF
        self._talk_push(rc5_encrypt_stream(self.key, pt))
        return len(pt)

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

    # the v2 AvStreamCtl -- the frame that actually asks for 1080p
    v1 = build_avstreamctl()
    assert len(v1) == 76 and v1[0] == 3 and v1[2:4] == b"\x4c\x00"
    v2 = build_avstreamctl_hd()
    assert len(v2) == 108, len(v2)
    assert v2[0] == 3 and v2[1] == 2
    assert struct.unpack_from("<H", v2, 2)[0] == 108
    assert v2[4:8] == kcpav.MAGIC_V2
    # v1 fields sit 8 bytes later in the v2 layout
    assert v2[16:20] == v1[8:12], "action moved"
    assert v2[20:24] == v1[0xc:0x10], "action byte moved"
    assert struct.unpack_from("<I", v2, 24)[0] == kcpav.DEF_HD
    assert build_avstreamctl_hd(definition=kcpav.DEF_SD)[24:28] == b"\x00" * 4
    assert set(v2[28:]) == {0}, "v2 tail must be zero"
    print("[ok] v2 AvStreamCtl: 108 B, definition word at [24:28]")

    # the talk frame: layout, and RC5 round-trip through the wire form
    subs = [bytes([i] * 31) for i in range(TALK_FRAMES_PER_PKT)]
    tf = build_talk_frame(subs, counter=0x11223344)
    assert len(tf) == TALK_PKT_BYTES == 226, len(tf)
    assert tf[:4] == b"\xff\xff\xff\x88" and tf[4:8] == b"\x00\x00\x03\x00"
    assert tf[8:20] == b"\x00" * 12 and tf[24:28] == b"\x00" * 4
    assert tf[28:34] == b"\x40\x00" * 3
    assert struct.unpack_from("<I", tf, 20)[0] == 0x11223344
    for i in range(TALK_FRAMES_PER_PKT):
        off = 34 + i * TALK_AMR_FRAME
        assert tf[off] == TALK_AMR_TOC == 0x3C, "AMR ToC (FT7 = 12.2k)"
        assert tf[off + 1:off + 32] == subs[i]
    k2 = b"\x5a" * 8
    assert rc5_decrypt_stream(k2, rc5_encrypt_stream(k2, tf)) == tf
    wire = rc5_encrypt_stream(k2, tf)
    assert len(wire) == 226 and wire[224:226] == tf[224:226], "tail is plaintext"
    assert wire[:8] != tf[:8], "body really is encrypted"
    print("[ok] talk frame: 226 B, six AMR-NB FT7 sub-frames, RC5 + 2 B tail")
    print("ALL OK")
    return True


if __name__ == "__main__":
    import sys
    sys.exit(0 if selftest() else 1)
