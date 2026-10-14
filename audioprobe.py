#!/usr/bin/env python3
"""Does the camera send us ANYTHING that is not video?

WHY THIS EXISTS
---------------
Audio is per-session and our session never sees it.  _on_tlv() only decrypts
linktype 4 and throws every other linktype away into a counter, so an audio
stream arriving on, say, linktype 5 would be invisible.  Before hunting for an
"enable audio" frame we must know whether the camera emits anything else at all.

This probe opens a normal session, requests the stream exactly as the product
does, then for `secs` seconds records:

  * a histogram of the raw TLV linktype byte (payload[0])  -- the "am I
    throwing something away" check;
  * for every linktype-4 body: the decrypted `ff ff ff 88 00 <type>` byte,
    the body length, and whether the plaintext carries an Annex-B H.264 start
    code;
  * the first 32 plaintext bytes of the first few bodies of each linktype.

Nothing is sent that we do not already send in production, so a clean result is
meaningful: if the only linktypes are 3 and 4 and every linktype-4 body is an
H.264 video frame, then the camera genuinely transmits no audio and the
enabling signal has to be something WE send.

Usage: python3 -u audioprobe.py [tid] [secs]
"""
import select
import struct
import sys
import time
from collections import Counter

sys.path.insert(0, "~/Downloads/wyze-re")
import kcpav                                         # noqa: E402
import p2p_client                                    # noqa: E402
import mtp_frame                                     # noqa: E402
from mtp_frame import wrap as mtp_wrap               # noqa: E402
from defsend import Probe, load_calling, any_calling   # noqa: E402


class AudioProbe(Probe):
    """Adds a full record of every TLV, decrypted, with no filtering."""

    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.linktype_hist = Counter()        # raw payload[0] -> count
        self.l4_hist = Counter()             # decrypted type byte -> count
        self.l4_sc = Counter()               # (type byte, has Annex-B start code)
        self.samples = {}                    # linktype -> [hex, ...]
        self.total_bytes = 0
        self.odd = []                        # (len, hex) of non-AV linktype-4
        self.odd_sizes = Counter()
        self.odd_hasav = 0               # contains ff ff ff 88 somewhere
        self.odd_hassc = 0               # contains an Annex-B start code
        self.oddraw = []                 # (len, raw hex, top-3 byte values)
        self.mulaw_score = []            # (len, fraction of bytes >= 0x60)
        self.audio_diff = []             # (len, mean |consecutive byte diff|)
        self.audio_blobs = []            # the non-AV plaintext bodies, in order
        self.audio_raw = []              # corresponding ciphertext
        self.conv_hist = Counter()           # (linktype, conv bit31) -> count
        self.seg_hist = Counter()            # (payload len bucket, frg, kcp len)

    def _pump(self, seconds, kcp_convs):
        """Same as CameraStream._pump, but records the conv each TLV came from."""
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
            if data[:2] == b"\xc0\x90":
                ack = p2p_client.make_meter_ack(data)
                if ack:
                    self._send(ack)
                continue
            if data[:2] == b"\xc0\x10":
                rr = mtp_frame.unwrap(data)
                if not rr or not rr[3]:
                    continue
                seg = kcpav.parse_seg(rr[0]) if len(rr) > 0 else None
                self._cur_seg = seg
                for conv, kc in kcp_convs:
                    kc.input(rr[0])
                    for payload, _sn in kc.take_received():
                        self._cur_conv = conv
                        self._on_tlv(payload)
                    for pkt in kc.take_packets():
                        self._send(mtp_frame.wrap(pkt, 0))
                continue

    def _on_tlv(self, payload):
        if not payload:
            return
        lt = payload[0]
        self.linktype_hist[lt] += 1
        self.conv_hist[(lt, self._cur_conv)] += 1

        if lt == 4:
            ln = struct.unpack_from("<H", payload, 2)[0]
            body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
            self.total_bytes += len(body)
            sg = self._cur_seg or {}
            self.seg_hist[(len(body) // 256, sg.get("frg"), sg.get("len"))] += 1
            if len(body) < 8:
                return
            pt = p2p_client.rc5_decrypt_stream(self.key, body)
            if pt[:4] == b"\xff\xff\xff\x88":
                self.l4_hist[pt[4]] += 1
                # Annex-B start code anywhere in the plaintext body.
                has_sc = b"\x00\x00\x01" in pt or b"\x00\x00\x00\x01" in pt
                self.l4_sc[(pt[4], has_sc)] += 1
            else:
                self.l4_hist[-1] += 1       # not an AV frame at all
                self.odd.append((len(body), pt[:48].hex()))
                self.odd_sizes[len(body)] += 1
                # does an AV magic or Annex-B start code appear ANYWHERE?
                if b"\xff\xff\xff\x88" in pt:
                    self.odd_hasav += 1
                elif b"\x00\x00\x01" in pt or b"\x00\x00\x00\x01" in pt:
                    self.odd_hassc += 1
                # keep the RAW (still-encrypted) form too
                self.oddraw.append((len(body), body[:48].hex(),
                                    Counter(body).most_common(3)))
                # mu-law audio lives almost entirely in [0x60, 0xff]
                hi = sum(1 for b in pt if b >= 0x60)
                self.mulaw_score.append((len(body), hi / max(1, len(pt))))
                # audio is low-pass: consecutive bytes differ by little
                if len(pt) > 8:
                    d = sum(abs(pt[i] - pt[i - 1])
                            for i in range(1, min(len(pt), 400)))
                    self.audio_diff.append((len(body), d / 399.0))
                self.audio_blobs.append(pt)
                self.audio_raw.append(body)
            self.samples.setdefault(4, []).append(pt[:32].hex())
        else:
            self.samples.setdefault(lt, []).append(payload[:32].hex())
        # NOTE: deliberately do NOT call CameraStream._on_tlv, so nothing is
        # appended to the H.264 buffer -- this probe only measures.


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728659223864"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("tid %s  camera %s:%s" % (tid, ip, port), flush=True)

    st = AudioProbe(ip, port, tid, any_calling(tid), local_port=0,
                    timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi

    def pump(n):
        for _ in range(int(n / 0.5)):
            st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])

    pump(secs)

    print("\n=== raw TLV linktype histogram (what _on_tlv would drop) ===",
          flush=True)
    for lt, n in sorted(st.linktype_hist.items()):
        note = {3: "AvStreamCtl (plaintext)", 4: "media (RC5)"}.get(
            lt, "  <== NOT HANDLED BY p2p_client")
        print("  linktype %-3d %8d  %s" % (lt, n, note), flush=True)

    print("\n=== linktype-4 decrypted bodies ===", flush=True)
    print("  total decrypted media bytes: %d" % st.total_bytes, flush=True)
    print("  AV type byte 4 (pt[4]) histogram:", flush=True)
    for t, n in sorted(st.l4_hist.items()):
        print("    pt[4]=%-4d %8d" % (t, n), flush=True)
    print("  (type byte, has H.264 start code) histogram:", flush=True)
    for k, n in sorted(st.l4_sc.items()):
        print("    (%s, %s) %8d" % (k[0], k[1], n), flush=True)

    print("\n=== (linktype, conv) -- which KCP channel carries what ===", flush=True)
    for k, n in sorted(st.conv_hist.items()):
        side = "HI (AvStreamCtl)" if k[1] & 0x80000000 else "LO (video)"
        print("  linktype %d  %-18s %8d" % (k[0], side, n), flush=True)

    print("\n=== (payload len / 256, KCP frg, KCP len) ===", flush=True)
    for k, n in sorted(st.seg_hist.items(), key=lambda x: -x[1])[:14]:
        print("    pl=%-4dB frg=%-3s kcplen=%-5s %8d" % (k[0] * 256, k[1], k[2], n),
              flush=True)

    print("\n=== linktype-4 bodies with NO ff ff ff 88 header (dropped by the product path) ===",
          flush=True)
    print("  size histogram:", flush=True)
    for sz, n in sorted(st.odd_sizes.items()):
        print("    %-6d %8d" % (sz, n), flush=True)
    for n, hx in st.odd[:8]:
        print("    len=%-5d %s" % (n, hx), flush=True)

    print("  odd blocks containing ff ff ff 88 anywhere: %d" % st.odd_hasav, flush=True)
    print("  odd blocks containing an Annex-B start code: %d" % st.odd_hassc, flush=True)

    print("\n=== RAW (undecrypted) odd bodies -- low entropy means unencrypted ===",
          flush=True)
    for n, hx, top in st.oddraw[:10]:
        print("    len=%-4d top=%s  %s" % (n, top, hx[:64]), flush=True)
    flat = Counter()
    for _, _, top in st.oddraw:
        for v, c in top:
            flat[v] += c
    tot = sum(flat.values())
    print("  aggregate top raw byte values: %s"
          % (" ".join("%02x:%.1f%%" % (v, 100 * c / tot)
                      for v, c in flat.most_common(6)), ), flush=True)

    print("\n=== mu-law score (fraction of bytes >= 0x60) per odd body ===", flush=True)
    big = [(n, s) for n, s in st.mulaw_score if n >= 900]
    sml = [(n, s) for n, s in st.mulaw_score if n < 900]
    for label, grp in (("1004-byte blocks", big), ("small blocks", sml)):
        if not grp:
            continue
        avg = sum(s for _, s in grp) / len(grp)
        print("  %-16s n=%-4d avg=%.3f  (uniform random would be ~0.53)"
              % (label, len(grp), avg), flush=True)
        for n, s in grp[:4]:
            print("      len=%-4d score=%.3f" % (n, s), flush=True)

    print("\n=== low-pass test: mean |consecutive byte diff| (random ~= 85) ===", flush=True)
    for label, grp in (("1004-byte", [(n, d) for n, d in st.audio_diff if n >= 900]),
                       ("small", [(n, d) for n, d in st.audio_diff if n < 900])):
        if grp:
            print("  %-11s n=%-4d avg=%.1f" % (label, len(grp),
                                                sum(d for _, d in grp) / len(grp)),
                  flush=True)

    # dump non-AV bodies: audio-like (low-pass) separately from the rest
    au = bytearray()
    oth = bytearray()
    for blob in st.audio_blobs:
        if len(blob) > 8:
            d = sum(abs(blob[i] - blob[i - 1])
                    for i in range(1, min(len(blob), 400))) / 399.0
            (au if d < 60 else oth).extend(blob)
        else:
            oth.extend(blob)
    open("/tmp/cam_audio.ulaw", "wb").write(au)
    open("/tmp/cam_other.bin", "wb").write(oth)
    print("\nwrote %d B mu-law -> /tmp/cam_audio.ulaw ; %d B other -> "
          "/tmp/cam_other.bin" % (len(au), len(oth)), flush=True)
    open("/tmp/cam_audio_raw.bin", "wb").write(b"".join(st.audio_raw))
    print("wrote %d B raw ciphertext -> /tmp/cam_audio_raw.bin" % len(b"".join(st.audio_raw)), flush=True)

    print("\n=== SMALL non-AV linktype-4 bodies, full plaintext ===", flush=True)
    small = [(n, hx) for n, hx in st.odd if n < 100]
    print("  count=%d" % len(small), flush=True)
    for n, hx in small[:24]:
        print("    len=%-4d %s" % (n, hx), flush=True)

    print("\n=== 1004-byte bodies: entropy + alternative-key test ===", flush=True)
    from listreq import rc5_setup, rc5_decrypt_block
    bigraw = [(n, hx) for n, hx in st.odd if n >= 900]
    print("  count=%d distinct=%d" % (len(bigraw),
                                      len(set(h for _, h in bigraw))), flush=True)

    # byte histogram of the first big block -> is it really random?
    if bigraw:
        for k, (n, hx) in enumerate(bigraw[:3]):
            b = bytes.fromhex(hx)
            hist = Counter(b)
            top = hist.most_common(5)
            print("  block %d (%d B) top bytes: %s"
                  % (k, n, " ".join("%02x x%d" % (v, c) for v, c in top)),
                  flush=True)
        # which offsets hold the most common byte?
        b = bytes.fromhex(bigraw[0][1])
        v = Counter(b).most_common(1)[0][0]
        offs = [i for i, x in enumerate(b) if x == v]
        print("  offsets of %02x in block0: %s" % (v, offs[:24]), flush=True)

    # try every 8-byte window of the CALLING as the RC5 key
    call = any_calling(tid)
    call_pt = p2p_client.decrypt(call) if False else None
    cands = {}
    for off in range(0, len(call) - 7):
        cands["calling[%d:%d]" % (off, off + 8)] = call[off:off + 8]
    # the encrypted CALLING's plaintext tail fields, and common derivations
    for off in range(0, len(call) - 7):
        cands["enc[%d:%d]" % (off, off + 8)] = call[off:off + 8]

    def score(key, blk):
        stt = rc5_setup(key)
        out = bytearray()
        for i in range(0, len(blk) - 7, 8):
            out += rc5_decrypt_block(stt, blk[i:i + 8], "little")
        # structured plaintext has a skewed byte histogram
        h = Counter(out)
        return max(h.values()) / len(out), bytes(out[:16])

    if bigraw:
        blk = bytes.fromhex(bigraw[0][1])
        best = []
        for name, key in cands.items():
            s, head = score(key, blk)
            best.append((s, name, head))
        best.sort(reverse=True)
        print("  best CALLING-window keys (max byte freq, lower=random):",
              flush=True)
        for s, name, head in best[:5]:
            print("    %.4f %-18s %s" % (s, name, head.hex()), flush=True)
        print("  (baseline with the AV key = %.4f)"
              % score(st.key, blk)[0], flush=True)

    print("\n=== first bodies per linktype ===", flush=True)

    print("\n=== first bodies per linktype ===", flush=True)
    for lt in sorted(st.samples):
        print("  linktype %d:" % lt, flush=True)
        for hx in st.samples[lt][:4]:
            print("    %s" % hx, flush=True)
    st.close()


if __name__ == "__main__":
    main()
