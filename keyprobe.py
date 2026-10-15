#!/usr/bin/env python3
"""What are the 1004-byte linktype-4 bodies that decrypt to noise?

audioprobe.py showed three classes of type-4 body:

  * 670 bodies starting with ff ff ff 88  -- all Annex-B H.264 (video)
  * ~178 bodies of EXACTLY 1004 bytes, no header, decrypting to noise
    (mean |consecutive diff| 85.2 == random, so the AV key is wrong for them)
  * ~130 bodies of assorted sizes that DO look like mu-law (diff 37.1)

The 1004-byte class alone is ~14.9 kB/s, which is suspiciously close to a
16 kHz mu-law audio stream.  So the working hypothesis is that audio comes
in fixed 1004-byte frames encrypted under a *different* key (or at a
different offset).

This probe captures raw ciphertext and, per body, sweeps:
  1. decryption offset 0..7        (misaligned TLV slice would look like this)
  2. every 8-byte window of the CALLING, both raw and RC5-decrypted
  3. the AV key with RC5 round counts 0..12
  4. RC5-CBC with a zero IV (the unreversed "mode 3" @ 0x2b500)

Score = mean |consecutive byte diff|.  Random == 85; mu-law == 20..50.

Usage: python3 -u keyprobe.py [tid] [secs]
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
import listreq                                       # noqa: E402
from defsend import Probe, any_calling               # noqa: E402

ROUNDS_SAVE = listreq.ROUNDS


def diff_score(b, n=400):
    if len(b) < 16:
        return 999.0
    m = min(len(b) - 1, n)
    return sum(abs(b[i] - b[i - 1]) for i in range(1, m + 1)) / m


def hiscore(b):
    return sum(1 for x in b if x >= 0x60) / max(1, len(b))


def rc5_dec_offset(key, data, off):
    st = listreq.rc5_setup(key)
    out = bytearray(data[:off])
    n = len(data) - off
    n -= n % 8
    for i in range(off, off + n, 8):
        out += listreq.rc5_decrypt_block(st, bytes(data[i:i + 8]), "little")
    out += data[off + n:]
    return bytes(out)


def rc5_dec_rounds(key, data, rounds):
    # monkeypatch the module-level ROUNDS used by setup/decrypt
    st = listreq.rc5_setup(key)
    out = bytearray()
    n = len(data) - len(data) % 8
    for i in range(0, n, 8):
        out += _dec_rounds(st, data[i:i + 8], rounds)
    out += data[n:]
    return bytes(out)


def _dec_rounds(S, blk, rounds):
    A = int.from_bytes(blk[0:4], "little")
    B = int.from_bytes(blk[4:8], "little")
    for i in range(rounds, 0, -1):
        B = (listreq._rotl32((B - S[2 * i + 1]) & listreq.MASK,
                             32 - (A & 31)) ^ A) & listreq.MASK
        A = (listreq._rotl32((A - S[2 * i]) & listreq.MASK,
                             32 - (B & 31)) ^ B) & listreq.MASK
    B = (B - S[1]) & listreq.MASK
    A = (A - S[0]) & listreq.MASK
    return A.to_bytes(4, "little") + B.to_bytes(4, "little")


def rc5_cbc_dec(key, data, iv=b"\x00" * 8):
    st = listreq.rc5_setup(key)
    out = bytearray()
    prev = iv
    n = len(data) - len(data) % 8
    for i in range(0, n, 8):
        blk = bytes(data[i:i + 8])
        d = listreq.rc5_decrypt_block(st, blk, "little")
        out += bytes(a ^ b for a, b in zip(d, prev))
        prev = blk
    out += data[n:]
    return bytes(out)


class KeyProbe(Probe):
    def __init__(self, *a, **k):
        Probe.__init__(self, *a, **k)
        self.bodies = []                  # (len, ciphertext) of HEADER-LESS bodies
        self.video_n = 0
        self.video_sizes = Counter()

    def _on_tlv(self, payload):
        if not payload or payload[0] != 4:
            return
        ln = struct.unpack_from("<H", payload, 2)[0]
        body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
        if len(body) < 16:
            return
        # video frames are 1004 B too -- split them off by the AV header so the
        # key/offset sweep below only ever sees the unknown class.
        pt = p2p_client.rc5_decrypt_stream(self.key, bytes(body))
        if pt[:4] == b"\xff\xff\xff\x88":
            self.video_n += 1
            self.video_sizes[len(body)] += 1
            return
        self.bodies.append((len(body), bytes(body)))


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658756018"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    if not got:
        print("no camera answered discovery", flush=True)
        return
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("tid %s  camera %s:%s" % (tid, ip, port), flush=True)

    st = KeyProbe(ip, port, tid, any_calling(tid), local_port=0, timeout=secs + 10)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])
    st.close()

    print("video (ff ff ff 88): %d bodies, sizes %s"
          % (st.video_n, st.video_sizes.most_common(4)), flush=True)
    big = [(n, b) for n, b in st.bodies if n >= 1000]
    small = [(n, b) for n, b in st.bodies if n < 1000]
    print("header-less: %d big (>=1000B) %d small"
          % (len(big), len(small)), flush=True)
    print("  big size hist: %s" % Counter(n for n, _ in big).most_common(4), flush=True)
    if not st.bodies:
        return
    body = (big or st.bodies)[0][1]
    print("  using %d-byte body" % len(body), flush=True)

    for label, grp in (("BIG", big), ("SMALL", small)):
        if not grp:
            continue
        ds = [diff_score(rc5_dec_offset(st.key, b, 0)) for _, b in grp[:60]]
        hs = [hiscore(rc5_dec_offset(st.key, b, 0)) for _, b in grp[:60]]
        print("  %-5s n=%-4d AV-key diff mean=%.1f (85=random)  hi mean=%.3f"
              % (label, len(grp), sum(ds) / len(ds), sum(hs) / len(hs)), flush=True)

    avkey = st.key
    print("\nAV key = %s" % avkey.hex(), flush=True)

    print("\n=== 1. decryption offset sweep (AV key) ===", flush=True)
    for off in range(8):
        pt = rc5_dec_offset(avkey, body, off)
        print("  offset %d  diff=%6.1f  hi=%.3f  head=%s"
              % (off, diff_score(pt), hiscore(pt), pt[:12].hex()), flush=True)

    print("\n=== 2. every 4-byte window of CALLING (raw + decrypted) ===", flush=True)
    call = any_calling(tid)
    cands = [("calling[%d]" % off, call[off:off + 8])
             for off in range(0, len(call) - 7, 4)]
    try:
        cpt = p2p_client.decrypt(call)
        cands += [("enc[%d]" % off, cpt[off:off + 8])
                  for off in range(0, len(cpt) - 7, 4)]
    except Exception as e:
        print("  (decrypt(CALLING) failed: %r)" % e, flush=True)
    cands.append(("AVKEY", avkey))

    scored = sorted((diff_score(rc5_dec_offset(k, body, 0)), n, k)
                    for n, k in cands)
    for d, name, key in scored[:10]:
        print("  %6.1f  %-16s %s" % (d, name, key.hex()), flush=True)
    print("  ...worst: %.1f" % scored[-1][0], flush=True)

    print("\n=== 3. RC5 round-count sweep (AV key) ===", flush=True)
    for r in range(0, 7):
        print("  rounds=%-2d diff=%6.1f" % (r, diff_score(rc5_dec_rounds(avkey, body, r))),
              flush=True)

    print("\n=== 4. CBC mode, zero IV (AV key) ===", flush=True)
    pt = rc5_cbc_dec(avkey, body)
    print("  diff=%.1f hi=%.3f head=%s" % (diff_score(pt), hiscore(pt), pt[:16].hex()),
          flush=True)

    print("\n=== 5. is the ciphertext itself mu-law? ===", flush=True)
    print("  raw diff=%.1f hi=%.3f" % (diff_score(body), hiscore(body)), flush=True)

    open("/tmp/body_unknown.bin", "wb").write(body)
    open("/tmp/bodies_unknown.bin", "wb").write(b"".join(b for _, b in st.bodies))
    print("\nwrote /tmp/body_unknown.bin, /tmp/bodies_unknown.bin (%d B)"
          % sum(len(b) for _, b in st.bodies), flush=True)


if __name__ == "__main__":
    main()
