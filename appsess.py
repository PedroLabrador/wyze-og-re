#!/usr/bin/env python3
"""Per-session view of the app's camera dialogue.

The capture spans several sessions (the app re-handshakes whenever the stream
is restarted -- each CALLING carries a fresh conv and a fresh AV key), so
anything grouped globally is a blend of sessions and its ciphertext will only
partly decrypt.  KCP convs are the session key: the app pushes on the hi conv
(conv | 0x80000000) and every CALLING declares its own.

For each session this prints the TLV types the app sent and the decrypted
plaintext of the non-AvStreamCtl ones -- which is where a light command or the
talk audio would live.

Usage: python3 appsess.py [a2c|c2a|both] [--dump]
"""
import struct
import sys
from collections import Counter, OrderedDict

sys.path.insert(0, "~/Downloads/wyze-re")
from mtp_frame import unwrap                              # noqa: E402
from listreq import rc5_setup, rc5_decrypt_block          # noqa: E402
from appcalling import mode1, ascii_of                    # noqa: E402


def load(path):
    out = []
    with open(path, "rb") as f:
        while True:
            b = f.read(4)
            if len(b) < 4:
                return out
            out.append(f.read(struct.unpack("<I", b)[0]))


def sessions(dgrams):
    """{conv: {'pushes': [...], 'callings': [...]}} keyed by ikcp conv."""
    sess = OrderedDict()
    for d in dgrams:
        if d[:2] == b"\xc0\x10":
            u = unwrap(d)
            if not u:
                continue
            s = u[0]
            if len(s) < 24:
                continue
            conv = struct.unpack_from("<I", s, 0)[0]
            e = sess.setdefault(conv, {"pushes": [], "callings": []})
            if (s[4] & 0x0F) == 1:
                ln = struct.unpack_from("<I", s, 20)[0]
                e["pushes"].append(s[24:24 + ln])
        elif d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4" \
                and len(d) > 100:
            pt = mode1(d)
            conv = struct.unpack_from("<I", pt, 28)[0]
            sess.setdefault(conv | 0x80000000,
                            {"pushes": [], "callings": []})
            sess[conv | 0x80000000]["callings"].append(pt)
            sess.setdefault(conv, {"pushes": [], "callings": []})
            sess[conv]["callings"].append(pt)
    return sess


def split_tlvs(pushes):
    buf = bytearray()
    for p in pushes:
        buf += p
    out, i = [], 0
    while i + 4 <= len(buf):
        lt = buf[i]
        ln = struct.unpack_from("<H", buf, i + 2)[0]
        if ln < 4 or i + ln > len(buf):
            break
        out.append((lt, bytes(buf[i + 4:i + ln])))
        i += ln
    return out


def dec(key, b):
    S = rc5_setup(key)
    return b"".join(rc5_decrypt_block(S, b[o:o + 8], "little")
                    for o in range(0, len(b) // 8 * 8, 8))


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    dump = "--dump" in sys.argv
    dirs = ["a2c", "c2a"] if which == "both" else [which]

    for d in dirs:
        dgrams = load("/tmp/applan_%s.bin" % d)
        sess = sessions(dgrams)
        print("\n############ %s: %d session conv(s)" % (d, len(sess)))
        for conv, e in sess.items():
            tl = split_tlvs(e["pushes"])
            if not tl:
                continue
            key = None
            if e["callings"]:
                key = e["callings"][0][120:128]
            hist = sorted(Counter(lt for lt, _ in tl).items())
            print("\n== conv=0x%08x  pushes=%d  TLVs=%d %s  key=%s"
                  % (conv, len(e["pushes"]), len(tl), hist,
                     key.hex() if key else "-"))
            for lt in sorted(set(lt for lt, _ in tl)):
                bodies = [b for l, b in tl if l == lt]
                print("   lt=%d: %d frames, sizes %s"
                      % (lt, len(bodies),
                         sorted(Counter(len(b) for b in bodies).items())[:6]))
                if lt == 3:
                    continue                     # AvStreamCtl, already known
                if not key:
                    continue
                uniq = OrderedDict()
                for b in bodies:
                    uniq.setdefault(b, 0)
                    uniq[b] += 1
                for n, (b, cnt) in enumerate(uniq.items()):
                    p = dec(key, b)
                    sync = "SYNC" if p[:4] == b"\xff\xff\xff\x88" else "    "
                    print("     %s x%-3d len=%-4d pt %s"
                          % (sync, cnt, len(b), p[:40].hex()))
                    if n >= (len(uniq) - 1 if dump else 2):
                        if len(uniq) > 3 and not dump:
                            print("     ... %d more" % (len(uniq) - n - 1))
                        break


if __name__ == "__main__":
    main()
