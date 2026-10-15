#!/usr/bin/env python3
"""Read the app's client->camera AV media (linktype 4) -- the talk direction.

Captured with PCAPdroid while the talk button was held.  The earlier capture
had ZERO linktype-4 frames in the app->camera direction, so anything here is
the app actually sending media *to* the camera.

The key comes from the app's own CALLING (mode-1 rule), which also validates
the approach: the camera->app media must decrypt to the known `ff ff ff 88`
AV sync.

Usage: python3 apptalk.py [a2c|c2a] [--all]
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


def tlvs(path):
    """Reassemble the KCP push stream and split it into TLVs."""
    buf = bytearray()
    for d in load(path):
        if d[:2] != b"\xc0\x10":
            continue
        u = unwrap(d)
        if not u:
            continue
        s = u[0]
        if len(s) < 24 or (s[4] & 0x0F) != 1:
            continue
        ln = struct.unpack_from("<I", s, 20)[0]
        buf += s[24:24 + ln]
    out, i = [], 0
    while i + 4 <= len(buf):
        lt = buf[i]
        ln = struct.unpack_from("<H", buf, i + 2)[0]
        if ln < 4 or i + ln > len(buf):
            break
        out.append((lt, bytes(buf[i + 4:i + ln])))
        i += ln
    return out


def av_key(calling):
    if calling[0] == 0x7E or calling[0] == 0x7F:
        pt = mode1(calling)
    else:
        pt = calling
    return pt[28:32], pt[120:128], pt


def rc5(pt_key, data):
    S = rc5_setup(pt_key)
    out = bytearray()
    for off in range(0, len(data) - 7, 8):
        out += rc5_decrypt_block(S, bytes(data[off:off + 8]), "little")
    return bytes(out), data[len(data) & ~7:]


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "a2c"
    show_all = "--all" in sys.argv

    dgrams = load("/tmp/applan_%s.bin" % which)
    # the app's CALLING always lives in the app->camera direction
    calling = next((d for d in load("/tmp/applan_a2c.bin")
                    if d[:1] in (b"\x7e", b"\x7f") and d[1:2] == b"\xa4"
                    and len(d) > 100), None)
    if calling is None:
        raise SystemExit("no CALLING in the capture")

    conv, key, pt = av_key(calling)
    print("CALLING %d B   conv=0x%08x   AV key=%s   class/flag byte [20:24]=%s"
          % (len(calling), struct.unpack("<I", conv)[0], key.hex(),
             pt[20:24].hex()))

    t = tlvs("/tmp/applan_%s.bin" % which)
    print("%s TLVs: %s" % (which, sorted(Counter(lt for lt, _ in t).items())))

    # validate the key on the media direction
    media = [b for lt, b in t if lt == 4]
    if media and which == "c2a":
        d, rest = rc5(key, media[10])
        print("key check (camera->app media #10): %s  sync_ok=%s  rest=%s"
              % (d[:16].hex(), d[:4] == b"\xff\xff\xff\x88", rest.hex()))

    if which != "a2c":
        return

    sizes = Counter(len(b) for _, b in t if _ == 4)
    print("app->camera linktype-4 sizes: %s" % sorted(sizes.items()))

    uniq = OrderedDict()
    for lt, b in t:
        if lt == 4:
            uniq.setdefault(b, 0)
            uniq[b] += 1

    print("\n--- decrypted client->camera media ---")
    for n, (b, cnt) in enumerate(uniq.items()):
        d, rest = rc5(key, b)
        print("\n#%d len=%d x%d" % (n, len(b), cnt))
        print("  ct  %s" % b[:48].hex())
        print("  pt  %s" % d[:64].hex())
        print("  asc %s" % ascii_of(d[:64]))
        if rest:
            print("  tail(not 8-aligned) %s" % rest.hex())
        if not show_all and n >= 5:
            print("\n... (%d more; pass --all)" % (len(uniq) - n - 1))
            break


if __name__ == "__main__":
    main()
