#!/usr/bin/env python3
"""Dump the camera's own AvStreamCtl (linktype 3) reply, field by field.

Our client builds AvStreamCtl with kcpav.avstreamctl() defaults, i.e.
id164 = ac = b0 = w160 = 0 and a zero blob -- every value zero except
action = ACT_START.  The SDK fills those from its session context
(iv_init_frm_AvStreamCtl reads ctx->0x164 / 0xac / 0xb0 / 0x1a4 / 0x160),
so we may be handing the camera a frame it considers unauthorised or
meaningless, and it then streams its default 640x360.

The camera answers our AvStreamCtl with its OWN linktype-3 frames.  Those
carry the same layout from the camera's side, so they should contain the
id164 / ac / b0 / w160 the camera is actually using -- the values we ought
to echo.

Usage: python3 -u ctlreply.py [tid] [seconds]
"""
import json
import struct
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402
import kcpav                                         # noqa: E402


def fields(buf, label):
    if len(buf) < 76:
        print("   %s: only %d B: %s" % (label, len(buf), buf.hex()))
        return
    print("   %s: %s" % (label, buf[:76].hex()))
    print("      [0]=%#x [1]=%#x total=%d" % (buf[0], buf[1],
                                              struct.unpack_from("<H", buf, 2)[0]))
    print("      id164  [4:8]   = %#010x" % struct.unpack_from("<I", buf, 4)[0])
    print("      action [8:12]  = %d   [0xc]=%d"
          % (struct.unpack_from("<I", buf, 8)[0], buf[0xC]))
    print("      ac     [0x10]  = %#010x" % struct.unpack_from("<I", buf, 0x10)[0])
    print("      b0     [0x14]  = %#010x" % struct.unpack_from("<I", buf, 0x14)[0])
    print("      w+0x18 [0x18]  = %#010x" % struct.unpack_from("<I", buf, 0x18)[0])
    print("      w160   [62:64] = %#06x (%d)"
          % (struct.unpack_from("<H", buf, 62)[0],
             struct.unpack_from("<H", buf, 62)[0]))
    print("      blob   [24:56] = %s" % buf[24:56].hex())
    print("      tail   [56:76] = %s" % buf[56:76].hex())


class Probe(p2p_client.CameraStream):
    def __init__(self, *a, **k):
        p2p_client.CameraStream.__init__(self, *a, **k)
        self.ctls = []

    def _on_tlv(self, payload):
        if len(payload) >= 4 and payload[0] == 3:
            ln = struct.unpack_from("<H", payload, 2)[0]
            body = payload[4:ln if 4 < ln <= len(payload) else len(payload)]
            if body and len(self.ctls) < 6:
                self.ctls.append((bytes(body),
                                  p2p_client.rc5_decrypt_stream(self.key, body)))
        p2p_client.CameraStream._on_tlv(self, payload)


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 25.0

    doc = json.load(open("~/Downloads/wyze-re/wire/p2p_frames.json"))
    rec = doc["devices"][tid]["frames"]
    calling = bytes.fromhex(rec["calling"] if isinstance(rec["calling"], str)
                            else "".join("%02x" % b for b in rec["calling"]))

    got = p2p_client.discover(duration=4.0, want_tid=tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]
    print("tid %s  camera %s:%s" % (tid, ip, port), flush=True)

    print("\n== what WE send ==", flush=True)
    fields(kcpav.avstreamctl(), "ours (defaults)")
    st = Probe(ip, port, tid, calling, local_port=0, timeout=secs)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi
    for _ in range(int(secs / 0.5)):
        st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])

    print("\n== what the CAMERA sends back (%d linktype-3 frames) =="
          % len(st.ctls), flush=True)
    from listreq import rc5_setup, rc5_decrypt_block
    S = rc5_setup(bytes(st.key))
    print("   rc5_dec(key, 8 zero bytes) = %s   (repeated block in replies)"
          % rc5_decrypt_block(S, b"\x00" * 8, "little").hex(), flush=True)
    for i, (raw, dec) in enumerate(st.ctls):
        print("   camera[%d] RAW  %s" % (i, raw.hex()), flush=True)
        fields(dec, "camera[%d] as if RC5" % i)
    st.close()


if __name__ == "__main__":
    main()
