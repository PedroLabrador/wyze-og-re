#!/usr/bin/env python3
"""w160 again, but as the FIRST AvStreamCtl of a FRESH session.

WHY THE EARLIER SWEEP WAS INVALID
---------------------------------
w160probe.py pushed 15 different w160 values into one live session and saw no
change.  But gutesprobe.py showed the camera emits only four linktype-3
replies in a whole session -- all of them at the very start -- so every INITREQ
after the first is ignored by the camera's state machine.  The sweep was
therefore poking a field the camera had already stopped reading.

iv_rcvpkt_AVSTREAMCTL_INITREQ (0x56f4c) reads exactly two fields:
pkt[4:8] (id164) and pkt[62:64] (w160, a u16).  So w160 is still the only
user-supplied value the camera consumes, and it has only ever been tried as
the *first* thing in a session with the value 0 (what our product sends).

Each candidate therefore gets its own complete session: discover, CALLING,
then a single AvStreamCtl carrying that w160, and the AV header is read from
the video that follows.  Sessions are spaced 35 s apart because the camera
holds its slot for ~30-40 s after a stream.

Usage: python3 -u w160fresh.py [tid]
"""
import random
import struct
import sys
import time

sys.path.insert(0, "~/Downloads/wyze-re")
import kcpav                                         # noqa: E402
import p2p_client                                    # noqa: E402
from mtp_frame import wrap as mtp_wrap               # noqa: E402
from defsend import Probe, load_calling              # noqa: E402


def fresh_id164():
    """iv_start_process_calling's id: 30 random bits, retried until non-zero."""
    while True:
        v = (((random.getrandbits(32) << 20) & 0xffffffff)
             | ((random.getrandbits(32) << 10) & 0xffffffff)
             | (random.getrandbits(32) & 0x3ff)) & 0x3fffffff
        if v:
            return v


def one_session(tid, w160, run_secs=10.0):
    """Full session, one INITREQ carrying `w160`, then the AV header."""
    got = p2p_client.discover(duration=4.0, want_tid=tid)
    ip = next(iter(got))
    port = got[ip]["p2p_port"]

    st = Probe(ip, port, tid, load_calling(tid), local_port=0, timeout=40.0)
    st.start()
    lo, hi = st.kcp_lo, st.kcp_hi

    def pump(n):
        for _ in range(int(n / 0.5)):
            st._pump(0.5, [(lo.conv, lo), (hi.conv, hi)])

    pump(2.5)                                    # CALLING ack + meter handshake

    frame = kcpav.avstreamctl(kcpav.ACT_START, id164=fresh_id164(), w160=w160)
    for kc in (lo, hi):
        for _ in range(3):                       # KCP retransmit
            kc.push(frame)
    for kc in (lo, hi):
        for pkt in kc.take_packets():
            st._send(mtp_wrap(pkt, 0))

    pump(run_secs)
    hdr = st.headers[0] if st.headers else None
    ntlv = st.tlv_counts.get(4, 0)
    st.close()
    return hdr, ntlv, port


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else "429728658691722"

    # 0 = what our product sends today (the control), then widths, then
    # the definition codes GwDefinitionLogEnum uses (2=SD 3=HD 4=2K).
    values = [0, 1920, 1080, 3, 4]

    print("w160 as the FIRST INITREQ of a FRESH session, tid %s" % tid,
          flush=True)
    for i, w in enumerate(values):
        if i:
            print("   ...waiting %d s for the camera to free its slot"
                  % 35, flush=True)
            time.sleep(35)
        try:
            hdr, ntlv, port = one_session(tid, w)
        except Exception as e:                   # noqa: BLE001
            print("w160=%-5d -> ERROR %s" % (w, e), flush=True)
            continue
        print("w160=%-5d -> header=%-22s media TLVs=%-5d (cam :%s)"
              % (w, str(hdr), ntlv, port), flush=True)


if __name__ == "__main__":
    main()
