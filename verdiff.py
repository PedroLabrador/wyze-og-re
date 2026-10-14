#!/usr/bin/env python3
"""Compare the exported symbol sets of Gwell's P2P libs across app versions.

    python3 verdiff.py            # summary + what changed 2.50 -> 3.0 -> 3.23
    python3 verdiff.py --grep q   # only names containing 'q'

Why this matters
---------------
The whole project was reversed out of app **2.50.7** (armeabi-v7a, ELF32).
The question "does a newer app speak a different protocol?" is answerable for
free from the exported symbols: if `iv_init_frm_CALLING`, `iv_init_frm_-
AvStreamCtl`, `iv_rcv_meter_req`, the GUTES type handlers etc. are all still
there, the wire format we documented did not change and the newer app is
just a reskin on top of it.

Versions compared (all from apkmirror APKs already extracted here):
  2.50.7.487   armeabi-v7a  ELF32   libiotp2pav.so 825 532 B
  3.0.0.b489   arm64-v8a    ELF64   libiotp2pav.so 912 160 B   <- arm32 GONE
  3.23.1.994   arm64-v8a    ELF64   libiotp2pav.so 1 028 584 B
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elfsym  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
V = {
    "2.50.7": ("com.hualai_2.50.7.487-62187_minAPI24(arm64-v8a,armeabi-v7a)"
               "(nodpi)_apkmirror.com/lib/armeabi-v7a/libiotp2pav.so"),
    "3.0.0.b489": ("com.hualai_3.0.0.b489-62189_minAPI28(arm64-v8a)"
                   "(nodpi)_apkmirror.com/lib/arm64-v8a/libiotp2pav.so"),
    "3.23.1.994": ("wyze_3.23/extracted/arm64/lib/arm64-v8a/libiotp2pav.so"),
}

# the specific functions whose disappearance would mean the protocol changed
CRITICAL = [
    "iv_init_frm_CALLING", "iv_init_frm_AvStreamCtl",
    "iv_send_av_stream_ctl_frm", "iv_rcv_meter_req", "iv_rcv_meter_ack",
    "iv_on_rcv_mtpCtrl_pkt", "iv_on_rcv_kcpdata_pkt", "iv_rcv_tlvfrm",
    "iv_mtp_session_rcv_proc", "iv_find_mtp_session",
    "iv_gute_frm_rc5_decrypt", "iv_gute_frm_rc5_encrypt",
    "iv_gutes_on_rcvpkt", "iv_gutes_pkt_send_ack",
    "giot_on_rcvpkt", "iv_gute_frm_init_chkval", "iv_check_chnnel_res_status",
    "iv_kcp_session", "ivkcp_send", "ivkcp_input", "ivkcp_create",
    "iv_send_MtpQuality", "iv_init_frm_mtp_quality",
    "iv_mtp_chnnel_eval_quality", "start_av_enc_dec",
    "iv_start_process_calling", "iv_rcvpkt_AVSTREAMCTL_ACCEPT",
    "iv_on_rcv_pkt_as_relay", "iv_create_kcb",
]


def names(path):
    out, _ = elfsym.parse(path)
    syms = out.get("dynsym", [])
    return {nm for nm, _v, _s, _t, _b, _sh in syms if nm}


def main():
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    grep = None
    for i, a in enumerate(sys.argv):
        if a == "--grep":
            grep = sys.argv[i + 1]

    sets = {}
    for ver, rel in V.items():
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            print("MISSING", ver, p)
            continue
        sets[ver] = names(p)
        print("%-12s %5d exported symbols   %s"
              % (ver, len(sets[ver]), os.path.basename(os.path.dirname(p))))

    order = [v for v in V if v in sets]
    if len(order) < 2:
        return

    print("\n=== the frames our client actually depends on ===")
    print("%-34s %s" % ("symbol", "  ".join("%-11s" % v for v in order)))
    missing_any = False
    for s in CRITICAL:
        row = []
        for v in order:
            hit = s in sets[v]
            row.append("%-11s" % ("YES" if hit else "-- ABSENT --"))
            if not hit:
                missing_any = True
        if grep and grep.lower() not in s.lower():
            continue
        print("%-34s %s" % (s, "  ".join(row)))
    print("\n  every one present in all versions => same wire protocol"
          if not missing_any else
          "\n  *** SOME SYMBOLS MOVED/RENAMED - see above ***")

    print("\n=== symbols NEW in 3.23.1 vs 2.50.7 ===")
    new = sorted(sets[order[-1]] - sets[order[0]])
    for n in new:
        if grep and grep.lower() not in n.lower():
            continue
        print("  +", n)
    print("  (%d new total)" % len(new))

    print("\n=== symbols REMOVED in 3.23.1 vs 2.50.7 ===")
    gone = sorted(sets[order[0]] - sets[order[-1]])
    for n in gone:
        if grep and grep.lower() not in n.lower():
            continue
        print("  -", n)
    print("  (%d removed total)" % len(gone))

    print("\n=== 3.0.0 -> 3.23.1 delta ===")
    if "3.0.0.b489" in sets and "3.23.1.994" in sets:
        a, b = sets["3.0.0.b489"], sets["3.23.1.994"]
        print("  + %d new: %s" % (len(b - a), ", ".join(sorted(b - a)) or "-"))
        print("  - %d gone: %s" % (len(a - b), ", ".join(sorted(a - b)) or "-"))


if __name__ == "__main__":
    main()
