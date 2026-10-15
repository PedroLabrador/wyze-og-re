#!/usr/bin/env python3
"""Offline: does _take_audio_frames find frames in a saved feed?

Feeds tested:
  /tmp/vf.h264   the full body stream from the live verifyfix run (0 matched)
  /tmp/mixed.bin bodies mixbody.py classified as audio (390 of them)

Prints, for each feed, how far each of the 4 conditions gets, so we can see
exactly which test rejects the audio AV frames.
"""
import sys

sys.path.insert(0, "~/Downloads/wyze-re")
import p2p_client                                    # noqa: E402

SYNC = b"\xff\xff\xff\x88"
HDR = SYNC + b"\x00\x00\x01\x00"
ZEROS = b"\x00" * 12
CON = b"\x87\x00\x00\x00"


def analyse(path):
    try:
        d = open(path, "rb").read()
    except OSError as e:
        print("%s: %s" % (path, e))
        return
    n_sync = n_hdr = n_zero = n_con = n_len = 0
    samples = []
    i = 0
    while True:
        i = d.find(SYNC, i)
        if i < 0:
            break
        n_sync += 1
        if d[i:i + 8] == HDR:
            n_hdr += 1
            if d[i + 8:i + 20] == ZEROS:
                n_zero += 1
                if d[i + 24:i + 28] == CON:
                    n_con += 1
                    ln = int.from_bytes(d[i + 28:i + 30], "little")
                    if 64 <= ln <= 4096 and i + 30 + ln <= len(d):
                        n_len += 1
                        if len(samples) < 4:
                            samples.append((i, ln, d[i:i + 30].hex()))
            else:
                if len(samples) < 0:
                    pass
        i += 1
    print("%s (%d B)" % (path, len(d)))
    print("   sync ff ff ff 88 : %d" % n_sync)
    print("   + hdr 00 00 01 00: %d" % n_hdr)
    print("   + 12 zeros       : %d" % n_zero)
    print("   + 87 00 00 00    : %d" % n_con)
    print("   + len ok         : %d   <-- would be extracted" % n_len)
    for i, ln, hx in samples:
        print("     @%-6d len=%d  %s" % (i, ln, hx))

    # What do the 12-zero candidates look like where they FAIL the 87-check?
    shown = 0
    i = 0
    while shown < 5:
        i = d.find(SYNC, i)
        if i < 0:
            break
        if d[i:i + 8] == HDR and d[i + 8:i + 20] == ZEROS and \
                d[i + 24:i + 28] != CON:
            print("     ZEROS-but-not-con @%-6d  [20:30]=%s"
                  % (i, d[i + 20:i + 30].hex()))
            shown += 1
        i += 1
    print()


def main():
    for p in ("/tmp/vf.h264", "/tmp/mixed.bin"):
        analyse(p)


if __name__ == "__main__":
    main()
