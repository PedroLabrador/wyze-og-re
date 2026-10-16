#!/usr/bin/env python3
"""LOCAL, SILENT check of the talk reader + tick.  No camera, no network.

Feeds 5 s of silence through the real encoder and the real
CameraStreamThread._talk_reader, then drives CameraStreamThread._talk_tick on a
simulated 50 ms pump loop against a stub CameraStream.  Reports what the camera
*would* have received.  Nothing here makes a sound or opens a socket.
"""
import sys
import threading
import time

sys.path.insert(0, "~/Downloads/wyze-re/wyze-cam-stream")
import server                                            # noqa: E402


class StubStream:
    def __init__(self):
        self.packets = 0
        self.frames = 0

    def open_talk(self):
        return True

    def send_talk(self, batch):
        self.packets += 1
        self.frames += len(batch)
        return len(batch)


def main():
    secs = 5.0
    w = server.CameraStreamThread({"tid": 0, "ip": "0.0.0.0",
                                   "name": "stub", "calling": b"\0" * 128})
    w.status = "streaming"
    err = w.talk_begin()
    if err:
        raise SystemExit("talk_begin: %s" % err)
    st = StubStream()

    # feed 16 kHz mono PCM16 silence at the browser's rate: 1024 B = 32 ms
    chunk = b"\x00" * 1024
    t0 = time.time()
    n = 0
    produced = []
    while time.time() - t0 < secs:
        w.talk_feed(chunk)
        n += 1
        # simulate the worker's pump loop: 50 ms select, then the talk tick
        time.sleep(0.032)
        w._talk_tick(st, time.time())
        produced.append(len(w.talk_frames))
    w._talk_tick(st, time.time())

    pcm_s = n * 1024 / 2 / server.TALK_MIC_HZ
    sent_s = st.packets * server.TALK_PKT_SECONDS
    # We hand the camera content that is deliberately 2x SLOW (its own playout
    # is 2x fast), so one declared second of what we ship carries only
    # TALK_CAMERA_PLAYOUT seconds of real speech.  Compare real-to-real, or this
    # looks like a 50 % drop when it is nothing of the kind.
    covered = sent_s * server.TALK_CAMERA_PLAYOUT
    print("fed      : %d POSTs = %.2f s of 16 kHz PCM" % (n, pcm_s))
    print("produced : %d AMR frames = %.2f s declared"
          % (w.talk_stats["frames"], w.talk_stats["frames"] * 0.02))
    print("sent     : %d packets = %.2f s declared = %.2f s of real speech "
          "(%.0f%% of the input)"
          % (st.packets, sent_s, covered, 100.0 * covered / pcm_s))
    print("queue    : max %d frames, final %d" % (max(produced), len(w.talk_frames)))
    w.talk_end()


if __name__ == "__main__":
    main()
