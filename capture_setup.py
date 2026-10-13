#!/usr/bin/env python3
"""Cold-start the Wyze app, wait until it is actually ready, tap into the
camera group, let the streams establish, then dump ONLY that app's logcat.

The goal is the P2P *setup* sequence (path selection, port, handshake),
not the steady-state stats we already have."""
import subprocess, time, sys, re

def sh(*a, timeout=25):
    return subprocess.run(["adb", "shell", *a], capture_output=True,
                          text=True, timeout=timeout).stdout

def host(*a, timeout=25):
    return subprocess.run(["adb", *a], capture_output=True, text=True,
                          timeout=timeout).stdout

def current_activity():
    o = sh("dumpsys", "activity", "activities")
    m = re.search(r"mResumedActivity:.*?([A-Za-z0-9_.]+/[A-Za-z0-9_.]+)", o)
    return m.group(1) if m else "?"

def wait_for(sub, deadline):
    t0 = time.time()
    while time.time() - t0 < deadline:
        act = current_activity()
        if sub in act:
            return act
        time.sleep(1)
    return current_activity()

# --- app pid ---
def app_pid():
    o = sh("pidof", "com.hualai")
    o = o.strip()
    return o.split()[0] if o else None

launch_wait = float(sys.argv[1]) if len(sys.argv) > 1 else 45
stream_wait = float(sys.argv[2]) if len(sys.argv) > 2 else 25

print("[*] clearing logcat", flush=True)
host("logcat", "-c")
print("[*] force-stop", flush=True)
sh("am", "force-stop", "com.hualai")
time.sleep(2)
print("[*] launching", flush=True)
sh("monkey", "-p", "com.hualai", "-c",
   "android.intent.category.LAUNCHER", "1")

act = wait_for("SmartHomeMainActivity", launch_wait)
pid = app_pid()
print(f"[*] activity={act} pid={pid}  (waited {launch_wait}s cap)", flush=True)

print("[*] tapping 'Casa' group at (960,448)", flush=True)
sh("input", "tap", "960", "448")
act = wait_for("WyzeCameraGroupPage", 25)
print(f"[*] now on {act}", flush=True)

print(f"[*] waiting {stream_wait}s for streams to establish", flush=True)
time.sleep(stream_wait)

raw = host("logcat", "-d", "-v", "time")
lines = raw.splitlines()
keep = [l for l in lines if (f"({pid})" in l if pid else False)]
open("/tmp/setup_lc.txt", "w").write("\n".join(keep))
print(f"[*] total={len(lines)} app-only={len(keep)}", flush=True)
