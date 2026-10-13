#!/usr/bin/env python3
"""Clear logcat, cold-start the app, navigate into the camera group, then dump
the connection-setup portion of logcat.  Used to recover the P2P handshake:
which port, which path (LAN vs relay), and in what order."""
import subprocess, time, sys

def adb(*a, timeout=20):
    return subprocess.run(["adb", "shell", *a], capture_output=True,
                          text=True, timeout=timeout)

def adbhost(*a, timeout=20):
    return subprocess.run(["adb", *a], capture_output=True, text=True,
                          timeout=timeout)

print("[*] clearing logcat", flush=True)
adbhost("logcat", "-c")
print("[*] force-stop", flush=True)
adb("am", "force-stop", "com.hualai")
time.sleep(1.5)
print("[*] launching", flush=True)
adb("monkey", "-p", "com.hualai", "-c",
    "android.intent.category.LAUNCHER", "1")
time.sleep(float(sys.argv[1]) if len(sys.argv) > 1 else 12)

print("[*] tapping camera group (960,448)", flush=True)
adb("input", "tap", "960", "448")
time.sleep(float(sys.argv[2]) if len(sys.argv) > 2 else 20)

r = subprocess.run(["adb", "logcat", "-d", "-v", "time"],
                   capture_output=True, text=True, timeout=30)
open("/tmp/setup_lc.txt", "w").write(r.stdout)
print(f"[*] logcat lines: {len(r.stdout.splitlines())}", flush=True)
