#!/usr/bin/env python3
"""Capture ground-truth LAN traffic while the Wyze app sets up streams.

Runs on the Mac:
  * UDP listener on :8900  (the port broadcast_fd_init binds, from libiotp2pav.so)
  * polls the phone's /proc/net/tcp{,6} for new connections to camera IPs
  * can trigger app restart via adb

Everything is printed with timestamps so the two channels can be correlated.
"""
import socket, threading, subprocess, time, binascii, datetime, sys

CAM_HEX = {"D900A8C0": "192.168.77.12",
           "A900A8C0": "192.168.77.17",
           "E000A8C0": "192.168.77.10",
           "7500A8C0": "192.168.77.11"}
PHONE_HEX = "F200A8C0"  # 192.168.77.19

stop = False
def ts():
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log(tag, msg):
    print(f"[{ts()}] {tag:6s} {msg}", flush=True)

# ---------------- UDP listener ----------------
LISTEN_PORTS = [8900, 51701, 53014, 39296, 48746, 47005]

def udp_listener():
    socks = []
    for port in LISTEN_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            pass
        try:
            s.bind(("0.0.0.0", port))
        except OSError as e:
            log("UDP", f"port {port} bind failed: {e}")
            s.close()
            continue
        s.settimeout(0.3)
        socks.append((port, s))
        log("UDP", f"listening on 0.0.0.0:{port}")
    if not socks:
        return
    while not stop:
        for port, s in socks:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception as e:
                log("UDP", f"port {port} recv err {e}")
                continue
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            log("UDP", f"myport={port} FROM {addr[0]}:{addr[1]} len={len(data)}")
            log("UDP", f"  HEX {binascii.hexlify(data).decode()}")
            log("UDP", f"  ASC {asc}")
    for _, s in socks:
        s.close()

# ---------------- TCP poller ----------------
def adb(cmd, timeout=5):
    try:
        r = subprocess.run(["adb", "shell", cmd], capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return f"__ERR__ {e}"

def read_tcp():
    out = adb("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null", timeout=5)
    return out.splitlines()

def parse(line):
    p = line.split()
    if len(p) < 5 or not p[0].rstrip(':').isdigit():
        return None
    try:
        la, lp = p[1].split(':')
        ra, rp = p[2].split(':')
        st = p[3]
    except Exception:
        return None
    return la.lower(), int(lp, 16), ra.lower(), int(rp, 16), st

ST = {"01": "ESTAB", "02": "SYN_SENT", "06": "TIME_WAIT", "07": "CLOSE",
      "08": "CLOSE_WAIT", "0A": "LISTEN"}

def tcp_poller():
    seen = set()
    last = set()
    while not stop:
        lines = read_tcp()
        cur = set()
        for ln in lines:
            r = parse(ln)
            if not r:
                continue
            la, lp, ra, rp, st = r
            # v4-mapped v6 -> last 4 bytes are the address
            if len(la) == 32 and la.startswith("00000000000000000000000000000000FFFF"):
                la = la[24:32]
            if len(ra) == 32 and ra.startswith("00000000000000000000000000000000FFFF"):
                ra = ra[24:32]
            cur.add((la, lp, ra, rp, st))
            cam = CAM_HEX.get(ra) or CAM_HEX.get(la)
            phone = (la == PHONE_HEX or ra == PHONE_HEX)
            if cam and st != "0A":
                key = ("CAM", la, lp, ra, rp, st)
                if key not in seen:
                    seen.add(key)
                    role = "phone->cam" if la == PHONE_HEX else "cam->phone"
                    log("TCP", f"{role} {hex(lp)} -> {hex(rp)} "
                               f"state={ST.get(st,st)} cam={cam}")
            elif phone and st in ("01", "02") and ra not in ("00000000",):
                pass
        # report brand-new non-camera outbound from phone too
        for r in cur - last:
            la, lp, ra, rp, st = r
            if la == PHONE_HEX and st in ("01", "02") and CAM_HEX.get(ra) is None:
                if r not in seen:
                    seen.add(r)
                    try:
                        rip = ".".join(str(int(ra[i:i+2], 16)) for i in (6,4,2,0))
                    except Exception:
                        rip = ra
                    log("TCP", f"new outbound phone:{lp} -> {rip}:{rp} {ST.get(st,st)}")
        last = cur
        time.sleep(0.4)

# ---------------- main ----------------
duration = float(sys.argv[1]) if len(sys.argv) > 1 else 30
restart = "--restart" in sys.argv
tap = None
for a in sys.argv:
    if a.startswith("--tap="):
        tap = tuple(int(x) for x in a.split("=", 1)[1].split(","))

t1 = threading.Thread(target=udp_listener, daemon=True)
t2 = threading.Thread(target=tcp_poller, daemon=True)
t1.start(); t2.start()
log("MAIN", f"watching for {duration}s restart={restart} tap={tap}")

t0 = time.time()
did_restart = False
did_tap = False
beat = 0.0
while time.time() - t0 < duration:
    el = time.time() - t0
    if el - beat >= 5:
        beat = el
        log("MAIN", f"t+{el:.0f}s ...")
    if restart and not did_restart and el > 2:
        did_restart = True
        log("MAIN", "force-stopping + restarting com.hualai")
        subprocess.run(["adb", "shell", "am", "force-stop", "com.hualai"],
                       capture_output=True, timeout=10)
        time.sleep(1)
        subprocess.run(["adb", "shell", "monkey", "-p", "com.hualai", "-c",
                        "android.intent.category.LAUNCHER", "1"],
                       capture_output=True, timeout=15)
        log("MAIN", "app restarted")
    if tap and not did_tap and el > 10:
        did_tap = True
        log("MAIN", f"tapping {tap}")
        subprocess.run(["adb", "shell", "input", "tap", str(tap[0]), str(tap[1])],
                       capture_output=True, timeout=10)
    time.sleep(0.2)

stop = True
time.sleep(1)
log("MAIN", "done")
