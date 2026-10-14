#!/usr/bin/env python3
"""Show the Wyze app's live sockets, decoded.

Reads /proc/net/{tcp,udp} from the phone via adb, filters by uid, and prints
decoded local/remote endpoints + state.  Used to answer "where is the app's
video actually coming from: our relay, or a direct LAN link to the camera?".
"""
import re
import subprocess
import sys

UID = sys.argv[1] if len(sys.argv) > 1 else "10317"
STATES = {"01": "ESTAB", "02": "SYN_SENT", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "0A": "LISTEN"}


def dec(addr):
    ip_hex, port_hex = addr.split(":")
    ip = ".".join(str(int(ip_hex[i:i + 2], 16)) for i in (6, 4, 2, 0))
    return "%s:%d" % (ip, int(port_hex, 16))


for table in ("tcp", "udp"):
    out = subprocess.run(["adb", "shell", "cat", "/proc/net/%s" % table],
                         capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) < 8 or f[7] != UID:
            continue
        rows.append((dec(f[1]), dec(f[2]), STATES.get(f[3], f[3])))
    print("=== %s (%d sockets for uid %s)" % (table.upper(), len(rows), UID))
    for loc, rem, st in rows:
        print("   %-24s -> %-24s %s" % (loc, rem, st))
