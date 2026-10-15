#!/usr/bin/env python3
"""Tap through Android UI dialogs by button text, via adb + uiautomator.

PCAPdroid shows a consent dialog and Android shows a VPN dialog before the
capture starts; driving them from adb needs the button bounds.  This dumps the
UI hierarchy, finds any node whose text matches a whitelist, and taps its
centre.  Used to start PCAPdroid captures unattended.

Usage: python3 adtap.py [seconds] [label1 label2 ...]
"""
import re
import subprocess
import sys
import time

TMP = "/sdcard/_adtap.xml"


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True).stdout


def dump():
    sh("adb", "shell", "rm", "-f", TMP)
    sh("adb", "shell", "uiautomator", "dump", TMP)
    return sh("adb", "shell", "cat", TMP)


def nodes(xml):
    out = []
    for m in re.finditer(r"<node\b[^>]*>", xml):
        tag = m.group(0)
        t = re.search(r'text="([^"]*)"', tag)
        r = re.search(r'resource-id="([^"]*)"', tag)
        b = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', tag)
        if not b:
            continue
        x1, y1, x2, y2 = map(int, b.groups())
        out.append((t.group(1) if t else "",
                    r.group(1) if r else "",
                    (x1 + x2) // 2, (y1 + y2) // 2))
    return out


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 12.0
    wanted = sys.argv[2:] or ["PERMITIR", "ACEPTAR", "Aceptar", "Permitir",
                              "OK", "CONFIRMAR", "Continuar", "start",
                              "INICIAR"]
    end = time.time() + secs
    tapped = set()
    while time.time() < end:
        xml = dump()
        did = False
        for text, rid, x, y in nodes(xml):
            key = (text, rid)
            if key in tapped:
                continue
            if text in wanted:
                sh("adb", "shell", "input", "tap", str(x), str(y))
                print("tapped %r @ (%d,%d)" % (text, x, y), flush=True)
                tapped.add(key)
                did = True
                time.sleep(1.5)
                break
        if not did:
            time.sleep(1.0)


if __name__ == "__main__":
    main()
