#!/usr/bin/env python3
"""Handshake grabber: the server collects its own CALLING, so the user never runs a capture.

All of this reuses the byte-for-byte proven capture path:

  * `forge_call.py` proved (captured 2026-10-13) that answering a discovery
    probe from our own IP -- with a genuine camera's advert, only the P2P
    port field edited and the XOR checksum rebalanced -- makes the official
    app dial us instead of the camera.  The handshake bytes then arrive on a
    UDP socket we own, in the clear.  Plain stdlib sockets: no root, no
    sniffing, no APK patching.
  * `dump_frames.py` proved how captured frames must be grouped: the
    per-session word (CALLING word = session+0x10, `P2P_PROTOCOL.md` 5e)
    makes `hello` and `calling` valid only as one internally consistent
    group.

What the user sees: start the server with no `wire/p2p_frames.json` on file
and this thread goes to work by itself -- it shadows the cameras, waits for
the official app on any phone of the Wi-Fi to be opened on ONE camera, then
the frames arrive, the JSON freezes, impersonation stops, and the grid
starts streaming.  One captured CALLING streams every camera (JOURNAL Phase
9), so one tap is all it ever takes.

Scope note: the capture mechanics are the proven forge_call scheme in daemon
form; its in-server variant is wired to live cameras the first time the
official app is opened while the server runs.  Nothing written leaves this
machine (`wire/*` is git-ignored).
"""
import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # repo root

from analyze_calls import decrypt          # noqa: E402
from discover import BROADCAST_PORT, broadcast_addrs, build_probe  # noqa: E402
from mtp_frame import unwrap               # noqa: E402
from p2p_call import extract_tid           # noqa: E402

DISC_PORT = 8899          # we answer the app's probes as a "camera" would
PHONE_PORT = 8900         # the port broadcast_fd_init binds on the phone
HELLO_LEN, CALLING_LEN, AVC_LEN = 74, 128, 76
KIND = {HELLO_LEN: "hello", CALLING_LEN: "calling", AVC_LEN: "avstreamctl"}
FAKE_P2P_PORTS = [29000, 29101, 29173]   # proven first, then fallbacks


def own_ips():
    """Every local IPv4 address this host sends probes from (self-gate)."""
    out = {"127.0.0.1"}
    try:
        if sys.platform == "darwin":
            txt = subprocess.run(["ifconfig"], capture_output=True,
                                 timeout=3).stdout.decode("utf-8", "replace")
        else:
            txt = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True,
                                 timeout=3).stdout.decode("utf-8", "replace")
        for mo in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)\b", txt):
            out.add(mo.group(1))
    except Exception:
        pass
    return out


def _word_of(d):
    """The session word of a captured frame, or None if unreadable."""
    try:
        if len(d) == HELLO_LEN:
            r = unwrap(d)
            return struct.unpack_from("<I", r[0], 4)[0] if r else None
        if len(d) == CALLING_LEN:
            return struct.unpack_from("<I", decrypt(d), 28)[0]
        if len(d) == AVC_LEN:
            return struct.unpack_from("<I", decrypt(d), 56)[0]
    except Exception:
        return None
    return None


class Grabber(threading.Thread):
    """One impersonation pass, then freeze what arrived and stop clean."""

    def __init__(self, root,
                 on_done=None,
                 out_path=None,
                 probe_targets=None,   # override: plain IPs to probe (tests)
                 allow_self=False,     # tests: answer probes from ourselves
                 disc_port=None,       # tests: loopback-bound advert port
                 fake_port=None,       # tests: loopback-bound dial port
                 quiet=False):
        super().__init__(name="wire-grab", daemon=True)
        self.root = root
        self.out_path = out_path or os.path.join(root, "wire", "p2p_frames.json")
        self.on_done = on_done
        # WIREGRAB_PROBE_TARGETS="ip,ip" limits every probe (tests, smoke runs)
        env_t = os.environ.get("WIREGRAB_PROBE_TARGETS")
        self.probe_targets = (probe_targets or
                              (env_t.split(",") if env_t else None) or None)
        self.allow_self = allow_self
        # Tests run the whole arc inside 127.0.0.1.  Passing explicit ports
        # here binds those sockets to loopback ONLY: a live server shadowing
        # the same LAN holds "0.0.0.0" on the same ports, and on macOS two
        # SO_REUSEADDR binds of one port overlap deliveries -- synthetic test
        # frames could leak into a running grabber's capture (seen live), so
        # tests must never share ports with a real one.
        self.disc_port = DISC_PORT if disc_port is None else disc_port
        self.loop = disc_port is not None
        self.fake_port = FAKE_P2P_PORTS[0] if fake_port is None else fake_port
        self.quiet = quiet
        self._halt = threading.Event()
        self._lock = threading.Lock()
        self._own = own_ips()
        self.status = {"phase": "probing", "phone": None, "genuine": 0,
                       "frames": 0, "complete_tid": None,
                       "note": "no handshake on file yet"}

    # -- housekeeping ---------------------------------------------------
    def stop(self):
        self._halt.set()
        try:
            self.join(timeout=4.0)
        except RuntimeError:
            pass

    def say(self, note):
        if not self.quiet:
            print("[grab] %s" % note, flush=True)

    def _set(self, **kw):
        with self._lock:
            self.status.update(kw)
            return dict(self.status)

    def state(self):
        with self._lock:
            return dict(self.status)

    # -- phase A: clone every powered camera's discovery advert ----------
    def _genuine(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind EVERYTHING, not loopback: real cameras answer to the probe's
        # source address -- our LAN IP -- so a loopback-only bind would never
        # hear them.  (The loopback test reaches this socket through 127.0.0.1
        # as well; binding *:port matches both.)
        rx.bind(("0.0.0.0", 0))
        rx.setblocking(False)
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        probe = build_probe(rx.getsockname()[1])
        targets = self.probe_targets or clone_ready(broadcast_addrs())
        for bc in targets:
            try:
                tx.sendto(probe, (bc, BROADCAST_PORT))
            except OSError:
                pass

        replies = {}
        deadline = time.time() + 3.0
        while time.time() < deadline and not self._halt.is_set():
            sel_r, _, _ = select.select([rx], [], [], 0.3)
            if os.environ.get("WIREGRAB_TRACE"):
                print("  [t-genuine] select(): rx=%r sel=%r" % (rx.getsockname(), sel_r),
                      flush=True)
            for s in sel_r:
                try:
                    data, addr = s.recvfrom(4096)
                except OSError:
                    continue
                if os.environ.get("WIREGRAB_TRACE"):
                    print("  [t-genuine] got %d B from %s, head=%s"
                          % (len(data), addr[:2], data[:4].hex()), flush=True)
                if len(data) == 138 and data[0] == 0x70 and data[1] == 0x03:
                    replies.setdefault(addr[0], data)
        rx.close()
        tx.close()
        return replies

    # -- phase B: shadow the cameras until the app hands us the handshake
    def _shadow(self, genuine):
        clones = []
        for ip, data in sorted(genuine.items()):
            forged = bytearray(data)
            real_port = struct.unpack_from("<I", data, 44)[0]
            delta = real_port ^ self.fake_port
            chk = struct.unpack_from("<I", data, 16)[0]
            struct.pack_into("<I", forged, 44, self.fake_port)
            struct.pack_into("<I", forged, 16, chk ^ delta)
            clones.append(bytes(forged))
            self.say("cloned the camera at %s (real P2P port %d -> ours: %d)"
                     % (ip, real_port, self.fake_port))

        disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        disc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        disc.bind(("127.0.0.1" if self.loop else "0.0.0.0", self.disc_port))
        disc.setblocking(False)

        p2p = None
        for p in ((self.fake_port,) if self.loop else FAKE_P2P_PORTS):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1" if self.loop else "0.0.0.0", p))
                s.setblocking(False)
                p2p = s
                break
            except OSError as e:
                self.say("could not bind %d (%r); trying the next port" % (p, e))
        if p2p is None:
            self.say("all candidate P2P ports are busy; grabbing is off")
            disc.close()
            return False

        cap = [disc, p2p]
        held = []
        port_name = {p2p.getsockname()[1]: "fake-p2p"}
        # also bind the cameras' REAL P2P ports: if the phone prefers the port
        # of the record paired with our IP, its CALLING still lands here.
        for data in genuine.values():
            p = struct.unpack_from("<I", data, 44)[0]
            if p in port_name:
                continue
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", p))
                s.setblocking(False)
                cap.append(s)
                held.append(s)
                port_name[p] = "camera-port-%d" % p
            except OSError:
                pass

        # the addresses the forged adverts go to: the phone once known, else
        # the subnet broadcasts (and, in tests, the probe_targets host)
        blast_targets = self.probe_targets or [b for b in broadcast_addrs()
                                               if b not in self._own]

        groups = {}            # (tid, word) -> {kind: hex}
        phone = None
        last_send = 0.0
        landed = False
        noise = {"n": 0, "t": 0.0}

        def note(msg, data, addr, port):
            # rate-limited visibility for everything that is NOT a handshake
            # frame; if a phone ever dials us, the server must say so with
            # size, source and first bytes instead of dropping it silently.
            noise["n"] += 1
            if noise["n"] <= 10 or time.time() - noise["t"] > 2.0:
                noise["t"] = time.time()
                self.say("%s: %d B on :%d from %s head %s"
                         % (msg, len(data), port, addr[0], bytes(data[:10]).hex()))
        try:
            self.say("shadowing the cameras: open the official app on any "
                     "phone of this Wi-Fi and view ONE camera once")
            while not self._halt.is_set() and not landed:
                if time.time() - last_send >= 0.002:
                    last_send = time.time()
                    for forged in clones:
                        for dest in ([phone] if phone else blast_targets):
                            try:
                                disc.sendto(forged, (dest, PHONE_PORT))
                            except OSError:
                                pass
                r, _, _ = select.select(cap, [], [], 0.2)
                for s in r:
                    try:
                        data, addr = s.recvfrom(65535)
                    except OSError:
                        continue
                    if s is disc:
                        # the phone probes; answer instantly, be the first
                        if len(data) == 28 and data[0] == 0x70 and \
                                data[1] == 0x02:
                            sip = addr[0]
                            if not self.allow_self and sip in self._own:
                                continue     # the server's own discovery: no
                            if phone != sip:
                                phone = sip
                                self.say("phone found at %s: answering its "
                                         "probes instantly" % phone)
                            try:
                                for forged in clones:
                                    disc.sendto(forged, (sip, PHONE_PORT))
                            except OSError:
                                pass
                            last_send = time.time()
                        else:
                            note("non-probe on the advert port", data, addr,
                                 self.disc_port)
                        continue

                    ln = len(data)
                    d = bytes(data)
                    # Self-sourced frames are never a phone: this machine's
                    # own discovery, or a test running here.  A loopback test
                    # once leaked into a live grabber and froze a synthetic
                    # capture; the self gate belongs on this intake too.
                    if not self.allow_self and addr[0] in self._own:
                        continue
                    if ln not in KIND:
                        note("non-handshake inbound", data, addr,
                             s.getsockname()[1])
                        continue      # later session traffic we do not need
                    tid = extract_tid(d)
                    w = None if tid is None else _word_of(d)
                    if tid is None or w is None:
                        note("tid/word UNREADABLE frame", data, addr,
                             s.getsockname()[1])
                        continue
                    self._set(frames=self.status["frames"] + 1)
                    self.say("handshake frame captured (%s of tid ...%s)"
                             % (KIND[ln], str(tid)[-4:]))
                    groups.setdefault((tid, w), {})[KIND[ln]] = d.hex()
                    for (t, w0), slot in groups.items():
                        if len(slot) == len(KIND):
                            self._freeze(t, w0, slot)
                            landed = True
                            break
        finally:
            disc.close()
            p2p.close()
            for s in held:
                s.close()
        return landed

    # -- phase C: freeze what arrived, same format as dump_frames.py ----
    def _freeze(self, tid, word, slot):
        out = {
            "_comment": (
                "P2P handshake frames captured by this server itself "
                "(wiregrab.py: discovery impersonation, as in forge_call.py). "
                "word = session+0x10 (P2P_PROTOCOL.md 5e); hello and calling "
                "MUST share one word.  This file is machine-local."
            ),
            "devices": {str(tid): {
                "word": "0x%08x" % word,
                "frames": dict(slot),
                "complete": sorted(slot) == ["avstreamctl", "calling", "hello"],
            }},
        }
        os.makedirs(os.path.dirname(self.out_path) or ".", exist_ok=True)
        tmp = self.out_path + ".part"
        with open(tmp, "w") as f:
            json.dump(out, f, indent=1, sort_keys=True)
        os.replace(tmp, self.out_path)
        self._set(phase="done", complete_tid=str(tid))
        self.say("freezing the handshake of tid ...%s -> %s"
                 % (str(tid)[-4:], self.out_path))

    # -- thread body ------------------------------------------------------
    def run(self):
        try:
            env_t = os.environ.get("WIREGRAB_PROBE_TARGETS")
            if self.probe_targets:
                self.say("armed; probing %s%s"
                         % (self.probe_targets,
                            " (set by WIREGRAB_PROBE_TARGETS)"
                            if env_t else ""))
            else:
                self.say("armed; probing the derived subnet broadcasts (%d)"
                         % len(broadcast_addrs()))
            while not self._halt.is_set():
                genuine = self._genuine()
                if not genuine:
                    self.say("no cameras answered yet; retrying every 5 s "
                             "(the app does not need to be running)")
                    self._halt.wait(5.0)
                    continue
                self._set(genuine=len(genuine))
                landed = self._shadow(genuine)
                if landed:
                    self._set(phase="done")
                    if self.on_done:
                        try:
                            self.on_done(dict(self.status))
                        except Exception:
                            pass
                    return
                if self._halt.is_set():         # shutting down / done elsewhere
                    return
                self._set(phase="waiting")
                self.say("nothing landed on this pass; retrying in 5 s")
                self._halt.wait(5.0)
        except Exception as e:
            self._set(phase="failed")
            self.say("grabber stopped: %r" % e)


def clone_ready(addrs):
    """Skip nil/non-broadcast values so the probe never aims at one host."""
    return [a for a in addrs if a and a != "0.0.0.0"]


if __name__ == "__main__":
    Grabber(os.path.dirname(os.path.abspath(sys.argv[0])) or ".").start()
    time.sleep(float(sys.argv[1]) if len(sys.argv) > 1 else 120.0)
