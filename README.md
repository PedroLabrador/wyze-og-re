# wyze-re — Wyze Cam OG LAN P2P research

Reverse-engineering notes for the **Wyze Cam OG** (Gwell/Kalay GC1 platform) wire
protocol, plus **wyze-cam-stream** — a proof-of-concept Python server that
streams and talks to the cameras straight from your **LAN**, with no Wyze cloud
account, no phone app, and no bundled Wyze SDK left on the bridge.

Everything here was done from the outside: decompiled app(s), captured LAN
traffic, and a lot of reading. The notes record the full journey — including the
dead ends — so nobody has to re-derive them.

## Why this repo exists

[docker-wyze-bridge](https://github.com/mrlt8/docker-wyze-bridge) is the
community's go-to for getting Wyze cameras into RTSP/HLS/WebRTC. But the bundled
Wyze SDK it depends on is aging, and the **Wyze Cam OG** was never a first-class
citizen of that SDK's cloud login path. We wanted the OG's *live stream and
controls* to work purely over the LAN like the older cameras do.

So we went two steps down: **(1)** reverse the phone app's camera protocol end
to end (this repo — discovery, the CALLING handshake, KCP transport, the AV
control channel, RC5 key derivation, two-way talk), **(2)** plug the result into
the bridge as a standalone LAN engine:

> **Fork implementation:** https://github.com/PedroLabrador/docker-wyze-bridge/tree/og-lan-engine#wyze-cam-og-lan-engine
> — a LAN P2P engine adapter over the protocol described here.
> **It is usable but needs a lot of work** (re-encode pipeline, per-model
> tuning, test coverage). Treat it as a working prototype, not a drop-in
> replacement.

## What you need to run this

* A computer on the same Wi-Fi as the cameras (macOS or Linux).
* **Python 3.8+** (standard library only -- no pip packages) and **`ffmpeg`**
  on `PATH`.
* A phone with the Wyze app on the same Wi-Fi, signed in to the account that
  owns the cameras.
* One camera you can unplug for a few minutes.
* Admin rights on the computer, for two `sudo` commands.

The server itself never talks to the cloud. The phone is used only while making
the capture (steps 1 and 6).

### First setup, start to finish

The only manual step in the project is collecting **one** camera-side
handshake (`hello` / `calling` / `avstreamctl`) into `wire/p2p_frames.json`.
One capture serves every OG on the LAN because the CALLING is not bound to a
device, and the file never leaves the machine (`wire/*` is ignored by git).

**0. Get the code and check the requirements.**

```sh
git clone https://github.com/PedroLabrador/wyze-og-re.git
cd wyze-og-re
python3 --version        # 3.8 or newer
ffmpeg -version | head -1
```

**1. Stream the target camera once from the phone.** Open the Wyze app, tap
that camera, wait until you see live video, then leave the live view. This is
what teaches the app the camera's LAN address; step 6 relies on that memory.
Change nothing in the app.

**2. Find the camera's address and P2P port.** With the camera plugged in and
powered on, run:

```sh
python3 forge_call.py 20
```

Wait about 15 seconds. One line per camera appears:

```
[clone] 192.168.77.50       port 50413  -> 29000  chk 0x... mac=... id=...
```

Write down the IP address and the **first** port number (the one before
`->`). `-> 29000` is the fake port this tool uses for the other capture route;
ignore it.

If it prints `captured no genuine replies`, the camera is off, on another
network, or the computer is on a different Wi-Fi or VLAN. Fix that first.

**3. Unplug the chosen camera.** It must be completely off, LED included.

**4. Give the computer the camera's address.** macOS:

```sh
sudo ifconfig en0 alias 192.168.77.50 255.255.255.0
```

`en0` is usually the Wi-Fi interface; `route -n get default` prints the real
name under `interface:`. Linux:

```sh
sudo ip addr add 192.168.77.50/24 dev wlan0
```

Confirm it took: `ifconfig en0 | grep 192.168.77.50` (macOS) or
`ip addr show wlan0` (Linux).

**5. Listen on the camera's port.** Leave this terminal running:

```sh
python3 forge_call.py 600 --listen=50413
```

It prints:

```
[listen] discovery :8899   fake p2p :29000   camera ports [50413]   for 600 s
```

The number in `camera ports` must match step 2. If it is empty or different,
stop and correct `--listen=`.

**6. Force-stop the app, then open the camera.** The force-stop throws away
the old session so the app builds a new one:

* Android: Settings -> Apps -> Wyze -> Force stop.
* iPhone: swipe up from the bottom and flick the Wyze card away.

Open the app and tap the same camera. Keep it on screen.

**7. Watch the terminal.** Within a few seconds to a minute, three lines
should appear:

```
[ 12.4s] *** INBOUND [camport:50413] from 192.168.77.20:46860  len=74 ***
[ 12.5s] *** INBOUND [camport:50413] from 192.168.77.20:46860  len=128 ***
[ 12.6s] *** INBOUND [camport:50413] from 192.168.77.20:46860  len=76 ***
```

74 bytes is `hello`, 128 is `calling`, 76 is `avstreamctl`. Each frame is also
saved under `/tmp/forge_in_*.bin`.

* Only the 76-byte line: the app reused an open session. Force-stop it again
  (step 6) and reopen the camera.
* Nothing at all: check the alias (step 4), the port (step 5), that the
  camera is really off, and that this phone streamed this camera in step 1.
* The app shows the camera as offline and will not open it: wait a minute and
  tap again. The address is cached, but the tile can be hidden once the cloud
  notices the camera is gone.

**8. Freeze the capture.** In a second terminal, from the repo root:

```sh
python3 dump_frames.py
```

It prints `wrote .../wire/p2p_frames.json` and one `tid=...` line per group it
kept. A line ending in `<-- INCOMPLETE` is missing one of the three frames;
the server cannot replay it, so repeat step 6 and capture again. Frames from
different sessions cannot be mixed -- the session word must match.

**9. Undo the address, power the camera back on, start the server.**

```sh
sudo ifconfig en0 -alias 192.168.77.50        # macOS
# sudo ip addr del 192.168.77.50/24 dev wlan0  # Linux

python3 wyze-cam-stream/server.py --port 8080
# open http://localhost:8080  (bind 0.0.0.0 with --host to reach it from phones)
```

All cameras on the LAN should appear. Restart the server after changing
`wire/p2p_frames.json`.

## What works

Simultaneous 1080p H.264 live view of all discovered cameras
(square 2×2 grid), delay measured per tile, mu-law audio listen (+gain),
two-way talk (push-to-talk AMR), snapshots, and focus mode — fullscreening one
camera drops the other cameras' sessions server-side after a 3 s grace, and
they come back when you return to the grid. Cameras that are off simply show
*camera offline*; the rest keep streaming.

## If you would rather let the server try

`wiregrab.py` runs inside the server and answers the phone's discovery probe
as a camera. It produced the 2026-10-13 capture on a freshly installed app,
but current app builds keep using the real camera's reply and ignore the
forged one (JOURNAL Phase 30, measured from the phone's own traffic). It
costs nothing to leave on: start the server, open one camera in the app, and
if `wire/p2p_frames.json` appears you are done. If nothing appears after a
few minutes, use the takeover above.

## Optional files

* **`wyze_devices.json`** at the repo root gives tiles their real nicknames;
  the cache format is the same JSON the Wyze cloud endpoints return for
  `get_device_list`. Without it the UI just shows generic camera labels.
* **`wyze-cam-stream/config.json`** only matters if you want to exercise the
  cloud-API side (`wyze_client.py`); the LAN streaming path never reads it.

## Why a capture instead of pure synthesis

Everything capture-related stays local (`wire/*` is ignored by git). JOURNAL
Phase 27 measured the alternative: a synthesized CALLING passes discovery but
six handshakes against two live cameras delivered zero video frames; replay of
a captured handshake streams every camera (Phase 17).

Privacy by construction: live credentials (`wyze_token.json`, captures,
keystores) are git-ignored; if you commit anything, the ignore list will yell
first (see `.gitignore`).

Privacy by construction: live credentials (`wyze_token.json`, captures,
keystores) are git-ignored; if you commit anything, the ignore list will yell
first (see `.gitignore`).

## Cheap starting points ( newcomer map)

| doc | what it covers |
|---|---|
| [`JOURNAL.md`](JOURNAL.md) | chronological attempt log — every hypothesis, what happened, what disproved it |
| [`wyze-cam-stream/REVERSE_ENGINEERING.md`](wyze-cam-stream/REVERSE_ENGINEERING.md) | master notes: auth, signature, P2P init, verdict board of confirmed/disproved leads |
| [`wyze-cam-stream/P2P_PROTOCOL.md`](wyze-cam-stream/P2P_PROTOCOL.md) | the wire format itself, byte by byte |
| [`wyze-cam-stream/STATUS.md`](wyze-cam-stream/STATUS.md) | current state, open problems |
| root-level `*.py` | the probe & RE tooling, one experiment per file (names explain themselves; the doc sections point to the relevant ones) |

## Legal / responsible notes

* Target of the research: your **own** hardware on your **own** LAN.
* No credentials, camera identifiers, or captures are published; every
  consumer must capture their own.
* This is interop research — expect hardware/firmware changes to break things.
