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

Requirements: **Python 3.8+** (standard library only — no pip packages) and
**`ffmpeg`** on `PATH`. That's it; the browser does the rest.

Discovery is automatic: the server derives the subnet broadcast at runtime
and finds cameras at every start. Before anything streams, it also needs
**one camera-side handshake** (`hello` / `calling` / `avstreamctl` frames in
`wire/p2p_frames.json`) — and **the server collects that one by itself**:
`wiregrab.py` runs in the server, shadows the cameras, and the first time the
official Wyze app on any phone of the Wi-Fi views ONE camera, the handshake
bytes land in the server, freeze into `wire/p2p_frames.json` (git-ignored),
impersonation stops and the grid streams permanently. No scripts to run, no
root, no APK patching — one tap in the app you already have.

Everything capture-related stays local (`wire/*` is git-ignored):
`wire/README.md` documents what the grabber freezes plus the manual
recipe (`forge_call.py`, `dump_frames.py`) for anyone who prefers the
command line. Why a capture instead of pure synthesis: JOURNAL Phase 27
measured it — a synthesized CALLING passes discovery but six handshakes
against two live cameras delivered zero video frames; replay of a captured
handshake streams every camera (Phase 17). If the phone-side of the auto
grab misses the window, the manual recipe is documented and byte-equivalent.
2. *(optional)* **`wyze_devices.json`** at the repo root gives tiles their real
   nicknames; the cache format is the same JSON the Wyze cloud endpoints return
   for `get_device_list`. Without it the UI just shows generic camera labels.
3. *(optional)* **`wyze-cam-stream/config.json`** only matters if you want to
   exercise the cloud-API side (`wyze_client.py`); the LAN streaming path never
   reads it.

Then:

```sh
python3 wyze-cam-stream/server.py --port 8080
# open http://localhost:8080  (bind 0.0.0.0 with --host to reach it from phones)
```

What works: simultaneous 1080p H.264 live view of all discovered cameras
(square 2×2 grid), delay measured per tile, mu-law audio listen (+gain),
two-way talk (push-to-talk AMR), snapshots, and focus mode — fullscreening one
camera drops the other cameras' sessions server-side after a 3 s grace, and
they come back when you return to the grid. Cameras that are off simply show
*camera offline*; the rest keep streaming.

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
