# Wire captures — Gwell/Kalay P2P list-server exchange

**The server does this capture itself now.** `wiregrab.py` runs inside
`wyze-cam-stream/server.py`: when `p2p_frames.json` is missing it shadows
the cameras, and the first time the official app on any phone of the Wi-Fi
views ONE camera the handshake freezes here, impersonation stops, and the
grid streams. The recipes below are the manual equivalent — same
impersonation (`forge_call.py`), same freezing (`dump_frames.py`) — kept
for anyone who prefers it or for debugging.

A zero-capture synthesis, in contrast, is a measured dead end (2026-10-18,
from the byte-differential map of three real captures): discovery answered
every time but the hardware rejected all six handshake variants with zero
video frames (JOURNAL Phase 27). Until that extra validated field is
isolated, one faithful capture — automatic or manual — is how every machine
produces the `p2p_frames.json` it needs. Captures stay **local**
(`wire/*` is git-ignored).

Captured **2026-10-12**. This is the ground truth that unblocked the wire protocol
(see `../wyze-cam-stream/P2P_PROTOCOL.md` §3a).

## How

1. Patch `GWApi.GWellP2PUrl` (smali, `getBaseServerUrl()` official branch) to `"|192.168.77.13"`.
2. `apktool b` → sign with `../wyze_debug.keystore` (alias `wyze`, pass `android`,
   `--ksKeyPass android`) → `adb install -r`.
3. `python3 ../cap_listsrv2.py 51701 110` listens on UDP **and** TCP 51701.
4. Restart the app; it reaches the home screen after ~45 s, then fires the list request.

## Files

The table below describes the local artifacts **you** generate during the pass; none of
them are committed to this repo (`.gitignore` covers all of `wire/*`).

| file | what |
|---|---|
| `list_request_app.hex` | the app's real `LIST_REQUEST`, 40 bytes, identical on every retransmit and across app restarts |
| `list_request_app_asc.txt` | same, with ASCII rendering |
| `list_resp_raw.hex` | the genuine server's reply from `18.118.90.161:51701`, 176 bytes |
| `list_resp_decrypted.hex` | same after RC5-32/6/8 LE decrypt (header + full payload) |
| `list_resp_decrypted.txt` | annotated dump of the decrypted response |
| **`p2p_frames.json`** | **the camera-side handshake frames** — per TID, one internally-consistent group of `hello` (74 B) / `calling` (128 B) / `avstreamctl` (76 B), hex-encoded. Frozen by `../dump_frames.py` so `../p2p_call.py` works from a clean checkout. |

### `p2p_frames.json` — read this before editing it

Captured **2026-10-13** by `../forge_call.py` (a discovery-reply impersonator that makes the
app dial the Mac instead of the camera). The field `word` is `session+0x10`
(`P2P_PROTOCOL.md` §5e) and it is **random per session**: the same TID appears with
`0xef34cbd9` in some captures and `0x7be6cb9a` in others. The camera looks the session up by
that word, so **`hello` and `calling` must be re-grouped together if you ever regenerate this
file** — `dump_frames.py` does that grouping for you. Do not hand-merge frames from different
captures.

## Verification

`../listreq.py`'s `build_list_request()` reproduces `list_request_app.hex` **byte for byte**.
`../probe_real.py` sends these bytes to the live server and prints the response.

## Secrets note

These frames contain only the app's P2P terminal IDs, no credentials. Live OAuth tokens are
**not** stored in this repo (see `.gitignore`; rotate anything you captured when done).
