# Wire captures — Gwell/Kalay P2P handshake

**One capture per machine, reused for every camera.** `p2p_frames.json` holds the
app's `hello` / `calling` / `avstreamctl` frames. The CALLING is not bound to a
device, so the same file streams every OG camera on the LAN. The server needs it
before anything plays, and it never leaves the machine (`wire/*` is ignored).

## Which capture route to use

| route | what it does | status |
|---|---|---|
| **takeover** (below) | the app dials the camera's known `IP:port`; power the camera off and let this machine own that address | works with the current app builds |
| `wiregrab.py` in the server, or `forge_call.py` | answers the phone's discovery probe as a camera and waits to be dialed | produced the 2026-10-13 capture on a freshly installed app; current builds keep using the real camera's reply and ignore it (JOURNAL Phase 30) |

The takeover exists because a running app already knows where each camera is,
so a second advert for the same device loses to the real camera's own reply.
Removing the competitor is reliable; racing its firmware from a Python process
is not.

## Takeover capture

1. Let the phone's app stream the target camera once on this Wi-Fi, so it has
   learned that camera's `LAN IP:port`.
2. With the camera **on**, read the endpoint off a genuine reply:

   ```sh
   python3 ../forge_call.py 20
   # [clone] <camera-ip>   port <p2p-port>  ...
   ```

3. Power that camera **off**.
4. Give this machine the camera's address (adjust the interface):

   ```sh
   sudo ifconfig en0 alias <camera-ip> 255.255.255.0
   ```

5. Listen on the camera's P2P port. The camera is off, so nothing can be
   cloned; `--listen` binds the port by number:

   ```sh
   python3 ../forge_call.py 600 --listen=<p2p-port>
   ```

6. Force-stop the app and open that camera again. It dials
   `<camera-ip>:<p2p-port>` — this machine — and every frame prints and lands
   in `/tmp/forge_in_<port>_<time>_<seq>.bin`:

   ```
   [ 87.9s] *** INBOUND [camport:<p2p-port>] from <phone-ip>:<src-port> len=76 ***
   ```

   A session built from scratch delivers three frames: `hello` (74 B),
   `calling` (128 B) and `avstreamctl` (76 B). If only the 76-byte `7eb9`
   arrives, the app reused an already-open session — force-stop it first.

7. Freeze the frames:

   ```sh
   python3 ../dump_frames.py        # groups one internally-consistent
                                    # (tid, session word) set per camera
   ```

8. Undo the address, then power the camera back on:

   ```sh
   sudo ifconfig en0 -alias <camera-ip>
   ```

The same steps work with the official app on any phone: the route depends on
the app's endpoint cache, not on the APK being patched.


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
