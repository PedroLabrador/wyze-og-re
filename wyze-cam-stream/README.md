# Wyze Cam Stream Server

A local web server that streams **all** of your Wyze Cam OG cameras into a
browser at once — grid, fullscreen, snapshot and two-way talk — with **no Wyze
cloud, no login, no subscription, no 1-camera limit**.  It speaks the camera's
own LAN P2P protocol, which this repo reverse-engineered end to end
(`../JOURNAL.md`, `REVERSE_ENGINEERING.md`).

## Run it

Requirements: **Python 3.8+** (standard library only — no pip installs) and
**`ffmpeg`** on `PATH`.  Nothing else.

On Windows, also allow **`python.exe` inbound UDP** in Windows Defender
Firewall once (Private profile) — the cameras answer discovery inbound; see
the [Windows](#windows) section below.

```bash
cd wyze-cam-stream
python3 server.py                 # http://127.0.0.1:8080
python3 server.py --port 9000     # pick a port
python3 server.py --discover      # scan the LAN once and exit
```

At startup the server **broadcasts on the LAN itself** (three retries) and
brings up a 2×2 grid — one column on a phone — for every camera that answers.
No names, no cloud, no `wyze_devices.json` needed; cameras are labelled
`Camera <id>` unless the optional nickname cache exists (below).  Powered-off
cameras sit in discovery backoff; the rest start streaming the moment the
browser opens.

### Windows

The LAN protocol is platform-neutral, but two Windows defaults can make the
cameras look absent.  Run `python server.py --discover` first: it prints the
local IPv4 addresses, the broadcast target per adapter, whether `ffmpeg` is
on `PATH`, every probe reply, and — on the last attempt — also sweeps the
local /24 with unicast probes.

* **Firewall.** Discovery is outbound UDP to `:8899`, but the **answer** is
  inbound UDP to an ephemeral port.  Windows Defender Firewall blocks that by
  default for an unknown program.  When the "allow access" prompt appears,
  allow **Private** networks; if it never appeared (or you clicked Cancel),
  run once in an *elevated* PowerShell, with the real `python.exe` path
  printed by `--discover`:

  ```powershell
  New-NetFirewallRule -DisplayName "wyze-cam-stream" -Direction Inbound `
    -Program "C:\Path\To\python.exe" -Protocol UDP -Action Allow -Profile Private
  ```

  Also confirm the adapter profile is Private:
  `Get-NetConnectionProfile`, then
  `Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private`.

* **Broadcast routing.** Windows has no `ip` command, so older builds fell
  back to a single `255.255.255.255` probe.  With a VPN, Hyper-V/WSL or
  VirtualBox adapter present, that packet often leaves through the wrong
  interface.  `discover.py` now derives each adapter's subnet broadcast from
  `ipconfig` (values only, so localised Windows works).  If it still finds
  nothing, disconnect the VPN and retry; `--discover`'s unicast sweep tells
  you whether the block is the broadcast path or the return path.

Use `python server.py` (on Windows `python3` usually does not exist).  A
timeout pinging a camera's IP with the PC and camera on the same subnet
points at the firewall or at AP/client isolation on the router.

### The handshake: the server grabs its own capture

Discovery is automatic, and so is the handshake. The server replays a
captured `CALLING` from `wire/p2p_frames.json`; a clean checkout does not
carry that file (git-ignored), so `wiregrab.py` — a thread inside the server —
arms itself instead: it shadows the cameras on the LAN and the first time the
official Wyze app on **any phone of this Wi-Fi** views ONE camera, that
phone's handshake walks into the server, freezes to `wire/p2p_frames.json`,
impersonation stops and the grid streams. One tap, once; no scripts, no
root, no APK patching. The phone takes part over the network only — it
stays wherever it is on the Wi-Fi, no USB, no adb, nothing ties it to the
PC. Steps:

* what the grabber does + what it freezes: [`wire/README.md`](../wire/README.md)
* background: `REVERSE_ENGINEERING.md` §5 (CALLING, RC5, KCP)
* why the capture cannot be replaced by synthesis: `../JOURNAL.md` Phase 27 —
  a zero-capture synthesized CALLING was tested against two live cameras;
  discovery answered every time, six handshakes produced **zero** video
  frames, so the honest conclusion is that the cameras validate more than
  the captures alone reveal.
* optional manual route: run `forge_call.py` + `dump_frames.py` yourself;
  byte-equivalent to what the grabber harvests.

Optional extras, never committed, all read if present:

| file | gives you |
|---|---|
| `../wyze_devices.json` | real camera nicknames (JSON from the cloud `get_device_list`) |
| `config.json` | only the cloud-API side (`wyze_client.py`); the LAN stream path never reads it |

## What works

* **Grid + fullscreen**: all cameras on one connection; focusing one camera
  stops the others (the P2P session is exclusive) and frees the camera for the
  official app.
* **Two-way talk** to a camera, **listen** to a camera, **snapshot** (client-side
  encode of the canvas), and per-tile live fps/lag/staleness badges — including
  an honest "streaming over a frozen picture" word when the worker stalls.
* With no viewer connected, the server stops decoding instead of streaming to
  nobody; opening the page brings the grid back cold in ~1–2 s.

Measured with all four cameras live for 25 s: **1992 frames, 70 MB, zero
dropped** (`pub == served` on every camera) — see `../JOURNAL.md` Phase 17.

## HTTP surface

| Route | What it does |
|---|---|
| `GET /` | the grid UI |
| `GET /api/state` | cameras + per-camera status/fps/error/talk state |
| `POST /api/discover` | rescan the LAN |
| `GET /feed` | **every camera on one connection** — what the page actually uses; `?focus=<tid>` narrows it to one camera |
| `GET /stream/<tid>.mjpg` | multipart MJPEG for one camera (scripting/fallback) |
| `GET /audio/<tid>.wav?gain=N` | 16 kHz mono PCM16 audio (`gain` 1–64) |
| `GET /pcm/<tid>.pcm` | raw PCM of the same audio |
| `GET /snapshot/<tid>.jpg` | newest decoded JPEG as a download |
| `POST /api/talk/start` / `stop` | hold-to-talk: `{"tid": N, ...}` fed PCM16 frames |
| `GET /probe`, `GET /api/micprobe` | small diagnostics used by `../JOURNAL.md` phases |

The `/feed` framing is a 20-byte header then the JPEG —
`<Q tid><Q publish-ms><I length>` — so the page can subtract the publish time
from its own clock and print the **true end-to-end delay** in each tile's
footer.

`/feed` exists because Chrome allows only **six** HTTP/1.1 connections per
origin.  One MJPEG socket per camera held four of them forever (`/api/state`
polls and the snapshot button sat in "pending" — that was the "slow page").  Now
the page holds one `/feed` socket plus one `<audio>` per camera you switch on,
reads it with `fetch().body.getReader()`, paints each camera into its own
`<canvas>`, and re-encodes snapshots from that canvas locally — no extra
request.  See `../JOURNAL.md` Phase 17.

Per camera the pipeline is:

```
discover -> CALLING -> meter_ack -> KCP -> AvStreamCtl (inside KCP)
        -> RC5-ECB decrypt (key = CALLING[120:128]) -> H.264 -> ffmpeg -> MJPEG
```

**Why no auth is needed** (each verified — `../JOURNAL.md` Phase 9):
discovery is a LAN broadcast the cameras answer unconditionally; the CALLING
frame is a bare UDP packet with no camera-bound field, so *any captured CALLING
streams any camera* (the capture itself is session-bound and stays on your
disk); and KCP/RC5 are negotiated inside that session with a key we supply.  The
`accessToken` / IOTC credentials the app fetches from `regist_gw_user` are never
used here.

## Historical record: the static-analysis trail (superseded)

Everything below this line is the **original static-analysis write-up** of the
app's cloud/auth structure (by reverse-engineering the
`com.hualai_2.50.7.487` APK).  It is kept as documented evidence of how the
official app works — **not** as the build path: the live stream does **not** use
KVS (verdict D1) and the login/signature findings were superseded by
`REVERSE_ENGINEERING.md` §1–§2.  Read it to understand the app; run the server
via the quick start above.

### Server topology — `assets/HL_ADDR`

```
URL_BASE_OFFICIAL = https://api.wyzecam.com/app/
URL_BASE_TEST     = https://test-api.wyzecam.com/app/
URL_PRE_DEPLOYMENT= https://beta-api.wyzecam.com/app/
```

### Per-endpoint secrets — `assets/HL_API_URL` (paths) + `assets/HL_API_SV` (secrets)

```
SC                       = 000102030405060708090a0b0c0d0e0f   (app key)
SC_KVS / SC_OLD          = "<REDACTED>"   (KVS app key)
URL_LOGIN                = user/login          SV_LOGIN                 = "<REDACTED>"
URL_GET_TOKEN            = user/refresh_token  SV_GET_TOKEN             = "<REDACTED>"
URL_GET_DEVICE_LIST_V2   = v2/device/get_device_list  SV_GET_DEVICE_LIST_V2 = 000102030405060708090a0b0c0d0e0f
URL_GET_KVS_URL_LIVE     = v2/kinesis/live_url/get   SV_GET_KVS_URL_LIVE    = "<REDACTED>"
URL_KVS_LIVE_REPLAY_GET  = api/v1/kinesis/live_replay_url/get  SV_KVS_LIVE_REPLAY_GET = "<REDACTED>"
URL_WYZE_REFRESH_TOKEN   = https://oauth.wyzecam.com/oauth/token
CLIENT_ID / CLIENT_SECRET = "<REDACTED>" / <REDACTED>
```

### Login

| Fact | Evidence |
|---|---|
| **Working path**: old-style `POST api.wyzecam.com/app/user/login` (the `auth-prod/v2/user/login` path returns "Creating an API Key" — the app's embedded key is rejected; the old-style path is what actually authenticates) | `CloudApi.smali:26533` (`URL_LOGIN`), `CloudProtocol.userLogin` |
| Body = `{sc, sv: SV_LOGIN, ts, access_token, phone_id, app_name, user_name, password}` — note **`user_name`** (not `email`), password is **MD5-hashed** | `CloudProtocol.smali` (`userLogin`), `LoginViewModel$login$1.smali:109` (`toMd5`) |
| **`app_ver` field triggers a WAF block (code 3005 UnauthorizedOperation) on the login endpoint** — must be excluded from the login body | discovered empirically during testing |
| Headers: `X-API-Key: <from config.json>`, `Content-Type: application/json`, `User-Agent: wyze_android_2.50.0.15`, `Phone-Id: <uuid>` | `AuthRepo.smali:165-229` |
| Response `{ts, code, msg, data}`; code `"1000"`/`"1"` = success, `"1001"` = wrong creds, `"3005"` = WAF-blocked | `CloudCallBack.smali:1003-1046` (code→result mapping) |
| **MFA/2FA**: login may return `mfa_options`/`mfa_details` instead of tokens; complete via `POST /v2/2fa/verify_code/send` then `POST /v2/2fa/verify_code/check` | `HL_API_URL` (`URL_CLOUD_POST_2FA_*`); UI has a 2FA code step |
| Tokens persisted in SharedPreferences (`login_username`, `login_access_token`, `login_user_id`, `login_password`) | `AuthRepo.smali:75-77, 367-446` |

### Signed API calls (old-style JSON body)

`HLApi/CloudAPI/CloudProtocol.composeHead`
(`smali_classes3/.../CloudProtocol.smali:226-374`):

```json
{ "sc": "<REDACTED>", "sv": "<SV for endpoint>", "app_ver": "2.50.7.487",
  "ts": <ms>, "access_token": "<token>", "phone_id": "<uuid>",
  "app_name": "wyze" }
```

POSTed to `https://api.wyzecam.com/app/<endpoint>`.

### Signed HTTP header scheme — `WpkWyzeExService.packageHeader`
(`smali_classes17/com/wyze/platformkit/network/WpkWyzeExService.smali:2664-2924`)

| Header | Value |
|---|---|
| `access_token` | login token (also a JSON-body field above) |
| `appinfo` | `wyze_android_<version>` |
| `app_version` | `android_<version>` |
| `phoneid` | UUID (persisted, `wpk_phone_id` in SP) |
| `requestid` | `MD5(MD5(currentTimeMillis))` (line 2806-2828) |
| `Signature` / `Signature2` | `WpkSecurityUtil.getSignature(appid, sortedParams)` |

`getSortParams` (line 2326-2581): add `nonce=<serviceTime>` to the params,
sort entries by key, join as `k=v&k=v`.

### ~~The signature is native~~ — superseded by `REVERSE_ENGINEERING.md` §2

The historical claim was that the wire form was "opaque from smali".  It was
subsequently cracked and **verified 30/30**:
`Signature2 = HMAC_MD5(getSortParams(query), md5(accessToken + secret))`.  Keep
the native-lib note below only as the trail of where the symbols were found:
`getSignature` → `com.wyze.olive.util.WpkSecurity` → native
(`smali_classes17/com/wyze/olive/util/WpkSecurity.smali`), loaded from
`libwyze_olive-lib.so` (`System.loadLibrary("wyze_olive-lib")`), exporting a
templated `hmac<MD5>` (`_Z4hmacI3MD5E...`, verified with `strings`).

### ~~Camera list → live view (KVS)~~ — [X] live view is P2P, not KVS (verdict D1)

> **Superseded — do not build on this.**  Live view does **not** come from AWS
> Kinesis/KVS.  Verified: `live_replay_url` → `"stream not exist"`, and **zero**
> `kinesis`/`live_replay`/`play_url` entries in logcat while cameras were
> opened.  The real path is **TUTK Kalay (IOTC) + Gwell IoTVideo P2P**, direct
> over LAN — see `REVERSE_ENGINEERING.md` §4 and verdicts **D1/D7/C6/C7**.

The historical evidence trail (kept for the app's own behaviour): device list
`v2/device/get_device_list` (`HL_API_URL` + `CloudProtocol.getDeviceList`);
live URL via `KvsAPI.smali:101` (`@GET("app/live_replay_url")`),
`WyzeEventPlatform.smali:1731-1757`; KVS headers `Authorization: <access_token>`,
`appId: 9319141212m2ik` (`RemoteKvsRepo.smali:268-288`); response `data` is a
JSON string containing `play_url` (`KvsAPI.smali:55-79`,
`WyzeEventPlatform.smali:1777-1792`).  The wake-up action is still valid and
useful: `runAction(target,"AN_RSCW","DEVICE")` → capability `iot-device` →
function `wakeup` → params `{"wakeup-live-view": 1}`
(`smali_classes17/zh/a.smali:600-707`); playback via media3/ExoPlayer
(`WyzeMediaPlayer.smali:5638`).
