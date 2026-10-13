# Wyze Cam Stream Server

> ## [!] THIS README IS STALE — READ `REVERSE_ENGINEERING.md` FIRST
> Written 2026-10-12 14:34, **before** most findings. Several sections below are
> **DISPROVED** and must not be trusted. See the **VERDICT BOARD** at the top of
> [`REVERSE_ENGINEERING.md`](./REVERSE_ENGINEERING.md) for [OK] confirmed vs [X] disproved.
>
> Specifically, in *this* file:
> - **§7 "camera list → live view (KVS)" is [X] DISPROVED.** Live view is **P2P**
>   (TUTK Kalay + Gwell IoTVideo), not AWS Kinesis. KVS returns
>   `"stream not exist"` — see verdict D1.
> - **§6 "the signature is native / an inference" is [X] DISPROVED.** `Signature2`
>   is now **cracked and verified 30/30**: see verdict C3.
> - **§2 legacy `client_id`/`client_secret`** are the *old* oauth pair, superseded
>   by the real app values in `REVERSE_ENGINEERING.md` §1.1.
> - Path references assume `~/Downloads/…`; everything now lives under
>   **`~/Downloads/wyze-re/`**.
>
> Use this README only for the historical static-analysis trail and the server's
> HTTP API surface (§"Run it").

Stream **your own** Wyze OG camera through a local web server, using the same
cloud auth + live-view flow as the Hualai/Wyze app — recovered by reverse
engineering the `com.hualai_2.50.7.487` APK (a white-label Wyze app).

> **Scope:** this uses *your own account* and *your own camera*. The app keys
> below are extracted from a shipped APK for interoperability; do not
> redistribute them. Wyze's ToS may restrict third-party clients — use at your
> own risk, rate-limit politely.

---

## How auth + streaming works in the app (the evidence)

All paths below are relative to the decompiled APK folder
`com.hualai_2.50.7.487-.../`. Line numbers are from the apktool output.

### 1. Server topology — `assets/HL_ADDR`
```
URL_BASE_OFFICIAL = https://api.wyzecam.com/app/
URL_BASE_TEST     = https://test-api.wyzecam.com/app/
URL_PRE_DEPLOYMENT= https://beta-api.wyzecam.com/app/
```

### 2. Per-endpoint secrets — `assets/HL_API_URL` (paths) + `assets/HL_API_SV` (secrets)
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

### 3. Login
| Fact | Evidence |
|---|---|
| **Working path**: old-style `POST api.wyzecam.com/app/user/login` (the `auth-prod/v2/user/login` path returns "Creating an API Key" — the app's embedded key is rejected; the old-style path is what actually authenticates) | `CloudApi.smali:26533` (`URL_LOGIN`), `CloudProtocol.userLogin` |
| Body = `{sc, sv: SV_LOGIN, ts, access_token, phone_id, app_name, user_name, password}` — note **`user_name`** (not `email`), password is **MD5-hashed** | `CloudProtocol.smali` (`userLogin`), `LoginViewModel$login$1.smali:109` (`toMd5`) |
| **`app_ver` field triggers a WAF block (code 3005 UnauthorizedOperation) on the login endpoint** — must be excluded from the login body | discovered empirically during testing |
| Headers: `X-API-Key: <from config.json>`, `Content-Type: application/json`, `User-Agent: wyze_android_2.50.0.15`, `Phone-Id: <uuid>` | `AuthRepo.smali:165-229` |
| Response `{ts, code, msg, data}`; code `"1000"`/`"1"` = success, `"1001"` = wrong creds, `"3005"` = WAF-blocked | `CloudCallBack.smali:1003-1046` (code→result mapping) |
| **MFA/2FA**: login may return `mfa_options`/`mfa_details` instead of tokens; complete via `POST /v2/2fa/verify_code/send` then `POST /v2/2fa/verify_code/check` | `HL_API_URL` (`URL_CLOUD_POST_2FA_*`); UI has a 2FA code step |
| Tokens persisted in SharedPreferences (`login_username`, `login_access_token`, `login_user_id`, `login_password`) | `AuthRepo.smali:75-77, 367-446` |

### 3b. Credentials & config
- **`config.json`** (created): `api_key` (your Wyze API key) + `oauth_client_id`. Override via `WYZE_API_KEY` / `WYZE_OAUTH_CLIENT_ID` env vars.
- **Email + password are entered in the browser** at `http://127.0.0.1:8080` — the server never stores them. If 2FA is on, a code is emailed and entered in the UI.
- **HTTP goes through the `curl` binary** — Wyze's WAF rejects Python's `requests`/`urllib` TLS fingerprint (3005) but allows curl.

### 4. Signed API calls (old-style JSON body)
`HLApi/CloudAPI/CloudProtocol.composeHead` (`smali_classes3/.../CloudProtocol.smali:226-374`):
```json
{ "sc": "<SC>", "sv": "<SV for endpoint>", "app_ver": "2.50.7.487",
  "ts": <ms>, "access_token": "<token>", "phone_id": "<uuid>",
  "app_name": "wyze" }
```
POSTed to `https://api.wyzecam.com/app/<endpoint>`.

### 5. Signed HTTP header scheme — `WpkWyzeExService.packageHeader`
(`smali_classes17/com/wyze/platformkit/network/WpkWyzeExService.smali:2664-2924`)
| Header | Value |
|---|---|
| `appid` | the `SC` key |
| `access_token` | login token (also a JSON-body field above) |
| `appinfo` | `wyze_android_<version>` |
| `app_version` | `android_<version>` |
| `phoneid` | UUID (persisted, `wpk_phone_id` in SP) |
| `requestid` | `MD5(MD5(currentTimeMillis))` (line 2806-2828) |
| `Signature` / `Signature2` | `WpkSecurityUtil.getSignature(appid, sortedParams)` |

`getSortParams` (line 2326-2581): add `nonce=<serviceTime>` to the params,
sort entries by key, join as `k=v&k=v`.

### 6. ~~The signature is **native**~~ [X] DISPROVED — now CRACKED, see `REVERSE_ENGINEERING.md` §2
> **Superseded.** This section's claim that the wire form is "opaque from smali" and that
> `sign()` "is an inference" is **wrong** — the scheme was subsequently cracked and
> **verified 30/30**:
> `Signature2 = HMAC_MD5(getSortParams(query), md5(accessToken + secret))`.
> Per-appid secrets are listed in `REVERSE_ENGINEERING.md` §2.2. Keep the notes below
> only as a trail of where the symbols were found.

Original (historical):
`WpkSecurityUtil.getSignature` → `com.wyze.olive.util.WpkSecurity` → `native`
(`smali_classes17/com/wyze/olive/util/WpkSecurity.smali`), loaded from
`libwyze_olive-lib.so` (`System.loadLibrary("wyze_olive-lib")`).
The `.so` exports a templated `hmac<MD5>` (symbol `_Z4hmacI3MD5E...`, verified
with `strings`). The exact wire form is opaque from smali — **the HMAC-MD5
implementation in `wyze_client.py` is an inference** from this symbol table
plus the visible sorted-params scheme. If the KVS endpoint rejects it, capture
the real headers with mitmproxy and adjust `sign()`.

### 7. ~~Camera list → live view (KVS)~~ [X] DISPROVED — live view is P2P, not KVS
> **Superseded — do not build on this.** Live view does **not** come from AWS Kinesis/KVS.
> Verified: `live_replay_url` → `"stream not exist"`, and **zero** `kinesis`/`live_replay`/
> `play_url` entries in logcat while cameras were opened. The real path is
> **TUTK Kalay (IOTC) + Gwell IoTVideo P2P**, direct over LAN TCP — see
> `REVERSE_ENGINEERING.md` §4 and verdicts **D1/D7/C6/C7**.
> (The wake-up action in the last row is still valid and useful.)

Original (historical):
| Fact | Evidence |
|---|---|
| Device list: `v2/device/get_device_list` | `HL_API_URL` + `CloudProtocol.getDeviceList` |
| Live URL request: `GET {kvs-service}/app/live_replay_url` | `KvsAPI.smali:101` (`Llv/f` = `@GET("app/live_replay_url")`), `WyzeEventPlatform.smali:1731-1757` |
| Query params: `device_id`, `product_model`, `start_time`, `nonce`, `resource_version=2` | `KvsAPI.smali:55-79`, `WyzeEventPlatform.smali:1777-1792` |
| KVS headers: `Authorization: <access_token>`, `appId: 9319141212m2ik` | `RemoteKvsRepo.smali:268-288` |
| Response `{code, data, message}`; `data` is a JSON string containing `play_url` | `KVSReplayUrlOutPut.smali`, `Data.smali` (`play_url`) |
| Alternative endpoints: `v2/kinesis/live_url/get`, `api/v1/kinesis/live_replay_url/get` | `HL_API_URL` (`URL_GET_KVS_URL_LIVE`, `URL_KVS_LIVE_REPLAY_GET`) |
| Wake camera before live view: `runAction(target,"AN_RSCW","DEVICE")` → capability `iot-device` → function `wakeup` → params `{"wakeup-live-view": 1}` | `smali_classes17/zh/a.smali:600-707` |
| Playback: media3/ExoPlayer plays the KVS URL (`WyzeMediaPlayer`, "kvsvideo") | `smali_classes13/com/wyze/camerasdk/ui/player/WyzeMediaPlayer.smali:5638` |

---

## Run it

```bash
cd wyze-cam-stream
pip install requests
export WYZE_EMAIL=you@example.com
export WYZE_PASSWORD=secret
python3 server.py            # http://127.0.0.1:8080
```

- `POST /api/auth` — login (email + password), tokens cached in memory
- `GET /api/devices` — your cameras
- `GET /api/live/{did}?model=...` — fetch the KVS `play_url` for a camera
- `GET /stream/{did}/live.m3u8` — HLS playlist proxy (segments auto-rewritten)
- `GET /stream/{did}/live.mjpg` — MJPEG transcode via ffmpeg (plain `<img>`)

## Limitations / unknowns

1. **Static analysis only** — nothing was executed at runtime; the flow is
   reconstructed from smali + assets.
2. **Signature scheme is native** — `hmac<MD5>` symbol observed in
   `libwyze_olive-lib.so`, but the exact string-to-sign layout inside the
   native code was not decompiled (no Ghidra/IDA available; REA's Android
   engine needs a caller-supplied JADX MCP JAR). The shipped `sign()` is the
   evidence-based inference. If KVS rejects requests, capture real headers
   with mitmproxy (`mitmproxy` + Android emulator or device with user cert)
   and patch `sign()`/`sorted_params()`.
3. **MFA/2FA accounts** — login response may return `mfa_details`/`mfa_options`
   instead of tokens; the server currently treats that as failure. 2FA
   endpoints exist (`/v2/2fa/verify_code/check`) if you need to extend it.
4. **Wyze OG camera must be online**; the wake-up action
   (`{"wakeup-live-view": 1}`) exists in the client for cameras that sleep.
