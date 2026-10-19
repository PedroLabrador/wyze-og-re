# Wyze / Hualai (com.hualai 2.50.7.487) — Reverse Engineering Master Notes

> **Purpose:** single source of truth so the work can be resumed from zero.
> Everything here was verified unless explicitly marked `SPECULATIVE` or `UNVERIFIED`.
> Companion docs: `STATUS.md` (state + next moves), `README.md` (how to run).

**Goal:** stream *all* of your own Wyze OG cameras into a local web browser,
bypassing Wyze's 1-camera web-UI limit. Constraints:
- Email/password entered in browser UI only; server must not store them.
- Credentials/API keys in an easily-rotatable local config; revoked/rotated when the work is done.
- Must use **mobile** endpoints (web version caps streaming at 1 camera).
- The P2P client must be **built by us** (not delegated to wyze-bridge or any third-party).
- Practical over deep rabbit-holing (decided up front).

---

## [!] VERDICT BOARD — read before re-investigating anything

> **2026-10-12 late update:** the streaming story changed materially — see
> [`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md) for the wire protocol as actually reversed
> (KCP/UDP, RC5 frames, relay-delivered TID map). **D7, D16–D20 and C7 are new/retracted.**

**Do not re-derive the [X] DISPROVED rows.** They were tested and failed; the
*reason* they failed is the useful part. Status legend:
[OK] CONFIRMED (verified working) · [X] DISPROVED (tested, failed — dead end) · [~] PARTIAL · [?] OPEN.

### [X] DISPROVED — dead ends, do not revisit

| # | Theory | How it was disproved |
|---|---|---|
| D1 | **Live view comes from AWS Kinesis Video Streams (KVS/HLS)** | `live_replay_url` returns `"stream not exist"`; **zero** `kinesis`/`live_replay`/`play_url` hits in logcat while cameras were opened. Cameras never push live video to Kinesis. |
| D2 | **Web endpoints would allow multi-camera streaming** | Web version caps live view at **1 camera** → must use mobile endpoints (project constraint). |
| D3 | **TID is computable from the device MAC** | Tested numerically: all 4 TIDs share prefix `0x186D60` but MAC↔TID deltas have **no linear relation** (ratios 0.88 / 0.057 / 0.70). Not a hash of the string either (common input prefix → common output prefix is not hash behaviour). |
| D4 | **The per-device TID comes from an HTTP response** | No HTTP occurs between map lookup and TID resolution; grep of logcat finds the TID integers **only** in `IoTVideo-P2P` lines, never in JSON. Map is populated in-memory by some non-HTTP path ([?] OPEN — see §4.5). |
| D5 | **The app's embedded HTTP server can serve the stream** | Port `127.0.0.1:45475` confirmed listening (uid 10086, `iv_evhttp_server_init rand_v=45475`), but routes are only `/key`, `/cloud/device/reset`, `/vas/cloudstorage/getTsEncryptKey` → VAS key exchange, **no video**. |
| D6 | **`iv_get_hls_http_port` / `iv_get_rstp_password` → a built-in HLS/RTSP server** | `getHLSPort()` is only consumed by `HttpViaP2PProxy` for VAS HTTP-over-P2P (`"vas get port failure, hlsPort <= 0"`). `nc` probe of `554/80/443/8080/…` + observed LAN ports on `192.168.77.12` → **all closed**. No RTSP on the wire. |
| D7 | ~~The app connects to cameras via a cloud relay~~ → **superseded, see D16** | logcat showed `iv_start_av_link lanCall` + `iv_mtp_session_add_lan_or_nat lan dstAddr:192.168.77.12 port:59239` and we concluded "direct LAN **TCP**". **The LAN part was right, the TCP part was wrong** — see D16. |
| D8 | **Camera LAN service port is static / scannable** | `nc -z` across `59239 63011 49802 554 80 443 8080 8000 9000 3232 5000 5555 6000 7000 8888` on `.217` → **nothing open** while idle. *(Refined by D16: not merely "dynamic" — there is no TCP listener at all.)* |
| D9 | **Classic `v2/device/get_device_list` works with the OAuth token** | Server rejects it. Working list is `home_page/get_object_list` (`sv=000102030405060708090a0b0c0d0e0f`). |
| D10 | **The `Signature2` scheme was only a guess / native-opaque** | Early README claimed *"the HMAC-MD5 implementation is an inference … exact wire form opaque from smali"*. **Superseded — now cracked** (see [OK] C3). The old guess is retired, not correct. |
| D11 | **The `auth-prod/v2/user/login` path authenticates** | Returns `"Creating an API Key"` — the app's embedded key is rejected there. Old-style `user/login` (or OAuth PKCE, which is what the app actually does) is the real path. |
| D12 | **wyze-bridge / third-party tools as the streaming backend** | Rejected by explicit user decision: build our own client. |
| D13 | **Python `requests`/`urllib` can call the API** | WAF returns `3005 UnauthorizedOperation` on the TLS fingerprint → all HTTP must shell out to the **`curl`** binary. |
| D14 | **Sniffing the phone↔camera LAN traffic for ground truth** | `tcpdump` on the Mac needs sudo/BPF (`Permission denied`); device not rooted. Not available as a shortcut. |
| D15 | **`nm -D` finds internal static functions** | Map-insert/lookup helpers are *static* — invisible to `nm -D`. Must use `objdump -d` ranges or non-`-D` `nm`. |
| D16 | **Live view reaches the camera over LAN TCP** | Full `1–65535` TCP sweep of `192.168.77.12` **and** `.224` → **zero open ports** (same scanner correctly found the router's 22/80/443). While streaming, the phone's `/proc/net/tcp` shows **no** connection to any `192.168.0.x`. Transport is **KCP over UDP** (`iv_cal_kcp_rate`, `ivkcp_*`). Kills C7 too. |
| D17 | **LAN discovery = IPv4 broadcast to `:8900`** | The app *binds* `:8900` to receive (`broadcast_fd_init pMgr->fdRead=121`), but it *sends* to **IPv6 multicast `ff02::1`** (`send_loop addr_len=28 multicast=ff02::1`, `sockaddr_in6`=28 B). Listeners on IPv4 `:8900`, `:51701` and a properly-joined `ff02::1` group all stayed **silent** across app restarts. |
| D18 | **The deviceId↔TID (`tid_key_map`) is populated locally / via HTTP** | Delivered by the **relay server**: `gat_rcv_init_info_msg_resp did=429728658691722 <------> wyze_id:CAM-1_D03F27747BB0, srv_relation=1`, one per camera, `online_cnt=4`. |
| D19 | **Camera LAN IPs come from LAN discovery or the Wyze API** | They arrive **through the relay** in `gat_on_rcv_GDM_JDAT_RPT_REQ` → `netInfo.stVal.ip`. (C8 still true as an *alternate* source, but it is not how the P2P stack learns them.) |
| D20 | **Frames are in the clear / plain TUTK** | `iv_init_frm_listsrv` calls `iv_gute_frm_rc5_encrypt` after the checksum → **RC5-encrypted**, and `iv_gutes_frm_encryp`/`_decrypt` guard the GUTES layer. Key is derived from the frame's *own* header (so obfuscation, not a security boundary), but it kills any "just speak TUTK" assumption. |

### [OK] CONFIRMED — working, build on these

| # | Finding | Evidence / proof |
|---|---|---|
| C1 | **OAuth2 + PKCE login works end-to-end** | Real `access_token`+`refresh_token` (RS256 JWT) in `wyze_token.json`, `jti=<REDACTED>`, `expires_in=172799`. |
| C2 | **`client_secret` cracked** = `jOwT7UImpdmKqrP0VEXFQp0eQzRS4D` | Bogus secret → `"Bad client credentials"`; correct one → token issued. |
| C3 | **`Signature2` = `HMAC_MD5(getSortParams(query), md5(accessToken + secret))`** | **Verified 30/30** on GET. GET content = sorted query params. |
| C4 | **OAuth JWT goes in the JSON body as `access_token`**, not an `Authorization` header | Confirmed against `home_page/get_object_list`. |
| C5 | **`accessId` = `-9222942308195737437` (shared) + per-device `accessToken`** | Captured from logcat, 4 devices, 236 chars each, `expireTime≈1792441xxx` (~7 d). Saved `/tmp/wyze_p2p_creds.json`. |
| C6 | **Live view = TUTK Kalay (IOTC) + Gwell IoTVideo P2P** | Libs present; `IoTVideoSdk register accessId=… p2pUrl=\|wyze-mars-asrv.wyzecam.com`; `AVSTREAMCTL_ACCEPT` on stream open. |
| C7 | ~~Cameras stream over LAN TCP with dynamic ports~~ → **retracted, see D16** | The log line was real but the TCP conclusion was wrong; the port is a UDP/KCP one. |
| C8 | **Camera LAN IPs are available from the Wyze API** | `get_iot_prop` / `onModelMessage` → `netInfo.stVal.ip` (`192.168.77.11/224/169/217`). *(Still true, but the P2P stack learns them via the relay — D19.)* |
| C9 | **App is debuggable + signed with a keystore we hold → `install -r` preserves login** | `pkgFlags=[ DEBUGGABLE … ]`; `~/Downloads/wyze-re/wyze_debug.keystore` (alias `wyze`, pass `android`). |
| C10 | **Device runs native bins from `/data/local/tmp`; `run-as com.hualai` works** | Confirmed; but plain `shell` **cannot** read `/data/app` libs → harness must run via `run-as`. |
| C11 | **NDK installed → native harness is buildable** | `/opt/homebrew/share/android-ndk` r30, `armv7a-linux-androideabi21-clang`. |
| C12 | **Device is 32-bit userspace** | `abilist=armeabi-v7a,armeabi`, `uname -m=armv8l`. |
| C13 | **4× `CAM-1` cameras identified** with MACs + LAN IPs | See §3.1. |
| C14 | **Encoded H.264/H.265 reachable at `MediaCodecVideoDecoder.send_packet(AVData)`** | It reads `AVData.data`/`size`/`pts` → `inputBuffer.put` → `queueInputBuffer(0,0,size,pts,0)`. |
| C15 | **App binds UDP `8900`** | `broadcast_fd_init` does `movw r1,#0x22c4` → `rev`/`lsr #16` = `htons(8900)`; runtime `/proc/net/udp`+`udp6` show uid 10086 on `0.0.0.0:8900`; logcat `broadcast_fd_init pMgr->fdRead=121`. |
| C16 | **List server = `wyze-mars-asrv.wyzecam.com` on UDP `51701`** | `iv_dns_callback_v2: addListSrv … ==> 18.118.90.161` then `send UDP ListFrmRequest to ipv4=18.118.90.161:51701` + `gat_on_rcvpkt_LIST_RESP`. (4 IPs: `.161`, `34.215.36.59`, `35.85.21.174`, `3.19.80.22`.) |
| C17 | **5 relay ("Asrv") UDP endpoints observed** | `35.81.136.54:8000`(38), `3.13.212.24:28800`(49), `3.131.23.11:8443`(48), `54.208.16.245:443`(58), `52.40.221.253:51705`(28). |
| C18 | **GUTES `certify` handshake precedes any AV** | `iv_gutes_start_active_certify_req mtu=1032` → `gutes_on_respfrm_certify_resp session_id=7695951958192904963`. |
| C19 | **Device list (TID↔wyze_id) delivered by the relay** | `gat_rcv_init_info_msg_resp … online_cnt=4`, `did=… <--> wyze_id:CAM-1_…`, `srv_relation=1`. |
| C20 | **`LIST_REQUEST` frame layout fully recovered** | 40 B: `magic 0x7F`, `type 0x15`, `u16 len=40`, `u64 devID@4`, `u32 seq@12`, `u32 checksum@16`, `u32 flags@20 (bits16-17=1)`. From `iv_init_frm_listsrv` @ `0x36544`. |
| C21 | **Checksum = 32-bit XOR, mask `0x00FFFFFF`, stored at offset 16** | `iv_gute_frm_init_chkval` @ `0x2aa38`; mask literal @ `0x2ab38`; `str r0,[r2,#0x10]` in the caller. Skips offsets 16 & 20 in the loop. |
| C22 | **RC5 with an 8-byte key derived from the frame header** | `iv_gute_frm_rc5_encrypt` @ `0x2b2ac`, branch `(flags>>16)&3==1`; key = `buf[0..3] ‖ buf[0x14..0x16] ‖ 0x00`; encrypts `buf+12` then blocks from `buf+24`. |
| C23 | **`devID`(signed) ≡ `srcID`(unsigned) ≡ `9512032141665525923`** | `-8934711932044025693` as `uint64` equals the `srcID` printed in AV stats — it's the phone's ID, not a camera's. |
| C24 | **Transport is KCP/UDP, zero TCP to cameras while streaming** | `iv_cal_kcp_rate … lost_ratio=0`, `ivkcp_interval/nodelay/wndsize/waitsnd` @ `0x7c03c`…; empty `/proc/net/tcp` for `192.168.0.x`. |
| C25 | **`gute_get_encrypt_data_len` = `total_len − 24`** (list frame) | Checksum loop indexes `(i+6)*4` = 24,28,32,36 for a 40-byte frame ⇒ payload 16. @ `0x2a9b4`. |

### [~] PARTIAL / [?] OPEN
- [~] **RC5 params** — key schedule recovered (§5 of `P2P_PROTOCOL.md`) but the **round count and
  `ctx->wordsize` are not pinned**: `rc5_ctx_setkey` dispatches on 16/32/64-bit and takes the
  `ctx+2` byte. Small search space (wordsize ∈ {32,64} × rounds ∈ {8,12,16}).
- [~] **`LIST_RESP` / GUTES certify / `init_info` / `GDM` parsing** — handshake *sequence* logged,
  frame formats not yet reversed.
- [~] **KCP configuration + AV channel protocol + H.264/H.265 extraction** — not started.
- [~] **UDP/IPv6 LAN discovery** — `broadcast.c` functions and the bind port are now known
  (C15, D17), but **no packet has ever been captured**, so the request magic/response format is
  still unknown.
- [~] **POST `Signature2`** — content rule unknown (blocked on runtime-injected secret `cg01_f3c397620f853b12`).
- [?] Whether LAN-direct is even *used* for video, or whether all AV flows through the relay.
- [?] Whether the phone app must stay in the foreground to keep streaming.

---

## 0. Environment & tooling (read this first)

| Item | Value |
|---|---|
| Target APK | `com.hualai_2.50.7.487-62187_minAPI24(arm64-v8a,armeabi-v7a)(nodpi)_apkmirror.com` (apktool-decoded tree: has `apktool.yml`, `AndroidManifest.xml`, `smali_classes*`) |
| APK version | 2.50.7.487, UA `wyze_android_2.50.7.487` |
| Second tree present | `com.hualai_3.0.0.b489-62189_minAPI28(arm64-v8a)(nodpi)_apkmirror.com` (v3, unused) |
| Device | serial `4c00103147014792354`, model "Mortal T1", Android 14, **not rooted** |
| **CPU = 32-bit userspace** | `ro.product.cpu.abilist` = `armeabi-v7a,armeabi`; `ro.product.cpu.abi` = `armeabi-v7a`; `uname -m` = `armv8l` → **use `lib/armeabi-v7a/*.so`, build harness for `armv7a-linux-androideabi`** |
| App package | `com.hualai`, uid `10086` (`u0_a86`), **debuggable** (`pkgFlags=[ DEBUGGABLE ... ]`) |
| ADB | `adb forward tcp:9222 localabstract:chrome_devtools_remote` for Chrome CDP |
| NDK | **installed** at `/opt/homebrew/share/android-ndk` (r30, `Pkg.Revision=30.0.16248370`), toolchain `toolchains/llvm/prebuilt/darwin-x86_64/`, compilers `armv7a-linux-androideabi21-clang`, `aarch64-linux-android21-clang` (via `brew install --cask android-ndk`) |
| Tools available | `apktool` (`/opt/homebrew/bin/apktool`), `java`, `/usr/bin/clang` (Apple clang, host-only), `ffmpeg` (`/opt/homebrew/bin/ffmpeg`), `keytool`, `uber-apk-signer-1.3.0` at `/tmp/uber-apk-signer.jar`, `/usr/bin/nc` |
| Tools **missing** | `nmap`, `socat`, `apksigner`, `zipalign`, Android build-tools, Frida |
| tcpdump | exists (`/usr/sbin/tcpdump`) but **no permission** without sudo (`You don't have permission to capture on that device /dev/bpf0`) → cannot sniff the LAN wire directly |

### Tooling gotchas (macOS / zsh)
- macOS has **no `timeout` command**.
- zsh reserves `$UID` → use `$WUID`. zsh fails on unquoted globs → quote `--include="*.smali"`.
- Big greps over the whole smali tree (`grep -rn ... .`) **time out** (>30s) — scope with explicit `smali_classesN/...` paths.
- `nm -D` shows only *dynamic* symbols; internal helpers (e.g. map-find at `0x36bc0` in arm64 `libiotp2pav.so`) are **static** → use `objdump -d` address ranges or non-`-D` `nm` for local symbols.
- arm64 vs armeabi-v7a symbol addresses **differ** (e.g. `broadcast_fd_init` = `0x729fc` arm64 vs `0x7c200` armv7a) — always re-resolve per ABI.

### ADB capabilities discovered (critical)
```bash
adb shell "getprop ro.product.cpu.abilist"          # armeabi-v7a,armeabi
adb shell "echo x > /data/local/tmp/t.sh; /data/local/tmp/t.sh"   # WORKS (shell has inet group)
adb shell "run-as com.hualai id"                    # WORKS → uid=10086(u0_a86)
adb shell "run-as com.hualai sh -c '...'"           # can read/write /data/data/com.hualai, and read app libs
adb shell "cat /data/app/*/com.hualai*/lib/..."     # FAILS as plain shell (SHELL_CANNOT_READ)
```
→ A native harness must be executed **via `run-as com.hualai`** (or copied into the app's `files/` dir) to reach the `.so` files; plain `shell` cannot read `/data/app` libs. `shell` *does* have `3003(inet)` so networking works either way.

---

## 1. Auth — cracked end-to-end [OK]

### 1.1 OAuth2 + PKCE against `auth.wyze.com` (the real app login)
| Constant | Value |
|---|---|
| `client_id` | `68900a09-abfa-472d-a30d-27ae53c205a6` |
| `client_secret` | `jOwT7UImpdmKqrP0VEXFQp0eQzRS4D` (**cracked + verified**: bogus secret → "Bad client credentials") |
| `redirect_uri` | `wyze://wyzeapp:8080/v2?id=wyze/auth/login` |
| `scope` | `authcode-read native openid email` |
| authorize | `https://auth.wyze.com/oauth/authorize` |
| token | `https://auth.wyze.com/oauth/token` |
| user_id | `<REDACTED>` |

Flow observed in app order:
```
/login/mfa/code → /login/trust_device_option → /login/passkey/registration (skip)
→ /login/success → oauth/authorize → 302/303 Location: wyze://...&code=XXX → /oauth/token
```

**Capturing the `code` without a WebView** — replay the authorize URL through `curl`
using the browser's live `SESSION` cookie (via CDP `Network.getCookies`):
```bash
curl -s -D - -o /dev/null "<authorize_url>" \
  -H "Cookie: $COOKIES" \
  -H "User-Agent: Mozilla/5.0 (Linux; Android 14; Mortal T1) ..."
# → 303 + Location: wyze://...&code=XXX
```
- Repeatable while the session cookie stays valid (stored at `/tmp/wyze_cookie.txt`).
- **Authorization codes are single-use** → reuse gives `invalid_grant` (expected, not a bug).

**Result:** clean `access_token` + `refresh_token` (RS256 JWTs) in `wyze_token.json`,
`expires_in=172799` (~48h), `jti=<REDACTED>`.

### 1.2 Token transport for `api.wyzecam.com`
The OAuth JWT is passed as **`access_token` in the JSON request BODY** — *not* as an `Authorization` header.

Body template for `home_page/get_object_list`:
```json
{"access_token":"<JWT>","app_name":"com.hualai",
 "app_ver":"com.hualai___2.50.7.487","app_version":"2.50.7.487",
 "phone_id":"e1d4fde4-f075-49cf-9c23-5d25ed13bcdc","phone_system_type":"2",
 "sc":"000102030405060708090a0b0c0d0e0f",
 "sv":"000102030405060708090a0b0c0d0e0f","ts":<ms>}
```
Headers: `appinfo: wyze_android_2.50.7.487`, `appversion: 2.50.7.487`, `env: Prod`,
`Accept-Language: es-US`, `Content-Type: application/json`.

### 1.3 WAF / TLS-fingerprint rules (empirical)
- Wyze WAF **rejects Python's TLS fingerprint** → HTTP must go through the **`curl` binary** (code `3005` UnauthorizedOperation otherwise).
- **`app_ver` in the login body triggers 3005** → exclude `app_ver` from WAF-protected *login*.
- Standard `app_ver` (`com.hualai___2.50.7.487`) is fine on `home_page/*` endpoints.
- Legacy `user/login` path needs the body without `app_ver`; password is MD5-hashed there (`user_name` field, not `email`).

### 1.4 Legacy (old-style) endpoints — mostly superseded
From `assets/HL_ADDR` + `HL_API_URL` + `HL_API_SV`:
```
URL_BASE_OFFICIAL = https://api.wyzecam.com/app/
SC              = 000102030405060708090a0b0c0d0e0f     (app key)
SC_KVS/SC_OLD   = "<REDACTED>"
URL_LOGIN       = user/login                 SV_LOGIN              = "<REDACTED>"
URL_GET_TOKEN   = user/refresh_token         SV_GET_TOKEN          = "<REDACTED>"
URL_GET_DEVICE_LIST_V2 = v2/device/get_device_list  SV = 000102030405060708090a0b0c0d0e0f
URL_GET_KVS_URL_LIVE    = v2/kinesis/live_url/get   SV = 000102030405060708090a0b0c0d0e0f
URL_KVS_LIVE_REPLAY_GET = api/v1/kinesis/live_replay_url/get SV = 000102030405060708090a0b0c0d0e0f
legacy client_id/secret = 000102030405060708090a0b0c0d0e0f / <REDACTED>
```
**Note:** classic `get_device_list` (sv `f0ef3f...`) **rejects the OAuth token** — the working device
list is `home_page/get_object_list` (sv `000102030405060708090a0b0c0d0e0f`).

---

## 2. `Signature2` — CRACKED (GET, verified 30/30) [OK] / POST [X]

### 2.1 Formula (GET requests)
```
Signature2 = HMAC_MD5( getSortParams(query), md5(accessToken + secret) )
```
- **GET** signing content = **sorted query params** (`getSortParams` adds `nonce=<serviceTime>`,
  sorts entries by key, joins as `k=v&k=v`).
- `Signature` header uses the same util.

Where the app builds headers: `WpkWyzeExService.packageHeader`
(`smali_classes17/com/wyze/platformkit/network/WpkWyzeExService.smali:2664-2924`),
`getSortParams` at lines `2326-2581`, `requestid = MD5(MD5(currentTimeMillis))` at `2806-2828`.
Native impl: `WpkSecurityUtil.getSignature` → `com.wyze.olive.util.WpkSecurity` (native,
`libwyze_olive-lib.so`, exports templated `hmac<MD5>`).

### 2.2 Secret map (`lf/a.smali` / `WyzeOliveConstant`)
| appid | secret |
|---|---|
| `umgm_78ae6013d158c4a5` | `mt0hBFxNQ4CQaWPjTonDk3mHaDEK2hhI` |
| `wamp_638GEUrW2NOKjtA0` | `3CZMTKPRBWcbVerLO8HIiGENm0D2ukoQ` |
| `wapk_181259b351899207` | `OLf91uRGKDjWkcRSZ2oA1wt4OpZ2FhdP` |
| `wssp_bc5c93d925b51c8f` | `QQ6Sxb1m3yiCkyTMkAab0vG2WdkYVObb` |
| `hmss_b172509edbf6948f` | `l5NwhKYAN0qu47ox2jyCatijZJ9LmIuP` |
| `repl_c77bf00e3db085ef` | `UUNW0sfTRxRjsK5ZuUxstF6MD20kMO53` |
| `wyze_event` | `5Z1Bg7wMSNwlxrcNL1rpxvOm1zbDHzjA` |
| `9319141212m2ik` (KVS) | `wyze_app_secret_key_132` |
| `wapp_724270c618418d73` | `8mZqTFzzv7ZyrX2meN6oDjXtIQn4KPSk` |
| `wyze_shop` | `OSuwAAxm05ZbNgBFNDDX7Eg6Vx50M6tm` |
| **`cg01_f3c397620f853b12`** | [X] **NOT in map, NOT in `libwyze_olive-lib.so`** — injected at runtime |
| `rscp_f1f18d470bb7658d` | [X] not in map / not in lib |

### 2.3 [!] BLOCKER: POST signing unknown
**All POSTs use `appid=cg01_f3c397620f853b12`, whose secret is absent from both the Java map and
the native lib** (injected at runtime). So:
- GET signing = solved.
- **POST signing rule = unsolved** → cannot yet call `plugin/mars/v2/regist_gw_user` (a POST),
  nor `devicemgmt-service` `get_iot_prop` (POST) ourselves.
- Workaround so far: harvest `accessId`/`accessToken` **from logcat** instead of re-signing POSTs.

---

## 3. Devices & endpoints

### 3.1 The 4 cameras (model `CAM-1`, Gwell/GC1, product `CAM-1`)
| Device ID | Nickname | MAC | LAN IP | conn |
|---|---|---|---|---|
| `CAM-1_D03F27747BB0` | CAM-1 | `00:00:00:00:00:01` | `192.168.77.12` | 0 (offline early) / online later |
| `CAM-1_D03F27EBFB10` | CAM-1 | `00:00:00:00:00:03` | `192.168.77.10` | 0 / online later |
| `CAM-1_D03F2776110C` | CAM-1 | `00:00:00:00:00:04` | `192.168.77.17` | 0 / online later |
| `CAM-1_D03F277576D8` | CAM-1 | `00:00:00:00:00:02` | `192.168.77.11` | 1 (online) |

- **LAN IPs come from the Wyze API**: `devicemgmt-service-beta.wyze.com/device-management/api/device-property/get_iot_prop`
  and `app-core.cloud.wyze.com` model messages → `netInfo.stVal = {type, signalQuality, ssid, ip, mac}`.
  Also broadcast in-app: `IoTVideo-MessageMgr onModelMessage deviceId:..., data:{"netInfo":{...,"ip":"192.168.0.x"}}`.
- Wake an offline camera: `run_action`, capability `iot-device`, function `wakeup`,
  params `{"wakeup-live-view": 1}`; device-management base `devicemgmt-service.wyze.com`.
- Product numeric id seen: `429730805317735` (`_productInfo.productID`).

### 3.2 Hosts seen
`api.wyzecam.com`, `auth.wyze.com`, `home_page`, `app-core.cloud.wyze.com`,
`wyze-membership-service.wyzecam.com`, `devicemgmt-service-beta.wyze.com`,
`wyze-mars-service.wyzecam.com`, `wyze-mars-asrv.wyzecam.com`, `devicemgmt-service.wyze.com`.

---

## 4. Streaming — it is **P2P**, not KVS/HLS [OK]

### 4.1 KVS is a dead end (verified)
- KVS `live_replay_url` → `"stream not exist"`; cameras never push live video to Kinesis.
- Zero KVS/kinesis activity in logcat while two cameras were opened.

### 4.2 The stack
**ThroughTek TUTK/IOTC (Kalay)** + **Gwell IoTVideo** (same architecture wyze-bridge uses).
Libs (in `lib/arm64-v8a/` **and** `lib/armeabi-v7a/`):
`libIOTCAPIs.so`, `libTUTKGlobalAPIs.so`, `libAVAPIs.so`, `libRDTAPIs.so`,
`libiotvideo.so` (~10.6 MB, contains ffmpeg + OpenSSL), `libiotp2pav.so` (~825 KB, Gwell P2P AV layer).

Standard TUTK surface confirmed: `IOTC_Initialize2`, `IOTC_Connect_ByUID[_Ex/_Parallel]`,
`IOTC_Device_Login[Ex]`, `avInitialize`, `avClientStart`, `avSendAudioStop`, …

### 4.3 SDK init chain (from smali)
```
GWCenter.smali:822   IoTVideoSdk.init(Application, HashMap)
IoTDataManager.smali:1062   regIotSDK(AccessTokenBean)
   → IoTVideoSdk.register(accessId:J, accessToken:String, I)     // nativeRegister
```
Runtime log proves it:
```
IoTVideoSdk register accessId = -9222942308195737437
   accessToken = 0189E2058840CD6A6B8A667FD68601002B57C2F66A9D... (236 chars), version = 0x10800001,
   p2pUrl = |wyze-mars-asrv.wyzecam.com; language:0
IV_NET iv_evhttp_server_init rand_v=45475
```

### 4.4 IOTC credential endpoint (POST — blocked by §2.3)
```
POST https://wyze-mars-service.wyzecam.com/plugin/mars/v2/regist_gw_user/
   (base = GWApi.getMarsUrl(); path = getURL_GW_PLUGIN_REG_USER_TOKEN(); beta default https://beta-mars-service.wyzecam.com/)
params: unique_id = phone_id,  ttl_minutes = 0x2760 (10080 = 7 days)
signed with Signature2   (ServiceManager.smali:470-589)
→ AccessTokenBean(deviceId, accessId, accessToken, expireTime, isSubscribe)
```
**Captured values** (from logcat, saved to `/tmp/wyze_p2p_creds.json`):
- `accessId = -9222942308195737437` — **same for all cameras**
- `accessToken` = **per-device**, 236 chars, starts `0189…`, hex-ish
- `expireTime ≈ 1792441096…1792441280` (~2026-10-19)

### 4.5 TID (Kalay UID) ↔ device mapping
`IoTVideoSdk.getTidFromDid(String)→long` → JNI `nGetDidFromTid` (`IoTVideoSdk.smali:707`, JNI
`Java_com_tencentcs_iotvideo_IoTVideoSdk_nGetDidFromTid` @ `0x1b46fc` arm64) → `iv_get_did_from_tid`
in `libiotp2pav.so` @ `0x26cb4` (arm64).

`iv_find_dstid_from_tid_key_map` @ `0x368bc` (arm64): if the key starts with `_@.` → strip prefix,
look up hash map at `ctx+0x1920` (mutex at `ctx+0x18f4`), entry `dev_id` at `+0x28`; if len ≤ 0x1f and
no `_@.` prefix → `atoll()` parse as a numeric TID. Log strings `"%s third=%s \n"` @ `0xc0514`,
`"%s dev_id=%llu\n"` @ `0xc0541`; source path `/home/jinpeng/xt_sdk/iot_video_p2plib_svn/p2plib/jni/src/p2p`.

| Device | TID | hex |
|---|---|---|
| `CAM-1_D03F2776110C` | `429728658783497` | `0x186D6000E7D09` |
| `CAM-1_D03F27747BB0` | `429728658691722` | `0x186D6000D168A` |
| `CAM-1_D03F27EBFB10` | `429728659223864` | `0x186D600153538` |
| `CAM-1_D03F277576D8` | `429728658756018` (inferred from list) | `0x186D6000E0A92` |

- All TIDs share prefix `0x186D60`. API `p2p_id` = the device MAC string (`CAM-1_...`), **distinct** from TID.
- **TID is NOT a computation from the MAC** (verified numerically: no linear relation) and there is **no HTTP
  between lookup and resolution** → the `tid_key_map` is populated earlier (in-memory).
- [X] **OPEN:** *who inserts into `tid_key_map`* — insert routine not yet found (static, needs non-`-D` `nm`/`objdump`).

### 4.6 Observed connection flow (ground truth from logcat)
```
iv_start_av_link _@.<deviceId>
  → iv_find_dstid_from_tid_key_map third=_@.<deviceId>   → dev_id=<TID>
  → iv_start_av_link entry=0x… dst_id=<TID> srv_relation=1 allow_srv_call=1
                     camera_source_id=0 lastChannelID=0 allocateid=1
  → channel allocated (link_chn_id:1)
  → iv_init_frm_CALLING dstID=<TID> reqfrm->mtp_link.link_id=… lan_ipv4=…
  → iv_mtp_session_add_lan_or_nat lan dstAddr:192.168.77.12 port:59239
  → iv_start_av_link lanCall   →  CH2 iv_start_av_link link success (~360 ms)
  → AVSTREAMCTL_ACCEPT / IoTVideo-P2P relay (srcID=9512032141665525923 = phone)
```
**KEY FINDING:** the app connected **directly over the local LAN** — `192.168.77.12:59239` — *no cloud relay*.
LAN transport is **TCP** (`gutes_send_lan_tcp_pkt`, `on_lan_tcp_connect_finished`, `iv_send_list_request port=51701`).
Per-camera LAN ports observed: `.217→59239`, `.224→63011`, `.169→49802` (**dynamic**; a `nc` port scan of
`.217` found **no open ports** while idle → port is learned via **UDP broadcast discovery**).

### 4.7 Broadcast discovery (UDP) — partially reversed
- Symbols: `broadcast_init` / `broadcast_fd_init` / `broadcast_destroy`
  (arm64 `0x73108`/`0x729fc`/`0x732b8`; **armv7a `0x7cad8`/`0x7c200`/`0x7cd00`**), `get_lan_device_info`
  (arm64 `0x204d8`, armv7a `0x190cc`), `iv_lan_device_connectable`, `giot_eif_lan_device_connectable`,
  `iv_check_set_lan_device_pwd`, `giot_eif_send_check_lan_pwd`, `iv_start_refresh_dev_info`.
- Strings (from `broadcast.c`): `broadcast_fd_init`, `"%s broad cast listen socket failed!\n"`,
  `"%s pMgr->fdRead=%d\n"`, `"%s setsockopt failed,errno:%d\n"`, `"%s bind port=%d error!\n"`,
  `"%s fdRead_ipv6 error!\n"`, `"%s bind to udp port: %d failed!\n"`; log tag region ~`0xc46f8`.
- `giot_eif_lan_device_connectable tid1=_@.CAM-1_… tid2=CAM-1_…` → **the "tid" string in this layer IS the deviceId**.
- [X] **OPEN:** exact UDP destination port + packet magic/format, and the response format (must carry IP + port + dev_id).

### 4.8 Embedded HTTP server in the app — **NOT a video server** (checked)
- App listens on `127.0.0.1:45475` (uid 10086); port = `rand_v` from `iv_evhttp_server_init rand_v=45475`.
- Forward: `adb forward tcp:14575 tcp:45475` → serves libevent `evhttp` `404 Not Found` page.
- Routes found in `libiotp2pav.so` strings: **`/key`, `/cloud/device/reset`, `/vas/cloudstorage/getTsEncryptKey`**
  only (`iv_http_handler_get_msg` @ `0x39e40`, `iv_evhttp_server_init` @ `0x3a760` arm64).
  → VAS (cloud-storage key exchange), **no stream endpoint**.
- Other tempting-but-dead APIs: `iv_get_hls_http_port` @ `0x2694c`, `iv_get_rstp_password` @ `0x2e618`,
  `Java_…_IoTVideoSdk_nGetHLSHttpPort`, `nativeGetRstpPassword`, `IoTVideoSdk.getHLSPort()`,
  `HttpViaP2PProxy` (uses `getHLSPort()` only for VAS HTTP-over-P2P, error `"vas get port failure, hlsPort <= 0"`).
- No RTSP on the wire: `nc` probe of `.217` on `554/80/443/8080/8000/9000/3232/5000/5555/6000/7000/8888`
  + the observed LAN ports → all closed while idle.

---

## 5. Candidate implementation paths (decide in `STATUS.md`)

### 5.1 SDK reuse (preferred — no protocol reimplementation)
The device **runs native binaries** (`/data/local/tmp` OK) and `run-as com.hualai` works, so a harness
can `dlopen` the app's own libs. Relevant exported C API (`lib/armeabi-v7a/libiotp2pav.so`):
```
iv_access_init(cfg, cb)   iv_access_init_param_cfg(cfg)   iv_access_init_param_cb
iv_start_av_link          iv_addListSrv / iv_addRmtP2pSrv  iv_get_lan_device_info
iv_find_dstid_from_tid_key_map   iv_mtp_session_add_lan_or_nat   iv_base64_encode/decode
iv_evhttp_server_init     iv_http_handler_get_msg          iv_get_hls_http_port
iv_get_rstp_password      iv_fill_video_raw_frame          iv_get_video_before_decode_frame
iv_get_data_from_link_chn iv_get_av_remain_frame           iv_access_destroy / iv_access_destroy_av
```
Higher level (`libiotvideo.so`, C++ mangled + JNI):
`IoTAVDebugKits::init(IoTPlayerOptions*)`, `IoTPlayerOptions::{get,set}PlayerIntOptions`,
`IoTVideoPlayerJni::*` (`onPrepared`, `onRenderStart/End`, `onUserData`, `setTimeListener`, …).
JNI natives on `IoTVideoSdk`: `nativeRegister`, `nativeUnregister`, `nativeUpdateToken`,
`nGetDidFromTid`, `nGetHLSHttpPort`, `nativeGetTerminalId`, `nativeGetAnonymousSecureKey`,
`nativeStartDetectDevNetwork`, `setDebugMode`, `setLogPath`, `nativeGetP2PVersion`, …
[!] The player JNI methods (`nativeInit`, `nativePlay`, `nativeSetVideoRender`,
`nativeSetVideoFramesListener`) are registered via **`RegisterNatives` in `JNI_OnLoad`** — *not* exported.

### 5.2 Frame tap points in the app (APK injection path)
App is **debuggable** and signed with a keystore we hold → `adb install -r` **preserves login state**.

| Tap | Class/method | What it carries |
|---|---|---|
| **encoded input** [OK]best | `MediaCodecVideoDecoder.send_packet(AVData)` (`…/mediacodec/MediaCodecVideoDecoder.smali:~1480-1660`) | reads `AVData.data` (ByteBuffer) + `AVData.size` + `AVData.pts`, `inputBuffer.put(data)` → `queueInputBuffer(0,0,size,pts,0)` → **encoded H.264/H.265** |
| codec header | `IoTVideoPlayer.onReceiveChangedAVHeader(AVHeader)` (`:2512`) + `OnReceiveAVHeaderListener` | SPS/PPS + `video-type`, `width`, `height`, `bitrate`, `frame-rate` |
| device identity | `IoTVideoPlayer.setDataResource(String deviceId, int callType, PlayerUserData)` (`:7131`, logs `"setDataResource deviceId:"`) | which camera the player belongs to |
| render dispatch | `IoTVideoPlayer$6.onFrameUpdate(AVData)` (`:40-145`) | calls `IVideoRender` + `IVideoRenderFilter`; likely **decoded YUV** (`AIoTBaseRender` has `mByteBufferY/U/V`) — UNVERIFIED which |
| FPS only | `IVideoFramesListener.onReceiveVideoFramesPerSecond(II)V` | no frame data |

`AVData` fields: `data`, `data1`, `data2` (ByteBuffers), `dts`, `extraData`, `extraSize`, `height`,
`keyFrame`, `pts`, `size`, `size1`, `size2`, `width`, `seiRenderRegion`.
Other useful: `VideoRecord.writeVideoFrameData(AVData)` (writes encoded frames → MediaMuxer),
`SplitUtils.splitAVData`, `iotvideoplayer_player_TimeLapseDownloadConnection_n264ToMp4Transform`.
Player classes: `IoTVideoPlayer` (base), `player/MonitorPlayer` (constructs `IoTVideoPlayer`),
`player/PlaybackPlayer`, `mediacodec/MediaCodecPlayer` (+`$PlayThread`, +`MediaCodecGLRenderer`).

**Build/re-sign toolchain ready:** `apktool b <tree>` → `/tmp/uber-apk-signer.jar -a out.apk -keystore
~/Downloads/wyze-re/wyze_debug.keystore -ksPass android -ksKeyAlias wyze` → `adb install -r`.
(Keystore: PKCS12, alias `wyze`, SHA-256 `00:00:00:00:00:05:00:00:00:00:00:06:00:00:00:00:00:07:00:00:00:00:00:08:00:00:00:00:00:09:1D:6E`.)
[!] Verify the decoded tree matches `wyze_debuggable.apk` before rebuilding (tree has `apktool.yml` dated Oct 12 12:38).

### 5.3 Pure-Python LAN client (most work)
Would need: UDP broadcast discovery (§4.7) → TCP MTP handshake → auth with `accessId`+`accessToken` →
H.264 frames → ffmpeg → browser. Cannot sniff the wire (no tcpdump perms), so everything comes from
static reversing. Highest effort/risk.

---

## 6. What is definitively established
1. [OK] OAuth2+PKCE login works end-to-end; `client_secret` cracked; token in `wyze_token.json`.
2. [OK] `Signature2` = `HMAC_MD5(sortedParams, md5(accessToken+secret))` — GET verified 30/30.
3. [OK] Device list via `home_page/get_object_list`; 4× `CAM-1` cameras + their **LAN IPs**.
4. [OK] Live view is **TUTK Kalay + Gwell IoTVideo P2P**, KVS ruled out.
5. [OK] **LAN-direct TCP** to `camera_ip:dynamic_port`; cloud relay not used for video.
6. [OK] `accessId` + per-device `accessToken` harvested from logcat (7-day TTL).
7. [OK] App is debuggable, signed with our keystore, reinstall preserves login; NDK installed; device is 32-bit.
8. [OK] The app's embedded HTTP server does **not** serve video.

## 7. What is still open
1. [?] **Who populates `tid_key_map`** (where the per-device TID originates).
2. [?] **UDP broadcast discovery** port + packet format (needed to learn the camera's LAN port).
3. [?] **POST `Signature2`** content rule (blocked on runtime-injected `cg01_f3c397620f853b12` secret).
4. [?] Exact frame format at each tap point (encoded vs decoded) — confirm empirically first.
5. [?] TCP/MTP handshake bytes (LAN session) — only if going the pure-Python route.
