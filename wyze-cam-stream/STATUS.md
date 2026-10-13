# STATUS — where we are, what's next

> Last updated: **2026-10-12**. Companion docs: [`REVERSE_ENGINEERING.md`](./REVERSE_ENGINEERING.md)
> (full findings + **VERDICT BOARD** of [OK] confirmed vs [X] disproved), [`SECRETS.md`](./SECRETS.md),
> [`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md) (**new — the wire protocol as actually reversed**),
> [`README.md`](./README.md) (stale — flagged).

## [!] READ THIS FIRST — big update (2026-10-12, late session)

**Everything below this banner that talks about "TCP to the camera" or "broadcast discovery on
UDP/8900" is superseded by [`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md).** The ground changed:

1. **The cameras have zero open TCP ports** (full 1–65535 sweep of every camera). Live view is
   **KCP over UDP**, confirmed by `logcat`.
2. **The frames are RC5-encrypted** (header-derived key) — the protocol is a TUTK-Kalay/Gwell
   GUTES stack, not plain TUTK like wyze-bridge assumes. This is exactly wyze-bridge's OG gap.
3. **The deviceId↔TID map and the cameras' LAN IPs are delivered by Wyze's relay servers**, not
   from the LAN. We were wrong to look for them locally.
4. Full `LIST_REQUEST` frame format, XOR checksum and RC5 key schedule are now recovered —
   see [`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md) §3–§5.

### The strategic fork (still undecided)

Reimplementing the rest from disassembly alone is possible but **blind**: the phone↔relay and
phone↔camera traffic is unicast, so we cannot capture a single real byte to diff against. We'd
validate only by "did the server answer". The two options are laid out in `P2P_PROTOCOL.md` §11:

- **(A) Keep going pure-Python** — RC5 params → LIST_RESP → GUTES certify → GDM → KCP → AV.
  Long, risky, no ground truth.
- **(B) Drive Gwell's own SDK** — obtain a Linux/x86 build of `libiotvideo` and call it from
  Python via ctypes with the `accessId`/`accessToken` we already have. Turns it into a glue job.
  Gray area vs. "no third-party", but it *is* the vendor's own protocol implementation, not a
  third-party client like wyze-bridge.

## Layout after reorganisation
Everything lives under **`~/Downloads/wyze-re/`**:
```
wyze-re/
├── wyze-cam-stream/                  # the server project + docs (README, REVERSE_ENGINEERING, SECRETS, STATUS)
├── com.hualai_2.50.7.487-…/          # apktool-decoded tree (2.3 GB)  ← primary RE target
├── com.hualai_2.50.7.487-….apk
├── com.hualai_3.0.0.b489-…/ + .apk   # v3 tree (1.8 GB, unused)
├── com.hualai_3.23.1.994-….apkm
├── wyze_3.23/ (458 MB)  wyze_xapk/ (321 MB)  Wyze+-+Never+Wonder_….xapk (336 MB)
├── wyze_debuggable.apk (+ .idsig, _aligned, _signed)  # installed on device, debuggable
├── wyze_debug.keystore               # signs the rebuild; install -r keeps login
├── uber-apk-signer.jar
├── wyze_token.json  wyze_devices.json
├── cdp_*.py  grab_*.py  watch_*.py  nav*.py  live_capture.py  clear_session.py  # capture scripts
├── auth_login.html  auth_url.txt  oauth_code.txt  pkce*.txt  pkce*.json  sp_secure.xml
└── wyze_api.xlog  wyze_capture.flow  cdp_capture.log  grab_all.log
```
`/tmp/` still holds **live/temporary** state: `wyze_p2p_creds.json`, `wyze_cookie.txt`,
`wyze_live.txt` + `wyze_log.txt` ([!] contain plaintext tokens — delete when done),
`uber-apk-signer.jar` (copy).

## [OK] Done
1. Full static analysis of auth + streaming flow.
2. `client_secret` cracked; OAuth2+PKCE works end-to-end → `wyze_token.json`.
3. `Signature2` GET rule cracked, **verified 30/30**.
4. Device list via `home_page/get_object_list` → 4 cameras → `wyze_devices.json`.
5. Streaming identified: **TUTK Kalay + Gwell IoTVideo P2P**, KVS ruled out.
6. **LAN-direct TCP** discovered (`dstAddr:192.168.77.12 port:59239`), camera LAN IPs from the API.
7. `accessId` + per-device `accessToken` harvested from logcat (7-day TTL).
8. Toolchain ready: NDK r30, apktool, uber-apk-signer, keystore; device runs native bins; `run-as` works.
9. Docs written with [OK]/[X] verdict board; files consolidated into `wyze-re/`.

## [X] Key open problems (in priority order)
1. **How to get frames out.** Two candidate routes — **decide next**:
   - **(A) APK frame-tap** *(lower risk)* — inject smali at
     `MediaCodecVideoDecoder.send_packet(AVData)` (encoded H.264/H.265) + capture SPS/PPS from
     `onReceiveChangedAVHeader`, label camera via `IoTVideoPlayer.setDataResource(deviceId,…)`; rebuild
     with `apktool b` → `uber-apk-signer` → `adb install -r` (keeps login); app already streams all 4
     cams simultaneously. *Caveat: needs the phone app running.*
   - **(B) Native harness** *(better end-state)* — C binary, built `armv7a-linux-androideabi21-clang`,
     run **via `run-as com.hualai`** (shell can't read app libs), `dlopen` the SDK's `iv_*` API, pull
     frames independently of the app. Needs the `iv_*` signatures reversed.
   - **(C) Pure-Python LAN client** *(highest effort/risk)* — must first crack UDP broadcast
     discovery (§4.7) + the TCP/MTP handshake; no packet capture available to shortcut it.
2. [?] **UDP broadcast discovery**: port + packet magic + response format (needed for C; also gives the
   dynamic LAN port). `broadcast.c` strings located, function bodies not yet reversed.
3. [?] **Who populates `tid_key_map`** (origin of the per-device TID).
4. [?] **POST `Signature2`** content rule — blocked on runtime-injected `cg01_f3c397620f853b12` secret.
5. [?] Confirm frame format (encoded vs decoded) at each tap point empirically.
6. Wire frames → `ffmpeg` → HLS/WebRTC → browser UI (grid of 4), into `wyze-cam-stream/server.py`.

## DECISION (locked, from user)
> **"I do not want an app running. I want to run a webserver, log in, and see all
> cameras at the same time, like on my phone."**

- **Route A (in-app frame-tap) is ELIMINATED** — it needs the phone app running/streaming.
- **Route B (native harness on the phone) is ELIMINATED** — the phone must not be involved.
- **Chosen: Route C — pure-Python P2P client running on the Mac.** The Mac is already on
  the camera LAN (`192.168.77.13`, cams at `192.168.0.x`), so it talks to the cameras
  **directly over the LAN**. **The phone is completely uninvolved** — not even plugged in.
- Cost: the whole LAN wire protocol must be reversed from static RE of
  `lib/armeabi-v7a/libiotp2pav.so`. **No packet capture is available** (tcpdump needs sudo;
  device not rooted) → there is no ground-truth wire log. Everything comes from disassembly.

### Route C build order
1. **UDP broadcast discovery** — find the destination port, request magic, and the response
   format (must yield the camera's LAN **IP + service port + dev_id**). Gateway step; nothing
   else works until this is solved.
2. **TCP session + MTP/GUTES framing** — handshake + certify (`iv_gutes_*`, `iv_init_frm_*`).
3. **Auth** — how `accessId`/`accessToken` (or a LAN password) is proven to the camera.
4. **AV stream** — channel setup (`iv_init_frm_AvStreamCtl`, `iv_rcvpkt_AVSTREAMCTL_*`),
   then H.264/H.265 frame extraction.
5. Python client → `ffmpeg` → HLS/WebRTC → browser grid of 4 → wire into
   `wyze-cam-stream/server.py`.

[!] **Known risk for B:** the per-device `accessToken` has a **7-day TTL**
(`expireTime≈1792441xxx`) and refreshing it needs `POST plugin/mars/v2/regist_gw_user/`,
whose signing secret `cg01_f3c397620f853b12` is **unknown** ([~] — see `SECRETS.md` §C).
So a *durable* solution needs either that POST cracked, or the SDK's own
`IoTVideoSdk.nativeUpdateToken` reused. Worth flagging: tokens harvested from
logcat buy ~7 days of operation.

## Immediate next action — Route B build order
1. Reverse the `iv_*` C API: init config struct, register(accessId, accessToken),
   `iv_start_av_link`, and the **frame-delivery callback** (encoded H.264/H.265).
2. Decide harness level: raw `iv_*` (`libiotp2pav.so`) vs C++ `IoTVideoPlayer` (`libiotvideo.so`).
3. Build with `armv7a-linux-androideabi21-clang`; run **via `run-as com.hualai`**
   (plain `shell` cannot read `/data/app` libs).
4. Emit raw Annex-B H.264 per camera over a TCP socket / pipe → Mac `ffmpeg` → HLS/WebRTC
   → browser grid of 4 → wire into `wyze-cam-stream/server.py`.

## Standing constraints (don't forget)
- Credentials only in browser UI; server must not store email/password.
- Keys in rotatable `config.json`; **rotate/revoke when done** (see `SECRETS.md`).
- **Mobile** endpoints only (web caps at 1 camera).
- **Build the P2P client ourselves** — no wyze-bridge/third-party.
- Prefer practical results over deep rabbit-holing.
