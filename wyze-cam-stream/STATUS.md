# STATUS — where we are, what's next

> Last updated: **2026-10-13**. Companion docs: [`REVERSE_ENGINEERING.md`](./REVERSE_ENGINEERING.md)
> (full findings + **VERDICT BOARD** of [OK] confirmed vs [X] disproved), [`SECRETS.md`](./SECRETS.md),
> [`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md) (**new — the wire protocol as actually reversed**),
> [`README.md`](./README.md) (stale — flagged).

## [!] READ THIS FIRST — big update (2026-10-13)

**The response-checksum blocker is SOLVED and the relay MITM works end-to-end.** Details in
[`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md) §4a + §5b. Short version:

1. **Requests**: our `init_chkval` model is byte-exact (§4).
2. **Responses**: the app computes `g(header[0:23]) ^ fold(payload)`. `fold(payload)` is a plain
   XOR-fold over the 38 payload words (oracle-proven), but `g(header)` depends on a decryption
   path we do **not** model — and static reproduction was **disproved**. Workaround: **keep the
   server's checksum word and make only fold-neutral payload edits** (XOR the byte-changes into
   the sacrificial word at offset 172). Verified offline *and* live: zero `chkval fail chk_val=`.
3. **`cap_relay.py`** now relays the whole list + relay conversation. The app prints
   `set current ListSrv to 192.168.77.13.` and `add udp_addr 192.168.77.13:28800 srv_id=49`.
4. **`init_info` → `GDM_JDAT_RPT` decoded and delivered through our own MITM** —
   `online_cnt=4`, the `did ↔ wyze_id` map, and each camera's **LAN IP + MAC + ssid**.
5. **The relay is only a rendezvous: the AV leg is LAN-direct.** After GDM the app calls the
   camera straight on the LAN (`iv_mtp_session_add_lan_or_nat lan dstAddr:<cam> port:<p>`),
   creates a KCP session, and reaches `video_decode_proc`. The whole chain
   `certify → init_info → GDM → lanCall → AVSTREAMCTL_ACCEPT → decode` now runs through
   `cap_relay.py`.
6. **The relay dials over TCP as well as UDP** — `ivtcp_start_connect` must be satisfied or the
   session stalls; all four genuine relays accept TCP.
7. **Remaining gate**: where the camera's P2P port comes from (not in `netInfo`, not `:8900`,
   not stable). See `P2P_PROTOCOL.md` §5c.

> [!] **The smali patch made our Mac the only list server.** Experiments now *require*
> `cap_relay.py`; with it off the app gets no list at all (GDM = 0).

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

### Ground truth achieved (2026-10-12, end of session)

The "no way to capture real bytes" handicap is **gone**. The app's list-server host was
redirected to the Mac (smali patch → rebuild → resign → reinstall), and the app then handed us
its own packets. Result:

- **Our Python builder reproduces the app's request byte for byte.**
- **The genuine Wyze list server answers it** — a real 176-byte `LIST_RESP`, decrypted clean.
- **RC5 is fully pinned**: RC5-32, 6 rounds, 8-byte key, 8-byte blocks, little-endian — every
  parameter confirmed by decryption, not inference.
- Captures live in [`../wire/`](../wire/) with a README; the recipe is in
  [`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md) §3a and §8.

Everything the app *originates* can now be captured this way (control plane). The AV plane is
still un-captured, but the redirect trick can be extended to it by rewriting the relay IPs in
the `LIST_RESP` and relaying traffic back.

### Two more layers decoded (2026-10-12, same session)

Since the ground-truth banner above, **two protocol layers were closed out from the
disassembly** — both fully documented in [`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md):

1. **`LIST_RESP` payload decoded** (§3a). Records start at **frame+32, stride 36**, four of
   them, exact fit. Each record = `IPv4@0 | IPv6@4 | kind@20 | srv_id@22 | port1@24 |
   port2@26 | port3@28 | port4@30`. Cross-verified against the phone's live logcat:
   record 0 decodes to `3.13.212.24:28800 srv_id=49` — exactly the `iv_addRmtP2pSrv` line
   the phone printed. Run `python3 decode_lr.py wire/list_resp_decrypted.hex` to see it.
2. **GUTES `certify` reversed** (§5a). `certify_req` = type `0x0c`, 64 bytes: a flags word
   at +20, `hash(nonce)` at +28, and a **32-byte RC5-encrypted nonce at +32**. The response
   carries an error code at +26 and an 8-byte token at +28..+36 (echoed in later requests).
   **The session RC5 key is the client's own nonce** —
   `rc5_ctx_setkey(ctx+0xd8, ctx+156, 32)` runs immediately after a successful `certify`.

So: `LIST_REQUEST` → `LIST_RESP` (relays) → `certify` (session key) → `init_info` → `GDM`
(camera LAN IPs) → KCP/AV. **The first two are done; `init_info`/`GDM` is the next gate.**

> Practical consequence: because the relay IPv4/port now sit at known offsets
> (`frame + 32 + i*36`), the redirect trick can be aimed at the **relay** too — rewrite those
> 4 bytes and the app dials the Mac instead of AWS. That is the fallback if `init_info`/`GDM`
> proves hard to read statically.

### The strategic fork (revisited)

Option **(A)** just got substantially cheaper — it is no longer blind. See `P2P_PROTOCOL.md`
§11 for the updated risk assessment:

- **(A) Keep going pure-Python** — [OK] `LIST_REQUEST`/`LIST_RESP` **done**.
  [OK] `certify` **done** (frame format + session key). Next: `init_info` → `GDM` → KCP → AV.
  Now has a byte-level oracle for anything the app sends.
- **(B) Drive Gwell's own SDK** — obtain a Linux/x86 build of `libiotvideo` and call it from
  Python via ctypes with the `accessId`/`accessToken` we already have. Turns it into a glue job.
  Gray area vs. "no third-party", but it *is* the vendor's own protocol implementation, not a
  third-party client like wyze-bridge. **Remains the fallback.**

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
├── wire/                              # captured LIST_REQUEST/LIST_RESP + README (ground truth)
├── listreq.py                         # byte-exact LIST_REQUEST builder (checksum + RC5-32/6/8)
├── cap_relay.py                       # list-server impersonator + relay MITM (UDP+TCP, fold-neutral)
├── chk_probe.py                       # app-as-checksum-oracle (proved §4a)
├── lansniff.py                        # UDP/8900 + [::]:8900 discovery sniffer (negative result, §5c)
├── netdump.sh                         # decode /proc/net/* for sockets to the camera LAN IPs
├── decode_lr.py                       # LIST_RESP payload decoder (prints the 4 relays)
├── probe_real.py                      # sends our packets to the real server, prints responses
├── cap_listsrv2.py                    # UDP+TCP list-server impersonator (app redirect target)
├── disfn.py                           # annotated disassembly reader: disfn.py <start> <end> [--calls|--fields]
├── fieldmap.py                        # r11-relative access → record offset (gave §3a's layout)
├── mkplt.py                           # rebuild PLT stub → symbol map from objdump -R
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

> Routes A and B were **eliminated -- deliberate scope cut** (see DECISION below) — the old "decide
> between A/B/C" list is retired. Route C is the only live path, and its first two stages are
> done, so the list starts where the work now actually is.

1. **The camera's P2P port** — `iv_mtp_session_add_lan_or_nat lan dstAddr:<cam> port:<p>` gives
   `192.168.77.17:63011` and `192.168.77.12:59239`, but the port is **not** in
   `ProReadonly.netInfo`, is not stable, and did not come from `:8900` (sniffed — 0 packets).
   Reverse `iv_mtp_session_add_lan_or_nat` / `iv_process_calling`, or find the
   `lst_devinfo_proc` broadcast response. **This is the current gate.**
2. **KCP + AV framing** — `iv_create_kcb`, `iv_start_process_transfer`,
   `iv_rcvpkt_AVSTREAMCTL_ACCEPT`, `gute_recv_fragment` (MTU 1032), zlib, then
   `start_av_enc_dec AudioType=5 VideoType=0`. Get from there to actual H.264/H.265 NAL units.
3. **Byte-exact `certify_req` (type `0x0c`) finalizer** — the format is known from §5a and the
   handshake completes live through our MITM, but no capture has been decrypted to verify the
   bytes (session RC5 key = client nonce, so it is now decryptable — just do it).
4. **Auth to the camera** — `accessId`/`accessToken` vs a LAN password
   (`iv_check_set_lan_device_pwd` / `giot_eif_send_check_lan_pwd`, unreversed). The app reaches
   `video_decode_proc` without an obvious auth step, so this may be a non-issue — verify.
5. [?] POST `Signature2` content rule — blocked on runtime-injected
   `cg01_f3c397620f853b12` secret (only needed to refresh tokens).
6. Wire frames → `ffmpeg` → HLS/WebRTC → browser UI (grid of 4), into
   `wyze-cam-stream/server.py`.
7. `d_real` provenance (§3a) — worked around by hardcoding; not understood.

### Retired / superseded (kept so nobody re-opens them)
- [X] *APK frame-tap (Route A)* — needs the phone app running. User vetoed.
- [X] *Native harness on the phone (Route B)* — phone must not be involved. User vetoed.
- [X] *UDP broadcast discovery as a gateway step* — superseded. The cameras are reached via the
  relay → KCP path, and their LAN IPs are handed to us by the relay (`GDM_JDAT_RPT`), not
  discovered locally. The app *binds* `:8900` to receive but sends discovery to **IPv6
  multicast ff02::1**, which our IPv4 listener never saw (verdict D17).

## DECISION (locked, from user)
> **"I do not want an app running. I want to run a webserver, log in, and see all
> cameras at the same time, like on my phone."**

- **Route A (in-app frame-tap) is ELIMINATED** — it needs the phone app running/streaming.
- **Route B (native harness on the phone) is ELIMINATED** — the phone must not be involved.
- **Chosen: Route C — pure-Python P2P client running on the Mac.** The Mac is already on
  the camera LAN (`192.168.77.13`, cams at `192.168.0.x`). **The phone is uninvolved at
  runtime** — it is only used as an RE oracle (logcat, screenshot, tap).
- Target: portable Python 3 + sockets, no macOS-specific code, runs unchanged on Windows.
  RE tooling stays Mac-only.

### Route C build order — where each stage stands

| # | Stage | Status |
|---|---|---|
| 1 | `LIST_REQUEST` / `LIST_RESP` → relay list | [OK] **DONE** — byte-exact builder, real server answers, payload decoded (§3, §3a) |
| 2 | GUTES `certify` → session key | [OK] **DONE** — frame format + `rc5_ctx_setkey(nonce, 32)` (§5a) |
| 3 | `init_info` → `GDM_JDAT_RPT` (did↔TID, camera LAN IPs) | [OK] **DONE live** — `online_cnt=4`, `did↔wyze_id`, per-cam LAN IP/MAC/ssid, through our own MITM (§5b, §5c) |
| 4 | Relay dial: transport + byte-exact type `0x0c` finalizer | [OK] **DONE live** — UDP **and TCP** both relayed; `certify`/`init_info`/`GDM` complete against our Mac. `Detect` 0x01/0x02 formats captured (§5b). Type `0x0c` bytes still not byte-verified. |
| 5 | KCP config + AV channel framing → H.264/H.265 | [~] **AV LINK UP** — LAN-direct call + KCP + `video_decode_proc` reached (§5c). Left: how the camera port is obtained, `iv_mtp_session_add_lan_or_nat`, framing/codec extraction |
| 6 | Auth to camera (`accessToken` vs LAN password) | [ ] not started |
| 7 | Python client → `ffmpeg` → HLS/WebRTC → browser grid of 4 → `server.py` | [ ] not started |

**Ground-truth tooling for stages 3–4:** redirect `GWApi.GWellP2PUrl` to the Mac
(`P2P_PROTOCOL.md` §3a recipe) to capture anything the app originates; to capture the
*relay* conversation too, rewrite `LIST_RESP` `record+0`/`record+24` (frame offsets
`32 + i*36`) to point at the Mac and relay traffic back.

[!] **Token durability:** the per-device `accessToken` has a **7-day TTL**
(`expireTime≈1792441xxx`) and refreshing it needs `POST plugin/mars/v2/regist_gw_user/`,
whose signing secret `cg01_f3c397620f853b12` is **unknown** ([~] — see `SECRETS.md` §C).
So a *durable* solution needs either that POST cracked, or the SDK's own
`IoTVideoSdk.nativeUpdateToken` reused. Worth flagging: tokens harvested from
logcat buy ~7 days of operation.

## Standing constraints (don't forget)
- Credentials only in browser UI; server must not store email/password.
- Keys in rotatable `config.json`; **rotate/revoke when done** (see `SECRETS.md`).
- **Mobile** endpoints only (web caps at 1 camera).
- **Build the P2P client ourselves** — no wyze-bridge/third-party.
- Prefer practical results over deep rabbit-holing.
