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
7. **[OK] Remaining gate SOLVED (2026-10-13 later): the camera's P2P port comes from the camera
   itself**, via LAN discovery on **UDP/8899** — 28-byte request, 138-byte cleartext reply with
   the port at **offset 44**, MAC at 58, `wyze_id` at 102, camera IP = reply source address.
   `discover.py` finds **all 4 cameras in 3 s from the Mac with no app at all**.
   Full spec + audit trail: `P2P_PROTOCOL.md` **§5d**.

### LAN discovery — solved (2026-10-13, this session)

The last unknown blocking our own client is gone, and it was hiding in plain sight:

- `send_loop` (`0x7d778`) passes `movw r2, #0x22c3` = **8899** as the destination port — we had
  been sniffing **8900**, which is only the app's *receive* socket. 0 packets was the wrong
  experiment, not a negative result.
- Empirical ICMP triage settled it: **8900 / 32300 / 4456 are closed on all four cameras,
  8899 and the advertised P2P port are open.**
- `python3 lansniff.py 95 replay` captured the whole exchange in 0.57 s.
- `python3 discover.py` then reproduced it **standalone**, without replaying any app traffic.
- The advertised ports match the logcat exactly: `.217→59239`, `.169→63011` — so
  `iv_mtp_session_add_lan_or_nat` was reading this reply all along.

### MTP layer + direct camera dialogue — solved (2026-10-13, later session)

Full write-up in [`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md) **§5e**. Headlines:

1. **The phone is gone from the handshake.** `p2p_call.py` discovers a camera, replays the
   app's own captured frames from local port 48171, and the camera answers. Three frames are
   all it sends: **74 B `C0 90 02 09` session hello, 128 B `7e a4 80 00` CALLING, 76 B
   `7e b9 4c 00` AvStreamCtl**. The camera replies with `7e a4 20 00` (CALLING ack) and
   `7e b9 20 00` (AvStreamCtl ack), plus its own ~1 Hz 74 B hello.
2. **`0xc0` is a *second*, unencrypted layer — the MTP layer.** 6-byte header +
   `chval = XOR_{i=0..11} rotl16(u16LE(payload[2i:2i+2]), i)` over **payload[0:24] only**.
   Verified **103/103** frames.
3. **`wire[1]` bit7 is the packet class selector** — the whole blocker for the first
   `0x25` probe. `C0 90` → `iv_on_rcv_mtpCtrl_pkt` (control), **`C0 10` →
   `iv_on_rcv_kcpdata_pkt` (raw KCP segment)**, `C0 80/00` → relay. Sending a control
   command with `flag=0` put it in the KCP bucket, where its first 4 bytes were read as a
   `conv` id — hence the silent drop.
4. **MTP command jump table decoded** (base `0x57f14`, table `0x57f18`): valid types **1..37**;
   type 1 → `iv_rcv_meter_req` (answers type 2), **type 37 `0x25` →
   `iv_rcv_kcp_create_msg`, which replies with nothing and creates nothing** — silence after
   a `0x25` is *correct behaviour*, not rejection.
5. **KCP wire format recovered**: `C0 10` + 6-byte MTP header + a **standard `ikcp` segment**
   (24 B header, cmds 81/82/83/84). Two KCP objects per session selected by **conv bit31**
   (`+0x330` / `+0x334`), and `iv_find_mtp_session` accepts *both* bit forms of the word —
   send both. `WASK → WINS` is a zero-payload round-trip liveness probe.
6. **Session lifecycle mapped**: `iv_on_rcv_calling` → `iv_mtp_session_new` → `iv_create_kcb`
   ×2 → `ivkcp_create(conv, 0)`; `ivkcp_update` runs from a 10 ms timer.

**Next gate: the relay rendezvous (`gat` layer) — not the LAN handshake.**

**Why the LAN route is a dead end for KCP (solved 2026-10-13, [`P2P_PROTOCOL.md`](./P2P_PROTOCOL.md) §5f):**
`kcb->output` — a *static* function at `0x5c1d8` that `objdump` mislabels
`iv_create_kcb+0x16c` — round-robins the session's channel pool and **only accepts
channel type 135**. Type-135 channels are created by exactly one function,
`gat_on_rcvpkt_MTP_RES_RESPONSE` (the relay rendezvous). LAN calling only ever adds
types **1/2**. So the camera receives our KCP segments, buffers them, wants to answer —
and then **discards every outgoing segment** because it has no relay channel. That is
why not a single `C0 10` packet has ever come back, and it is *not* a bug in
`p2p_call.py`.

**So the remaining work is the relay rendezvous — and the hope that we could skip AWS (§5g)
is DISPROVED (§5h).**

`giot_on_rcvpkt @ 0x520c8` is a 220-entry jump table on `frame[1]` (decoded with
[`jumptab.py`](../jumptab.py)), and it settles both questions at once:

- **type 162 = `7f a2` (`MTP_RES_REQUEST`) → `0x5267c` → immediate `pop {r11, pc}`.**
  It is never handled by any peer. That is *why* our 294 direct-camera captures contain
  zero `7f` frames — the camera builds it in `iv_on_rcv_calling` and sends it **to the
  relay**, not to us. It was never a message we could answer.
- **type 163 = `7e a3` (`MTP_RES_RESPONSE`) → `gat_on_rcvpkt_MTP_RES_RESPONSE @ 0x4bafc`**,
  the *only* caller of `iv_mtp_session_add_udp_relay` — the sole producer of type-135
  channels. `/tmp/cap_relay.log` contains `7e a3` arriving **from AWS**, which closes the
  loop independently of the disassembly.

And it explains §5f's channel table in one stroke: `iv_on_rcv_calling` does give us a working
LAN channel, but **type 2**, which `kcb->output` rejects; only `add_udp_relay`/`add_tcp_relay`
produce **135/136**, and only a `7e a3` from the relay triggers them. The camera acks our
CALLING directly (source-address reply, we capture it) while its `MTP_RES` goes to the relay —
two behaviours that looked contradictory until the type table explained them.

**Immediate next work (no longer an experiment — a build):** write the relay client.

1. TCP/UDP to a relay from `LIST_RESP` (`3.13.212.24:28800`, srv 49) with the `regist_gw_user`
   `accessId` + per-device `accessToken` (§1).
2. GUTES `certify` (§5a, already byte-exact; session key = our own 32-byte nonce) →
   `init_info` → `init_info_msg_resp` → `GDM_JDAT_RPT_REQ`.
3. Send the app's `7e a4` CALLING **through the relay** — `cap_relay.py` already captures the
   exact bytes — then receive the camera's `7f a2` and the `7e a3` naming its LAN address.
4. `add_udp_relay` → type-135 exists → §5f's gate opens → **KCP runs LAN-direct** (§5f proved
   the relay never carries a `C0` frame).

Then `AVSTREAMCTL` → H.264/H.265. The relay is a postman for control frames only; every byte
of video travels the LAN, and that half of the protocol is already reversed.

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
├── lansniff.py                        # UDP/8899 + :8900 discovery sniffer (found §5d; `55 replay`)
├── discover.py                        # STANDALONE camera discovery → P2P port (§5d), 3 s, no app
├── forge_call.py                      # discovery-reply impersonator → captures the app's CALLING (§5e)
├── p2p_call.py                        # phone-free camera dialogue: replay hello/CALLING/AvStreamCtl + KCP probe (§5e)
├── mtp_frame.py                       # the 0xc0 MTP codec: header, chval, packet-class bit (§5e)
├── analyze_calls.py                   # decodes every captured frame (RC5 key rule)
├── find_fields.py  find_fields2.py     # session+0x1c..+0x28 tracker (negative result, kept)
├── resolve_cb.py                      # resolves PC-relative callback literals -> static fns (§5f, §8)
├── jumptab.py                         # decodes ARM jump tables -> GUTES type map (§5h) — reads the ELF
├── dump_frames.py                     # freezes /tmp/forge_in_*.bin -> wire/p2p_frames.json
├── re_run.sh                          # fallback: run RE cmds -> /tmp/re_out.txt when the shell is wedged
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
6. **LAN-direct call** identified (`dstAddr:192.168.77.12 port:59239`), camera LAN IPs from the API.
   *(Corrected: it is **UDP**, not TCP — full TCP sweep empty. The port itself was real and is
   now explained: discovery reply offset 44, §5d.)*
7. `accessId` + per-device `accessToken` harvested from logcat (7-day TTL).
8. Toolchain ready: NDK r30, apktool, uber-apk-signer, keystore; device runs native bins; `run-as` works.
9. Docs written with [OK]/[X] verdict board; files consolidated into `wyze-re/`.

## [X] Key open problems (in priority order)

> Routes A and B were **eliminated -- deliberate scope cut** (see DECISION below) — the old "decide
> between A/B/C" list is retired. Route C is the only live path, and its first two stages are
> done, so the list starts where the work now actually is.

1. **The relay rendezvous (`gat` / `MTP_RES`)** — [OK] *diagnosed*, not yet built. Every
   other gate on the LAN layer is passed (`C0 90` acked, session created, `session+0x10`
   matches, `0x25` reaches `iv_rcv_kcp_create_msg`), but **KCP cannot run over LAN at all**:
   `kcb->output` (`0x5c1d8`) accepts only channel **type 135**, which only
   `gat_on_rcvpkt_MTP_RES_RESPONSE` creates; LAN calling adds only types 1/2. Full proof in
   §5f, and the earlier "`iv_create_kcb` is the gate" belief is recorded as **disproved (D24)**
   — same conclusion, wrong mechanism. **Work to do:** speak the relay protocol from the Mac
   using the `regist_gw_user` creds (§1) + the endpoints from `LIST_RESP` (§3), replaying the
   app's dialogue that `cap_relay.py` already captures. Then
   `iv_rcvpkt_AVSTREAMCTL_ACCEPT` (over KCP) → `gute_recv_fragment` (MTU 1032) → zlib →
   `start_av_enc_dec AudioType=5 VideoType=0` → H.264/H.265. **This is the current gate.**
   **§5h now pins the exact wire direction** — we *receive* `7e a3` from the relay (we do not
   send `7f a2`), and type **162/163/164** are confirmed against bytes we already hold
   (`7e a3` seen arriving from AWS; `7e a4` = `CALLING_REQ` matches every CALLING capture).
   Build order: `certify` → `init_info` → CALLING **through** the relay → read `7f a2` →
   receive `7e a3` → `add_udp_relay` → type 135 → KCP LAN-direct.
2. ~~**The LAN calling handshake**~~ — [OK] **solved.** The bytes were recovered by capturing the
   app's frames and replaying them straight at the camera; see §5e for the layouts of the
   74 B hello, 128 B CALLING and 76 B AvStreamCtl, the three camera replies, the byte-23
   retransmit rule and the fold-neutral checksum recipe. What remains is *forward* progress
   (KCP), not recovery of these bytes.
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
- [OK] **UN-retired:** *"UDP broadcast discovery is a dead end"* was **wrong** (old D17). Discovery
  is real and now fully reversed — it is **IPv4 broadcast to :8899**, not IPv6-only, and it is
  exactly how our client gets the P2P port. See `P2P_PROTOCOL.md` §5d. What the relay (`GDM`)
  hands the app and what discovery hands us are two views of the same data; **use discovery**.
- [X] **D25 — *"the `MTP_RES` rendezvous can be done peer-to-peer over the LAN, so AWS is
  unnecessary."*** **DISPROVED.** `giot_on_rcvpkt`'s jump table has **no handler for type 162
  (`7f a2`)** — it falls straight through to `pop {r11, pc}`. No peer can answer it, because it
  is a message *for the relay*. Only type **163 (`7e a3`)** reaches
  `gat_on_rcvpkt_MTP_RES_RESPONSE`, the sole producer of the type-135 channels that
  `kcb->output` requires. The AWS relay is **mandatory** — but only for control frames.
  (Caught in §5g as a hopeful experiment and killed by reading the table first; this saved a
  session that would have been spent sending frames into a void.)

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
| 4b | **LAN discovery → camera P2P port** | [OK] **DONE standalone** — `discover.py`, all 4 cameras in 3 s, no app, no phone (§5d) |
| 5 | LAN calling handshake + KCP config + AV channel framing → H.264/H.265 | [~] **Handshake replayed from the Mac; LAN route now proven a dead end for KCP.** All three frames replayed, camera acks both, MTP + command table + KCP wire format reversed (§5e). **Root cause of the missing KCP found (§5f): KCP output only emits over a type-135 *relay* channel, which only `gat_on_rcvpkt_MTP_RES_RESPONSE` creates.** Next: the relay `gat`/`MTP_RES` dialogue |
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
