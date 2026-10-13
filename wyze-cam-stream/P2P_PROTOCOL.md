# P2P PROTOCOL — Gwell IoTVideo / TUTK-Kalay (Wyze OG, model `CAM-1`)

> **This file is ground truth recovered on 2026-10-12** from static disassembly of
> `lib/armeabi-v7a/libiotp2pav.so` **corroborated by live `logcat`** from the running app.
> Confidence is marked per item: **[CONFIRMED]** = seen in disassembly *and/or* log output,
> **[INFERRED]** = read out of code but not yet observed on the wire.
>
> Companion docs: [`STATUS.md`](./STATUS.md), [`REVERSE_ENGINEERING.md`](./REVERSE_ENGINEERING.md),
> [`SECRETS.md`](./SECRETS.md).

---

## 0. TL;DR — what changed everything

1. **The cameras have ZERO open TCP ports.** A full `1–65535` TCP sweep of every camera
   returned nothing (the same scanner correctly found the router's 22/80/443). They ping fine
   and their MACs match the device IDs. → **live view is not TCP**.
2. **The transport is KCP over UDP.** `logcat` shows `iv_cal_kcp_rate ... lost_ratio=0.000000`
   and steady-state `CH1: srcID=… dstID=… score=77` while 3–4 channels stream ~20 fps video /
   ~50 fps audio.
3. **The `tid_key_map` (deviceId → numeric TID) is delivered by the relay server**, not
   computed locally and not learned from LAN broadcast. See `gat_rcv_init_info_msg_resp` below.
4. **LAN discovery uses IPv6 multicast `ff02::1`, not IPv4 broadcast.** `logcat`:
   `send_loop addr_len=28 multicast=ff02::1` (`sockaddr_in6` is 28 bytes). This is why an
   IPv4 listener on UDP/8900 sees nothing. *(Not yet observed producing packets in practice.)*
5. **Even the "discovery" frame is RC5-encrypted** — but the key is derived from the
   frame's own plaintext header, so it is obfuscation, not a security boundary.

---

## 1. Credentials (from the `mars` service, not from OAuth)

```
access_id   = -9222942308195737437          # shared, signed int64
access_token= 0189E205…384WE=               # 236 chars, PER DEVICE, ~7-day TTL
devID       = -8934711932044025693          # this install's terminal ID (random)
```

- Minted by `POST https://wyze-mars-service.wyzecam.com/plugin/mars/v2/regist_gw_user/`.
- Harvested from `logcat`; saved in `/tmp/wyze_p2p_creds.json`.
- **[CONFIRMED]** `devID` (signed) and `srcID` (unsigned) are the same number:
  `-8934711932044025693` as `uint64` = **`9512032141665525923`**, which is exactly the `srcID`
  printed in the AV-stream stats. This is the *phone's* ID, not a camera's.

---

## 2. Control-plane architecture [CONFIRMED — live logcat]

Full observed sequence on app cold start (logcat, pid-trimmed, `IoTVideo-P2P` tag):

```
iv_access_init_param_cfg access_id=-9222942308195737437 pcfg->access_token=0189E205…
iv_access_init_param_cfg loginToken.type=1
iv_access_init_param_cfg pcfg->devID=-8934711932044025693 iv_broadcast=1
broadcast_init enter..
broadcast_fd_init pMgr->fdRead=121          # binds UDP :8900 (local receive socket)
broadcast_init succeed!
broadcast recv proc start! / broadcast send proc started!
access_av_control_create chnnel_id=0..15
Compile Date: Apr 20 2023 12:06:10
iv_fast_connect_srv srv_num=3 fast_connect=1
IoTVideoSdk register … version=0x10800001, p2pUrl=|wyze-mars-asrv.wyzecam.com

iv_addRmtP2pSrv: add udp_addr 35.81.136.54:8000   srv_id=38
iv_addRmtP2pSrv: add udp_addr 3.13.212.24:28800   srv_id=49
iv_addRmtP2pSrv: add udp_addr 3.131.23.11:8443    srv_id=48

gat_send_detecReq_2_allp2psrv: len=68 to 35.81.136.54:8000
iv_dns_callback_v2: addListSrv wyze-mars-asrv.wyzecam.com ==> 18.118.90.161
send_loop addr_len=28 multicast=ff02::1           # IPv6 LAN discovery
iv_send_list_request mode=0 / port=51701
iv_on_timeout_query_listsrv_resend: send UDP ListFrmRequest to ipv4=18.118.90.161:51701

iv_gutes_start_active_certify_req mtu=1032
iv_gutes_add_send_pkt type=12 …
gutes_on_respfrm_certify_resp session_id=7695951958192904963     # SESSION UP

gat_rcv_init_info_msg_resp srv_id=49 frm_len=209
gat_rcv_init_info_msg_resp offline_cnt=0 online_cnt=4
gat_rcv_init_info_msg_resp did=429728658691722 <------> wyze_id:CAM-1_D03F27747BB0
gat_rcv_init_info_msg_resp srv_relation=1        # (×4, one per camera)
gat_rcv_init_info_msg_resp IV_ACCESS_SRV_LINK_ONLINE

gat_on_rcv_GDM_JDAT_RPT_REQ id=429728658691722
  content={"ProReadonly":{"_online":{"stVal":1},"netInfo":{"stVal":{"type":2,
           "signalQuality":-57,"ssid":"Jose","ip":"192.168.77.12","mac":…}}}}
gat_send_heart_frm begin...term_id=-8934711932044025693 ip 3.13.212.24 port 28800 srv_id=49
gat_on_rcvfrm_HeartResp current_interval=50 heartbeat_interval=65
```

### Roles

| Thing | What it is | Endpoint |
|---|---|---|
| **List server** | "which P2P relays exist" | `wyze-mars-asrv.wyzecam.com` → `18.118.90.161` / `34.215.36.59` / `35.85.21.174` / `3.19.80.22`, **UDP 51701** |
| **Relay servers ("Asrv")** | the actual P2P rendezvous | UDP `35.81.136.54:8000` (srv 38), `3.13.212.24:28800` (srv 49), `3.131.23.11:8443` (srv 48), `54.208.16.245:443` (srv 58), `52.40.221.253:51705` (srv 28) |
| **LAN broadcast socket** | local discovery | binds **UDP 8900**, sends to **ff02::1** |
| **Heartbeat** | keepalive to chosen relay | `gat_send_heart_frm` every ~50–65 ms ticks |

**Device list + camera LAN IPs arrive *through the relay*** (`GDM_JDAT_RPT_REQ`), not from LAN
discovery. The `tid_key_map` therefore originates server-side (open question #3 is answered:
it is `gat_rcv_init_info_msg_resp`).

---

## 3. Wire frame format — `LIST_REQUEST` [CONFIRMED — disassembled]

`iv_init_frm_listsrv` @ `0x36544` (armeabi-v7a) builds a **40-byte** frame:

```
off  size  field
  0    1   magic          = 0x7F
  1    1   frame type     = 0x15 (21) = LIST_REQUEST
  2    2   total length   = 40            (uint16 LE)
  4    8   terminal ID    = devID as uint64 LE   (from ctx+0x240 / ctx+0x244)
 12    4   sequence no.   (uint32 LE, monotonically incremented)
 16    4   CHECKSUM       (computed, see §4)      ← excluded from its own XOR
 20    4   flags          (uint32 LE); bits 16–17 set to 1 → 0x00010000
 24    2   |= 1
 26    2   (0)
 28    4   (0)
 32    4   (0)
 36    4   (0)
```

`memset(buf,0,40)` first, then the fields above, then checksum, then RC5.

**[CONFIRMED]** flags bits 16–17 control the crypto mode: `iv_gute_frm_rc5_encrypt` branches on
`(*(u32*)(buf+0x14) >> 16) & 3`; only the `== 1` branch (header-derived key) is taken here.

---

## 4. Checksum — plain XOR over 32-bit words [CONFIRMED]

`iv_gute_frm_init_chkval` @ `0x2aa38`:

```python
def chkval(buf, payload_len):          # payload_len = gute_get_encrypt_data_len(buf)
    nwords = payload_len >> 2
    chk = struct.unpack_from("<I", buf, 0x14)[0] & 0x00FFFFFF   # mask literal @ 0x2ab38
    for off in (0x00, 0x04, 0x08, 0x0C):
        chk ^= struct.unpack_from("<I", buf, off)[0]
    for i in range(nwords):
        chk ^= struct.unpack_from("<I", buf, (i + 6) * 4)[0]   # offsets 24, 28, 32, …
    return chk
```

- Mask literal = **`0x00FFFFFF`**.
- Words at offsets **16 (checksum itself)** and **20 (flags)** are deliberately not XORed in the
  loop — offset 20 contributes only via the masked seed.
- Result is stored at **offset 16** (`str r0, [r2, #0x10]` in `iv_init_frm_listsrv`).
- `gute_get_encrypt_data_len` @ `0x2a9b4` returns the *payload* length; for a 40-byte frame the
  checksum loop indexes offsets 24/28/32/36 ⇒ payload = 16 ⇒ **`payload_len = total_len − 24`**.

---

## 5. RC5 — key derived from the plaintext header [CONFIRMED]

`iv_gute_frm_rc5_encrypt` @ `0x2b2ac`, mode `(flags>>16)&3 == 1`:

```python
key = bytes([buf[0], buf[1], buf[2], buf[3],
             buf[0x14], buf[0x15], buf[0x16], 0x00])    # 8 bytes, built on the stack
rc5_ctx_setkey(ctx, key, keylen=8)
rc5_ctx_enc(ctx, buf + 12, 8)                            # encrypts seq(12..15) + checksum(16..19)
nblocks = payload_len >> 3
for i in range(nblocks):
    rc5_ctx_enc(ctx, buf + 24 + i*8, 8)                  # encrypts payload from offset 24
```

So the on-wire layout is:
- **offsets 0–11**: plaintext header (magic, type, length, terminal ID)
- **offsets 12–19**: RC5-encrypted (sequence + checksum)
- **offsets 20–23**: plaintext flags (part of the key)
- **offsets 24+**: RC5-encrypted payload

### Open on RC5
- `rc5_ctx_setkey` @ `0x64b08` dispatches on `ctx->wordsize` (byte at `ctx+2`): **16 / 32 / 64**.
  The 32-bit path is `0x64e7c`, 64-bit `0x650f8`. P = `0xB7E15163` is present in `.rodata`;
  **the round count and the exact wordsize used for this context are not yet pinned down.**
  `rc5_ctx_enc` operates on 8-byte blocks, consistent with RC5-64, but this is **[INFERRED]**.
- Related symbols: `rc5_ctx_new 0x64994`, `rc5_ctx_free 0x64ae8`, `rc5_enc32 0x65dbc`,
  `rc5_enc64 0x65ee4`, `rc5_encrypt 0x66044`, `rc5_ctx_dec 0x658d0`.
- `iv_gute_frm_encrypt_id 0x2ac40` / `iv_gute_frm_decrypt_id 0x2acec` also exist (separate from
  the frame crypto).

---

## 6. Transport [CONFIRMED]

- **KCP over UDP.** Steady state emits `iv_cal_kcp_rate sta_cur->real_snd=… resend_frm=0
  lost_ratio=0.000000` per channel and `ivkcp_interval/nodelay/wndsize/waitsnd` exist as API
  (`0x7c03c`…`0x7c1dc`).
- **No TCP anywhere.** `adb shell cat /proc/net/tcp` on the phone while streaming shows **no**
  connection to any `192.168.0.x`; the only camera-adjacent sockets are UDP, and the app binds
  `0.0.0.0:8900` (uid 10086).
- Channel stats seen: `srcID=9512032141665525923`, `dstID=<camera TID>`, `camera_sid=0`,
  `type=2`, `score=77`, `select=0`.
- Camera LAN IPs (from `GDM_JDAT_RPT`): `.217 / .169 / .224 / .117`, SSID `Jose`.

---

## 7. Key symbols (armeabi-v7a) — the map for further RE

```
Control plane
  iv_init_frm_listsrv              0x36544   build LIST_REQUEST (40 B)
  iv_send_list_request             (log)     port 51701
  iv_dns_callback_v2 / iv_addListSrv         resolve + add list server
  iv_addRmtP2pSrv                            add relay ("Asrv") UDP endpoint
  gat_start_process_detect_all_p2psrv 0x41ab0
  gat_detect_fastest_p2psrv_v2      0x49f4c
  gat_on_rcvpkt_DetectReq           0x4a808
  iv_gutes_start_active_certify_req 0x31ed8   certify handshake
  gutes_on_respfrm_certify_resp     0x32bb0   -> session_id
  iv_init_frm_nat_detect            0x36690

Frame / crypto
  iv_gute_frm_init_chkval           0x2aa38   XOR checksum (mask 0x00FFFFFF)
  iv_gute_frm_rc5_encrypt           0x2b2ac   RC5, header-derived key
  iv_gute_frm_rc5_decrypt           0x2ad98
  iv_gutes_frm_encryp / _decrypt    0x2e260 / 0x2c668
  rc5_ctx_setkey                    0x64b08
  gute_get_encrypt_data_len         0x2a9b4   == total_len - 24 (for the list frame)

AV / channels
  iv_init_frm_CALLING               0x542c0
  iv_init_frm_AvStreamCtl           0x53274
  iv_init_frm_mtp_quality           0x582e4
  ivkcp_interval/nodelay/wndsize    0x7c03c / 0x7c094 / 0x7c17c

LAN discovery
  broadcast_fd_init  0x7c200   binds UDP 8900 (movw r1,#0x22c4 then rev/lsr #16 = htons)
  broadcast_init     0x7cad8
  recv_loop          0x7d08c
  send_msg           0x7d340   generic UDP send(fd, buf, len, port, addr)
  send_loop          0x7d778   emits to multicast ff02::1
  start_recv_thread  0x7d5f4   send_loop ipv6 variant uses send_msg_ipv6 0x7d45c
```

> [!] **Address caveat:** these are **armeabi-v7a** addresses. The arm64-v8a copies of the same
> functions live at different addresses. The device is 32-bit (`abilist=armeabi-v7a,armeabi`),
> so armeabi-v7a is the one that actually runs.

---

## 8. Tooling notes for anyone reproducing this

- `objdump -d -j .text` — **section names are stripped**, so `-j .text` is mandatory or you get
  nothing. `.text` VMA `0x14f40`, size `0xa4470`.
- Code is **ARM, not Thumb**. `-M force-thumb` produces garbage (`ldrbtmi`).
- PLT stubs are **unnamed**. Build the map from `objdump -R`'s `R_ARM_JUMP_SLOT` entries in
  order: `PLT_stub[n] = 0x12588 + n*12`. (Stubs are 12 bytes: 3 ARM words.)
- `nm -D` for dynamic symbols; `nm` alone misses statics.
- Scripts written today: `watch_lan.py` (UDP + `/proc/net/tcp` poller), `capture_mcast.py`
  (IPv6 multicast listener), `capture_setup.py` (cold-start + navigate + pid-filtered logcat).
  Helper `run()` wraps `tools.rea.capture_process_scenario`.
- **The `execute` harness kills a PTY that goes silent** — long-running listeners need a
  heartbeat print or a large `idle_timeout_ms`. Also `normalization.ports` masks port numbers
  in output unless disabled, and `terminal.columns × (rows+scrollback) ≤ 1,000,000`.

---

## 9. Disproved / corrected earlier beliefs

| # | Earlier belief | Reality |
|---|---|---|
| D16 | Live view is LAN-direct **TCP** to `192.168.77.12:59239` | **False.** Full TCP sweep of all cameras is empty; transport is KCP/**UDP**. The old `port:59239` log line was misread. |
| D17 | LAN discovery is **IPv4 broadcast to :8900** | **False / unproven.** App binds :8900 to *receive*, but discovery sends to **IPv6 multicast ff02::1**. IPv4 listeners see nothing. |
| D18 | `tid_key_map` is populated locally or via HTTP | **False.** Delivered by the relay: `gat_rcv_init_info_msg_resp did=… <--> wyze_id:…`. |
| D19 | Camera LAN IPs come from LAN discovery | **False.** They arrive through the relay in `GDM_JDAT_RPT_REQ` `netInfo.stVal.ip`. |
| D20 | Frames are in the clear | **False.** RC5-encrypted — but with a header-derived key (§5), so not a hard barrier. |

## 10. Confirmed today

| # | Fact |
|---|---|
| C15 | App binds **UDP 8900** (`broadcast_fd_init pMgr->fdRead`, uid 10086) |
| C16 | List server = `wyze-mars-asrv.wyzecam.com` on **UDP 51701**, `ListFrmRequest`/`LIST_RESP` |
| C17 | 5 relay ("Asrv") UDP endpoints observed, `srv_id` 28/38/48/49/58 |
| C18 | GUTES `certify` handshake yields a **session_id** before any AV |
| C19 | Device list (4 cams, TID↔wyze_id) delivered by relay, `srv_relation=1` |
| C20 | `LIST_REQUEST` frame layout fully recovered (40 B, magic `0x7F`, type `0x15`) |
| C21 | Checksum = 32-bit XOR, mask `0x00FFFFFF`, stored at offset 16 |
| C22 | RC5 with 8-byte key derived from the frame header |
| C23 | `devID`(signed) == `srcID`(unsigned) == `9512032141665525923` |
| C24 | Transport is **KCP/UDP**; zero TCP sockets to cameras while streaming |
| C25 | `gute_get_encrypt_data_len` = `total_len − 24` for the list frame |

---

## 11. Honest risk assessment for Route C

**What is now easy:** the list-server request is fully specified (§3–§5) except the RC5
round-count/wordsize, and the server's response is a *validation oracle* — we can send a
crafted packet and see whether we get a `LIST_RESP`.

**What is still hard, and blind:**
- RC5 params not pinned (small search space: wordsize ∈ {32,64} × rounds ∈ {8,12,16}).
- `LIST_RESP` parsing, then the whole GUTES certify + `init_info` + `GDM` layer.
- KCP configuration and the AV channel/frame protocol, then H.264/H.265 extraction.

**The fundamental handicap:** the phone↔relay and phone↔camera traffic is *unicast*, so it
cannot be sniffed from the Mac (no root on the phone; `tcpdump` lacks permission; adb is over
USB so the Mac isn't in the path). Every layer must be rebuilt from disassembly and validated
only by "did the server answer". That is workable but slow, and there is no ground-truth byte
log to diff against when something subtly fails.

**This is the crux of the strategic decision** — see `STATUS.md`.
