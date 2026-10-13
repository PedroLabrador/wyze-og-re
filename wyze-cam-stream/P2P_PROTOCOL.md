# P2P PROTOCOL — Gwell IoTVideo / TUTK-Kalay (Wyze OG, model `CAM-1`)

> **This file is ground truth recovered on 2026-10-12** from static disassembly of
> `lib/armeabi-v7a/libiotp2pav.so` **corroborated by live `logcat`** from the running app.
> Confidence is marked per item: **[CONFIRMED]** = seen in disassembly *and/or* log output,
> **[WIRE]** = captured on the wire (highest confidence — byte-exact), **[INFERRED]** = read out
> of code but not yet observed on the wire.
>
> **The `LIST_REQUEST`/`LIST_RESP` exchange is now [WIRE]-confirmed end to end.** Our Python
> builder reproduces the app's own packet **byte for byte**, and the genuine list server answers
> it. See §3a.
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

**Correction on offset 4 and on the sequence number** (learned from the wire, §3a):
the value written at `buf[4:12]` at *build* time is **not** the value that goes on the wire, and
`seq` is **always 0** for this frame type.

---

## 3a. Ground truth — the real packet, captured [WIRE]

### How it was captured

Rather than guessing crypto parameters against a silent server, the app's **own** list-server
host was redirected at this Mac:

1. `smali_classes6/com/gwell/common/data/GWApi.smali` line 727, inside
   `getBaseServerUrl()` (the `:cond_5` official branch):
   `const-string v0, "|192.168.77.13"` (was `"|wyze-mars-asrv.wyzecam.com"`).
   `MarsUrl` deliberately left untouched so OAuth still works.
2. `apktool b` → `uber-apk-signer --ks wyze_debug.keystore --ksAlias wyze --ksPass android
   --ksKeyPass android` → `adb install -r` (same signature ⇒ login preserved).
3. `cap_listsrv2.py` listens on **UDP+TCP 51701** (both — see the HTTP fallback below).

> `GWApi.GWellP2PUrl` is a pipe-delimited list: `"" , host [, fallback_ip]`, and it is written
> only by `getBaseServerUrl()`. `setGWellP2PUrl` is never called.
> Install needs free space (`pm trim-caches 4G`) — a 244 MB APK alongside the old one overflowed
> `/data` the first time.

### The request the app actually sent

```
7f152800 4b64b35d7f2dddab 94d93411 e3835696 00000100
000102030405060708090a0b0c0d0e0f
```
identical on every retransmission and **identical across a full app restart** (only the UDP
source port changes).

### The response, decrypted

```
magic 0x7F  type 0x16 (22) = LIST_RESP  total 176  flags 0x000185f4
key  = 7f16b000f4850100            # same header-derived rule as the request
[12:20] -> seq=1596074741  chk=0xaa0ab28a
payload = 176 - 24 = 152 bytes, 19 RC5 blocks, decrypted clean (no residual garbage)
```

Decrypted payload (offsets are from the frame start):

```
 24: 02 00 00 00 81 00 04 00 03 0d d4 18 00 00 00 00
 40: 00 00 00 00 00 00 00 00 00 00 00 00 01 00 31 00
 56: 70 80 70 80 a0 29 67 e8 00 00 00 00 2c ee 68 fc
 72: 26 00 1f 13 0a c8 36 0b ff c0 38 53 a1 f3 e9 92
 88: 09 00 12 00 01 bb 01 bb 1f 41 67 e8 00 00 00 00
104: 36 d0 10 f5 00 00 00 00 00 00 00 00 00 00 00 00
120: 00 00 00 00 01 00 3a 00 01 bb 01 bb b1 bd 67 e8
136: 00 00 00 00 34 28 dd fd 26 00 1f 13 0a c8 36 0c
152: f5 86 1a db 61 e6 88 f9 09 00 1c 00 c9 f9 c9 f9
168: 52 09 67 e8 00 00 00 00
```

### Decoded — frame header [CONFIRMED — disassembled]

Recovered from `gat_on_rcvpkt_LIST_RESP` @ `0x4ad64`. The handler takes `(ctx, pkt)` and does
`base = pkt + 400` — the 400-byte `pkt` wrapper ends exactly where the raw frame begins, so
**`base` = the frame start**. Two reads prove it:

| read | purpose |
|---|---|
| `ldrh r1, [base+2]` compared to `pkt+0x34` | frame's `total_len` sanity check |
| `ldrh r1, [base+24]` then `and r1, #1` | the same `flags |= 1` bit our request builder sets |

```
frame +0   u8  magic   0x7f
       +1   u8  type    0x16 = 22 = LIST_RESP
       +2   u16 total_len   LE  (= 176 here)
       +4   u32 / +8 u32 / +12 u32   header words (0xb106f64d / 0x5c73f1ba / 0x5f222af5)
       +16   16 B            000102030405060708090a0b0c0d0e0f
       +24   u16 flags        LE, bit0 = request-flag bit
       +26   6 B             000081000400
       +32   records[]       stride 36, count = (total_len - 32) / 36
```

**Records start at `base+32`, stride exactly 36** — the loop is
`cursor = base+32; while (i < count) { iv_addRmtP2pSrv(ctx, cursor); cursor += 36; }`
followed by `iv_store_srv_info(ctx, base+32, count)`. Here `176 - 32 = 144 = 4 × 36`, remainder 0.

### Record layout [CONFIRMED — disassembled + WIRE]

`iv_addRmtP2pSrv` @ `0x410d0` starts with `movw r3, #0x24` / `memcpy(local, rec, 36)` — the
record copy sits at `r11-64`, so every `[r11, #-K]` reads record offset `64-K`. That map gives
the whole layout (`fieldmap.py` regenerates it):

| rec | field | type | maps to |
|---|---|---|---|
| `+0` | **IPv4** | u32, **network order** | key to `iv_findP2PSrv`; `sin_addr` of all 4 sockaddrs |
| `+4` | **IPv6** | 16 B | passed bytewise; the client may overwrite it via `iv_get_ipv6_addr_from_ipv4(ctx, ipv4, rec+4)` |
| `+20` | kind | u8 | `ubfx #1,#2` (2 bits) → `entry+0x5c` |
| `+22` | **srv_id** | u16, LE | `entry+94` |
| `+24` | **port1** | u16, **network order** | `sockaddr_in` at `entry+12` |
| `+26` | port2 | u16, network order | `sockaddr_in` at `entry+112` |
| `+28` | port3 | u16, network order | `sockaddr_in` at `entry+132` |
| `+30` | port4 | u16, network order | `sockaddr_in` at `entry+148` |
| `+32` | — | u32 | never read (zeros) |

Each of the four targets is a plain `struct sockaddr_in { u16 family = AF_INET=2; u16 port;
u32 addr; }` — `movw r0,#2 / strh [entry+12|112|132|148]` then the port, then the address.

Port byte order is proven by the handler itself:
`ldrh r4, [entry+14]; rev r4; lsr #16; uxth` converts the stored u16 back to host order for
the log line — i.e. the wire bytes are big-endian.

### The four relay servers it hands out

```
rec  srv_id  ipv4              ipv6                                    kind  ports +24/+26/+28/+30
0    49      3.13.212.24       -                                       1     28800 / 28800 / 41001 / 26600
1    18      44.238.104.252    2600:1f13:ac8:360b:ffc0:3853:a1f3:e992   9     443   / 443   / 8001  / 26600
2    58      54.208.16.245     -                                       1     443   / 443   / 45501 / 26600
3    28      52.40.221.253     2600:1f13:ac8:360c:f586:1adb:61e6:88f9   9     51705 / 51705 / 21001 / 26600
```

**Cross-check against the phone's live logcat — MATCH:**
`iv_addRmtP2pSrv: add udp_addr 3.13.212.24:28800 srv_id=49` ↔ record 0
(IPv4 from `rec+0`, port from `rec+24` big-endian, srv_id from `rec+22` LE). This is what
closes the layout.

Notes:
- `port1 == port2` in all four records (the two sockaddrs are fed identical values).
- `port4 = 26600` is **constant across every record**.
- `kind` is `1` exactly when the IPv6 field is empty, `9` when it is populated — so bit3
  most likely means "IPv6 present"; the 2 bits the code actually extracts (`bits[1:2]`) are
  `0` in all four.
- `192.168.77.15` / `192.168.77.16` (seen at `+76`/`+148` in the raw dump) are **not** IPv4s —
  they are bytes 4–7 of records 1 and 3's *IPv6* field, inside `2600:1f13:0ac8:360b::`.
- The relay set here (srv 49/18/58/28) is **different** from the built-in fast-connect list the
  phone logs at startup (`35.81.136.54:8000` srv 38, `3.13.212.24:28800` srv 49,
  `3.131.23.11:8443` srv 48) — only srv 49 overlaps.

Decode it with `python3 decode_lr.py wire/list_resp_decrypted.hex`.

### What the server actually accepts (probed against `18.118.90.161:51701`)

| packet | `[4:12]` | checksum over | result |
|---|---|---|---|
| app verbatim | `d_real` | `d_log` | [OK] **176-byte `LIST_RESP`** |
| self-consistent | `d_log` | `d_log` | [X] timeout |
| self-consistent | `d_real` | `d_real` | [X] timeout |
| `seq=1` | `d_real` | `d_log` (seq 1) | [X] timeout |

where
```
d_log = 9512032141665525923   = 0x840186d6001260a3   # = logcat devID/srcID (terminal ID)
d_real= 12384104575394866251  = 0xabdd2d7f5db3644b   # value that goes on the wire at [4:12]
```

So the wire format is: **`buf[4:12] = d_real`, but the checksum is computed over `d_log`.**
Both are **stable constants** for this install (verified across a restart), and `seq` **must be
0** — consistent with the builder, which only increments when `(*(ctx+0x1548))->field_0x68 != 0`;
for `LIST_REQUEST` that field is `0`, so it writes `0` and skips the increment.

- `d_log` is the phone's P2P terminal ID (see §1) and is what the server evidently looks the
  client up by. **[OPEN]** where `d_real` comes from — it is *not* RC5 of `d_log` (tried the
  header key), and it does not XOR to any obvious constant. Practical answer: **hardcode both.**
- `iv_init_frm_listsrv` writes `ctx+0x240 / ctx+0x244` into `buf[4:12]` **once**, *before*
  `chkval` @ `0x36654`, and nothing in the function touches it afterwards ⇒ the swap to
  `d_real` happens between the build and the send. **[OPEN]** where.

### HTTP fallback [WIRE]

The client alternates transports, both on port 51701:

```
iv_send_list_request mode=0 -> UDP ListFrmRequest
iv_send_list_request mode=1 -> evhttp_connection   (HTTP fallback)
iv_on_timeout_query_listsrv_resend: send HTTP ListFrmRequest to ipv4=…:51701, ms_timeout = 1000
iv_http_list_request_done: pkt->data_len=0
```

The HTTP request body is the same 40 raw bytes.

### Our builder reproduces the app exactly

```python
build() == app_packet   # True
```

i.e. frame layout + checksum + RC5-32/6/8 little-endian are all **byte-exact**. See
`listreq.py` and `probe_real.py`.

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
- **[WIRE]** the algorithm above is byte-exact: feeding it the plaintext terminal ID reproduces
  the app's encrypted `chk` field exactly, and the same function validates against the decrypted
  `LIST_RESP`. [!] but note the `d_log`/`d_real` split in §3a — the words at offsets 4/8 that go
  into the checksum are **not** the ones that end up on the wire.

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

### RC5 parameters — PINNED [WIRE]

**RC5-32, 6 rounds, 8-byte key, 8-byte blocks, little-endian block words.**

Evidence chain:
- call site does `movw r1,#0x8; movw r2,#0x6` → `rc5_ctx_new(8,6)`, stored at `struct+0xd4`
  (the context `iv_gute_frm_rc5_encrypt` reads).
- `ctx[0]=6` (rounds), `ctx[1]=8`, `ctx[2]=ctx[1]<<2 = 32`.
- `rc5_enc64` requires `ctx[1]==8` (ours), `rc5_enc32` requires `==4` ⇒ we take the 64-bit-block
  routine. Function names mean **block size in bits**; `ctx[2]` is the **word** size.
- S-table = `(6+1)*8 = 56 B = 14 × 4-byte words` = `2(r+1)` ⇒ word = 32 bits ⇒ **RC5-32**.
- inner routine `movw r0,#0x20` → rotate mask `32`.
- `rc5_ctx_setkey` switches on `ctx[2] ∈ {16,32,64}` = word bits.

**Byte order = little-endian** — proven on the wire: decrypting `LIST_RESP[24:40]` yields
`0100000000000000`, exactly the planned `u16(1)` at offset 24 with zero padding.

Decryption (the inverse of §5):
```python
def rc5_dec(S, blk):                       # RC5-32/6, blk = 8 bytes
    A = int.from_bytes(blk[0:4], "little"); B = int.from_bytes(blk[4:8], "little")
    for i in range(6, 0, -1):
        B = rotr32((B - S[2*i+1]) & MASK, A) ^ A
        A = rotr32((A - S[2*i])   & MASK, B) ^ B
    B = (B - S[1]) & MASK; A = (A - S[0]) & MASK
    return A.to_bytes(4, "little") + B.to_bytes(4, "little")
```

Still **[OPEN]**: `iv_gute_frm_encrypt_id 0x2ac40` / `iv_gute_frm_decrypt_id 0x2acec` — a
separate ID transform, possibly the source of `d_real` (§3a).
Related symbols: `rc5_ctx_new 0x64994`, `rc5_ctx_free 0x64ae8`, `rc5_ctx_setkey 0x64b08`,
`rc5_enc32 0x65dbc`, `rc5_enc64 0x65ee4`, `rc5_encrypt 0x66044`, `rc5_ctx_dec 0x658d0`.

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
  (IPv6 multicast listener), `capture_setup.py` (cold-start + navigate + pid-filtered logcat),
  **`listreq.py`** (frame builder + checksum + RC5, byte-exact), **`cap_listsrv2.py`**
  (UDP+TCP list-server impersonator), **`probe_real.py`** (send to the genuine server).
  Helper `run()` wraps `tools.rea.capture_process_scenario`.
- **Ground truth without a root phone:** patch the app's list-server host to the Mac, rebuild
  with `apktool`, re-sign with `wyze_debug.keystore`, `adb install -r`, and listen. This is
  how §3a was obtained and it unblocks any "the server never answers" investigation.
  *Flag:* the app takes ~45 s to reach the home screen, so the listener must outlive it.
- `uber-apk-signer` flag is `--ksKeyPass` (not `--keyPass`); `adb install` of a 244 MB APK
  needs ~1 GB free — run `adb shell pm trim-caches 4G` first.
- **The `execute` harness kills a PTY that goes silent** — long-running listeners need a
  heartbeat print or a large `idle_timeout_ms`. Also `normalization.ports` masks port numbers
  in output unless disabled, and `terminal.columns × (rows+scrollback) ≤ 1,000,000`.
  A stale owned PID wedges cleanup (`cleanup_incomplete`) — kill -9 the stale PID first.

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
| C26 | **[WIRE]** Real `LIST_REQUEST` captured: `7f1528004b64b35d7f2dddab94d93411e383569600000100b403bcb04c02f4141b543c610e1bce3b` |
| C27 | **[WIRE]** Genuine `LIST_RESP` = 176 B, magic `0x7F`, **type `0x16` (22)**, `flags 0x000185f4`, payload 152 B |
| C28 | **[WIRE]** RC5 decrypt verified: `LIST_RESP[24:40]` → `0100000000000000`; **block byte order = little-endian** |
| C29 | **[WIRE]** Our Python builder reproduces the app's packet **byte for byte** (`build() == app`) |
| C30 | **[WIRE]** Server accepts *only* `[4:12]=d_real` + `checksum(d_log)` + `seq=0`; both IDs stable across restart |
| C31 | **[WIRE]** There is an **HTTP fallback** for the list request on the same port 51701 (`mode=1`, `evhttp_connection`) |
| C32 | Redirecting `GWApi.GWellP2PUrl` to the Mac works end-to-end and preserves login (same-signature reinstall) |
| C33 | **[DISASSEMBLED]** `LIST_RESP` records start at **frame+32, stride 36**; `count = (total_len-32)/36` — exact fit (4×36) |
| C34 | **[DISASSEMBLED]** record = `IPv4@0 (BE) | IPv6@4 (16B) | kind@20 | srv_id@22 (LE) | port1@24 | port2@26 | port3@28 | port4@30 (all BE)` |
| C35 | **[WIRE+LOGCAT]** Layout cross-verified: record 0 decodes to `3.13.212.24:28800 srv_id=49`, exactly the phone's live `iv_addRmtP2pSrv` line |

---

## 11. Honest risk assessment for Route C

**Updated 2026-10-12 late — the two biggest handicaps were removed today.**

**Now easy / solved:**
- Frame layout, checksum and **RC5-32/6/8 little-endian** are byte-exact — our builder
  reproduces the app's own packet (§3a, C29).
- **There is now a ground-truth byte oracle.** Redirect `GWApi.GWellP2PUrl` to the Mac and the
  app hands us its real packets; send them to the real server to get a real `LIST_RESP`.
  This is the same trick that de-blocked the list exchange and applies to anything else the
  app builds and sends. It also means we are no longer limited to "did the server answer".

**Still hard:**
- the whole GUTES `certify` → `session_id` → `init_info` → `GDM` layer (next up — the
  builders are `iv_gutes_start_active_certify_req` @ `0x31ed8`, `gat_send_init_info_msg` @
  `0x3eac4`, `gat_rcv_init_info_msg_resp` @ `0x46960`).
- KCP configuration and the AV channel/frame protocol, then H.264/H.265 extraction.
- `d_real` provenance (§3a) — worked around by hardcoding, not understood.
- **[OPEN]** whether the server will accept a *different* terminal ID than this install's
  `d_log`. If it keys the client by it, a Python client may need to register its own ID
  (probably via `regist_gw_user`, §1).

**Remaining handicap (reduced):** phone↔relay and phone↔camera traffic is unicast and still
cannot be sniffed from the Mac (no root, `tcpdump` unprivileged, adb over USB). But the
redirect technique turns the *app itself* into the sniffer for anything it originates, which
covers the control plane. The AV plane still has to come from disassembly unless we can
redirect the relay endpoints too — **now precisely specified**: rewrite `record+0` (the IPv4,
4 bytes at `frame + 32 + i*36`) and/or `record+24` (the port) in the `LIST_RESP`, and the app
will dial the Mac instead of AWS. Field positions are known exactly (§3a), so this is a
5-line change to `cap_listsrv2.py`.

**This is the crux of the strategic decision** — see `STATUS.md`.
