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
- **[WIRE]** the algorithm above is byte-exact for **requests**: feeding it the plaintext terminal
  ID reproduces the app's encrypted `chk` field exactly. [!] but note the `d_log`/`d_real` split in
  §3a — the words at offsets 4/8 that go into the checksum are **not** the ones that end up on
  the wire.

### §4a. Responses — `g(header)` is NOT modelled, and you don't need it [WIRE — oracle-proven]

[!] **Requests and responses are NOT symmetric.** The same `init_chkval` disassembly validates
nothing on its own for an inbound frame, and this was proven with the running app as an oracle
(`chk_probe.py`: patch a byte → re-encrypt → the app prints
`iv_gute_frm_rc5_decrypt … chkval fail chk_val=<its answer> frm_chkval=<stored word>`).

**What the oracle proved (do not re-derive these):**

| # | Result | Verdict |
|---|---|---|
| 1 | Varying **any** payload word `24..172` by `D` moves the app's answer by exactly `D`: `chk(probe) ^ chk(base) == D` — all 38 words, one probe each | [OK] **payload is a plain XOR-fold, nwords = 38** |
| 2 | `app_chk ^ our_chk` is **constant** under payload edits (identical `X` for an edit at off 100 and at off 24) | [OK] **`app_chk = g(header[0:23]) ^ fold(payload)`** |
| 3 | Editing `W4`/`W8`/`W12`/flags each produced a *non-linear, non-`D`* change in `X` (e.g. `X(BASE)=0x9eb4f247`, `X(W4^=D)=0x0fb6ffd6`, `X(W8^=D)=0x43573b74`, `X(W12^=D)=0xa257e663`, `X(flags^=1)=0xde1f448f`) | [X] **static byte-exact reproduction of `g(header)` is NOT tractable** — it depends on `iv_gute_frm_decrypt_id` (`0x2ac40`) / a decryption path not modelled |

**Consequence — the workaround that actually ships.** `g(header)` is a *constant* for a fixed
header, so **keep the server's own checksum word (offset 16) and make only fold-neutral payload
edits**. Then the app recomputes the identical value and accepts the frame.

```
1. decrypt genuine LIST_RESP          → plain
2. rewrite IPv4 / ports in the records
3. xor the sum of those byte-changes into a sacrificial payload word
4. LEAVE offset 16 and the whole 32-byte header untouched
5. re-encrypt, re-send  → app accepts
```

- Sacrificial word used: **offset 172** (record 3's trailing 4 bytes, `0` in every observed
  record, and the *last* word of the fold — so no record field is disturbed).
- [!] **Endianness trap (cost us a whole test run):** `delta` must be accumulated **and applied**
  with the same endianness. IPv4 and the port fields are big-endian on the wire, so accumulate
  with `struct.unpack(">I", …)` **and** apply with `struct.pack_into(">I", …)`. Applying with
  `"<I"` XORs the bytes with the reversed sequence — a rotate-right-8 — and the fold comes out
  off by `0x95c8bec8` instead of `0xc8bec895`. Verify **offline** before going live:
  `checksum(plain_orig) == checksum(plain_mod)` and the XOR of all changed payload words is `0`.

**Proof it works:** `cap_relay.py` rewrites all four relays to `192.168.77.13:28800` this way →
zero `chkval fail chk_val=` in logcat, and the app prints
`set current ListSrv to 192.168.77.13.` + `add udp_addr 192.168.77.13:28800 srv_id=49`.

> Note the two distinct `chkval fail` lines in logcat: filter on **`chk_val=`**. The
> `opt_encrypt=2 … chkval fail...` line carries no value and is unrelated noise.

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

## 5a. GUTES `certify` — how the session key is agreed [CONFIRMED — disassembled]

This is the layer right after `LIST_RESP`: the app dials a relay from §3a and runs `certify`
to get a session, then `init_info` → `GDM`. Two functions give the whole exchange away.

### `iv_gutes_start_active_certify_req(ctx)` @ `0x31ed8`

Same `pkt` wrapper as before — `calloc(1, 0x268)`, 608 B zeroed, then
**`frame = pkt + 400`** (the identical 400-byte header seen in `LIST_RESP`). It then writes:

```
frame+0    0x7f
frame+1    0x0c            <- type 12 = certify_req
frame+2    u16 LE  64      <- total_len (grows, see TLVs below)
frame+4    u32   } terminal id, from ctx+0x240 / ctx+0x244
frame+8    u32   }         <- same two words as LIST_REQUEST[4:12]
frame+12   (untouched here — the common finalizer owns the checksum)
frame+20   u32 = 0x01410000   flag/ver word, built by three mask/orr steps:
             bits16-17 = ctx->field_0x94 & 3        (1 on the first call)
             bit22     = 1
             bit24     = 1
frame+24   u16 flags     bit0 = "extended tail",  bit2 = "append 8-byte token"
frame+26   u16           (left 0 in the request; it is the *error code* in the response)
frame+28   u32 = giot_hash_string(nonce, 32)     <- hash of the PLAINTEXT nonce
frame+32   32 B nonce, then RC5-encrypted in place:
             for i in 0..1: rc5_ctx_enc(ctx->rc5_B /*ctx+0xdc*/, frame+32+i*16, 16)
```

The nonce itself:

```
if (time_adj != ctx->field_0x98) {          // cache it; only regenerate when it changes
    ctx->field_0x98 = time_adj
    iv_getRandomValue(ctx+156, 32)           // 32 random bytes live at ctx+156
}
memcpy(frame+32, ctx+156, 32)
```

`time_adj` comes from `time(NULL)` fed through an unnamed helper @ `0xb794c` with a second
argument of `0x1c20` = **7200** — i.e. a UTC+2 (local) offset. **[OPEN]** exactly what that
helper is, but it only feeds the cache key, so it does not affect the wire bytes.

**Optional tail TLVs** (each one both sets a bit in `frame+24` and grows `total_len`):

| condition | bit set | bytes appended | len delta |
|---|---|---|---|
| `cfg->field_0xd4 >= 556` | `frame+24` bit0 | `cfg+0xd4..0xd7` (4 B) at `frame+64+off` | +4 |
| `cfg->field_0xde8 \| cfg->field_0xdec != 0` | `frame+24` bit2 | `cfg+0xde8..0xdef` (8 B) | +8 |

The second one is the **echo of the token the server handed back in `certify_resp`** (below) —
so it is absent on the very first `certify` and present on every later one.

Finally `iv_gutes_add_send_pkt(ctx, pkt, &{cmd=3, timeout=30, ?=0, ?=3}, …)` and
`ctx->field_0xc0 = 1` (state = waiting).

### `gutes_on_respfrm_certify_resp(arg0, arg1, arg2, arg3)` @ `0x32bb0`

`arg2` is the response packet — again read as `arg2 + 400` = the frame. `arg3` is a status
code: **`arg3 == 2` means failure** (it logs, clears `ctx->field_0xc0`, clears bit1 of
`cfg->field_0x1c`, bumps a counter at `cfg+0x14bc`, zeroes `cfg+5312` and returns).

On the success path:

| read | meaning |
|---|---|
| `u16 frame[+26]` | **error code** — non-zero ⇒ log + `ctx->field_0xc0 = 0` and stop; `3` is a special "fatal" case that also invokes a callback through `cfg+0x1124` and sets `cfg+0xde0 = 1` |
| `u16 frame[+24] & 1` | if set ⇒ `cfg+0xdf2 = 1` |
| `u32 frame[+28]` → `cfg+0xde8` | \  the 8-byte token echoed in later requests |
| `u32 frame[+32]` → `cfg+0xdec` | / |

then, critically:

```
rc5_ctx_setkey(ctx+0xd8, ctx+156, 32)     //  <-- THE SESSION KEY
ctx->field_0x94 = 2
ctx->field_0xc0 = 2   (state = certified)
gat_send_init_info_msg(ctx)               // 0x3eac4, next message in the chain
```

> ### The key exchange, in one sentence
> The client makes up **32 random bytes** (`iv_getRandomValue`), sends them inside
> `certify_req[32:64]` RC5-encrypted under the **header-derived key** (§5), keeps a copy at
> `ctx+156`, and on a successful `certify_resp` installs that same 32-byte value as the RC5
> key for everything that follows — `rc5_ctx_setkey(ctx, nonce, 32)`.
> So GUTES session traffic is RC5 with a **32-byte key = the client nonce**, while the
> `LIST_*` and `certify_req` frames use the **8-byte header key**. Same `rc5_ctx_setkey`
> routine, different key length ⇒ RC5-32/6/**256** rather than /6/8.

**Chain so far:** `LIST_REQUEST` → `LIST_RESP` (relays) → TCP/UDP to a relay →
`certify_req`(type 0x0c) → `certify_resp` (session key installed) → `init_info` →
`GDM_JDAT_RPT` (camera LAN IPs) → KCP/AV.

---

## 5b. End-to-end: the app talking to *us* [WIRE — live, 2026-10-13]

With §4a's fold-neutral rewrite in place, `cap_relay.py` runs a **full MITM**:

```
app --UDP--> 192.168.77.13:51701 (cap_relay) --UDP--> 18.118.90.161:51701 (genuine list srv)
app <--MOD-- 192.168.77.13:51701                  (4 relays repointed at us, chk kept)
app --UDP--> 192.168.77.13:28800 (cap_relay) --UDP--> 3.13.212.24:28800 (genuine relay)
app <--UDP-- 192.168.77.13:28800
```

**Verified:** zero `chkval fail chk_val=`, `gat_on_rcvpkt_LIST_RESP … set current ListSrv to
192.168.77.13.`, `add udp_addr 192.168.77.13:28800 srv_id=49`, and 9–12 relay packets relayed
both ways per run.

### Observed control-plane sequence (logcat, in order)

```
iv_fast_connect_srv srv_num=3 fast_connect=1
iv_addRmtP2pSrv … add udp_addr 3.13.212.24:28800   srv_id=49   ← ip_env=0, FROM DISK CACHE
iv_addRmtP2pSrv … add udp_addr 44.238.104.252:443  srv_id=18   ← ip_env=0, FROM DISK CACHE
iv_addRmtP2pSrv … add udp_addr 54.208.16.245:443   srv_id=58   ← ip_env=0, FROM DISK CACHE
iv_send_list_request mode=0 / port=51701
iv_on_timeout_query_listsrv_resend: … to ipv4=192.168.77.13:51701 … list_req_cnt=…
gat_on_rcvpkt_LIST_RESP … set current ListSrv to 192.168.77.13.
iv_addRmtP2pSrv ip_env=1 → add udp_addr 192.168.77.13:28800 srv_id=49   ← OURS
gat_send_detecReq_2_allp2psrv: cnt_all_srv_detect=N len=68 to 192.168.77.13:28800
iv_gutes_on_respfrm_Detect chkval=… snd_sqnum=…
iv_gutes_start_active_certify_req mtu=1032
gutes_on_respfrm_certify_resp session_id=7696021469729393155
gat_rcv_init_info_msg_resp srv_id=… frm_len=209 offline_cnt=0 online_cnt=4
   did=429728658691722 wyze_id:CAM-1_D03F27747BB0   … (4 devices)
gat_on_rcv_GDM_JDAT_RPT_REQ … content={"ProReadonly":{"_online":…,"netInfo":{"stVal":
   {"ssid":"Jose","ip":"192.168.77.12", …}}}}   … (per camera)
```

> **`init_info` → `GDM` answered every open question in STATUS open-problem #1**: it carries
> `online_cnt=4`, the `did`/`wyze_id` map, and each camera's **LAN IP + MAC + ssid**.
> Cameras: `.217` D03F27747BB0 · `.224` D03F27EBFB10 · `.169` D03F2776110C · `.117` D03F277576D8.
> [!] `netInfo` still has **no TCP/UDP port** — that comes from the KCP/GDM layer, not here.

### [!] Imperfections — real, but no longer blocking

1. **The app restores the real relays from a disk cache at startup** (`ip_env=0`), *before* our
   `LIST_RESP` arrives, so `iv_fast_connect_srv srv_num=3` initially describes the genuine AWS
   relays. Our relays are added afterwards with `ip_env=1`. The cache is **not** a file under
   `/data/data/com.hualai` (searched for both the text `3.13.212.24` and the raw bytes
   `03 0d d4 18` — nothing), so it is either in `com.hualai_wyze_sp_secure.xml` (encrypted) or
   supplied by the Java layer at SDK init.
2. **`NET64 IPV4_TO_IPV6 FAIL`** still fires ~37×/run for the records other than the first one.
   With one shared address they were *duplicates*; with per-record ports the first record is
   always added (`add udp_addr 192.168.77.13:28800 28900 srv_id=49`) and only the rest fail.
   **Benign** — one relay is enough; the whole control plane completes on `srv_id=49`.
3. **`iv_gutes_on_respfrm_Detect not find p2p...`** fires repeatedly and is **also benign** —
   `certify_resp` / `init_info` / `GDM` / the AV link all proceed despite it.

> [!] **Our smali patch made the Mac the ONLY list server.** With `cap_relay.py` not running the
> app gets *no* list response at all (GDM count = 0, every request times out on
> `192.168.77.13:51701`, including the HTTP fallback). So the MITM is now mandatory for any
> experiment — there is no "genuine" baseline without rebuilding the APK with the original URL.

**Relay wire formats captured in the clear** (both legs, `cap_relay.py` transcript):

- `Detect` request — **type `0x01`, 68 B**, flags `0x00010000` (RC5, 8-byte header key), a
  per-request nonce at `+4..+19`, and the constant 8-byte cookie `fcd4f19a43f516ee` repeated
  4× at `+32..+63` (`+64..+67 = 0`).
- `Detect` response — **type `0x02`, 56 B**, plaintext-looking: `d_log` (`a3601200 d6860184`)
  at `+4..+11`, varying `+12..+19`, `0x0000855c` at `+20`, `1` at `+24`, a counter at `+36`,
  and **Unix time at `+48`** (`f1c4cd6a` = 2026-10-13).
- [!] `iv_gutes_on_respfrm_Detect not find p2p...` fires regardless. It was first blamed on
  collapsing all four records onto one address; giving each record its own local port
  (28800/1/2/3 primary, 28900/1/2/3 secondary, each forwarding to its genuine relay) **did not
  remove it** — and it turned out not to matter.

### The app also dials the relay over **TCP**

`gat_start_tcp_connect_p2psrv -> ivtcp_start_connect addr=<relay> port=<p>` runs alongside the
UDP Detect. With only a UDP listener the app logged `on_p2psrv_tcp_connect_finished
conn_status=CONNECTING` then `ivtcp_close_socket: fd=-1` and stalled. **All four genuine relays
accept TCP** (`3.13.212.24:28800`, `44.238.104.252:443`, `54.208.16.245:443`,
`52.40.221.253:51705` — probed from the Mac, 90–166 ms) so `cap_relay.py` now runs a thread per
accepted TCP connection and pipes bytes both ways. After that: `conn_status=CONNECTED`.

---

## 5c. The AV leg is **LAN-direct** [WIRE — live logcat]

Chain observed, in order, with `cap_relay.py` carrying the control plane:

```
gat_rcv_init_info_msg_resp srv_id=49 frm_len=209 offline_cnt=0 online_cnt=4
   did=429728658691722 <-> wyze_id:CAM-1_D03F27747BB0   srv_relation=1   (×4)
gat_rcv_init_info_msg_resp opt_with_gdm_SP=0
gat_rcv_init_info_msg_resp IV_ACCESS_SRV_LINK_ONLINE
gat_on_rcv_GDM_JDAT_RPT_REQ … content={"ProReadonly":{"netInfo":
   {"stVal":{"ssid":"Jose","ip":"192.168.77.12","mac":"00:00:00:00:00:01"}}}} … content_len=880
iv_start_av_link entry=… dst_id=… srv_relation=1
iv_start_av_link allow_srv_call=1 / lastChannelID=0 allocateid=1 / lanCall
CH1: iv_start_process_calling … session_id=… dev_id=… camera_id=0
iv_mtp_session_new link_id=…
iv_create_kcb                                          ← KCP control block ×2
iv_init_frm_CALLING dstID=… reqfrm->mtp_link.link_id=… lan_ipv4=<phone>
iv_process_calling lanCallIp=<camera>
iv_mtp_session_add_lan_or_nat lan dstAddr:192.168.77.12 port:59239   ← 
gutes_on_ackfrm_Lan_Calling
iv_on_time_out_check_into_transfer → iv_start_process_transfer
iv_rcvpkt_AVSTREAMCTL_ACCEPT mtps->link_id=…  →  0 0 0 0
CH1: iv_notify_p2pconnReady normal_sqn=2
start_av_enc_dec chnnelid=1 conn_type=1 / avctl_start_recv_and_dec
CH1: start_video_dec_proc… / video_decode_proc…        ← decoder running
start_av_enc_dec AudioType=5 VideoType=0                ← audio PCM(5), video raw(0)
```

**The relay is only a rendezvous.** After `init_info` gives the `did ↔ wyze_id` map and `GDM`
gives each camera's LAN IP + MAC + ssid, the client calls the camera **directly on the LAN**
(`lanCall`), and KCP runs phone→camera, not phone→relay.

**The camera endpoint** is logged as `iv_mtp_session_add_lan_or_nat lan dstAddr:<cam>
port:<p>`. Two observations, two different cameras:

| camera | endpoint seen |
|---|---|
| `192.168.77.17` | `port:63011` |
| `192.168.77.12` | `port:59239` |

**The port's origin is now SOLVED — see §5d.** It is advertised by the camera itself over the
LAN discovery protocol on UDP/8899, and the two values above match the reply field at offset 44
byte-for-byte (`.169 → 63011`, `.217 → 59239`).

**Beliefs that were WRONG, now corrected** (kept here so nobody re-walks them):

- [X] "The port comes from `ProReadonly.netInfo`." — it does not; that JSON carries ip/mac/ssid
  only (`content_len=880`, dumped in full).
- [X] "The port comes from the GDM / relay / a NAT mapping." — no `ip`/`port` key exists anywhere
  in the GDM blob, and no camera IP bytes appear in the relay frames.
- [X] "Sniff `:8900` to see discovery." — the app **binds** :8900 to *receive*, but it **sends**
  the probe **to :8899**. Sniffing 8900 saw 0 packets; sniffing 8899 saw everything in the first
  second. (`send_loop` passes `movw r2, #0x22c3` = 8899 as the destination port.)
- [X] "8900 is where the cameras listen." — 8900/32300/4456 answer with **ICMP port-unreachable**
  on all four cameras; **8899 and the advertised P2P port do not** (open).

Other AV-leg facts already pinned from these logs:

- **Fragmentation**: `gute_recv_fragment_init mtu=1032 … all_cnt=2 … fragdata_size=1008`
  → payloads are split at **MTU 1032**, reassembled (`rcv frag_idx=… rcv_cnt=…`).
- **Compression**: `unzip ok ! origlen 2482 , ziplen 1565` → **zlib** over the GDM blob.
- GDM data objects are queried over the AV link too:
  `giot_get_gdm_data_object_resp tid=CAM-1_D03F27747BB0 … error_code=0 … renew json tree`.
- Channel types seen: `start_av_enc_dec AudioType=5 VideoType=0`, `conn_type=1`.

---

## 5d. LAN discovery — **how the client learns each camera's P2P port** [WIRE + standalone]

> This closes the last unknown blocking our own client: *where does `port:<p>` come from?*

### The exchange

```
us  --UDP 28 B-->  192.168.77.18:8899        (also ff02::1 port 8899 from the phone)
cam --UDP 138 B->  <whatever port we put in the probe>   from <cam>:8899
```

The camera's IPv4 is simply the **source address of the reply** — nothing in the payload.

### Request — 28 bytes, NOT encrypted, no checksum

| offset | size | value |
|---|---|---|
| `0` | 1 | `0x70` magic |
| `1` | 1 | `0x02` = discovery request |
| `2` | u16 LE | `28` — total length |
| `4` | 8 | terminal-id slot, all zero on the wire |
| `12` | u32 LE | probe counter, +1 every send (`6d44b3de → 6e44b3de → …`) |
| `16` | 4 | checksum slot — **left zero**, never computed |
| `20` | u32 LE | flags `0x02010000` (`(flags>>16)&3 == 1`, i.e. "RC5") |
| `24` | u16 | 0 |
| `26` | u16 LE | **the port the camera must answer on** (app uses its bound `8900`) |

Although the flags word advertises RC5, the counter at `[12:16]` is plainly visible in the
clear, so **no encryption and no checksum are applied to this frame type.**

### Reply — 138 bytes, cleartext

| offset | size | value |
|---|---|---|
| `0` | 1 | `0x70` |
| `1` | 1 | `0x03` = discovery reply |
| `2` | u16 LE | `138` total length |
| `4` | 8 | zero |
| `12` | 8 | random |
| `20` | 4 | zero |
| `24` | u32 | `1` |
| `28` | u32 | `0x000e11b2` — **constant across all four cameras** |
| `32` | u32 | `0x000186d6` — **constant across all four cameras** |
| `36` | 4 | zero |
| `40` | u32 | `0x02000054` (`u16@40 = 84`) |
| **`44`** | **u32 LE** | **the camera's P2P port** |
| `48` | 10 | zero |
| **`58`** | **6** | **MAC address** |
| `64` | u16 | `8` |
| `66` | 36 | zero |
| **`102`** | 24 | **ASCII `wyze_id`, NUL padded** (`CAM-1_D03F27747BB0`) |

The payload is **identical on every reply from the same camera** — it is a static advertisement,
not a session state. So there is no handshake and no cookie: *send 28 bytes, read the answer.*

### Proof — reproducible, no phone, no app

`discover.py` builds the probe from scratch (it does not replay anything) and finds all four
cameras in 3 s:

```
$ python3 discover.py
  192.168.77.11    p2p_port=49706  mac=00:00:00:00:00:02  CAM-1_D03F277576D8
  192.168.77.10    p2p_port=49802  mac=00:00:00:00:00:03  CAM-1_D03F27EBFB10
  192.168.77.12    p2p_port=59239  mac=00:00:00:00:00:01  CAM-1_D03F27747BB0
  192.168.77.17    p2p_port=63011  mac=00:00:00:00:00:04  CAM-1_D03F2776110C
[done] 4 camera(s)
```

Both **broadcast** (`192.168.77.18:8899`) and **unicast** to a known camera IP work.
All four advertised ports then pass the ICMP-open test (silent, no port-unreachable), while
`8900` / `32300` / `4456` are provably closed on all four.

[!] IPv6 multicast `ff02::1%en0` fails from the Mac with `OSError(65, No route to host)` —
**IPv4 broadcast is the reliable path**; the IPv6 leg is optional.

### How it was found (audit trail)

1. `GDM` payload dumped in full → **no port key anywhere** (disproved that route).
2. `nm -D libiotp2pav.so` → `send_loop @ 0x7d778`, `recv_loop @ 0x7d08c`,
   `get_lan_device_info @ 0x190cc`, `find_dst_id_inlan @ 0x18a74`.
3. `disfn.py 0x545f8 0x54e24` on `iv_process_calling` → it reads `ctx+0x22c` (IPv4) and
   `ctx+0x230` (u16, `strh`) and hands both to `iv_mtp_session_add_lan_or_nat`.
4. `disfn.py 0x7d778 0x7dc00` on `send_loop` → `movw r2, #0x22c3` (8899) passed as the
   destination port; `send_msg @ 0x7d340` is a plain `sendto()` with `htons(port)`.
5. Empirical ICMP test → 8899 open on all four cameras, 8900 closed → **sniff the right port**.
6. `python3 lansniff.py 95 replay` → full request + reply captured in 0.57 s.

---

## 5e. The MTP layer (`0xc0`) and KCP — the session channel [WIRE + disassembled]

Two encodings live side by side on the same UDP port:

| magic | layer | encryption | used by |
|---|---|---|---|
| `0x7e` / `0x7f` | **GUTES** | RC5-32/6/8 + chk | `certify`, `CALLING` (0xa4), `AvStreamCtl` (0xb9) |
| `0xc0` | **MTP** | **none** — only a 16-bit `chval` | session hello, meter, `create_kcp_session`, KCP |

### The 6-byte MTP header

```
[0]     0xc0                    mov r1,#192 / strb
[1]     0x10 | (class << 7)     p[1] = ((prev & 0x9f) | 0x10) & 0x7f | (flag << 7)
[2]     (total & 7)             low 3 bits; upper 5 are preserved (& ~7)
[3]     (total >> 3) & 0xff     total = (p[2] & 7) | (p[3] << 3)   -- 11 bits
[4:6]   u16 LE = chval ^ u16LE(p[2:4])
[6:]    payload                 total - 6 bytes
```

`chval` (`iv_mtpfrm_calc_chval` @ `0x5f110`) covers **only the first 24 bytes of
payload**, rotating each u16 by its index:

```python
acc = 0
for i in range(12):
    acc ^= rotl16(u16le(payload[2*i:2*i+2]), i)
```

Verified **103/103 ok, 0 bad** against captured frames.

### `wire[1]` bit7 is the PACKET CLASS selector — this was the blocker

The UDP receive loop (the `recvfrom` driver whose objdump symbol lands on
`iv_comm_exit`, at `0x340c4`) routes purely on two bits:

```
wire = pkt + 56
if wire[0] == 0xc0:
      bit7 == 1 && bit4 == 1  ->  iv_on_rcv_mtpCtrl_pkt    (C0 90)  MTP control
      bit7 == 0 && bit4 == 1  ->  iv_on_rcv_kcpdata_pkt    (C0 10)  raw KCP segment
      bit4 == 0               ->  iv_on_rcv_pkt_as_relay   (C0 80 / C0 00)
else: GUTES path; if u16LE(wire[2:4]) > 1536 the packet is rejected (log line 0x93)
```

Sending a control command with `flag=0` puts it in the **KCP** bucket, where the
first 4 payload bytes are read as a `conv` id — that is why the first type-0x25
probe vanished without a trace.

Bits 5..6 of `wire[1]` are an "extra 8-byte header" selector every handler reads
as `(wire[1] >> 5) & 3`: 0 → payload at `+6`, nonzero → payload at `+14`. The
send path masks those bits off (`& 0x9f`), so on the wire they are always 0.

### MTP command dispatch — `iv_on_rcv_mtpCtrl_pkt` @ `0x57e58`

1. `iv_find_mtp_session(ctx->0x8, payload[4])`; **drop if NULL**
2. `type = payload[1] - 1`; `if (type > 36) -> default`  → **valid types are 1..37**
3. jump table at `0x57f18`, PC-relative base `0x57f14`, `target = base + table[i]`

Decoded straight out of the ELF (raw `s32` words):

| inner type | handler | notes |
|---|---|---|
| **1** (`0x01`) | `iv_rcv_meter_req` @ `0x57fac` | replies with inner **type 2**, 68 B |
| 2 (`0x02`) | `iv_rcv_meter_ack` @ `0x57fbc` | |
| 34 (`0x22`) | `iv_rcv_tcp_link_close` @ `0x57fe8` | |
| **37 (`0x25`)** | **`iv_rcv_kcp_create_msg`** @ `0x57fcc` | |
| 3–33, 35, 36 | no-op | |

**`iv_rcv_kcp_create_msg` @ `0x619f8` sends NO reply and creates nothing.** It
compares `session+0x10` against `payload[4]` (exact, no bit masking), writes
log line `0x6ce` (1742) on mismatch, and returns. **Silence after a `0x25` is the
correct behaviour, not a rejection.** It never reads `payload[12:28]`.

### KCP on the wire — `C0 10` + a standard `ikcp` segment

```
C0 10 <len> <chval> | conv u32 | cmd u8 | frg u8 | wnd u16 | ts u32
                    | sn u32 | una u32 | len u32 | data...        (all LE)
```

`ivkcp_*` is **standard ikcp renamed**: `ivkcp_input` @ `0x79ca0` rejects
anything with `remaining < 24`, and its dispatch tests `#81 #82 #83 #84`
(`PUSH/ACK/WASK/WINS`).

* `iv_on_rcv_kcpdata_pkt` @ `0x630c0` strips the 6-byte header and uses
  **`recvfrom_length - 6`** for the payload length (the header length field is
  not what drives it).
* session lookup is `iv_find_mtp_session(ctx->0x8, conv)`.
* **two KCP objects per session**: conv bit31 = 1 → `ivkcp_input(session+0x334)`,
  bit31 = 0 → `session+0x330`.
* `iv_find_mtp_session` @ `0x5d96c` matches
  `conv == s->0x10 | 0x80000000` **or** `conv == s->0x10 & 0x7fffffff`
  (mask literal `0x7fffffff` at `0x5da04`), so **both bit forms of the same
  word are accepted** — send both.
* receiving `WASK` (83) sets `kcp->probe |= 2` (`0x7a24c`) and `ivkcp_flush`
  then emits `WINS` (84) at `0x7ae7c` — a **zero-payload round trip** that needs
  no guessed fields, i.e. the ideal liveness probe.
* `ivkcp_flush` early-returns unless `kcp+0x74 (updated) != 0`; `ivkcp_update`
  (`0x7bc64`) sets it to 1 and calls flush. `ivkcp_update` is driven by
  `iv_mtp_session_send_rcv_proc` (`0x64668`, `0x6468c`) from
  `iv_on_timer_10ms_v2` (`0x3bb80`).

### Session lifecycle

```
iv_on_rcv_calling @ 0x4d0f0  ──┐
iv_process_calling @ 0x545f8 ──┴──> iv_mtp_session_new @ 0x5da08
                                      calloc, memclr, rand x3, iv_getRandomValue,
                                      rc5_ctx_new + rc5_ctx_setkey (session key),
                                      8x iv_ringbuf_new, ivudp_listen_new,
                                      iv_create_kcb x2   (0x5df84, 0x5dfa0),
                                      iv_mtp_session_meter_proc, ivtimer_create
iv_on_rcv_calling  ──> iv_mtp_session_add_lan_or_nat  (0x4d478, 0x4d548)
gat_on_rcvpkt_MTP_RES_RESPONSE ──> the same (x6)      [relay path]
```

`iv_create_kcb(a, b)` @ `0x5c06c` → **`ivkcp_create(a, 0)` unconditionally**; on
success it installs the output/log callbacks at `+0xfc`/`+0x104`, stores
`+0xe8 = b`, and calls `ivkcp_nodelay`. Its tail loops over the channel array at
`session+0x378` looking for channel type 135/136 and, when found, re-sends a
frame through `iv_mtp_chnnel_send_mtp_frm(ch, frm, len, 0)` — i.e. **flag 0, a
`C0 10` KCP packet**.

### The session word `session+0x10`

* It is the u32 at `CALLING[28:32]` **and** at `hello payload[4:8]` — verified
  equal in every capture pair.
* **It is random per session**, not derived from the TID: the same TID
  (`429728658691722`) appears with `0xef34cbd9` in some captures and
  `0x7be6cb9a` in others. Replays therefore only work within one session's
  frame set — pick `hello` and `CALLING` for the **same** word.
* The camera echoes it back: its replies carry `payload[4] == 0xef34cbd9` for the
  session built from our `CALLING` — proof our `conv` is right.

### The three frames we replay, and the answers we get

```
74 B   C0 90 02 09  <chval>  00 01 44 00 | word | 0 | sender u64 | receiver u64
                                     | counter | tick | ...      session hello
128 B  7e a4 80 00 ...        GUTES, RC5 key = f[0:4]||f[0x14:0x17]||00   CALLING
 76 B  7e b9 4c 00 ...        GUTES, same key rule                        AvStreamCtl
```

Replies, all 32 bytes unless noted:

| frame | meaning |
|---|---|
| `7e a4 20 00` | CALLING ack — `[12:16]` echoes request seq |
| `7e b9 20 00` | AvStreamCtl ack — `[12:16]` echoes request seq |
| both | `[20:24] = 00 00 11 02`, `[24:28] = 4` |
| `C0 90 02 09` (74 B) | camera's own hello, `payload[1] = 1`, sent ~1 Hz |
| `C0 90 02 09` (74 B) | camera's reply to our hello, `payload[1] = 2` |

Retransmit rule: identical `CALLING` retransmits differ **only at byte [23]**
(the retransmit counter, stamped after the checksum), so `g(header)` is constant
and edits stay fold-neutral:

```
chk_new = chk_tmpl ^ fold_tmpl[24:] ^ fold_new[24:]      (BE u32 words)
```

### [!] Still open on this layer

* ~~**KCP never starts.**~~ → [OK] **Explained. See §5f.** It is not a bug in our
  bytes: the camera's KCP output callback only ever transmits over a
  **type-135 UDP-relay channel**, and that channel only exists after a relay
  rendezvous. Pure LAN calling can never carry KCP.
* `iv_send_av_stream_ctl_frm` has not been shown to emit over GUTES vs KCP;
  `iv_rcvpkt_AVSTREAMCTL_ACCEPT` is definitely reached from
  `iv_on_rcv_kcp_cmdfrm` (`0x58008`, called by `iv_rcv_tlvfrm` `0x628e8`), so
  **the ACCEPT arrives over KCP**, while the `7e b9 20` we get is a separate
  GUTES-level ack.
* Unknown: the four words `session+0x1c/+0x20/+0x24/+0x28` written into the
  `0x25` payload. The receiver never reads them, so they are probably ignorable.
* Discovery-reply checksum rule still unknown (sidestepped with identical
  clones).

---

## 5f. Why KCP never starts — the type-135 relay channel  [SOLVED — DISASSEMBLED]

This was the last "why is the camera silent?" question on §5e, and the answer is
**architectural, not a mistake in our bytes**. It redirects the whole strategy, so read this
before touching `p2p_call.py`.

### The short version

> **KCP output is hard-wired to a *relay* channel (type 135). The type-135 channel is created
> by exactly one function — `gat_on_rcvpkt_MTP_RES_RESPONSE`. So without a relay rendezvous,
> `kcb->output` finds nothing, returns `-1`, and the camera drops every KCP segment on the
> floor, silently. That is why we have never seen a single `C0 10` packet.**

Our LAN replay is therefore doing everything right — the camera *did* get our `WASK`, *did*
set `probe |= 2`, *did* want to answer `WINS` — and then threw the answer away.

### The evidence, step by step

**1. `iv_create_kcb` is *not* the gate — it always succeeds.**

It ends at `0x5c1ac`:

```
0x5c0a0  ldr r0, [r11,#-0x10]      ; arg0
0x5c0a4  mov r1, #0
0x5c0a8  bl  ivkcp_create          ; ikcp_create(conv, user=0)
...
0x5c158  str lr, [r4,#0xfc]        ; kcb->output = local fn @0x5c1d8   <-- §below
0x5c160  str r12, [lr,#0x104]      ; kcb->log    = local fn @0x5c3d0
0x5c16c  str r1, [r2,#0xe8]        ; kcb->user   = arg1 (the session)
0x5c184  bl  ivkcp_nodelay
0x5c194  bl  0x5c43c               ; a second local helper
0x5c1ac  pop {r4, r5, r11, pc}     ; return kcb
```

`0x5c1b0..0x5c1cc` is just the literal pool. The `return -1` and the type-135 loop people
(including us, earlier) attribute to `iv_create_kcb` actually live in **a separate unexported
function at `0x5c1d8`**. `objdump` labels it `iv_create_kcb+0x16c` because `nm` has no symbol
for it — a classic mis-attribution trap: *objdump annotates with the nearest preceding
exported symbol, so any static function inherits the previous one's name.*

**2. That function at `0x5c1d8` IS the KCP output callback.**

Confirmed by resolving the PC-relative literal pool:

```
kcb->output (+0xfc) = 0x5c1d8      # add lr,pc,lr @0x5c150 + word@0x5c1c4 (=0x80)
kcb->log    (+0x104)= 0x5c3d0      # add r12,pc,r12 @0x5c148 + word@0x5c1c0 (=0x280)
```

`0x5c3d0` is the first byte after `iv_create_kcb`'s `pop` and before
`iv_find_mtp_session_by_term_id @ 0x5c4e0` — i.e. another unexported static. Both resolve to
real code starts.

Its signature is the IKCP one: `output(buf, len, kcb, user)`, where `user` was set to the
**session** in step 1.

**3. The output callback round-robins a channel pool and only accepts type 135.**

```
0x5c1e8  str r0, [r11,#-0x8]                ; buf
0x5c1ec  str r1, [r11,#-0xc]                ; len
0x5c1f0  str r2, [r11,#-0x10]               ; kcb
0x5c1f4  str r3, [r11,#-0x14]               ; user = the session
0x5c1f8  ldr r0, [r11,#-0x14]
0x5c1fc  str r0, [r11,#-0x18]               ; base = session
0x5c204  add r1, r0, #300                   ; base + 0x12c
0x5c208  ldr r0, [r0, #0x48c]               ; idx = session->0x48c
0x5c20c  add r0, r1, r0, lsl #2
0x5c210  ldr r0, [r0]
0x5c214  str r0, [r11,#-0x1c]               ; ch = pool[idx]
0x5c220  ldr r1, [r0, #0x48c]
0x5c224  add r1, r1, #1
0x5c228  str r1, [r0,#0x48c]                ; idx = (idx + 1)
0x5c230  cmp r0, #128
0x5c238  blt 0x5c248                        ; 128-entry pool, wrapping
...
        if (ch == 0)   continue
        if (ch->0x10 != 135) continue      ; 0x5c2f8  ldrb r1,[r1,#0x10] / 0x5c2fc cmp r1,#135
...
0x5c340  movw r0, #0x0
0x5c344  ldr  r1, [r11,#-0x1c]             ; ch
0x5c348  cmp  r0, r1
0x5c34c  bne  0x5c360                      ; found -> send
0x5c350  mvn  r0, #0                       ; <-- NO CHANNEL: return -1, send nothing
0x5c37c  bl   iv_mtp_chnnel_send_mtp_frm   ; (ch, buf, len, flag=0) -> C0 10
```

`flag = 0` is exactly the `C0 10` KCP class from §5e. So a found type-135 channel is what
turns a KCP segment into an actual datagram.

**4. Channel types 1, 2 and 135 all live in the *same* session pool.**

```
iv_mtp_session_add_udp_relay   0x5e5e4   -> 0x5e738  movw r0,#0x87   (135)
iv_mtp_session_add_tcp_relay   0x5f500   -> 0x5f840/0x5f954  (135/136)
iv_mtp_session_add_lan_or_nat  0x5ffcc   -> type = its arg1
```

Both the relay and the LAN builders register in the **same** place —
`session+0x374` (count) and `session+0x378` (pointer array), the very array the output
callback walks:

```
iv_mtp_session_add_udp_relay :  0x5e7c8 ldr r0,[r0,#0x374] ... 0x5e7ec str lr,[r2,#0x374]
iv_mtp_session_add_lan_or_nat:  0x601c4 ldr r0,[r0,#0x374] ... 0x601e8 str lr,[r2,#0x374]
```

The LAN builders pass a *small* type: `1` (`0x4bd4c`, `session+76`), `2` (`0x4d474`, the
incoming sockaddr when `sin_family == 2`). **`iv_create_kcb`'s predecessor check at `0x4d458`
is literally `ldrh r0,[r0,#16]; cmp r0,#2` — an `AF_INET` test.** So LAN calling can only ever
add type 1/2 channels.

**5. Only the relay creates type 135.**

```
$ grep "bl.*0x13800"   # PLT of iv_mtp_session_add_udp_relay
0004bafc <gat_on_rcvpkt_MTP_RES_RESPONSE>:  4c944
$ grep "bl.*0x137e8"   # PLT of iv_mtp_session_add_tcp_relay
0004bafc <gat_on_rcvpkt_MTP_RES_RESPONSE>:  4c76c
```

`gat_on_rcvpkt_MTP_RES_RESPONSE @ 0x4bafc` is the **relay rendezvous response handler**. It
parses the peer address the relay reports and hands it to `iv_mtp_session_add_udp_relay`.
Before doing so it de-duplicates with `iv_find_udpNode_by_addr` (`0x4c904`).

### What this means for the client

* `p2p_call.py`'s LAN replay is **complete and correct for the control plane** — it will keep
  getting `C0 90` acks forever, and it will **never** get KCP. Do not keep debugging it.
* The kcb **is** created (`session+0x330` = `word & MASK`, `session+0x334` =
  `word | 0x80000000`, see §5e) — so `iv_on_rcv_kcpdata_pkt` → `iv_find_mtp_session` →
  `ivkcp_input` all work on the camera. The segment is consumed. It is the *reply* that dies.
* **The relay is not optional.** It is the rendezvous that mints the type-135 channel; the
  AV payload may still end up flowing LAN-direct after that (the channel's sockaddr is whatever
  the relay reported, which on one subnet is the peer's LAN address), but you cannot get there
  without it.
* **Good news:** we already have everything the relay route needs — the `accessId` +
  per-device `accessToken` from `regist_gw_user` (§1), the relay endpoints from `LIST_RESP`
  (§3), and a full relay MITM (`cap_relay.py`) that already carries the app's dialogue
  end-to-end. The next job is to replay the `gat`/`MTP_RES` dialogue from the Mac, exactly as
  `p2p_call.py` did for the LAN frames.

### Correction to earlier notes

`iv_create_kcb` was previously described as "loops the channel array for type 135/136 and
returns -1 if absent". That was **wrong**: the loop belongs to the static output callback at
`0x5c1d8`. `iv_create_kcb` never fails and never looks at a channel. The *consequence* is the
same (no type-135 channel ⇒ no KCP), but the mechanism is in the output path, which matters
because it means the camera **accepts and buffers** our KCP segments regardless — it just can
never emit.

---

## 5g. The missing handshake step: `MTP_RES` (`7f a2`)  [REVERSED — NOT YET SENT]

Follow-on from §5f. Three independent checks all point at the same missing frame.

**1. The LAN calling path *builds* an MTP_RES request.** `init_frm_mtp_res_request @ 0x4cc04`
is called from **`iv_on_rcv_calling @ 0x4d6c4`** — i.e. the peer that receives a `CALLING`
turns around and emits an `MTP_RES`. Layout (all little-endian):

| offset | field |
|---|---|
| `[0]` | `0x7f` |
| `[1]` | `0xa2` |
| `[2:4]` | `u16` total length = **122** |
| `[4:12]` | `u64` = `ctx+0x240` (low) / `ctx+0x244` (high) — an ID |
| `[24:26]` | `u16` = 0 (or'd with 4 when `ctx+1012 != 0`) |
| `[26:30]` | `u32` = `arg2+0x1c` |
| `[30:38]` | `u64` = `arg2+0x20` / `arg2+0x24` |
| `[38:46]` | `u64` = `arg2+0x28` / `arg2+0x2c` |
| `[46:82]` | 36 B copied from `arg2+48` |
| `[82:122]` | tail (40 B, not yet fully decoded) |

**2. The relay-class path exists on the *LAN* socket.** The receive router at `0x340c4` splits
`C0` frames by `wire[1]` bit 4, and its **`bit4 == 0` branch (`C0 80`/`C0 00`) calls
`iv_on_rcv_pkt_as_relay @ 0x63330`** — reachable from the same UDP port the camera advertises.
Non-`C0` GUTES frames continue on to `giot_on_rcvpkt @ 0x520c8`, which is the very function
that dispatches `gat_on_rcvpkt_MTP_RES_RESPONSE @ 0x4bafc`.

So the rendezvous protocol is **not** confined to the AWS relay connection: it is routable on
the P2P socket itself.

**3. Wire evidence that we simply never did it.** Across **294** captured camera replies there
are exactly three frame types and nothing else:

```
len=74  c0 90   x215     the camera's own MTP hello
len=32  7e b9   x56      AvStreamCtl ack
len=32  7e a4   x23      CALLING ack
zero 7f frames.  zero C0 10 (KCP) frames.
```

And on the relay leg of the `cap_relay.py` session there are **zero `C0` frames** too — which
is the important negative: even when the control plane ran end-to-end through the relay, KCP
never went over it. The type-135 channel is *created by* the rendezvous but *carries the
traffic itself* (its sockaddr is whatever the peer reported — LAN on one subnet).

### What to do next

Send a `7f a2` `MTP_RES` ourselves. It is a plain GUTES frame, so the §4 request checksum and
the §5 RC5 rule apply and are both already byte-exact for outgoing frames. Two sub-questions
remain and both are cheap to settle by experiment:

* **Is `MTP_RES` peer-to-peer or peer-to-relay?** §5g(2) says the machinery is present on the
  P2P socket, and `init_frm_mtp_res_request` is built in the *LAN* calling handler — both argue
  peer-to-peer. If so, the relay is unnecessary and `p2p_call.py` only needs one more frame.
* **Who answers, and with which GUTES type?** Only `MTP_RES_RESPONSE` is exported, so the
  reply type is whatever `giot_on_rcvpkt` maps to it. Capturing one from a real app session
  (re-run `cap_relay.py`) would settle it without more disassembly.

The relay route (§5f) is the fallback if peer-to-peer rendezvous turns out to be refused.



## 6. Transport [CONFIRMED]

- **KCP over UDP.** Steady state emits `iv_cal_kcp_rate sta_cur->real_snd=… resend_frm=0
  lost_ratio=0.000000` per channel and `ivkcp_interval/nodelay/wndsize/waitsnd` exist as API
  (`0x7c03c`…`0x7c1dc`).
  > [!] **But KCP only ever runs over a *type-135 relay channel*** (§5f). LAN calling adds
  > type 1/2 channels only, which `kcb->output` refuses. So "KCP over UDP" is true, yet a
  > pure-LAN peer can never carry it.
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

LAN discovery — see §5d (the whole thing now reversed)
  broadcast_fd_init  0x7c200   binds the RECEIVE socket on UDP 8900
                               (movw r1,#0x22c4 = 8900, then rev/lsr #16 = htons)
  broadcast_init     0x7cad8   ctx+8 = 8900, echoed into every probe's [26:28]
  recv_loop          0x7d08c   parses the 138-B reply -> lan_device_info list
  send_msg           0x7d340   sendto(fd, buf, len, ip, htons(port))   [IPv4 only]
  send_msg_ipv6      0x7d45c   the ff02::1 variant (optional leg)
  send_loop          0x7d778   emits the 28-B probe to **port 8899**
                               (movw r2,#0x22c3 = 8899) via IPv4 broadcast + IPv6 mcast
  start_recv_thread  0x7d5f4
  find_dst_id_inlan  0x18a74   <-- iv_start_av_link's LAN lookup (called at 0x1c970/0x1c9cc)
  get_lan_device_info 0x190cc  copies the discovered list (52-B stride, max 256)
  lst_devinfo_proc   0x18e0c   discovery result handler
  start_devinfo_proc_thread 0x19a14

LAN call chain (what our client must reproduce next)
  iv_start_av_link            0x1c860   decides lanCall via find_dst_id_inlan
  iv_start_process_calling    0x539a8
  iv_init_frm_CALLING         0x542c0   frame carries the *client's* lan_ipv4
  iv_process_calling          0x545f8   reads ctx+0x22c (cam IPv4), ctx+0x230 (cam port, strh)
  iv_mtp_session_add_lan_or_nat 0x5ffcc  logs "lan dstAddr:<ip> port:<p>"
                                          type = arg1; LAN sites pass 1 or 2
  iv_mtp_session_add_udp_relay  0x5e5e4  *** creates channel type 135 ***
  iv_mtp_session_add_tcp_relay  0x5f500  *** creates channel type 135/136 ***
  gat_on_rcvpkt_MTP_RES_RESPONSE 0x4bafc *** ONLY caller of both add_*_relay ***
                                          -> the relay rendezvous (see 5f)
  init_frm_mtp_res_request     0x4cc04   builds the 122-B GUTES 7f a2 MTP_RES;
                                          CALLED FROM iv_on_rcv_calling 0x4d6c4
                                          -> the LAN calling path! (see 5g)
  iv_on_rcv_pkt_as_relay       0x63330   relay-class C0 frames, reachable from
                                          the LAN socket (router 0x340c4 bit4=0)
  giot_on_rcvpkt               0x520c8   top-level GUTES dispatcher; routes
                                          gat_on_rcvpkt_* (incl. MTP_RES_RESPONSE)
  gutes_on_ackfrm_Lan_Calling 0x5456c
  iv_on_ackfrm_Calling        0x54e24
  iv_mtp_session_new          0x5da08
  iv_mtp_kcp_create           0x61798   <-- KCP session
  iv_create_kcb               0x5c06c   <-- KCP control block; ALWAYS succeeds
                                          (ends 0x5c1ac, no channel check)
  [static] kcb->output        0x5c1d8   *** THE GATE *** round-robins
                                          session->0x12c[idx] (128 entries,
                                          counter at +0x48c); accepts ONLY
                                          channel type 135, else returns -1
  [static] kcb->log           0x5c3d0
  iv_mtp_chnnel_new           0x59ea8   (session, type_byte, sockaddr)
  iv_mtp_chnnel_send_mtp_frm  0x5b148   dispatch on ch->0x10; flag=0 -> C0 10
  iv_init_frm_AvStreamCtl     0x53274
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
- **[!] `objdump` annotates every address with the nearest *preceding* exported symbol**, so
  any unexported static function is silently reported as `prevSymbol+offset`. This bit us:
  `0x5c1d8` is a distinct function (a `push {r11, lr}` immediately after the previous one's
  literal pool) that `objdump` insisted was `iv_create_kcb+0x16c`, and we built a whole wrong
  theory on it. **Rule: treat a `bl 0x????` target as a real function boundary even when
  `objdump` names it `+something`, and confirm with the literal pool + the `pop {…, pc}`.**
  To resolve a PC-relative callback, read the literal word `w` and compute
  `target = (add_instruction_addr + 8) + word`. Use **`resolve_cb.py`** for this
  (`--pool` dumps a literal pool, `--sym` names an address).
- **The `execute` harness kills a PTY that goes silent** — long-running listeners need a
  heartbeat print or a large `idle_timeout_ms`. Also `normalization.ports` masks port numbers
  in output unless disabled, and `terminal.columns × (rows+scrollback) ≤ 1,000,000`.
  A stale owned PID wedges cleanup (`cleanup_incomplete`) — kill -9 the stale PID first.

---

## 9. Disproved / corrected earlier beliefs

| # | Earlier belief | Reality |
|---|---|---|
| D16 | Live view is LAN-direct **TCP** to `192.168.77.12:59239` | **Half-right.** TCP was correctly ruled out (full TCP sweep empty; transport is KCP/**UDP**), but `59239` is *not* misread — it is a genuine camera port, advertised at reply offset 44 (§5d). |
| D17 | LAN discovery is **IPv4 broadcast to :8900** → "unproven, IPv4 listeners see nothing" | **The conclusion was wrong, the sniff was on the wrong port.** The app **binds** :8900 to receive and **sends to :8899**. Sniffing 8899 captures everything in <1 s (§5d). |
| D18 | `tid_key_map` is populated locally or via HTTP | **False.** Delivered by the relay: `gat_rcv_init_info_msg_resp did=… <--> wyze_id:…`. |
| D19 | Camera LAN IPs come from LAN discovery | **False** for the app's path — they arrive via the relay in `GDM_JDAT_RPT_REQ` `netInfo.stVal.ip`. But LAN discovery *does* also return the IP as the reply's source address, and that is what our client should use (§5d). |
| D20 | Frames are in the clear | **False.** RC5-encrypted — but with a header-derived key (§5), so not a hard barrier. |
| D21 | Camera P2P port might live in `ProReadonly.netInfo`, the GDM blob, the relay frames, or be NAT-mapped back by the relay | **All false.** It is advertised by the camera over **UDP/8899 discovery, reply offset 44** (§5d). |
| D22 | Sniffing `0.0.0.0:8900` proves discovery is not IPv4 | **False methodology.** The bind port and the destination port differ. Always ICMP-probe first (8900 closed, 8899 open) before concluding a protocol is absent. |
| D23 | The advertised P2P port changes between runs | **False so far.** `.217→59239` and `.169→63011` reproduced byte-identically across an app restart and independent probes (cameras not rebooted). |
| D24 | `iv_create_kcb` is the KCP gate — it loops the session's channel array for **type 135/136** and returns `-1` when it finds none, so `session+0x330/0x334` must be NULL | **Wrong function, right conclusion.** `iv_create_kcb` ends at `0x5c1ac` and never inspects a channel — it always succeeds. The type-135 loop belongs to an **unexported static at `0x5c1d8`, which is `kcb->output`**, mislabelled by `objdump` as `iv_create_kcb+0x16c`. The consequence stands: no type-135 channel ⇒ `kcb->output` returns `-1` ⇒ **every KCP segment the camera produces is silently discarded** (§5f). The kcb itself is fine, and so is everything `p2p_call.py` sends. |

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
| C36 | **[DISASSEMBLED]** `certify_req` = type `0x0c`, 64 B header+body: flags word `0x01410000` @+20, `hash(nonce)` @+28, **32-B RC5 nonce @+32** |
| C37 | **[DISASSEMBLED]** `certify_resp` reports `u16 errcode` at `+26` and an **8-byte token** at `+28..+36`, echoed in later requests by `frame+24 bit2` |
| C38 | **[DISASSEMBLED]** **The GUTES session RC5 key = the client's own 32-byte nonce** — `rc5_ctx_setkey(ctx+0xd8, ctx+156, 32)` right after a successful `certify` |
| C39 | **[WIRE]** **LAN discovery solved**: 28-B request → `192.168.77.18:8899`, 138-B cleartext reply; **P2P port at offset 44, MAC at 58, `wyze_id` at 102**; camera IP = reply source address |
| C40 | **[STANDALONE]** `discover.py` finds **all 4 cameras in 3 s** from the Mac with no app and no phone involved; broadcast and unicast both work |
| C41 | **[EMPIRICAL]** On all four cameras UDP **8899 and the advertised P2P port are open**; **8900 / 32300 / 4456 are closed** (ICMP port-unreachable) |

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
- `init_info` → `GDM` layer (the builders are `gat_send_init_info_msg` @ `0x3eac4`,
  `gat_rcv_init_info_msg_resp` @ `0x46960`, `gat_on_rcvpkt_GDM_JDAT_RESP` @ `0x44a14`,
  `gat_on_rcvpkt_GDM_JDAT_REQ` @ `0x44aa4`) — this is what carries the camera LAN IPs.
- Which transport the relay dial actually uses (TCP? UDP?) and the exact `certify_req`
  finalizer — the checksum + RC5 over `[24:…]` for type `0x0c` is assumed to follow §4/§5
  but has not been byte-verified against a capture (no `certify` capture yet).
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
