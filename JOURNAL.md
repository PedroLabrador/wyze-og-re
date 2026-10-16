# Attempt Journal — every hypothesis tried, and how it turned out

A chronological record of the reverse-engineering effort. Companion to
`P2P_PROTOCOL.md`, which is organised **by topic**; this file is organised
**by time**, so a reader can see the shape of the search: which ideas were
pursued, which dead ends were hit, and exactly where the breakthrough was.

Verdicts used:
- **WORKED** — proven live or byte-exact against ground truth
- **FAILED** — attempted, produced no result
- **RULED OUT** — disproved by evidence, not merely untried
- **ABANDONED** — dropped by choice (wrong direction or lower priority)

Legend for evidence type: `[wire]` = captured packets, `[static]` = disassembly,
`[live]` = observed on the phone at runtime (logcat), `[probe]` = our own
experiment against a real camera.

---

## Phase 1 — Auth and the cloud API

| # | Attempt | Verdict | Evidence |
|---|---------|---------|----------|
| 1 | OAuth PKCE login against Wyze | **WORKED** | needed `client_secret` |
| 2 | Recover `client_secret` from the APK | **WORKED** | = `jOwT7UImpdmKqrP0VEXFQp0eQzRS4D` |
| 3 | Device list via `home_page/get_object_list` | **WORKED** | 4 cameras |
| 4 | `Signature2` rule for GET | **WORKED** | `HMAC_MD5(getSortParams(q), md5(token+secret))`, verified 30/30 |
| 5 | IOTC credential endpoint `regist_gw_user` | **WORKED** | shared `accessId`, per-device `accessToken` |
| 6 | `Signature2` rule for POST | **FAILED** | needs runtime-injected `cg01_f3c397620f853b12`; never resolved — avoided by using GET-only + `curl` |

---

## Phase 2 — What is the transport?

| # | Attempt | Verdict | Evidence |
|---|---------|---------|----------|
| 7 | Full TCP scan 1–65535 on every camera | **FAILED → RULED OUT** | **zero** open ports; TCP to the camera is impossible |
| 8 | Assume AWS KVS / HLS (Wyze's web path) | **ABANDONED** | live view is P2P (ThroughTek TUTK/IOTC + Gwell), not KVS |
| 9 | Use `wyze-bridge` (third-party) | **ABANDONED** | user requirement: the P2P client must be ours |
| 10 | Conclusion: **KCP over UDP** | **WORKED** | confirmed later by live logcat (`iv_cal_kcp_rate`) |

---

## Phase 3 — Control plane, via impersonating the list server

| # | Attempt | Verdict | Evidence |
|---|---------|---------|----------|
| 11 | Patch the APK's list-server URL to the Mac | **WORKED** | ground truth achieved |
| 12 | Reverse GUTES `certify` / `certify_resp` / `init_info` | **WORKED** | session RC5 key = client's own 32-byte nonce |
| 13 | Solve the response checksum | **WORKED** | `app_chk = g(header) ^ fold(payload)`, live-proven |
| 14 | Relay MITM end-to-end (UDP **and** TCP) | **WORKED** | full control plane runs through us |
| 15 | RC5 key-mode split (`(flags>>16)&3`) | **WORKED** | mode 1 = header key, verified byte-exact |
| 16 | Bit-21 / checksum-solving to forge frames | **ABANDONED** | replaced by fold-neutral XOR compensation |
| 17 | Fold-neutral payload edit (balance every change) | **WORKED** | lets us forge any mode-1 frame |

---

## Phase 4 — Talking to the cameras directly

| # | Attempt | Verdict | Evidence |
|---|---------|---------|----------|
| 18 | LAN discovery broadcast probe | **WORKED** | ~3 s, but flaky — needs a retry loop |
| 19 | Replay the app's captured frames at the camera | **WORKED** | cameras answer; no phone, no MITM needed |
| 20 | Blast the handshake every second | **FAILED** | resets the camera state machine; must be **ordered, one-shot** |
| 21 | Solve `verity_chkval` / seed | **WORKED** | byte-identical to `init_chkval` |
| 22 | Silent-drop bug (`bit25` connection-id check) | **WORKED** | fixed with `FLAGS1 = 0x02050000`, proven on two cameras |

---

## Phase 5 — The long hunt for "what starts KCP"  *(mostly failures)*

Every entry here produced **zero `C0 10`** packets.

| # | Attempt | Verdict | Evidence |
|---|---------|---------|----------|
| 23 | Route A: tap the app's frames in-app | **ABANDONED** | violates the "no app running" constraint |
| 24 | Route B: headless harness on the phone | **ABANDONED** | same constraint |
| 25 | Route C: pure-Python client on the Mac | **CHOSEN** | |
| 26 | Trigger = `7e a3` MTP_RES_RESPONSE | **FAILED** | creates a session, but no KCP |
| 27 | Trigger = `7f cb` PortStatResp | **FAILED** | frame accepted, no KCP |
| 28 | Trigger = `7f ca` PortStatReq | **FAILED** | provokes a camera reply, no KCP |
| 29 | Trigger = type-185 PASSTHROUGH_MSG `cmd=1` | **FAILED** | reaches the handler, still no KCP |
| 30 | Harvest 10 live ack ctx-ids, retry cmd=1 | **FAILED** | 20 frames sent, 0 KCP |

> Each of these was a reasonable inference from real disassembly. They failed
> because the premise was wrong: **there is no separate "create KCP" handshake
> on the LAN path** (see #38).

---

## Phase 6 — Getting real ground truth from the phone  *(the turning point)*

| # | Attempt | Verdict | Evidence |
|---|---------|---------|----------|
| 31 | Run `cap_relay.py`, open a live view, capture `adb logcat` | **WORKED** | a **fully working session**: `iv_cal_kcp_rate ... lost_ratio=0.000000`, `renderVideoFrame`, `video packet rate` |
| 32 | Extract the real client sequence from logcat | **WORKED** | CALLING → hello → timeout → transfer → AvStreamCtl → ACCEPT → video |
| 33 | Resolve every `bl` in `iv_send_av_stream_ctl_frm` | **WORKED** | it calls **`ivkcp_send` twice** and never the GUTES sender |
| 34 | Decode the receive router (0x340c4) | **WORKED** | `C0` + bit7/bit4 of `buf[1]` selects MTP-ctrl vs KCP vs relay |
| 35 | Decode `iv_on_rcv_kcpdata_pkt` (0x630c0) | **WORKED** | conv lookup, bit31 → `+0x334`/`+0x330`; **our framing was already correct** |
| 36 | Decode `iv_find_mtp_session` (0x5d96c) | **WORKED** | accepts **either** conv bit-form |
| 37 | Duplicate-cache theory (replayed CALLING dropped) | **RULED OUT** | the camera answers every CALLING with a hello |
| 38 | `iv_create_kcb` runs inside `iv_mtp_session_new` | **WORKED** | KCP is created at **session creation**; there is no KCP handshake step |

**Key reframing:** the `7e b9` frames we had been replaying as "avstreamctl"
are `PASSTHROUGH_MSG` (type 185) — a *different* message class that merely
shares the 76-byte size. We were never sending the right frame.

---

## Phase 7 — Send the real AvStreamCtl, inside KCP

| # | Attempt | Verdict | Evidence |
|---|---------|---------|----------|
| 39 | Build `kcpav.py`: minimal ikcp + `iv_init_frm_AvStreamCtl` builder | **WORKED** | selftest passes, incl. historical WASK round-trip |
| 40 | Send AvStreamCtl as a KCP PUSH (`--av`) | **FAILED** | sent to both conv forms, 0 KCP back |
| 41 | Investigate the `c0 90` hello: inner type = **1** = `iv_rcv_meter_req` | **WORKED** | MTP-control table @0x57f18: type 1 → 0x57fac, type 2 → 0x57fbc |
| 42 | **Answer the meter request with a meter ACK (inner type 2)** | **[OK] WORKED** | **KCP UP — 603 `C0 10` packets, 306,200 bytes of AV data** |

**Root cause of the entire Phase-5 dead end:** we had been *echoing the
camera's meter request back verbatim*. That makes the camera re-run
`iv_rcv_meter_req` (which sends up to 5 more UDP replies), producing an echo
loop — literally 19 identical hellos per run — and the state machine never
advanced. Answering with inner type **2** instead of **1** unlocked it.

Also confirmed independently from the send path (`iv_rcv_meter_req`
0x60824..0x6089c), validating `mtp_frame.py` byte-for-byte:
`buf[1] |= 0x10 | 0x80`, `buf[1] &= ~0x60`, `buf[0] = 0xC0`, 11-bit length
split across `buf[2]`/`buf[3]`.

---

## Phase 8 — Decoding the AV stream  *(in progress)*

| # | Attempt | Verdict | Evidence |
|---|---------|---------|----------|
| 43 | Walk the reassembled payload as frames | **WORKED** | 660 frames land **exactly** on 306,200 — framing is `[0]=type`, `[2:4]=u16LE total len` |
| 44 | Classify frame types | **WORKED** | `0x03` len 76 ×40 = AvStreamCtl control; `0x04` ×620 = AV data |
| 45 | Look for Annex-B H.264 start codes | **FAILED** | no `00000001` / `000001` anywhere |
| 46 | Try zlib decompression | **FAILED** | not raw deflate |
| 47 | Byte statistics of the type-`0x04` bodies | **WORKED** | entropy 7.96/8.0 ⇒ encrypted; only **62 unique frames out of 620** (10× KCP retransmission — our ACKs are not landing). Frames sharing a header also share their first 12 body bytes, then diverge ⇒ constant plaintext + constant key. |
| 48 | Scan the `.so` for cipher constants | **WORKED** | **only RC5 present** (`P32=0xB7E15163` @0x650f0). No AES S-box, no SHA/MD5/ChaCha/TEA/Blowfish. |
| 49 | Find the AV decrypt via the KCP recv path | **WORKED** | `ivkcp_recv` → `iv_mtp_session_rcv_proc` → **`iv_rcv_tlvfrm` (0x628e8)** → `rc5_ctx_dec` @0x62c54 → `iv_ringbuf_write` |

### The AV decrypt, fully decoded (`iv_rcv_tlvfrm`, 0x628e8)

```c
if (*(u16*)(frame + 2) <= 4) skip;                   // [2:4] = u16LE total length
nblocks = (*(u16*)(frame + 2) - 4) / 8;
for (i = 0; i < nblocks; i++)
    rc5_ctx_dec(ctx->0x488, frame + 4 + i*8, 8);     // RC5, 8-byte blocks, IN PLACE
iv_ringbuf_write(ctx->0x4b0, frame + 4, len - 4, 0);
```

So: the TLV frame is `[0]=type, [1]=?, [2:4]=u16LE total length, [4:]=payload`.
The payload is RC5-encrypted **in place in 8-byte blocks** with the key context
at `ctx->0x488`, then handed to the decoder ring buffer.

This confirms the observed data exactly — our type-`0x04` frames have
`[2:4]` = their walked length, and `732 - 4 = 728 = 91 × 8` blocks. It also
explains the constant `ef3b6e719e4cc5544bed381a` invariant: constant plaintext
at `[4:20]` under a constant key.

**Remaining:** the value of the RC5 key context `ctx->0x488` (where it is
initialised), and confirming the RC5 parameters (rounds/key length — the GUTES
path uses a 32-byte nonce key). Then the decrypted stream is plain
H.264/H.265 for ffmpeg.

### THE AV KEY — SOLVED: `CALLING[120:128]`

`ctx->0x488` has exactly **one** writer in the whole binary, and
`ctx+0x480` (the 8-byte key buffer passed to `rc5_ctx_setkey`) likewise.
Both are in `iv_mtp_session_new` (0x5db90..0x5dbe0), which has **two
branches**:

```c
// branch A (local / LAN initiator):
iv_getRandomValue(ctx + 1152);            // 1152 = 0x480 -- random 8-byte key
ctx->0x488 = rc5_ctx_new(a & 0xff, b & 0xff);
rc5_ctx_setkey(ctx->0x488, ctx + 0x480, 8);

// branch B (session built FROM a received CALLING):
ctx->0x10  = arg->0x1c;                   // the conv -- CALLING[28:32]
ctx->0x484 = arg->0x7c;                   // CALLING[124:128]
ctx->0x480 = arg->0x78;                   // CALLING[120:124]
```

Branch B reads the session straight out of the parsed CALLING, and `arg->0x78`
is a frame-buffer offset ⇒ **the 8-byte AV RC5 key is the last 8 bytes of the
128-byte CALLING frame.**

**Verified live.** Key = `889fcf8a9318d6b3` (cam2's captured CALLING), RC5-ECB
in 8-byte blocks, little-endian word order, via `listreq.rc5_setup` /
`rc5_decrypt_block`:

```
unique frames      : 62
decrypted stream   : 30068 bytes
start codes 000001 : 64
NAL types          : SPS 1, PPS 1, IDR 1, non-IDR 14
ffprobe            : codec_name=h264  width=640  height=360  frames=15
```

**So the complete pipeline works end to end:**
login → device list → LAN discovery → CALLING → **meter_ack** → KCP up →
AvStreamCtl over KCP → RC5 AV decrypt (`CALLING[120:128]`) → **H.264 → ffmpeg**.

---

## Phase 9 — From a script to "open a browser and see every camera"

**E1 — a single captured CALLING works for EVERY camera.  WORKED.**
Sent cam2's CALLING *verbatim* to cam4 (.117): 19 replies including a
`7ea42000` GUTES response and meter requests carrying *our* conv.
⇒ **the TID field is not checked**, so there is no per-camera capture gap and
cam4 (which never had one) is not a special case.  This killed the "solve the
CALLING checksum so we can forge per-camera frames" line of work.

**E2 — a camera streams off a borrowed CALLING.  WORKED.**
cam4 → 377,504 B H.264 → **187 JPEG frames**; cam2 → 230,057 B → 192 frames.

**E3 — two cameras at once.  WORKED.**
Two threads on ephemeral ports **62008** and **55939**: `.117` 307,190 B /
176 JPEG, `.224` 211,995 B / 177 JPEG.  The camera replies to the UDP *source*
port, not the advertised 48171 — so no shared-socket demux is needed and each
worker just binds its own port.

**CALLING field layout — DECODED** (from a decrypted CALLING):

| offset | field |
|---|---|
| `[0:4]` | `7ea48000` |
| `[4:12]` | id8 |
| `[16:20]` | checksum (formula still unknown) |
| `[20:24]` | flags `1e2805a2` — mode1 / bit25 / ack all set |
| `[28:32]` | `conv` |
| `[32:40]` | `d_log 0x840186d6001260a3` (shared across all cameras) |
| `[40:48]` | TID as u64 LE |
| `[54:56]` | local port `2bbc` = 48171 |
| `[64:68]` | local IP (the phone's) |
| **`[120:128]`** | **AV RC5 key** |

**KCP retransmission — FAILED FIRST, then FIXED.**
`kcpav.KCP.input()` appended every PUSH with no dedup, and `p2p_client` read
raw segments, so duplicates were spliced into the H.264 stream and the decoder
desynced permanently — **ffmpeg produced 0 frames.** Measured on conv
`0x77e202cb`: 576 PUSH but only **64 unique sn** (0–63).
Fix: ACK every PUSH with `una=rcv_nxt`, dedupe by `sn mod 0x8000`, deliver in
order via a `pending` dict, filter foreign convs, snap `rcv_nxt` to the first
sn.  Also fragment on `mtu - KCP_OVERHEAD(24)` = 1008 (matches observed max).
⇒ **0 frames → 222 JPEG frames.**

**ffmpeg → JPEG.  WORKED.** 265,444 B H.264 → 222 JPEGs, `ffprobe -f mjpeg`
reports `mjpeg 640x360, 222 frames`.

**The web server needs NO LOGIN.  RULED OUT (the whole login requirement).**
Everything above used **zero** cloud credentials: discovery is a LAN broadcast,
the CALLING is a bare UDP frame the camera accepts unconditionally, and
KCP/RC5 are session-local with a key we chose.  The `accessToken` / IOTC
credentials the *app* fetches from `regist_gw_user` are never used on this
path.  The only thing a cloud login ever bought was *nicknames*, and those are
cached in `wyze_devices.json` and read locally.  ⇒ `server.py` was written
without any auth gate.

**MJPEG delivery — FAILED, then FIXED (three separate bugs).**

1. *`KeyError: 'p2p_port'`* — `discover()` returns `{ip: {...}}` but the code
   read it as a single camera record.  FAILED, fixed by taking
   `next(iter(got.values()))`.
2. *`EADDRINUSE`* — every worker bound the app's advertised port 48171, so the
   second camera could not bind.  Fixed with `local_port=0`; proven safe by E3.
3. *Only 19 of 132 frames reached the browser* — **the interesting one.**
   Socket writes cost 0.00 s, and the poll loop ran at exactly 32 ms, yet
   `served` stayed far below `published`.  Traced it by recording
   `(cur, seq, served)` per sample: `seq = cur` **jumps over skipped frames**,
   and `_publish` overwrote a single `self.frame` slot.  ffmpeg hands JPEGs over
   in **bursts** (the producer is busy decrypting, so the pipe accumulates), so
   a burst of ~7 collapsed into exactly one delivery.
   Fix: buffer in a `collections.deque` and **drain** (`take()`) each poll.
   ⇒ **19/132 → 199/199.**
   Two red herrings cost time here: condition-variable wakeups really were slow
   (~1.7 Hz under GIL contention), and a stats reset I added to isolate the bug
   raced with the producer's `self.stats["h264"] += n`, raising `KeyError` and
   killing the stream outright.

**Server verified end to end** (`server.py`, stdlib only):

```
page            : 6096 bytes, JS syntax OK (node --check)
discovery       : 192.168.77.11 "CAM-1"  +  192.168.77.10 "CAM-1"
                  (nicknames from the local cache -- no login)
concurrent 20 s : Camera 4  3,110,522 B  237 JPEG   pub=243 served=243
                  Camera 2  1,503,112 B  245 JPEG   pub=252 served=252
```

**Three more bugs found while scaling from 2 cameras to 4.**

4. *The UI could never start a stream.*  The JS attached `<img>` only when
   `status === 'streaming'`, but the status only becomes `'streaming'` when
   something requests `/stream/` — a deadlock that no amount of polling breaks.
   Fixed twice over: the server now starts a worker for every camera the moment
   `refresh()` finds it, and the JS attaches for any status except `offline`.

5. *Multiple viewers split the stream.*  `take()` **drained** the frame deque,
   so each frame went to exactly one viewer.  Proved with two simultaneous
   clients on camera 2: a draining take would halve each.  Now `take(cursor)`
   is non-destructive and every viewer keeps its own cursor (frames age out
   after 120, so a stalled viewer skips rather than grows).  Verified: two
   viewers got byte-identical files.

6. *`ffmpeg` pipe deadlock — the one that froze all four cameras.*  The loop
   wrote to `ff.stdin` and only read `ff.stdout` **afterwards**.  Once
   ffmpeg's output backed up it blocked writing stdout, stopped reading stdin,
   and our `ff.stdin.write()` blocked forever.  The symptom is perfectly
   disguised: `h264` freezes, nothing raises, status stays `streaming`, because
   the stall check lives *inside* the `for chunk` body — which never runs when
   the loop is wedged.  Two cameras occasionally won the race (which is why the
   earlier tests passed); four froze within ~8 s every time.  Fixed by draining
   stdout on its own thread.  `timeout` also dropped 30 s → 12 s so a genuine
   stall re-handshakes instead of showing a frozen frame.

**Four cameras, simultaneously — the actual goal:**

```
Camara 1   21,353,949 B   500 JPEG   pub=500 served=500   19.9 fps
Camara 4   19,500,937 B   500 JPEG   pub=500 served=500   19.9 fps
CAM-1   16,005,596 B   491 JPEG   pub=502 served=502   18.8 fps
Camara 2   13,739,612 B   501 JPEG   pub=501 served=501   18.9 fps
TOTAL      70,600,094 B  1992 JPEG   in 25 s -- zero dropped
```

All four cameras auto-start at boot with no login, no click, and no phone.

---

## Phase 10 — "Why only ~20 fps?"  *(answered: the camera; every client-side
theory DISPROVED)*

The question came up because the stream is LAN-local, so it *should* be fast.  It is fast —
the network is not the limit.  The **camera's encoder** is.

### The measurement that settles it

`/tmp/bottleneck.py` instruments the raw UDP/KCP layer instead of guessing:

```
wall 13.5s
udp packets        1152  (85.3/s)
retransmits           0  (0.0/s)   <- nonzero means WE are too slow
cmd83 WASK from cam    0           <- nonzero means its window is full (US)
our ACKs sent       1152  (85.3/s)
unique sn/cam      1152  sn gaps 0
TLV payloads       1152  (85.3/s)
decoded frames      266  -> 19.70 fps over the capture window
ffmpeg: frame= 266 ... time=00:00:13.30      (266 / 13.30 = 20.0 fps of content)
payload KB/s        49.2
```

Read it as four independent facts:

1. **0 retransmits.** Every segment the camera allocated, we received.  If we
   were the bottleneck the camera would be resending.
2. **0 WASK (cmd 83).** The camera never once asked to enlarge its send
   window, i.e. its window was never full.  Nothing on our side is throttling.
3. **0 sn gaps.** No loss anywhere in the path.
4. **ffmpeg decodes 266 frames in 13.30 s of media time = exactly 20.0 fps.**
   The content itself is 20 fps, not 20 fps *after* we drop some.

And the independent corroboration, straight from the vendor's own library
running in the official app (`adb logcat`, 2026-10-13 20:15:05):

```
IoTVideo-IoTVideoPlayerImpl: iv_recv_avheader VideoType : 1, VideoWidth : 1920,
  VideoHeight : 1080, videoFrameRate : 20, AudioType : 2, ...
```

The **camera tells the official app `videoFrameRate : 20`.**  The frame rate is
a camera property, not an app property, so the app being "old" is irrelevant —
the app is only relaying a number the camera chose.

Four cameras, measured independently, all identical:

```
camera             variant     res      fps      KB/s
691722             zeros    640,360     20.0      44.0
783497             zeros    640,360     20.0      44.3
223864             zeros    640,360     20.0      40.8
```

**Being local buys zero loss and low latency; it cannot make the sensor or the
H.264 encoder run faster.**

### [X] DISPROVED — the AvStreamCtl we send is throttling the camera

Our `build_avstreamctl()` zeroes every field.  `iv_mtp_chnnel_eval_quality`
(0x5aa40) was then found to *compute* exactly those fields:

```
obj->0xac  = int_div(0xc4 - 0xd4, dt)   -> AvStreamCtl[0x10:0x14]
obj->0xb0  = int_div(0xc8 - 0xd8, dt)   -> AvStreamCtl[0x14:0x18]
obj->0xb4  = (f32)(0xbc - 0xcc) / dt    -> AvStreamCtl[24:56]   x4 floats
obj->0x160                             -> AvStreamCtl[62:64]
```

i.e. **the frame is a throughput report**, and we had been telling the camera
"this link does 0 bytes/s".  Perfect hypothesis for "camera falls back to its
cheapest profile".  Tested against a live camera (`/tmp/qtest.py`,
`/tmp/fieldprobe.py`), one field at a time, each run its own control:

| case | result |
|---|---|
| `base` (all zeros) | 640x360 @ **20.0** |
| `blob` = 4x 1e6 floats | 640x360 @ 20.0 — **no change** |
| `b0` = 50000 | 640x360 @ 20.0 — **no change** |
| `ac` = 1 | 640x360 @ 20.0 — **no change** |
| `w160` = 15 / 25 / 30 / 60 | 640x360 @ 20.0 — **no change** |
| `id164` = 1 | 640x360 @ 20.0 — **no change** |
| `ac` = 100 / 1k / 8k / 30k / 50k / 1e6 | **stream dies entirely** |
| `act1` then `act2` reply (alt=1080) | 640x360 @ 20.0 — **no change** |
| push only on the `lo` conv | **no video** — only `hi` (bit31 set) works |
| `act2` alone (no prior start) | **no video** — needs prior state |

**No field we control changes resolution or frame rate.**  The throughput
report is accepted only at tiny magnitudes and merely *breaks* the stream
beyond them; it never raises the ceiling.

### [X] DISPROVED — the app's `7e b9` PASSTHROUGH_MSG is the profile selector

`wire/p2p_frames.json[..]['avstreamctl']` is a 76-byte `7e b9` (type 185) cmd 0
frame we had never sent.  Decrypted, all three copies are identical in shape:

```
[52]      cmd     = 0
[56:60]   conv    = 0xef34cbd9 / 0x7ff1a426 / 0xf7e202cb   (per camera)
[64:68]   state   = 0x4e22
[0x1c:]   d_log   = 0x840186d6 001260a3
```

Per `passthrough.py`, cmd 0 does `iv_start_process_reset(chan)` — it is a
**channel reset**, not a quality request.  Sent before the AvStreamCtl it
yields **0 TLV payloads / no video**; sent never, we stream.  So it is not the
HD switch, and sending it would be actively harmful.

### The one real gap that remains: resolution, not fps

The app's header says **1920x1080**; our JPEG SOF marker says **640x360**.
Both at 20 fps.  So the *only* thing that differs between our session and the
official app's is the **profile**, and we have not found the selector.  Worth
solving — it is a ~9x pixel-count win for the picture — but it will **not**
raise the frame rate, because the app's 1080p stream is also 20 fps.

Candidates still untested for that: `iv_send_MtpQuality` (0x588f0) /
`iv_init_frm_mtp_quality` (0x582e4, GUTES type **188 `0xbc`**, 64 B header +
8 B per channel), `iv_create_kcb`/`PortStat`, and capturing the app's real
AvStreamCtl bytes by forcing its P2P through a relay we impersonate (the
patched APK already points `GWApi.GWellP2PUrl` at this Mac).

---

## Open questions still unanswered

- **CALLING checksum formula** — `iv_gute_frm_init_chkval` is byte-exact for
  LIST frames but matches none of the 3 captured CALLINGs.  Not needed any
  more (E1: any CALLING works for any camera), and `calling_forge.py`'s
  round-trip fails on region A `[12:20]` anyway.  Only revisit if per-camera
  CALLING *editing* becomes necessary.
- Discovery-reply checksum rule (edited clones rejected 102–108/0; sidestepped
  by using identical clones).
- POST `Signature2` rule (needs runtime-injected `cg01_f3c397620f853b12`).
- RC5 mode 3 (unread, @0x2b500); `iv_gute_frm_decrypt_id`'s use of `ctx->0xd0`.
- `AVSTREAMCTL` field values — **now measured, see Phase 10**: `obj->0xac` /
  `0xb0` / `0xb4` come from `iv_mtp_chnnel_eval_quality` (0x5aa40) and the
  frame is a *throughput report*.  Zeroed or plausible, they never change the
  profile; large values kill the stream.  Still unknown is what selects
  1920x1080 for the app vs our 640x360.
- **What selects the stream profile (1080p vs 360p)?**  The only observed
  difference between our session and the official app's.  Not AvStreamCtl,
  not the `7e b9` frame, not the CALLING (we replay the app's own bytes).
- `init_frm_mtp_res_request`'s `[82:122]` tail; `gat_rcv_init_info_msg_resp`
  @ 0x46960; `certify_req` finalizer for type `0x0c`.
- The zlib layer the logcat mentions (MTU 1032 fragment reassembly).

**Resolved since the last update:** the type-`0x04` AV cipher (RC5, key =
`CALLING[120:128]`), H.264 framing (ffmpeg decodes it), authentication to the
camera (**none required** — see Phase 9), and cam4 having no capture of its own
(a borrowed CALLING streams it fine).

## Phase 11 -- the resolution question (640x360 vs 1920x1080)

> Phases 11–14 close this as "a client-side ceiling" and are **wrong**; the
> answer is Phase 19 / §12d. Kept verbatim as a record of what was ruled out
> and why the wrong conclusion looked airtight at the time.

Goal after Phase 10: the app streams 1920x1080 and we stream 640x360, both at
20 fps.  Find the byte that selects the profile.

### The premise, re-measured independently

App 3.23.1.994 was installed on the new device (Moto G52, Android 13, arm64)
and its account logged in.  The app's own logcat no longer prints
`iv_recv_avheader` (the 2026 SDK build, `IoTVideo 1.5.20ad`, cut verbosity),
so the resolution was confirmed a second way -- **throughput**, via
`adb shell dumpsys netstats` on uid 10312 while the app held a live view:

    app   2 788 481 B / 15 s = 181.5 KB/s = **1487 kbps**
    ours  ~49 KB/s           =  ~400 kbps   (Phase 9/10)

3.7x the bitrate.  The app really is getting the HD encoder; we really are
getting the sub-stream.  (Also new: `gidp_WYZE_CAMERA_CONNECTION_INFO` telemetry
reports `video_definition=2`, `active_connect_count=3`, `transport_protocol=UDP`,
`connect_mode=2`, `device_firmware_version=CAM-1`.)

### changeDefinition, fully reversed (2.50.7 smali -> libiotvideo)

The app's HD request is *not* in the handshake.  It is a runtime API:

    GmLiveManager.changeDefinition(int d, ...)          # Kotlin `when`: 0/1/2 pass through
      -> MonitorPlayer.changeDefinition(B d, ...)
      -> IoTVideoPlayer.changeDefinition(B d, ...)
           if (!connected)  waitSendDefinition = d; return;
           sendInnerUserData((byte)5, new byte[]{d}, listener)   # <-- CMD 5
           if (!force) reviseNativeDefinition(currentDefinition)

    IoTVideoPlayer$28.subscribe()  (the Single that does the work)
        seq  = ByteUtils.lowBit32(System.currentTimeMillis())
        data = addHeader((byte)0, (byte)5, seq, new byte[]{d})

    addHeader(BBBJ[B) @ IoTVideoPlayer.smali:1102       <-- WIRE FORMAT
        buf = new byte[8 + len(data)]
        buf[0]=arg0(0)  buf[1]=cmd(5)  buf[2]=third&0xff(0)  buf[3]=0
        buf[4:8] = seq as u32 LITTLE-ENDIAN
        buf[8:] = data                                   # [0x02] for HD
    => changeDefinition(2) is exactly 9 bytes:
       00 05 00 00 <seq:u32LE> 02

    IoTVideoPlayerImpl::sendUserData(uint8_t*,int,bool) @ 0xfa349  (THUMB)
        hdr = sequence ? 0x1c : 8
        buf[0..5] = ff ff ff 88 00      buf[5] = sequence ? 0x03 : 0x02
        *(u16*)(buf+6) = len                       # payload length
        memcpy(buf + hdr, data, len)
        sequence ? iv_send_data_link_chn(...) : iv_send_user_data_link_chn(...)
          -> giot_eif_send_user_data -> iv_ringbuf_write(ctx->0x4c0, buf, len)

    reviseNativeDefinition(int) @ 0xf9978 -- 84 bytes, sends NOTHING:
        if (state != 6) this->0xc = (uint8)definition;        # just a store

The requested profile is therefore declared **at session start**, by the
persisted per-device app setting:

    SpUtils.getDefinitionToSp(deviceId)
      -> MonitorPlayer.setDataResource(did, x)   # x becomes the definition
      -> new PlayerUserData(x)                   # PlayerUserData.definition:I
      -> IoTVideoPlayer_SetDataResource          # definition -> IoTVideoPlayerImpl->0xc

**Note `ff ff ff 88` is the AV-link sync, and the byte at offset 5 is the AV
link type** (2 = user data, 3 = user data with sequence header, 4 = AV media).
That is the same `ffffff88` we decrypt at the start of every type-4 body.

### AvStreamCtl, fully reversed -- and exonerated

    iv_init_frm_AvStreamCtl @ 0x53274:
        memset(buf, 0, 0x4c)
        buf[0]=3                                   # link type
        buf[4:8]   = ctx->0x164                    # id
        buf[8:12]  = action                        # 1 start / 2 alt / 6 stop
        (action==1): buf[1] |= 2
        buf[0x10:0x14] = ctx->0xac
        buf[0x14:0x18] = ctx->0xb0
        buf[0x18:0x38] = 32 B copied from ctx+0x1a4
        buf[62:64] = u16 ctx->0x160

    iv_send_av_stream_ctl_frm @ 0x541a8:
        iv_init_frm_AvStreamCtl(...);  buf[0xc] = arg2
        action != 6 -> ivkcp_send(chnnel->0x334, buf, *(u16*)(buf+2))   # hi conv
        action == 6 -> ivkcp_send(chnnel->0x330, buf, *(u16*)(buf+2))   # lo conv

Two things fall out.  (a) **`[2:4]` really is the total length**, read back by
the send path -- `kcpav.avstreamctl()` was right to write `0x4c` there, and
`iv_init_frm_mtp_quality`-style memsets to zero are for other frame types.
(b) **The camera's own AvStreamCtl reply is parameterless**: we capture four
of them per session and every byte except `03 / 4c 00 / action` is zero, with
`action` alternating 2 and 6.  Echoing them back changes nothing.

### Five experiments, all clean negatives

Each ran a full session against camera 1 (`429728658691722`, 192.168.77.12),
and each kept the stream alive (hundreds of AV frames after the attempt), so a
null result really is a null result.  The readout every time was the camera's
own AV header (decrypted type-4 body: `ffffff88`, type@`[5]`, fps@`[19]`,
width u32@`[20:24]`, height u32@`[24:28]`).

1. **`defprobe.py`** -- the changeDefinition(2) frame in six plausible KCP
   framings (linktype 2 raw / wrapped / RC5-wrapped on the lo conv, linktype 4
   RC5-wrapped, linktype 3 and linktype 2 on the hi conv).  Header unchanged;
   +350..440 AV frames after every attempt.
2. **`ctlprobe.py`** -- echoed the camera's own AvStreamCtl reply verbatim, with
   `action` forced to 1, and re-sent our frame with the camera's blob and with
   the camera's ac/b0/w160.  All four were no-ops (and the reply's params are
   zero, so they were no-ops by construction).
3. **`sweepprobe.py`** -- 8 restarts of the stream with `ac`/`b0`/`w160`/blob
   set to 1920x1080, 1080x1920, definition 1/2, 4000 kbps, fps 20, and a
   `1920,1080` blob.  Header pinned at 640x360 through all of them.
4. **`gutesprobe.py`** -- accounted for every datagram of a live session.  The
   camera sends us **zero GUTES frames**: only `C0 90` meter_req (inner type 1,
   x9), KCP linktype 3 AvStreamCtl (x4) and linktype 4 AV (x1472).  So the
   app's extra frame types are app-initiated, never camera-requested.
5. **`replay_app.py`** -- parsed `/tmp/cap_relay.log` by direction (`T->R`) and
   replayed all 30 of the app's captured post-CALLING frames verbatim
   (`0xa6 x2`, `0xa7`, `0xaa x6`, `0xa0 x7`, `0xa5 x2`, `0xbc x3`, `0xd8 x3`,
   `0xb9 x2`, `0xb7`).  The camera ignored every one (no GUTES replies) and the
   header stayed 640x360.

### Where this leaves the search

Ruled out, with evidence: changeDefinition / inner-user-data CMD 5; AvStreamCtl
as a resolution carrier; every AvStreamCtl field; echoing the camera's reply;
wholesale replay of the app's control dialogue.  `iv_init_frm_mtp_quality`
(0x582e4) was also decoded and is **transport** adaptation, not encoder
selection: `buf[0]=0x7f`, `buf[1]=188`, device ids at `[4]`/`[8]`, channel
counters at `[0x1c..0x34]` (order swapped on `ctx->0x154==1`), timing deltas at
`[44]`/`[46]`, bit 0 of `[0x19]` set.

Candidates still standing:

- **The 164-byte `7f 0c a4 00 ...` frame** the app sends at 8.33 s, immediately
  after `TOPEN` and *before* the 0xa6 exchange.  **RULED OUT** (see below).
- `iv_create_kcb` (0x5c06c) -- iotv2.log shows it firing twice right after
  `iv_start_process_calling`.
- Whether the camera grants HD only after completing the 0xa6/0xa7/0xaa
  exchange *properly* (the replayed bytes embed the relay session's connection
  id `00001200660b40155cf08858`, so a verbatim replay may simply have been
  malformed rather than meaningless).

### Addendum: the `7f` frames are relay plumbing, and the meter frame is the map

Two more eliminations, both free.

**The 0x7f frames never reach the camera.** `wrapperchk.py` walks
`cap_relay.log` properly (using `[2:4]` as the total length, which the earlier
walker in `replay_app.py` got wrong -- that is why it reported an `0xa7` of
1132 B when the real one is 209 B).  The full ordered sequence is:

```
  0  app->relay  7f 01  len=36    1  relay->app  7f 02  len=40
  2  app->relay  7f 0c  len=164   3  relay->app  7f 0c  len=48
  4  relay->app  7f 0d  len=72    5  app->relay  7f 0d  len=32
  6..  7e a6 / 7e a7 / 7e aa / 7e a0 ... then 7e a4 CALLING (128 B)
```

The `0x7f` prefix appears **only in the first six frames**, bracketing the
TCP connect, and the app's 128-byte CALLING is *not* a substring of the 164-B
frame.  `0x7f` is the relay's own protocol (its own type namespace: 1/2/3/12),
`0x7e` is tunneled camera protocol.  Our LAN-direct client has no relay, so
there is nothing to send.  **The last "untried candidate" on the old list is
gone.**

**Our handshake already matches the app's.** With an instrumented probe
(`gutesprobe.py` now records from the first byte instead of letting `_pump()`
silently discard non-MTP traffic) the camera answers our CALLING with exactly

```
   7e a4  [1]=0xa4  len=32   000102030405060708090a0b0c0d0e0f1011121314151617
```

-- the same `7e a4 20 00` ack it sends the app (relay indices 22, 27, 28, 33,
50, 51).  Then `C0 90` meter_req x3 and KCP.  **The camera treats our session
identically to the app's at the control plane.**

**It is not a session-slot effect.** `adb shell am force-stop com.hualai`,
then a fresh session: still `header=(640, 360, 20)`.  The camera hands us the
sub-stream even when we are the only client, so "HD goes to the first
connection" is disproved.

**The meter frame, fully dumped** (74 bytes, from `/tmp/gutes_full.log`):

```
c0 90 02 09 4b 33                 MTP hdr, total = 74
00 01 44 00                       inner type 1 = meter REQUEST, len 68
d9 cb 34 ef                       <- connection id = our hi conv (0xef34cbd9)
00 00 8a 16 0d 00
d6 86 01 00 a3 60 12 00 d6 86 01 84    <- the device id (d_log split)
01 00 00 00
7b 1d 79 02                       <- getTickCount64 (increases each frame)
00 00 00 00 00 00 00 00 00 00 00 00     <- measurement section: ALL ZERO
04 00 00 00  44 00 00 00         <- item count 4, item length 68
00 00 00 00 00 00 00 00 00 00 00 00
```

`iv_rcv_meter_ack` @ 0x61338 -- *the function the camera runs on our reply* --
is now decoded: it takes `pkt+56` as the payload, reads `body[1]` bits 5..6 as
a sub-type to pick a 6- or 8-byte offset, checks `body[4:8] == ctx->0x10`
(that is the connection id above, which we echo, which is why the check
passes), then reads `body[+8, +0x1c, +0x20, +0x2c, +0x34, +42]`, calls
`iv_get_meter_item`, stores `getTickCount64()`, and runs
`iv_mtpSession_optimize_proc`.

So the meter record is a **path-measurement** structure, and its measurement
section is zero-filled in the camera's own request.  `make_meter_ack` echoes
those zeros back verbatim.  If the app fills that section with its measured
downlink rate, that is a live, still-untested lever -- and we now have the
byte offsets to aim at.


### Tooling notes

- **`llvm-objdump` is at `/opt/homebrew/Cellar/llvm@22/22.1.8/bin/llvm-objdump`**
  and is the only Thumb-capable disassembler here (Apple's `objdump` rejects
  both `-M force-thumb` and `--triple`).
- **`libiotvideo.so` is Thumb; `libiotp2pav.so` is ARM.**  Use
  `--triple=thumbv7-none-linux-androideabi` for the former and the default for
  the latter.
- **A Thumb symbol's `st_value` has bit 0 set as a flag; disassemble from
  `st_value & ~1`.**  Getting this wrong by one byte yields `<unknown>` followed
  by plausible-looking garbage -- this wasted a cycle on `sendUserData`
  (`0xfa349` -> start at `0xfa348`).
- `adb`'s daemon can die silently between calls (logcat exits 255); `adb devices`
  restarts it.  Never name a shell variable `UID` -- zsh treats it as read-only.

## Phase 12 -- capturing the 3.23.1 app's real session *(patched app, live capture)*

### The patch itself

Only **one file** in the whole APK changes: the Gwell SDK's config holder
`com/gwell/common/data/GwApiService` (in `classes34.dex`).  It holds the
list-server host the SDK asks for camera addresses:

```
- URL_GWELL_P2P_BETA/OFFICIAL/TEST = "|beta-mars-asrv.wyzecam.com"  (x3 fields)
- const-string copies of the same host                              (x3 sites)
+ "|192.168.77.13"                                                  (all 6)
```

That is the entire patch: the app still runs its genuine, unmodified protocol
against the genuine camera -- we only become the directory it asks first, so
its traffic passes through `cap_relay.py` where we log raw bytes.  Re-signing
with a debug key forced uninstall + re-login (accepted).  Restore from
`wyze_3.23/extracted/`.

### What the capture actually contained

`frameparse.py` reassembles the relay's TCP reads (they are NOT frame-aligned)
and walks both `7e` and `7f` frames -- both use
`<magic> <type> <u16LE total-incl-header> <payload>`.

- app -> camera: 54 frames; camera -> app: 53 frames; **~12 KB total**
- GUTES types the 3.23.1 app exchanges: `a0 a1 a4 a6 a7 aa b0 b1 b7 b8 b9 bc
  c3 d8 d9` -- a dozen types **our client never emits**
- **zero `c010` / `c090`** -- no KCP ever crossed the tunnel
- the app's CALLING is **66 B** (16 B nonce, 4 B flags, 16 B session id, conn id
  twice, 10 B tail) vs our replayed 2.50.7 CALLING's 128 B.  The payload is
  RC5 with the frame-derived key `frame[0:4]+frame[20:23]+0x00`
  (`calling_decode.py`).

### Three structural findings

1. **The app's AV plane never touches the relay.**  `phone_socks.py` reads
   `/proc/net/{tcp,udp}` over adb: the app's only non-loopback socket is the
   tunnel `192.168.77.14:48650 <-> 192.168.77.13:28803` at **13.9 KB** for the
   whole session (`nettop`), while `dumpsys netstats` shows it pulling
   **1.79 MB / 10 s**.  Its live view kept rendering after the relay's window
   expired.  So the app streams **direct to the camera over LAN**; the tunnel
   carried only the control handshake.
2. **Quality is decided per-session, by the camera.**  While the app was
   live-viewing camera 2 at ~1.4 Mbps, our client opened its *own* session to
   the same camera and got the usual 400 kbps / 640x360.  The camera happily
   serves both at once, so this is not a slot or bandwidth effect -- the two
   dialogues genuinely select different encoder settings.
3. **Our session has no GUTES dialogue at all.**  `gutesprobe` on a free camera
   shows the camera answering our CALLING with exactly one `7ea4` ack, then
   MTP meter requests and straight into KCP/AV.  The app negotiates first.

### Experiments *(both null, both well-grounded)*

**A. The new CALLING dialect is not the switch -- and the camera refuses it.**
`dialectprobe.py` replays the 3.23.1 app's CALLING verbatim, and again with the
per-session fields (nonce, session id, conn id) randomised.  The camera replies
with **nothing at all**, while the same camera answers our 2.50.7 CALLING
instantly with a full stream.  Either the new dialect needs a step we have not
replicated, or that CALLING is bound to the relay path it arrived on.

**B. The SDK's own definition frame does not change the resolution.**
`IoTVideoPlayerImpl::sendUserData` (`libiotvideo 0xfa348`, re-verified this
round) builds an AV-link user-data frame:

```
ff ff ff 88 00 02 <u16LE len> <payload>          -> 8 B header
ff ff ff 88 00 03 <u16LE len> <20 B seq/time>    -> 28 B header
```

and hands it to `iv_send_data_link_chn`.  The changeDefinition path builds the
9-byte payload `00 05 00 00 <seq:u32LE> <definition>`, and `GwDefinitionLogEnum`
gives the values `2=DEF_SD 3=DEF_HD 4=DEF_2K`.  `defsend.py` swept 16
combinations (definition 1-4 x linktype 3/4, plaintext vs RC5 with the AV key x
AV type 2/3), mid-stream and again immediately before re-pushing AvStreamCtl:
the header stayed `640x360 @ 20 fps` every time.

### Tooling / gotchas from this round

- `frameparse.py <log>` -- GUTES frame timeline from a relay capture, both
  magic bytes, with per-type byte totals.
- `phone_socks.py <uid>` -- the app's live sockets decoded from `/proc/net`
  (readable without root on this device).  The app's uid changed 10312 ->
  **10317** after the reinstall.
- `cap_relay.py` writes BOTH stdout and `/tmp/cap_relay.log` (fixed path), so a
  rerun silently overwrites the older capture.  Args are
  `[list_port] [relay_port] [seconds]` -- passing just a number sets the PORT.
- **RC5 is 8-byte-blocked**: decrypting `body[:28]` leaves the height u32 at
  `[24:28]` as raw ciphertext.  Decrypt 32 B to read the AV header.  The header
  is `ffffff88 | 00 | type | ... | sample-rate u32@[12:16] | fps@[19] |
  width u32@[20:24] | height u32@[24:28]`, and the media type byte is **1**.
- `adb shell ip -s link` is permission-denied; use `dumpsys netstats` or
  `nettop -x -l 1 -p <pid>` on the Mac.

### Where this leaves the resolution question

The remaining ways to see what the app sends on its **AV plane** (where the
definition clearly lives, since nothing on the GUTES/AvStreamCtl path works):

1. **Force the app's AV plane through the relay** -- the list response carries
   only relay records (`nrec = (total-32)//36`, all four rewritten), so the app
   must be finding the camera by its own LAN search.  Suppressing that would
   route its AV through us.
2. **LAN MITM** -- answer the app's LAN search with the camera's TUID but our
   IP, then forward app<->camera.  Captures everything, but the payloads stay
   end-to-end encrypted with the app's session key, which we cannot derive for
   the new dialect; we would have to brute-force candidates against the
   recognisable `ffffff88` AV header.
3. **Find the definition's real carrier in the disassembly** -- the meter
   measurement section (Phase 11) and `iv_send_av_ringbuf`'s contents are both
   still unread, and both sit on the path we cannot observe.



## Phase 13 -- reading the AvStreamCtl INITREQ off the other side

Every parameter we had been guessing at could now be read in the SDK's own
*receive* handler, because ThroughTek runs the same code on both ends.  Five
more theories were eliminated and one real bug was fixed.

### The complete AvStreamCtl field map

`iv_init_frm_AvStreamCtl @ 0x53274` (was: partially known):

```c
memset(buf, 0, 0x4c);
buf[0] = 3;                       /* linktype                       */
*(u32*)(buf + 4)  = ctx->0x164;   /* id164                          */
*(u32*)(buf + 8)  = action;       /* cmd                            */
if (action == 1) {                /* ACT_START                      */
    buf[1] = (buf[1] & ~2) | 2;
    *(u32*)(buf + 0x10) = ctx->0xac;
    *(u32*)(buf + 0x14) = ctx->0xb0;
    *(u16*)(buf + 62)   = ctx->0x160;   /* w160                     */
    memcpy(buf + 24, ctx + 0x1a4, 0x20);
}
if (action == 2) {                /* ACT_ALT                        */
    *(u32*)(buf + 0x14) = ctx->0x1e4;
    memcpy(buf + 24, ctx + 0x1c4, 0x20);
}
*(u16*)(buf + 2) = 0x4c;          /* total length, header included  */
```

and `iv_send_av_stream_ctl_frm @ 0x541a8` writes `buf[0xc]` from its own fourth
argument *after* the builder returns.  So the message is
`<cmd @ [8:12]> <subcmd @ [0xc]>`, two independent fields -- not one action
byte as previously assumed.  Constants: `ACT_START=1, ACT_ALT=2, ACT_STOP=6`.

`iv_send_av_stream_ctl_frm` then calls `ivkcp_send` directly.  **No RC5**: the
AvStreamCtl goes out in the clear, which is what our client already did.

### id164 is not a parameter -- it is a per-session random

`iv_start_process_calling @ 0x539a8` generates it:

```c
do {
    v = (rand() << 20) | (rand() << 10) | (rand() & 0x3ff);
} while (v == 0);
ctx->0x164 = v;
ctx->0x158 = ctx->0xa0;  ctx->0x15c = ctx->0xa4;  ctx->0x160 = ctx->0xa8;
```

30 random bits, nothing to do with resolution.  The `0xa0/a4/a8 -> 0x158/15c/160`
mirror means the interesting values are the **`ctx+0xa0..0xb0` block**, which
`iv_start_av_link @ 0x1c860` fills straight from its arguments:

```c
ctx->0xa4 = arg(u32);  ctx->0xa0 = arg(u32);  ctx->0xa8 = arg(u16);
ctx->0xac = *(arg + 8);  ctx->0xb0 = *(arg + 0xc);
ctx->0x1e4 = 0;  ctx->0x16c = 0;
```

`iv_start_av_link` is the exported entry point (no internal callers; the JNI
layer in libiotvideo calls it), so those five values are exactly what the app
hands the SDK.

### What the camera actually reads back

`iv_rcvpkt_AVSTREAMCTL_INITREQ @ 0x56f4c`, after its state machine, reads
precisely two fields out of the packet:

```c
chn->0x160 = *(u16*)(pkt + 62);      /* also pkt_ctx->0x18            */
chn->0x164 = *(u32*)(pkt + 4);       /* also chn->0x8c                */
```

It never touches `pkt[0x10]` (ac), `pkt[0x14]` (b0) or the 32-byte blob at
`[24:56]`.  **Every earlier sweep of ac/b0/blob was sweeping bytes the camera
discards.**  A repeated INITREQ is answered with an AvStreamCtl of
`cmd=3, subcmd=7` (or dropped, depending on `chn->0x154` and a bit-8 test on
`chn->8->0x1c`).

### Five eliminations

* **`w160` is not a resolution knob** -- 15 values (1920/1280/1080/720/640/360/
  2560/2/3/4/5/20/30/1/0), one fresh random `id164` each, header stayed
  `640x360` throughout (`w160probe.py`).
* **the subcmd byte is not a verb for quality** -- `[0xc]` in 2,3,4,5,7.
* **the cmd byte is not either** -- `[8:12]` in 2,3,4,5.
* **GUTES `0xb9` is not an AvStreamCtl.**  It is 76 B and was labelled
  "avstreamctl" in `wire/p2p_frames.json` purely because the length matches.
  Decrypted with the frame-derived key its blob is
  `03000000 000d168a 000186d6 001260a3 840186d6 00...` -- the product code and
  `d_log` -- and its tail is the conv id (`ef34cbd9`, `7ff1a426`, `f7e202cb`
  for the three cameras).  It is an identity/link frame.
* **`init_frm_mtp_res_request @ 0x4cc04` is a relay resource, not video.**  Now
  fully mapped: magic `0x7f`, type `0xa2`, total `0x7a` (122 B);
  `[4:12] = ctx->0x240/0x244`, `[0x1a..0x2a] = src->0x1c..0x2c`,
  `memcpy([46:82], src+48, 36)`, `memcpy([82:118], src+84, 36)`,
  `[0x62] = ctx->0x28`, `[88] = *(u16*)(ctx+0x130)`.  It pairs with
  `gat_on_rcvpkt_MTP_RES_RESPONSE`, i.e. GAT/relay bookkeeping.

### The frame-derived RC5 rule reads the whole captured dialogue

`frames_clear.py` decrypts every frame of a capture with
`key = frame[0:4] + frame[20:23] + 0x00` over `[12:20]` and `[24:]` in 8-byte
blocks.  It holds structurally: retransmitted frames decrypt identically
(ECB), the plaintext flag word at `[20:24]` survives, and its third byte is a
per-type class code (0x06 / 0x0a / 0x0e / 0x12).  The app's 3.23.1 dialogue is
now readable end to end -- 14 frame types, `a6 a7 a0 a4 aa b0 b1 b7 b8 b9 bc
c3 d8 d9`.  No frame in it carries anything resembling a width, height or
definition code.

The JSON's `hello` is the meter frame (`c090...`, same shape as the meter_req
we receive).

### Fixed: linktype 3 is plaintext, and we were shredding it

`_on_tlv` decrypted *every* KCP body with the AV key and appended it to the
H.264 buffer.  Linktype 3 is plaintext -- the camera's replies decode directly
to `00000000 02000000 00...` (id164=0, cmd=2) and `00000000 06000000 00...`
(cmd=6), and `rc5_dec(key, 8 zero bytes) = 49d8aa887750e980` reproduced the
repeated block we had been seeing.  Only linktype 4 is decrypted now; 659 media
TLVs / 391 KB / 718 start codes per 8 s, unchanged, with 4 control frames no
longer injected.

### Where this leaves the resolution question

The camera reads exactly two fields from the only parameterised frame our client
can send, and neither changes the encoder.  Combined with Phase 12 (the app's
AV plane is direct-LAN and therefore unobservable from the Mac), the remaining
candidates are:

1. **A cloud-side device setting.**  The app's definition lives in
   `SpUtils` (`sp_definition_2`), and Wyze cameras carry a device-level video
   quality property that may be what the encoder actually follows.  The cached
   `wyze_devices.json` (`home_page/get_object_list`) has no such key, so it
   would need `get_device_info`/property read + write.  Testable with the
   existing OAuth + Signature2 + curl path, but it mutates a camera's live config, so it waits for a spare test camera.
2. **A stream resource we never request.**  `setDataResource` / "data resource"
   is the SDK's own vocabulary for the definition path, and `iv_start_av_link`'s
   `ctx+0xa0..0xb0` block is fed from the app side, not from anything we can
   synthesise blindly.
3. **LAN MITM** to finally read the app's AV plane (Phase 12, route 2).

`w160probe.py`, `ctlreply.py`, `frames_clear.py` are kept; `ctlreply.py` is the
one to rerun after any protocol change, since it dumps both directions of the
AvStreamCtl exchange field by field.


## Phase 14 -- the client side is exhausted; 640x360 is the camera's decision

> **Superseded by Phase 19.** The conclusion below is wrong, and the reason is
> instructive: the v1 AvStreamCtl fields really are inert, so every experiment
> here was correct *and* correctly reported — but the camera switches layouts
> (and quality) on the frame's **length**, and 3.23.1 sends a 108-byte one
> whose `definition` word selects 1080p. Read §12d of `P2P_PROTOCOL.md`.

Phase 13 left one live candidate: `w160`, the only field the camera's INITREQ
handler actually parses.  This phase tested it properly and closed it, then
mapped the last unread frame and checked the cloud.  Nothing reachable from a
client changes the resolution.

### The earlier w160 sweep was invalid, and this is why it matters

`w160probe.py` pushed 15 values into one session and saw no change.  That
result should be DISREGARDED as a test of w160: `gutesprobe.py` shows the
camera emits only four linktype-3 replies in an entire session, all of them at
the very start, so every INITREQ after the first is swallowed by the state
machine.  The sweep was poking a field the camera had stopped reading.

`w160fresh.py` re-runs it correctly -- one value per **fresh** session
(discover -> CALLING -> a single AvStreamCtl carrying that w160), 35 s apart
for the slot:

```
w160=0     -> header=(640, 360, 1, 20)   media TLVs=1059
w160=1920  -> header=(640, 360, 1, 20)   media TLVs=1048
w160=1080  -> header=(640, 360, 1, 20)   media TLVs=1072
w160=3     -> header=(640, 360, 1, 20)   media TLVs=1085
w160=4     -> header=(640, 360, 1, 20)   media TLVs=1050
```

All five sessions streamed normally, so this is not a silent failure.  `w160`
is dead as a definition lever.  Its only other appearance in the library,
`0x1a544`, is a struct clone (`dst[0x60] = src->0x160`), not an encoder read.

### The CALLING is now completely mapped, and it has no resolution

`iv_init_frm_CALLING @ 0x542c0` builds a **128-byte** frame, magic `0x7e` on
the wire, type `0xa4` (`7ea48000`).  This also settles the dialect confusion:
the 66-byte `7ea6` CALLING in the 3.23.1 capture is the *newer* form, which
this camera firmware ignores (`dialectprobe.py`); the 128-byte form is the one
that works, and what `wire/p2p_frames.json` calls "calling" is that 128-byte
frame, not a 66-byte one.

Full layout, confirmed by decrypting all three stored CALLINGs:

| offset | source | meaning |
|---|---|---|
| `[0:2]` | `0x7e a4` | magic, type |
| `[2:4]` | `0x0080` | total length, 128 |
| `[4:8]`   | `ctx->8->0x240` | `d_log` low |
| `[8:12]`  | `ctx->8->0x244` | `d_log` high |
| `[0x18:0x1a]` | 0 | zero |
| `[0x1c:0x20]` | `ctx->0x94->0x10` | **conv id** (per camera) |
| `[0x20:0x24]` | `ctx->8->0x240` | `d_log` low again |
| `[0x24:0x28]` | `ctx->8->0x244` | `d_log` high again |
| `[0x28:0x2c]` | `ctx->0x158` | per-camera constant (0x0d168a / 0x0e7d09 / 0x153538) |
| `[0x2c:0x30]` | `ctx->0x15c` | 0x186d6 on all three |
| `[0x32]` | `\|= 1` | flag |
| `[0x34:0x36]`, `[88:90]` | 0 | zero |
| `[0x3c:0x40]`, `[0x60:0x64]` | 0 | zero |
| `[0x40:0x44]` | `get_local_ip()` | our LAN IP |
| `[54:56]` | `*(u16*)(ctx->8 + 0x130)` | our port |

The two "0x158/0x15c" constants are the same pair that appears in the meter
frame and in the `b9` identity blob, so they are device identity, not stream
parameters.  There is no width, height, fps or definition code anywhere in the
frame -- the last place one could have been hiding.

### The camera never asks us for anything

`gutesprobe.py` over a full 25 s session accounts for **every** datagram the
camera sent: one `7ea4` ack (32 B), two `c090` meter requests, four linktype-3
AvStreamCtl replies, then 2047 media TLVs.  **Zero GUTES frames.**

So the five `0xbc` (**`iv_init_frm_mtp_quality`, type 188**, 56 B) frames in
the app's captured dialogue are telemetry the app *volunteers*; the camera
does not solicit them.  The "we never answer the quality prompt" theory is
dead.  Layout, for the record: `[4:12]` = `d_log`, and session statistics at
`[0x1c] [0x20] [0x24] [0x28] [0x30] [0x34]` copied from `ctx->0x94` at
`0x1c/0x20/0x24/0x28/0x50/0x70`, with the two pairs **swapped** depending on
`ctx->0x154 == 1`; `[44:46]` and `[46:48]` are elapsed-time counters and
`[0x19] |= 1` a flag.  It is link telemetry, not a stream request.

**Caveat on `frames_clear.py`:** its frame-derived RC5 rule does not apply to
type `0xbc`.  Those frames' `[4:12]` does not decrypt to `d_log`, and their
flags word implies a mix of modes (0 and 2) rather than the uniform mode 2 the
other types use.  `iv_gute_frm_rc5_decrypt`'s **mode 3 branch at `0x2b500` is
still unread** and is the likely home of the difference.  Treat `bc` output
from that script as unreliable.

### The cloud has no video-quality property

`propread.py` (strictly read-only) calls `v2/device/get_property_list`
(`SV_GET_PROPERTY_LIST="<REDACTED>"`, body needs
`did`, `device_mac` **and** `device_model`, else 1001 "cannot be empty") and
returns 9 properties per camera:

```
P1=1  P3=1  P5=1  P20=1  P1018=1  P1020=1  P22=<public ip>  P30=0  P3000=0
```

Status flags and the public IP; no quality, definition, resolution or bitrate
pid, and only `pid`/`value`/`ts` per record -- no names.  This is consistent
with the app reading its own definition from `SpUtils` (`sp_definition_2`),
i.e. locally.  **Nothing was written to any camera.**

### Conclusion

Every lever reachable from a client has now been eliminated:

| lever | result |
|---|---|
| `changeDefinition` user-data frame (`defsend.py`) | negative |
| AvStreamCtl `ac` / `b0` / blob (`sweepprobe.py`) | negative |
| AvStreamCtl `w160`, 15 values in-session | negative |
| `w160` as the FIRST INITREQ of a fresh session (`w160fresh.py`) | negative, definitive |
| AvStreamCtl cmd / subcmd bytes | negative |
| 3.23.1 CALLING dialect (`dialectprobe.py`) | negative, camera silent |
| GUTES `0xb9` as a definition carrier | it is an identity frame |
| CALLING fields | fully mapped, no resolution present |
| MtpQuality `0xbc` handshake | the camera never solicits one |
| cloud device property | no quality pid exists |

The camera serves 640x360 to our session and ~1.4 Mbps to the app's, at the
same time, on the same device (Phase 12).  Whatever selects it is decided by
the camera using something we cannot synthesise, and the only untried route is
a **LAN MITM** to finally read the app's AV plane -- heavy, needs the phone
awake, and the payloads stay end-to-end encrypted with a key we cannot derive
for the new dialect.  640x360 stands as the documented outcome.


## Phase 15 — the audio/video regression, and the frame format that was hiding in plain sight

Once other camera models entered the rotation and audio was played while video
ran, video became unwatchable and the sound stopped reproducing altogether.
Both halves had one cause: **commit `73585b2` rewrote `p2p_client._on_tlv`.**

### Root cause

`73585b2` changed the type-4 body handling from "append everything to `_buf`"
to a three-way split:

```python
if   pt[:4] == b"\xff\xff\xff\x88": _buf += pt        # "video"
elif _looks_like_mulaw(pt):         _abuf += pt       # "audio"
else:                               tlv_other += 1    # dropped
```

Two bugs, both fatal:

1. **Video.** A frame larger than one TLV is split; only the *first* fragment
   carries the `ff ff ff 88` header, the rest are bare H.264 continuation bytes.
   They fail the sync test, and they fail `_looks_like_mulaw` too (mean&#124;diff&#124;
   ≈ 80–85 vs audio's 20–32), so they were **dropped** — frames arrived truncated
   and ffmpeg logged 20–164 decode errors.  Feeding every body instead gives
   **0 errors** (measured repeatedly: `ALL`, `wh_ALL`, `verifyfix`).
2. **Audio.** The audio AV frame carries the **same `ff ff ff 88` sync**, so it
   matched the first branch and went to `_buf`.  `_abuf` therefore **never
   received a single byte in any session** — which is exactly "sound does not
   even reproduce".  `_looks_like_mulaw` was never reachable by real audio.

### The audio frame format

Established by `mixbody.py` (dumping whole bodies), `audmatch.py` and
`audgap.py`:

```
 0   ff ff ff 88 00 00 01 00   sync
 8   00 x12                     reserved
20   u32 timestamp, microseconds (0x4e20 = 20000 per frame)
24   u32 session byte            0x87 in one session, 0x88 in another
28   u16 payload length = 320
30   320 B G.711 mu-law      -> 350 B total
```

**Trap:** an earlier version of this analysis treated `[24:28] == 87 00 00 00`
as a constant and the matcher scored **0 of 970 bodies**.  It is not constant —
it is the high half of the timestamp word.  The tests that do hold across
sessions are the sync, the 12 reserved zeros and a sane length.

Bodies carrying audio, all measured: **350** = one frame; **700** = two
back-to-back; **1004** = audio at `[0:350]` then video (first NAL ≈ `[379]`);
**728** = the 28-byte AV descriptor then two frames (`28+350+350`).

### Disproved along the way

* *"Header-less bodies are not video."*  Disproved — dropping them is what
  broke the feed.
* *"All 462 media frames contain a start code, so all H.264, so no audio."*
  **False positive:** the AV header `ff ff ff 88 00 00 01 00` contains
  `00 00 01` at offset 4.  Count start codes from `pt[8:]`, never `pt[0:]`.
  This is what let `P2P_PROTOCOL.md §12a-2` claim the camera sends no audio;
  §12a-3 now documents the correction.
* *"`_looks_like_mulaw` / entropy ≥ 6.5 can separate the two."*  Unreliable in
  both directions; the 12-reserved-zeros test is exact.  In one capture 749
  syncs split **512 audio + 237 video headers**, and ffmpeg decoded **236**
  frames — a clean partition.
* *"The payload is 8 kHz."*  No: 320 samples / 20000 µs = **16 kHz**.  The unit
  is proved by wall clock — a 12.00 s capture spans 11.94 s of timestamps; at
  2 µs per unit it would have been 23.88 s.
* *"The audio is loud (rms 8231, 0.3 % full scale)."*  That measurement came
  from `audioprobe.py`'s fixed 399-byte stride and from `whatsin.py`'s
  `p[30:]` over *multi-frame* bodies — both leak header `00` bytes, and `00` is
  mu-law −32124.  Correctly sliced, the stream reads rms 3–12.

### Loss, and why the clip came out short

The camera drops ≈1 frame in six: 110 single `40000` µs gaps across 488 frames /
11.94 s, never two in a row, and **0 frames straddle a TLV boundary** (so
extraction itself is lossless).  Concatenating what arrives gave 152 kB for a
12 s view — a clip that plays **26 % fast** and out of sync with the video.
`_take_audio_frames` now pads each hole with `0xff` (mu-law zero) using the
timestamp: **191 kB, 11.96 s for a 12.00 s capture.**

### Server side

* The WAV header said `fmt=7, 8000 Hz, 8 bit` — wrong twice over.  Now
  `fmt=1 (PCM), 1 ch, 16000 Hz, 32000 B/s, 16 bit`, with the mu-law decoded
  server-side, because browser support for WAV format 7 is uneven (Safari
  especially) and 32 kB/s over the LAN is free.  `audioop` is removed in
  Python 3.13, so the table is hand-rolled and checked **256/256 against
  `audioop.ulaw2lin`** (`audiocheck.py`).
* A new listener now starts at `audio_tail()`, not sequence 0 — otherwise it
  replays the whole 200-chunk backlog (~2 s) as one burst on the first click.
* UI: the icon entities were replaced with `SND` / `FS` / `JPG`
  labels, which also removes a real bug — `sndb.textContent = '&#128266;'`
  writes the *entity string* literally, so after one click the button printed
  `&#128266;`.  `play()`'s rejection is no longer swallowed: the button reverts
  and shows the reason in its tooltip.
* `p2p_call.py` parsed `sys.argv` at **import** time, so
  `server.py --host 127.0.0.1` died with
  `could not convert string to float: '127.0.0.1'`.  Its CLI flags are now read
  only under `__main__`.

### Result

| | before `73585b2` fix | after |
|---|---|---|
| video (12 s) | 20–164 ffmpeg decode errors | **236 frames, 0 errors** (≈19.7 fps) |
| audio bytes | **0** | 191 kB / 11.96 s (99 % of wall clock) |
| audio frames/s | 0 | 49.7 (38.6 real + gap-filled) |

Verified end-to-end over HTTP (`httptest.py`): `/` (no emoji entities),
`/api/state`, `/stream/<tid>.mjpg` (SOI/EOI present),
`/audio/<tid>.wav` (`fmt=1 ch=1 rate=16000`, 65514 samples decoded).

### The mic level: live, and it just tracks the room

Both live cameras (`.224`, `.117`) transmitted **real but extremely quiet** audio
during the long captures: per-second rms 2–4 out of 32767, 85 % digital zero,
only codes `{ff,7f,7e,fe,7d,fd}` = {0,0,−8,+8,−16,+16} — i.e. ≈ −76 dBFS, flat
for 15 s on both cameras.  The pipeline is right (even/odd byte histograms
identical → byte-oriented mu-law, not PCM16; `frac_fullscale == 0` → the window
never touches a header).

That is **not** a dead mic, though: two `httptest.py` runs against the *same*
camera (`429728658691722`) minutes apart read

| run | nonzero at unity | peak at unity |
|---|---|---|
| first | 33.2 % | 24 (−70 dBFS) |
| later | 70.8 % | 1024 (−30 dBFS) |

so the level responds to what is actually happening in the room.  The
App-side `mute()` is local-only (Phase 14), so nothing holds it down in-session.

Because −70 dBFS is correct but inaudible, `server.py` gained `?gain=N`
(1…64, multiply-then-clip) and the page an **Audio gain** selector in the
header (default 8×, re-points any `<audio>` that is already playing).  It is
both a listening aid and the diagnostic: if even 64× is pure silence, the
microphone really is off in the camera's settings.



## Phase 16 — where the delay actually was, and the UI bugs that came with it

The driving concern: delay -- the stream is LAN-local, so why does it take
this long -- plus a batch of UI bugs (JPG button slow, "connecting"
shown mid-playback, requests stacking in pending, fullscreen has no audio
control and no way to see whether audio is on, and a request for icons instead
of the text labels).

### Localizing the delay by measurement

Rather than guess, each stage was timed (`camclock.py`, `fflag.py`).  Every
audio AV frame carries the **camera's own capture clock** (u32 µs at offset 20,
advancing exactly 0x4e20 = 20000 per frame), so comparing it against wall-clock
receive time separates transport delay from everything else:

| stage | measured | verdict |
|---|---|---|
| camera → our socket | min 68.8 / **p50 82.4** / p90 88.6 / max 118.2 ms | fine |
| drift of `wall_recv − cam_ts` | **+0.013 ms per wall-second** over 25 s, spread 49.5 ms | flat — nothing accumulates |
| ffmpeg decode | residual **−0.04 s** at EOF | holds no backlog |
| server publish → socket write | `served == pub` (5564/5564), `t_write` 1.13 s over 28 min | keeps up exactly |

The absolute transit needed the camera's clock epoch, which is unknown (its
value is *uptime*, not wall time).  Anchoring it on the moment we sent
AvStreamCtl fixes it, and transit **includes** the camera's own encoder
buffering — the one part invisible from anywhere else.

`fflag.py` feeds a captured stream into the *shipped* ffmpeg command at the real
arrival rate and counts frames still buffered at EOF.  **`-fflags nobuffer` is
actively worse** (218 → 158 JPEGs), so it was measured rather than assumed and
not adopted.

**Conclusion: the transport and the decoder were never the problem.**  The only
remaining place the delay could be added was the browser.

### The one real server-side bug: a viewer could never catch up

`take()` returns everything newer than the cursor, so a browser reading even
marginally slower than we write accumulates a backlog, replays it, and then
stays that far behind **for the rest of the session** — a permanent, invisible
delay.  `lagtest.py` reproduces it by reading ~33 kB/s against a ~50 kB/s
camera.

Frames now carry their publish time, and `_stream` drops to the newest frame
once the oldest pending one is older than `MAX_LAG` (0.5 s — well above
ffmpeg's natural 7-frame output burst, so healthy viewers are untouched).
Verified both ways: a slow reader stays at **21 ms lag** with 119 stale frames
skipped rather than replayed; a fast reader gets **0 drops**, lag 1–35 ms.

### A listener-accumulation bug in the page

`tile()` runs on every `/api/state` poll (2 s), and the sound button's click
handler was registered *outside* the create-once `if (!el)` block — so a fresh
handler was appended every 2 s.  Ten minutes in, one click on SND ran 300
handlers against 300 separate `audioOn` closures that all read `false`.  That
is very likely the "I cannot tell whether sound is on" symptom.  Handlers are
now wired once, guarded by `dataset.wired`.

### UI

* **Icons, not emoji and not text** — inline SVG (`ICON` map, `currentColor`
  throughout so the existing hover/active colours apply unchanged).  The
  speaker pair is a real state change (struck-through cone vs. sound waves),
  not a colour you have to squint at.
* **Fullscreen gained a sound button** and the overlay bar shows the live
  status plus the measured `lag`.  Tile and fullscreen drive the *same*
  `<audio>` element through `setAudio()`/`syncAudioUi()`, so they cannot
  disagree.  Closing fullscreen no longer silently mutes the camera.
* **The false "connecting" badge** — the worker flips to `connecting` the
  instant a pump fails while the tile keeps showing a perfectly good picture.
  The badge is now driven by how stale the frames actually are (`stats.last`),
  so it reads `live` until the picture genuinely stops.
  *(Superseded by Phase 18 — it was still conflating two different failures.)*
* The tile footer shows `fps · frames · lag ms · -dropped`, so a viewer can
  see whether a sluggish picture is our queueing or the browser's decoding.

## Phase 17 — the delay was the browser's connection budget *(the last hop)*

Phase 16 proved the camera→server path costs ~82 ms and that the server writes
immediately (`served == pub`, 1.13 s of writes in 28 min).  Two complaints were
still open and turned out to be **the same bug**:

* "sometimes state endpoint ends in pending, it just queues a lot of requests,
  and all of them stack in pending"
* "jpg button didn't work / took minutes"

### The cause: six connections per origin

Chrome allows only **six** HTTP/1.1 connections to one origin.  The page used
one `GET /stream/<tid>.mjpg` per camera, and those sockets never close, so four
powered-on cameras held four slots permanently.  Switch sound on and each
camera's `<audio>` held another.  A `POST /api/discover`, a `/api/state` poll or
the snapshot's `<a download>` then had nothing left to run on and sat in
"pending" until some stream ended — which, for a live MJPEG socket, is never.
the delay on screen was therefore not transport, decoder or server
queueing: it was the browser replaying/starving on a saturated pool.

### The fix: one connection for every camera

New `GET /feed` multiplexes all cameras onto a **single** fetch stream, framed
as a 20-byte header then the JPEG::

    <Q tid   u64   camera id
    <Q t_ms  u64   publish time, epoch milliseconds
    <I len   u32   JPEG size

Binary rather than multipart so the client slices frames with a `DataView` and
never scans for a boundary.  The page reads it with
`fetch().body.getReader()` and paints each camera into its own `<canvas>`
(`<img>` cannot be fed from JS).  Socket cost is now **1 feed + one `<audio>`
per camera you actually switch on**, so the pool is essentially empty and
`/api/state` can no longer queue.  Polling also went 2 s → 2.5 s.

Per-camera latency is now bounded *at the painting layer too*: `slot` holds only
the **newest** frame per camera, overwriting rather than queueing, so a slow
decode drops frames instead of building the backlog `MAX_LAG` exists to
prevent.

### The snapshot button no longer touches the network

It is now `canvas.toBlob()` on the frame already on screen, downloaded via a
`blob:` URL.  No HTTP request at all, which is why it can no longer hang: the
old `<a download href="/snapshot/...">` needed a free connection that never
came.  `/snapshot/<tid>.jpg` is kept on the server for scripting.

### The delay is now measurable *in the browser*

`X-Time` on a multipart part is unreadable to JS, so the browser could never see
its own contribution.  Now the page subtracts the header's publish time from
`Date.now()` and prints the result in each tile's footer — the true end-to-end
delay, published → painted.  Server and browser share a clock here, so the
number is direct rather than estimated.

Measured by `httptest.py` against a live camera: **3–50 ms** end-to-end
(`end-to-end age of the newest local camera frame`).  If the picture
still feels behind while that footer reads single/two-digit ms, the remaining
delay is inside the camera or the browser's compositor, not in our code.

### A mistake worth recording

The first `/feed` implementation **forgot to append the JPEG bytes** after the
header (`out += j`).  The symptom was deceptive: the server looked healthy and
burned 12.8 % CPU, but the page never painted because the parser kept waiting
for payload that was never sent (`frames ok=0`, 20 bytes per frame).  Two
`httptest.py` runs hung for 30 s on it before `curl` showed the byte rate
collapsing to 12 kB per 15 s.  Fixed; a `feedtest.js` now guards exactly this.

### Tests

* `httptest.py` — page, `/api/state`, `/feed` framing (ok/bad/cameras/age),
  `/stream`, `/audio?gain=32`, JS parses, ids referenced by
  `getElementById` all exist, and no regression back to `<img>` per camera.
* `feedtest.js` (**new**) — pulls the page's own `parseFeed()` out of the served
  `<script>` and runs it against a 24-frame, 4-camera synthetic stream at chunk
  sizes 1, 2, 7, 19, 20, 21, 1024, 65536 and "everything at once"; plus a
  header split in half, a truncated tail, and a corrupt 4 GB length that must
  resync instead of throwing.  This is the only real guard on the framing,
  because there is no browser on this machine.
* `lagtest.py` (slow/fast), `verifyfix.py`, `camclock.py`, `fflag.py` unchanged.

## Phase 18 — "it says connecting/streaming while the camera is streaming"

The Phase 16 badge was still wrong, and the symptom that exposed it was precise:
a camera that is clearly streaming sometimes shows `connecting` or `streaming`
in the badge, and other cameras do not.

### Why the word appeared

The badge was falling back to the **worker's own status string** whenever the
picture went stale.  But the worker is a poor narrator, because of one number:

    # CameraStreamThread.run(), the stall check
    if time.time() - last_h264 > 8.0:
        raise RuntimeError("stream stalled")

It only gives up on a silent camera after **8 seconds**, and until then it keeps
reporting `streaming`.  The badge, meanwhile, declared the picture stale after
**4 seconds**.  So for every stall there was a 4-second window in which:

* the picture on screen was frozen, and
* the badge printed `streaming` — the worker's *opinion*, which was still wrong.

At 8 s the worker finally tore down and re-handshook, so the badge then printed
`reconnecting`, then `connecting`, then `streaming` again the moment the
handshake finished — while the frozen frame was still the last thing painted.
That reproduces the symptom exactly, start to finish.

"Other cameras don't show it" is the useful half: a camera on a healthy Wi-Fi
path never stalls, so its badge never leaves `live`.  The badge was not
random — it was naming the one camera whose link was dropping.

### The fix: the badge describes the picture, not the worker

Two failures were being conflated and are now separate words:

| Badge | Meaning |
|---|---|
| `live` | painted a frame within 2.5 s — the picture is genuinely moving |
| `stalled` | nothing painted for >2.5 s while the worker still claims `streaming` |
| `no video` | the worker has a stream but this browser has never painted a frame (broken `/feed`) |
| `connecting` / `reconnecting` / `discovering` | the worker really has lost the camera |
| `offline` / `error` | powered off, or a hard error |

The worker's words now appear **only** when the worker really has lost the
camera; a frozen picture says `stalled` instead.  2.5 s is far above the ~50 ms
frame interval and above ffmpeg's output bursts, so a healthy camera never
trips it.  The badge also gained a tooltip giving the two facts side by side —
`picture: frozen for 6.2 s` / `server: streaming` / `frames decoded: 4211` —
which is what lets a stalling camera be told apart from a broken feed.

The placeholder no longer says `streaming…` either; it is only visible when
nothing is being painted, so it says `waiting for video…`.

Not changed, deliberately: the worker's 8 s stall timeout.  Lowering it would
recover ~3 s sooner but risks tearing down a healthy stream during a gap, and
each teardown costs an 8–10 s re-handshake.  Revisit only with evidence that
recovery time is the problem.

---

## Phase 19 — 1080p. The stream *request* was the switch, not the login

Phases 11–14 concluded that 640×360 was a client-side ceiling and closed the
question.  It was reopened twice more, and this phase closes it for real: the
camera was always able to send 1080p, and the difference is **one 32-bit word
in the AvStreamCtl** — the stream *request*, not the CALLING, not the token,
not the login.

### The evidence that had never existed before

Phase 12–14 had to guess, because two things were invisible:

1. The app's actual **camera** dialogue was never captured — `cap_relay.py`
   sits in the *cloud* path (Mars / list-server), which is a different
   conversation with a different peer.  Several "facts" recorded from
   `/tmp/cap_relay_323.log` are about the cloud protocol and say nothing
   about resolution.
2. We could never see a KCP packet on the wire, so the AvStreamCtl's real
   contents were unknown — `kcpav.FIELDS` was a parameter sweep over fields
   we had to guess.

Both gaps closed by capturing the phone itself: **PCAPdroid** (Android's
VPN-API capture, no root, no LAN changes — see the recipe at the end of this
file).  `wyze3.pcap` (13.1 MB) is 30 s of the app's live view:

* the app streams **direct LAN UDP** to `192.168.77.10:55013`; the SDK does
  **not** bypass the VPN, so the capture sees everything;
* ~3.2 Mbps camera→app, in **our** dialect (`7ea4`, `c090`, `c010`, `7eb9`);
* the app's CALLING is **213 bytes** where ours is 128, and its AvStreamCtl
  is **108 bytes** where ours is 76.

`pcapparse.py` reads the pcap (DLT_RAW, not Ethernet), `applan.py` splits it
into the two flow-direction files, `appkcp.py` reassembles the app's KCP
push stream and prints its TLVs.  That last one is what produced the fix.

### What did *not* matter — every negative, so nobody repeats it

| Tried | Result |
|---|---|
| Replay the app's 213-byte CALLING **verbatim** | still 640×360 / 267 kbps |
| Replay it with a rewritten conv / key / IP | camera ignores it entirely |
| The 32-hex-character token in the CALLING | irrelevant |
| The same token inside the AvStreamCtl | irrelevant (zero it: still HD) |
| The AvStreamCtl's trailing bytes `body[60:72]` | irrelevant |
| The v2 header's *value* (`85 9f 76 f7`) | irrelevant (random works) |
| `definition` = 1 or 3 | camera stops sending entirely |
| A 76-byte or 84-byte frame carrying `definition`=2 | camera stops sending entirely |
| Our own CALLING (128 B, 2.50.7) + the app's request | **1920×1080** [OK] |

That last row is the whole answer: the CALLING was never the problem.

### What mattered: a 108-byte v2 AvStreamCtl

The camera picks its interpretation of an AvStreamCtl from the frame **length**,
and the definition word lives in the v2 layout.  The complete frame is 28
meaningful bytes plus 80 zero bytes:

```
03 02 6c 00                        TLV: linktype 3, length 108
85 9f 76 f7 01 00 00 00            v2 header (constant)
00 00 00 00                        obj->0x164     (v1 [4:8])
01 00 00 00                        action = START (v1 [8:12])
01 00 00 00                        action byte    (v1 [0xc])
02 00 00 00                        definition     (v1 [0x10])  <-- the knob
00 .. 00                           unchanged in every capture
```

    definition 2 -> 1920x1080 @ ~1.2 Mbps
    definition 0 ->  640x360  @ ~0.26 Mbps   (the SD sub-stream)

`kcpav.avstreamctl_v2()` builds it and `p2p_client.build_avstreamctl_hd()`
exposes it; the bytes are byte-identical to the frame captured from the app.

### A methodological trap, recorded because it cost an hour

The camera holds **one session per conv**, so a probe that reuses the same
CALLING starts colliding with its own previous session.  The symptom is
poisonous: **two byte-identical frames produced different results** (`our7`
gave nothing, `mintail` gave 1080p), which looks exactly like "the camera
rejects this field" and isn't.  Rules that follow from it:

* a "no media at all" result is **not** evidence on its own — re-run it;
* only re-running with spacing isolates a real rejection;
* rewriting the CALLING to get a fresh conv does **not** work (the camera
  ignores a re-signed frame), so probes are inherently serialized;
* the trustworthy signals are `1920x1080` (positive) and `640x360` (the
  camera's own fallback), never zero.

### Product changes

* `CameraStream(..., definition=2)` sends the v2 request; `definition=None`
  keeps the old 76-byte frame.  **Default is now HD.**
* A camera that refuses the HD request answers with *no media*, not with SD,
  so the worker counts empty runs and falls back to definition 0 only after
  `HD_RETRIES` (3) of them — a single transient collision must not silently
  pin a camera to 640×360 for the rest of the run.  `WYZE_DEFINITION=2|0`
  overrides the starting value.
* `WYZE_WIDTH` now defaults to **1280** instead of 640.  Four native 1080p
  JPEG encodes pin the CPU, and a saturated encoder *is* user-visible delay:

  | WYZE_WIDTH | idle | fps (4 cams) | JPEG traffic |
  |---|---|---|---|
  | 0 (native 1920×1080) | ~10 % | 15.5–21.2, jittery | ~20 MB/s |
  | 1280×720 | ~66 % | ~20–23, steady | ~9 MB/s |
  | 960×540 | ~54 % | ~20.2–20.6, steady | ~7 MB/s |

  1280 is 4× the pixels of the old 640×360 for ~2.5× the bytes.
  `WYZE_WIDTH=0` restores native 1080p.

Verified with all four cameras streaming **1920×1080** at once through the
full product path (server → ffmpeg → `/feed` → canvas), and per-camera with
our own CALLING via `ctlsweep.py`.

### Reproduction, from zero

```
# 1. capture the app's LAN dialogue (phone must be showing live view)
adb install -r PCAPdroid_v2.0.2.apk
adb shell am start -e action start -e pcap_dump_mode pcap_file \
  -e pcap_name wyze.pcap -e app_filter com.hualai \
  -n com.emanuelef.remote_capture/.activities.CaptureCtrl
python3 adtap.py 14                 # tap the Spanish consent/VPN dialogs
# ...watch the app... then:
adb shell am start -e action stop -n com.emanuelef.remote_capture/.activities.CaptureCtrl
adb pull /sdcard/Download/PCAPdroid/wyze.pcap /tmp/
# 2. pull the app's stream request out of it
python3 pcapparse.py /tmp/wyze.pcap
python3 applan.py    /tmp/wyze.pcap
python3 appkcp.py a2c               # prints the linktype-3 AvStreamCtl
# 3. confirm against a live camera
python3 ctlsweep.py <tid> 9 45 mintail
python3 ctlsweep.py <tid> 9 45 ours
```

`SECRETS.md` holds the OAuth `client_id` / `client_secret` and the checklist.


Delete the plaintext token files (`/tmp/wyze_token.json`, `/tmp/wyze_live.txt`,
`/tmp/wyze_log.txt`) and revoke the token when finished.


## Phase 20 — Two-way audio: the camera hears us

The talk button was the last thing the app did that we could not do.  It turned
out to be the *only* place the client sends real media, and it is now proven on
hardware: a voice spoken into the app on the phone, then streamed through our server, came out of Camera 1's
speaker (`192.168.77.12:64146`).

### The capture that had the answer

Everything came from one PCAPdroid capture (`/tmp/ctrltalk.pcap`, 24 MB) taken
while the app was showing live view, then holding the talk button, then tapping
the light and IR toggles.  Sorting it by direction and linktype was the whole
job:

| direction | linktype | count | what it is |
|---|---|---|---|
| app -> camera | 3 | many | AvStreamCtl (the resolution command, Phase 19) |
| app -> camera | 4 | **130** | the talk audio, and only while the button is held |
| app -> camera | 4 | 0 | (*not* present in a session where talk was not used) |

The linktype-4 frames belong to one conv (`0x00f82bbf`) and appear **only**
while the button is held -- zero of them in `wyze3.pcap`, 130 in this session.
That is what identified them; nothing in the app's UI exposed a "talk stream".

### Reading it

The 226-byte body is RC5 with the session AV key, the trailing two bytes left
in the clear.  Decrypted, it is six AMR-NB sub-frames behind a 34-byte header
(`P2P_PROTOCOL.md` §13b has the byte map).  Two independent checks said AMR-NB
12.2 kbit/s: the sub-frames are `0x3c` + 31 bytes, which is RFC 4867's ToC for
FT=7, and re-encoding digital silence with ffmpeg's `libopencore_amrnb -b:a
12.2k` produces the same ToC and near-identical payloads.  Concatenating the
sub-frames as `#!AMR\n` + frames and handing them to ffmpeg decodes to 15.2 s
of clean speech (about 3 s of silence, then bursts).

### The slow-motion surprise, and the measurement that explained it

First hardware test: the camera **did** speak, but in slow motion.  That single
symptom could have been the capture, the framing or the camera, so it was
measured rather than guessed:

* **Pacing was not the cause.**  Re-computing the packet arrival times from the
  pcap gave 129 media datagrams spanning 15.2 s, i.e. the app sent 120 ms of
  audio every ~120 ms -- realtime.  (The p90 gap of 240 ms and one 13 s gap are
  the session pausing between two presses.)
* **The capture was not pitched down.**  An autocorrelation estimator said
  50 Hz, which would have meant a 16 kHz mic fed to an 8 kHz encoder -- but
  160 samples is exactly one AMR frame, so that was a frame-boundary artefact.
  A cepstrum over 45 ms windows gives 86-145 Hz for the loud voiced segments:
  an ordinary male voice, i.e. the audio itself is fine.
* **The camera renders declared AMR time at half rate.**  Sending the *same*
  clip 2x faster (`asetrate=16000,aresample=8000`, halving the duration and
  doubling the pitch) read back as normal speed.  That is the whole answer:
  feed it 2x-rate content.
  > **This is wrong -- see Phase 22.**  It was measured while only 33 % of the
  > audio reached the wire (Phase 21's `read` bug), so the camera was starved
  > to a third of a feed.  A 1 kHz tone recorded from the speaker comes back at
  > **2000 Hz**, and a 1x feed leaves it silent 51 % of the time: it consumes
  > 2.0 declared seconds per real second, so it needs 2x-*slower* content and a
  > packet every 60 ms.

Whether the camera plays the 8 kHz samples at ~4 kHz or inserts a gap after
each 20 ms frame is not known (the ear cannot tell), and it does not matter:
both give the same rule, and it is the app's own behaviour that over-feeds the
camera 2x.  `P2P_PROTOCOL.md` §13d records this as open.

### Negative results, so nobody repeats them

* Talk media is **not** needed on the high conv; only the AvStreamCtl uses it.
* The counter field's value does not gate anything -- starting at 0 works.
* **AMR-WB rejects** the captured frames and AMR-NB decodes them cleanly.
* **Light / IR / detection are not on the LAN at all.**  The same capture was
  searched for them: while the toggles were tapped, the app sent **only** UDP
  to the cameras' `:55013` with linktype 3 and 4 -- no TCP, no local HTTP.  The
  rest of the traffic is TLS to the cloud relay and carries no readable
  payload.  So there is no local P2P path to find for the controls, and that
  goal is parked as cloud-only until the cloud channel is read.

### Tooling

`talkplay.py` is the proof tool and stays useful:

```
python3 talkplay.py <tid> [--amr FILE] [--secs N] [--loop]
                    [--gain D] [--speed D] [--quiet]
```

Its default source is the app's own captured talk audio from
`/tmp/applan_a2c.bin`, so a run that makes the camera speak proves the framing,
cipher, conv and codec all at once.  `--speed 2.0` is the slow-motion fixup and
`--gain` is a re-encode volume knob; both need ffmpeg
(`/opt/homebrew/bin/ffmpeg`, which has the `libopencore_amrnb` encoder).

The analysis scripts that got there (`apptalk2.py` -- per-session conv
grouping; `talkblocks.py` -- sub-block layout; `talkmap.py`, `talkrt.py` --
timing and byte rate; `talkamr.py` -- the AMR round-trip) are kept next to it.

### Product work

The camera holds **one** session, and the server's worker already owns it, so
talk cannot open its own `CameraStream`.  It has to be pushed through the same
socket the worker is pumping -- see Phase 21.

## Phase 21 -- two-way audio, productised: two thirds of every sentence was being thrown away

The talk path is in `wyze-cam-stream/server.py`: a hold-to-talk button per tile
and in the fullscreen bar, three endpoints (`POST /api/talk/start`,
`/api/talk/pcm/<tid>`, `/api/talk/stop`), and the packing done by the *worker*,
not the HTTP thread, because the camera holds one session and `send_talk()`
pushes on that session's low conv (`kcp_lo`), which the pump thread owns.

The browser captures 16 kHz mono with `getUserMedia` + the deprecated
`ScriptProcessorNode` (no build step) and POSTs 1024-byte (32 ms) Int16LE
chunks; ffmpeg resamples 16k -> 8k and encodes AMR-NB 12.2k; the worker sends
one 226-byte packet per 120 ms.

### The first live test sounded awful, and the reason was measurable

The camera **did** make noise, so the framing, cipher, conv and codec were all
right.  What was wrong showed up in the counters: 5.02 s of PCM accepted
(139 264 B = 4.35 s of 16 kHz audio) produced ~215 AMR frames at the encoder,
but only **72 frames (1.44 s) reached the wire -- 33 %**.  Two thirds of every
sentence was simply discarded.

**Root cause: `ff.stdout.read(1024)`.**  `read(n)` on a pipe's buffered reader
blocks until it has *all* n bytes.  The encoder emits ~1.6 kB/s (12.2 kbit/s),
so the reader sat there ~640 ms and then handed up ~32 frames in one lump --
and the queue was capped at 12 frames, so each lump lost ~20 frames as it
arrived.  That is exactly the observed 33 %.

This is the *same* bug the video side had already been fixed for (`_drain`
uses `read1`); the talk reader was written later and never got the lesson.
Fix: `read1(4096)`.

Two smaller faults in the same path:

* the queue was bounded twice (a `maxlen=60` deque plus an explicit
  `popleft()` loop down to 12) -- the explicit loop was the binding one.  Now a
  single `deque(maxlen=TALK_QUEUE_FRAMES)` = 24 frames (480 ms) drops the
  oldest, which is the right end to lose.
* `_talk_tick` sent **at most one packet per call**, but it is called once per
  pump-loop iteration and that loop's cadence is the *video* side's (a 50 ms
  `select` that overruns whenever ffmpeg applies back-pressure on stdin).  So
  120 ms silently stretched to whatever the video took.  It now sends every
  packet that is *due*, capped at `TALK_MAX_BURST = 3`, and forgives the debt
  if the loop was starved for more than 0.5 s (replaying a starved backlog would
  only add latency, which is what the listener actually hears).

### Verified locally, silently, with no camera and no network

A stub `CameraStream` plus the real encoder and the real reader, fed 4.42 s of
silence (`talkreadertest.py`):

| | before | after |
|---|---|---|
| delivered to the camera | 1.44 s (33 %) | **4.32 s (98 %)** |
| queue depth reached | pinned at its 12-frame cap | max 6 frames (120 ms) |

The remaining 2 % is the encoder's own tail latency.  Queue depth is the thing
to watch here, because the queue *is* latency -- the camera plays it at 1x.
> **Corrected in Phase 22:** the camera plays it at **2x**, so 24 frames of
> queue is 240 ms of real audio, not 480 ms.  The delivery fix here stands; the
> pacing conclusion does not.

### Also settled, offline: the app's own content is 1x, not 2x

`talkrate.py` re-reads `/tmp/ctrltalk.pcap` keeping timestamps (the shared
`pcapparse.read_pcap` throws them away, which is how the wrong number got into
Phase 20): **128 talk packets, 17.87 s wall span, 15.36 s of declared audio,
ratio 0.86**; p50 gap 0.110 s; the frame counter steps 55-62 per packet against
our `TALK_COUNTER_STEP = 60`.  So the app sends one 120 ms packet per ~110 ms
of real time -- its content is natural, and it is *not* over-feeding the camera
2x.  That contradicts Phase 20's "half rate" conclusion, so `P2P_PROTOCOL.md`
§13d is marked broken and the next step there is a **headphone** A/B on the
capture alone (silent to the room, no camera trip).

### Still to do, in order

1. Headphone A/B (above) to close the pacing question without a camera.
2. One warned camera test of the fixed product path -- on Camera 1 (`192.168.77.12`).
3. The camera-controls goal stays parked: the capture shows the light/IR
   toggles never touch the LAN, so there is nothing local to reverse.

### Notes for next time

Do not walk a camera test on the strength of a counter alone.  This phase's
bug was visible in `talk_stats` for several runs (72 frames for 4.35 s of
input) while the code "compiled, streamed, and worked" -- the audio was just
one third of itself.  Compare *delivered declared seconds* against *PCM
seconds fed* every time; they must match within the encoder's tail.

## Phase 22 -- two-way audio SOLVED: the camera plays our frames at 2x

Phase 20 and Phase 21 both tried to settle the talk rate by judging clips by ear, and both got answers that fit two different models.
This phase stopped guessing: **the Mac's external microphone was pointed at the
camera's speaker and the camera's own output was recorded** while a known
signal was played through the real product path.  A recording you can measure
beats an adjective you have to interpret.

### The signal, and the controls that make it readable

`python3 talkverify.py` (now in the repo -- it is the only check that measures
what the camera's speaker really does), three phases in one sitting:

* **A (18 s)** a normal voice take, trimmed
  to its loudest 7 s, peak-normalised and becomes the test clip.  It also gives the take's natural pitch.
* **B (8 s silence)** mic moved to the camera's speaker.
* **C (14 s)** the real path plays **1.5 s of 1 kHz tone, 0.8 s of silence,
  then the voice from A**, paced exactly like the browser's POSTs, while the
  mic records.  Then everything is measured offline with stdlib only.

Two controls before trusting any of it:

| control | result |
|---|---|
| 2 s recording of the quiet room, nothing played | peak 100 ms RMS **8.3**, `-72 dBFS`, no tone in any band |
| our own encoder's output, decoded and Goertzel'd | **1000 Hz dominant at 0.126**, every other band < 0.001 |

So when a tone appeared at 2000 Hz it could not be room noise, and it could
not have come from our side: the wire content was provably 1 kHz.

### The measurement: 2x pitch and a 51 % duty cycle

| observed | value |
|---|---|
| the 1 kHz tone, at the camera | **2000 Hz dominant** (96.7 % of band energy) |
| tone duty, 2 ms windows, fed one packet per 120 ms | **51 %**, on-runs 50 ms, off-runs 20-90 ms |
| 5.6 s of true silence right after the tone | `-72 dBFS` -- the camera had run dry |
| the speech that followed | sparse bursts, ~1-3 % duty |

Two independent things point the same way: the pitch comes back an octave up,
*and* a 1x feed leaves the camera silent half the time.  A camera that plays
each 160-sample (8 kHz, 20 ms) AMR frame in 10 ms explains both at once -- it
runs a 16 kHz DAC over 8 kHz frames, which is exactly what §13c's opening frame
asks for (it declares **16000 Hz / 320 samples**).  It consumes **2.0 declared
seconds per real second**.

That also retires Phase 20's rule.  The old reading ("the camera renders
declared time at *half* rate, so feed 2x-*faster* content and pace one packet
per 240 ms") predicts a *lower* pitch and a ~100 % duty at a 1x feed.  What was
actually measured is the opposite of both.  Phase 20's ear evidence was taken
with the 33 % delivery bug of Phase 21 still in the code, so the camera was
being starved to a third of a feed; nothing measured then about *rate* is
trustworthy.

### The fix, and both halves are needed

`wyze-cam-stream/server.py`:

| constant | before | after | why |
|---|---|---|---|
| encoder `asetrate` | 16000 (a no-op) | **8000** (`TALK_CONTENT_HZ`) | relabel the 16 kHz mic as 8 kHz: same samples, 2x the declared duration, half the pitch -- the camera's 2x puts it back |
| `TALK_PKT_REAL_SECONDS` | 0.120 | **0.060** | one 120 ms packet every 60 ms = the 2.0 declared/real the camera eats |
| `TALK_PREBUFFER` | 0.36 s | 0.18 s | still 3 packets, now shorter ones |

`TALK_CAMERA_PLAYOUT = 0.5` (real seconds the camera spends per declared
second) drives all three, so the numbers cannot drift apart again.  Stretching
without the faster feed only fixes the pitch and leaves the holes; feeding
faster without stretching only removes the holes and leaves a chipmunk.

Local, silent (`talkreadertest.py`, real encoder + real reader): **99 % of the
input reaches the wire, 8.16 s declared from 4.13 s real = 2.01
declared/real**, queue depth max 6 frames.  Before the change the same harness
was 98 %.

### On hardware: exactly the pitch we asked for

Same sitting, with the fix in place:

| observed | before | after |
|---|---|---|
| the beep (shipped as 500 Hz content) | 2000 Hz | **990-1000 Hz**, i.e. 2x of the 500 Hz we sent |
| beep duty, 2/5/10 ms windows | 51 % | **90-100 %** -- continuous 3.03 -> 4.30 s, **no interior hole**; the only "off-run" was the beep's own tail |
| user's verdict | "slow, and chopped" | **"Beep: steady, no cutting" / "Voice: normal speed/pitch"** |

The ear and the instrument now agree, which is the first time in three phases.

### What is left

* **~200 ms at the very start of a talk session is lost** (the beep started
  200 ms late relative to the packets we sent).  That is the camera's playout
  initialising, not our pacing; the pre-buffer covers packet jitter, not the
  camera's own start-up.
* **The browser live-mic path has not been re-tested end to end.**  It POSTs
  the same 1024-byte/32 ms 16 kHz PCM as the file path and shares every line of
  server code from `talk_feed()` onward, but only the file-driven version has been heard so far.
* **The app's own talk audio is still a puzzle, and now not a blocking one.**
  Its captured content measures F0 ~68-82 Hz (autocorrelation median 68.5,
  harmonic spacing 78-82) against this user's natural **105-111 Hz**, and
  Phase 20's cepstral estimate of the same capture was 86-145 Hz.  Three
  estimators, three answers -- not evidence of a clean 2x.  It does not matter
  for us any more: we invert the camera's playout directly and measure the
  result, so we do not need to know what the app does.  A cheap human check is
  still worth having: ask what the *app's* talk sounds like from these cameras.
  Under this phase's model it should be as starved as our 1x feed was, because
  the app ships ~1.0 declared/real (Phase 21) while the camera eats 2.0.

### Notes for next time

Play a **tone**, not speech, when the question is about rate: a beep's pitch is
a number you can compare against a control, while "sounds slow" fits both a
starved camera and a stretched voice.  Record the camera's speaker with the
Mac's external mic (`ffmpeg -f avfoundation -i ":1"`) and always take a
silent-room control first -- with it, one 90-second sitting settled what two
phases of adjectives could not.


## Phase 23 -- live browser talk: the page was JSON-encoding the audio

Phase 22's file-driven talk was clean and verified by ear; the browser path was
not, and had never been. The two paths differ in exactly one place -- who POSTs
the PCM -- so the fault had to sit on the page's side of that boundary. It did,
and it was one line.

### The instrument that found it

Everything below is one tab, dry (`?drytalk=1`, no camera involved):

| reading | value |
|---|---|
| what the page captured | 15,823 samples/s, 121 callbacks at 31/s, longest 512, **0 callbacks from another node** |
| what the page said it POSTed | 123,904 B in 121 POSTs (= 121 x 1024) |
| what the server counted receiving, while broken | **293,324 B/s from 1 connection** = **9.2x** the 32,000 B/s a 16 kHz microphone sends |
| idle junk (`TALK_JUNK`) | **0 B/s** |

The last row is the one that mattered. A stray tab or an orphaned capture node
would have appeared as junk, and there was none -- so this was not eight leaked
microphones, it was one honest page whose bytes were nevertheless nine times too
long. That left the bytes themselves.

### The bug

`talkReq()` JSON-encoded every body it was handed. `TALK.pending.slice()` is a
`Uint8Array`, and `JSON.stringify()` of a `Uint8Array` is not a list, it is an
**object of indices**:

    {"0":42,"1":42,...,"1023":7}

about **nine characters per audio byte**, and not PCM at all. The camera was
being fed braces, quote marks and decimal digits. One fact explains every
symptom at once: the continuous noise, the unintelligible voice, "it makes
sound even when I am not speaking", and the 9.2x arrival rate. It is also
exactly the difference between the two paths, because the file-driven test
posted raw bytes from Python. `json.dumps` of a real 1024-byte chunk came to
**14,380 bytes** (14x), which brackets the measured 9.2x across the range of
sample values.

### The fix, and the guard that keeps it fixed

* Binary bodies now go as `application/octet-stream`; only JSON objects are
  stringified.
* The server **refuses** any body that is entirely printable ASCII with
  `HTTP 400 "the page is sending text, not PCM samples"`, logged once. PCM16
  uses all 256 byte values and silence is zeros, so an all-printable body is
  never audio -- a stale page can only ever put a message on the button, never
  text into a speaker.

### Verified at both ends, live

    page: 43,008 B in 42 POSTs      server: 43,008 B in 42 POSTs at 32,329 B/s
    page: 35,840 B in 35 POSTs      server: 35,840 B in 35 POSTs at 32,095 B/s
    102 AMR frames -> 17 packets, 2040 ms declared, 1 connection, junk 0

By ear: **"It worked - it's my voice."**

### Kept, but not the cause

The race the session stamp fixes is real and worth keeping: `talkStart()` sets
`TALK.tid` only after `getUserMedia` and the start POST resolve, so a tap inside
that ~100-300 ms window made `talkStop()` a no-op *and* let a second capture
node start, whose microphone then stayed open. Slots are now claimed
synchronously, sessions are stamped, and a stale node's callbacks are inert.
It is a real leak -- but it was not the 9.2x, and the 0 B/s junk reading is what
ruled it out.

### The lesson

Both halves of the evidence were needed, and neither alone would have found it.
The page's *claim* (15.8 kHz, one node) and the server's *count* (293 kB/s)
disagreed 9x, and the honest conclusion was neither "the page is lying" nor "the
server is miscounting" but "the same bytes are longer than they should be".
Counting one quantity at both ends of the same session is what made a one-line
bug visible.


## Phase 24 -- the camera's sound was 2.4 s late, and it was the browser

The symptom, right after Phase 23: our voice reaches the camera almost
instantly, but the sound *from* the camera takes seconds to reach the stream. They are two different mechanisms, and only one of them is ours.

| direction | who owns it | measured |
|---|---|---|
| us -> camera | our own paced push (`TALK_PREBUFFER` 0.18 s) | ~0.2 s |
| camera -> server | `_abuf` -> `audio_chunks`, drained in a tight loop, starting at the **tail** and never the backlog | newest chunk is **24-50 ms** old (`audio.age`) |
| **server -> speaker** | the page's `<audio>` element | **2.47 s** |

`/audio/<tid>.wav` is a streaming WAV (RIFF with 0xFFFFFFFF sizes), and an
`<audio>` element pointed at a live stream is a *media player*: it fills a
read-ahead buffer so that a stall cannot make it stutter, and it cannot be told
"stay 150 ms behind and no more". `buffered.end() - currentTime` is exactly that
buffer, and having the page report it on the poll it already makes produced the
2.47 s -- while the same page measured the video at **7-21 ms** publish to
painted. The delay was neither the camera nor Python.

### The replacement

* `GET /pcm/<tid>` -- the same 16 kHz mono PCM16, no WAV header.
* The page reads it with `fetch()` + `body.getReader()` and schedules 16 kHz
  `AudioBuffer`s on an `AudioContext` at `SND_LEAD` = 0.15 s ahead. The node
  resamples to the device rate, so the page never has to know it.
* `SND_MAX_AHEAD` = 0.6 s is the inbound twin of the video path's `MAX_LAG`:
  past it we are replaying history rather than listening, so the queue is
  dropped and the timeline jumps back to live.
* The gain slider is now a `GainNode` -- instant, in float, and no longer
  restarts the stream.

### Measured result

| | before | after |
|---|---|---|
| behind live (the page's own report) | 2.47 s | **0.23-0.30 s** |
| dropped / resyncs | -- | **0** |
| `/pcm` delivery | -- | 32,133 B/s = real time, first bytes in 50 ms, 8.02 s of audio per 8.00 s |

By ear: **"Delay is gone - it's in sync."** The zero drops is the part that
matters -- the latency is not being bought with glitches.

### What the residual 0.25 s is, and what would go below it

`behind` is `SND_LEAD` plus one delivery unit. The camera's audio reaches
`_abuf` and is flushed once per 0.05 s worker pump, about 20 chunks/s, so
0.15 + 0.05..0.10 is what is observable. Lowering `SND_LEAD` alone cannot go
below that floor; the delivery unit would have to shrink, which means a faster
worker loop, not a smaller lead.

### A trap worth recording

A `/pcm` client read 4,096 B in **14 s** (290 B/s) and the obvious conclusion --
"the audio path is 100x slow" -- was wrong. The worker log showed
`definition=2 gave no video`, then `stream stalled`, then a fresh `CALLING`: the
camera had restarted mid-read, so the counters belonged to a brand-new worker.
Read the worker's log before believing a throughput number, and never conclude
anything from one bad run.

### Still open

* **Individual cameras stop delivering audio while their video continues.**
  Camera 4 was seen at `audio.age` **33.999 s** and camera 2 at 3.593 s with a
  full 200-chunk queue, both streaming at ~20 fps. The worker is alive, so this
  is the camera's audio, not our reader thread.
* The ~200 ms lost at the start of a talk session (Phase 22) is still there.
* `getUserMedia` still asks for `echoCancellation` / `noiseSuppression` /
  `autoGainControl`; those are now the prime suspects for real-talk *quality*
  (they cannot explain anything measured in Phases 23 or 24).


## Phase 25 -- what night vision actually changes in the feed

The question: the cameras switch to night vision on their own -- does the video feed look
the same when it does?  Night vision is three
things stacked, and only the last is about the feed:

1. **the control** -- `night-shot` / `night-shot-state` / `infrared-mode`
   ("infrared night vision LEDs"), a **cloud thing-model property**
   (`assets/get_capabilities_mock_response_api.json`), consistent with Phase 19's
   finding that the camera's controls have no LAN path.  In Auto the camera
   also drives it from its own ambient light sensor, so this is not ours to
   command and not ours to see coming;
2. **the picture** -- the IR-cut filter slides out and the IR LEDs come on, so
   the sensor sees infrared and the firmware goes monochrome;
3. **the feed** -- H.264 in the profile *we* asked for, the frame rate, and what
   the encoder spends on the new picture.

### The instrument

`nightprobe.py` (new, silent, safe to run while the page streams): it reads the
server's own `/snapshot/<tid>.jpg` -- the newest decoded frame, which the server
keeps beside the viewer deque exactly so a still cannot steal a frame from a
live viewer -- and decodes it with ffmpeg at 64x36 to get two numbers:

* **chroma** decides day vs night.  IR-cut out plus monochrome processing
  collapses colour, so mean chroma falls to ~0.  Brightness does **not** decide
  it, and the measurement shows why: the IR LEDs made the night frame *brighter*
  than the day frame.
* **JPEG bytes/frame** is what the encoder is spending, which is the closest
  thing to "is the feed the same" that can be read off the wire.

### The measurement (camera 1, lights switched off and back on)

| | day (70 samples) | night (34) | change |
|---|---|---|---|
| colour (mean chroma) | 35.0 | **2.9** | **-92 %** -- monochrome |
| brightness (mean luma) | 119.5 | 151.1 | **+26 %** -- the IR LEDs light the room |
| JPEG bytes/frame (median) | 84,693 | **67,099** | **-21 %** -- no chroma left to encode |
| **frame rate** | 20.0 | **15.1** | **-24 %** |

Controlled, not assumed: over the same window cameras 4, 3 and 2 sat in day mode
at **20.0 fps** each, so the frame-rate drop belongs to camera 1's night mode and
not to load from the probe.  Camera 1 returned to day mode at t=170 s and back to
21.6 fps with it.

The switch is not instant: the first night frame is **blown out (luma 254)** and
auto-exposure hunts for roughly **8-9 s** (109 -> 168 -> 54 -> 142) before it
settles.  Judged by eye from the saved JPEG, the settled night picture is
genuinely good -- crisp monochrome, IR-lit, no visible noise.

### What this does and does not settle

* **Does settle**: the transport does not change.  Same session, same conv, same
  codec, same AvStreamCtl profile, no renegotiation -- the camera switches
  internally and our side never sees a protocol event.
* **Does not settle**: the camera's **raw** resolution.  The probe sees
  `1280x720` in both states, but that is *ours*: `_stream` scales with `-vf
  scale=WYZE_WIDTH:-2` and `WYZE_WIDTH` defaults to **1280**.  A camera-side
  change of the H.264 geometry would be invisible here (though visible to
  ffmpeg).  `WYZE_WIDTH=0` would serve the camera's native size, and an SPS
  fingerprint is the clean way to check it properly.
* **Why it would not matter anyway**: the page sizes its canvas from the decoded
  bitmap (`cv.width = bmp.width`), ffmpeg is size-agnostic, and the canvas is
  repainted per frame -- so a resolution change anywhere in this chain is
  transparent, not a breakage.

So the answer is: **yes for the feed's shape, no for its
content.**  Nothing about the stream's structure changes, and nothing in our
viewer needs to; but the picture goes monochrome and brighter, the encoder
spends ~21 % less per frame, and the camera itself drops to about 15 fps.

### Notes for next time

Put **`nightprobe.py`** at the top of the tool list for anything about picture
quality: it is silent, it never touches a camera, it is safe beside a live page,
and `chroma`/`luma`/`jpeg bytes` are three numbers that make "is the image
worse?" answerable.  A **probe every 2 s is cheap** (one snapshot + one ffmpeg
at 64x36) -- arming one *before* changing anything is what
caught the transition and the 8 s of auto-exposure hunting, which a
before/after pair would have missed entirely.
