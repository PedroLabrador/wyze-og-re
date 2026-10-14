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

## Rotation reminder

`SECRETS.md` holds the OAuth `client_id` / `client_secret` and the checklist.
Delete the plaintext token files (`/tmp/wyze_token.json`, `/tmp/wyze_live.txt`,
`/tmp/wyze_log.txt`) and revoke the token when finished.
