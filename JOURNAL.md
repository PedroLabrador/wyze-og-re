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

---

## Open questions still unanswered

- The type-`0x04` AV payload cipher and key derivation (the current blocker).
- Fragment reassembly (MTU 1032) and the zlib layer the logcat mentions.
- H.264/H.265 codec framing and extraction.
- Discovery-reply checksum rule (sidestepped by using identical clones).
- Auth to the camera (per-device `accessToken` vs LAN password).
- POST `Signature2` rule.
- RC5 mode 3 (unread, @0x2b500).
- cam4 (.117) has no captured frames, so it is always skipped.

## Rotation reminder

`SECRETS.md` holds the OAuth `client_id` / `client_secret` and the checklist.
Delete the plaintext token files (`/tmp/wyze_token.json`, `/tmp/wyze_live.txt`,
`/tmp/wyze_log.txt`) and revoke the token when finished.
