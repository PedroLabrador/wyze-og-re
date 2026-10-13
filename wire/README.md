# Wire captures — Gwell/Kalay P2P list-server exchange

Captured **2026-10-12**. This is the ground truth that unblocked the wire protocol
(see `../wyze-cam-stream/P2P_PROTOCOL.md` §3a).

## How

1. Patch `GWApi.GWellP2PUrl` (smali, `getBaseServerUrl()` official branch) to `"|192.168.77.13"`.
2. `apktool b` → sign with `../wyze_debug.keystore` (alias `wyze`, pass `android`,
   `--ksKeyPass android`) → `adb install -r`.
3. `python3 ../cap_listsrv2.py 51701 110` listens on UDP **and** TCP 51701.
4. Restart the app; it reaches the home screen after ~45 s, then fires the list request.

## Files

| file | what |
|---|---|
| `list_request_app.hex` | the app's real `LIST_REQUEST`, 40 bytes, identical on every retransmit and across app restarts |
| `list_request_app_asc.txt` | same, with ASCII rendering |
| `list_resp_raw.hex` | the genuine server's reply from `18.118.90.161:51701`, 176 bytes |
| `list_resp_decrypted.hex` | same after RC5-32/6/8 LE decrypt (header + full payload) |
| `list_resp_decrypted.txt` | annotated dump of the decrypted response |

## Verification

`../listreq.py`'s `build_list_request()` reproduces `list_request_app.hex` **byte for byte**.
`../probe_real.py` sends these bytes to the live server and prints the response.

## Secrets note

These frames contain only the app's P2P terminal IDs, no credentials. Live OAuth tokens are
**not** stored in this repo (see `.gitignore` and `SECRETS.md`).
