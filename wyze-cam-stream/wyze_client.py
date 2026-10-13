"""
Wyze cloud client — evidence-based reimplementation of the Hualai/Wyze app
(package com.hualai 2.50.7.487, a white-label Wyze app) auth + live-view flow.

All constants were recovered from the decompiled APK (see README.md "Evidence"):
  assets/HL_ADDR       base URLs (api.wyzecam.com/app/, kvs-service.wyzecam.com, ...)
  assets/HL_API_URL    endpoint path map (every endpoint path)
  assets/HL_API_SV     per-endpoint signing secrets (SV_*)
  smali AuthApi/AuthRepo/LoginViewModel/RemoteKvsRepo/WyzeEventPlatform/KvsAPI

HTTP note: Wyze's WAF rejects Python's TLS fingerprint (code 3005
UnauthorizedOperation) but allows curl. All HTTP is therefore routed through
the `curl` binary via subprocess (no shell injection — args are passed as a list).

Caveat: the request Signature header is computed by native code
(libwyze_olive-lib.so, symbol `hmac<MD5>`). The HMAC-MD5 implementation below is
an inference from the symbol table + the sorted-params scheme visible in
WpkWyzeExService.getSortParams(); it may need adjustment (see README).
"""

import hashlib
import hmac
import json
import subprocess
import time
import uuid

# ---------------------------------------------------------------- constants
API_BASE = "https://api.wyzecam.com/app/"
KVS_BASE = "https://kvs-service.wyzecam.com"
IOT_BASE = "https://devicemgmt-service.wyze.com"

USER_AGENT = "wyze_android_2.50.0.15"                  # AuthRepo HEADERS

SC = "000102030405060708090a0b0c0d0e0f"                 # HL_API_SV SC / V2_SC
SC_KVS = "<REDACTED>"             # HL_API_SV SC_KVS / SC_OLD

SV_LOGIN = "<REDACTED>"
SV_GET_TOKEN = "<REDACTED>"
SV_GET_DEVICE_LIST_V2 = "000102030405060708090a0b0c0d0e0f"
SV_GET_KVS_URL_LIVE = "<REDACTED>"
SV_KVS_LIVE_REPLAY_GET = "<REDACTED>"

OAUTH_TOKEN_URL = "https://oauth.wyzecam.com/oauth/token"
OAUTH_CLIENT_ID = "<REDACTED>"
OAUTH_CLIENT_SECRET = "<REDACTED>"

KVS_APP_ID = "9319141212m2ik"   # RemoteKvsRepo header "appId"

APP_NAME = "wyze"               # Center.app_name default
APP_VERSION = "2.50.7.487"      # versionName from apktool.yml

# API key is read from config.json (from your own Wyze API key).
import os
_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
try:
    with open(_CONFIG_PATH) as _f:
        _CONFIG = json.load(_f)
except Exception:  # noqa: BLE001
    _CONFIG = {}

X_API_KEY = os.environ.get("WYZE_API_KEY") or _CONFIG.get("api_key", "")
OAUTH_CLIENT_ID = (os.environ.get("WYZE_OAUTH_CLIENT_ID")
                   or _CONFIG.get("oauth_client_id", OAUTH_CLIENT_ID))


def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def request_id() -> str:
    """WpkWyzeExService.packageHeader: requestid = MD5(MD5(currentTimeMillis))."""
    return md5(md5(str(int(time.time() * 1000))))


def sorted_params(params: dict) -> str:
    """WpkWyzeExService.getSortParams: nonce=<service time> added, entries
    sorted by key, joined as 'k=v&k=v' (trailing & stripped)."""
    items = dict(params)
    items["nonce"] = str(int(time.time() * 1000))
    return "&".join(f"{k}={items[k]}" for k in sorted(items))


def sign(appid: str, params: dict) -> str:
    """WpkSecurityUtil.getSignature(appid, sortedParams) -> 'Signature' header.

    NATIVE implementation lives in libwyze_olive-lib.so (hmac<MD5> symbol).
    This HMAC-MD5 form is the evidence-based inference — see README caveats.
    """
    return hmac.new(appid.encode(), sorted_params(params).encode(),
                    hashlib.md5).hexdigest()


def old_signature(appid: str, params: dict) -> str:
    """getOldSignature -> 'Signature2' header (same scheme family)."""
    return sign(appid, params)  # inference; adjust if API rejects


# ---------------------------------------------------------------- curl HTTP
def _curl(method: str, url: str, headers: dict, body: dict | None = None,
          params: dict | None = None, timeout: int = 30) -> dict:
    """HTTP via the curl binary (Wyze's WAF blocks Python's TLS fingerprint).
    Returns the parsed JSON response. Raises RuntimeError on HTTP errors."""
    cmd = ["curl", "-s", "--http1.1", "-X", method, url,
           "--max-time", str(timeout),
           "-H", "Accept: */*",
           "-H", "Accept-Encoding: identity",
           "-H", "Connection: close"]
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if params:
        from urllib.parse import urlencode
        sep = "&" if "?" in url else "?"
        cmd[-1] = url + sep + urlencode(params)
    if body is not None:
        cmd += ["-H", "Content-Type: application/json",
                "--data-binary", json.dumps(body)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    if result.returncode != 0:
        raise RuntimeError(f"curl failed ({result.returncode}): {result.stderr[:200]}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"non-JSON response: {result.stdout[:200]}")


# ---------------------------------------------------------------- client
class WyzeClient:
    def __init__(self, phone_id: str | None = None, app_version: str = APP_VERSION):
        self.phone_id = phone_id or str(uuid.uuid4())
        self.app_version = app_version
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.user_id: str | None = None
        self.email: str | None = None
        self._mfa_state: dict | None = None

    # ---- headers -------------------------------------------------------
    def _base_headers(self) -> dict:
        return {
            "X-API-Key": X_API_KEY,
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "Phone-Id": self.phone_id,
        }

    def _api_head(self, access_token: str | None) -> dict:
        """WpkWyzeExService.packageHeader — header set for signed API calls."""
        tok = access_token if access_token is not None else (self.access_token or "")
        head = {
            "appid": SC,
            "access_token": tok,
            "appinfo": f"{APP_NAME}_android_{self.app_version}",
            "app_version": f"android_{self.app_version}",
            "phoneid": self.phone_id,
            "requestid": request_id(),
        }
        head["Signature"] = sign(SC, head)
        head["Signature2"] = old_signature(SC, head)
        return head

    # ---- auth ----------------------------------------------------------
    def login(self, email: str, password: str) -> dict:
        """Old-style login: POST api.wyzecam.com/app/user/login
        (CloudApi.userLogin -> CloudProtocol.userLogin: composeHead(SV_LOGIN)
        + {user_name, password}). Password is MD5-hashed (same as v2 path).
        Response {ts, code, msg, data}; code "1000"/"1" = success.
        """
        body = self._compose_head(SV_LOGIN)
        body.pop("app_ver", None)  # WAF rejects app_ver on the login endpoint (3005)
        body["user_name"] = email
        body["password"] = md5(password)
        data = _curl("POST", API_BASE + "user/login", self._base_headers(), body=body)
        payload = data.get("data") or {}

        # MFA required
        if payload.get("mfa_options") or payload.get("mfa_details"):
            self._mfa_state = payload
            return {"mfa_required": True, "mfa_options": payload.get("mfa_options"),
                    "mfa_details": payload.get("mfa_details")}

        if str(data.get("code")) not in ("1000", "1"):
            raise RuntimeError(f"login failed: code={data.get('code')} msg={data.get('msg')}")
        self.access_token = payload.get("access_token")
        self.refresh_token = payload.get("refresh_token")
        self.user_id = payload.get("user_id")
        self.email = email
        return payload

    # ---- 2FA (endpoints from HL_API_URL: /v2/2fa/verify_code/{send,check}) --
    def mfa_send_code(self) -> dict:
        """POST /v2/2fa/verify_code/send — trigger the email/SMS code."""
        return _curl("POST", API_BASE + "v2/2fa/verify_code/send",
                     self._base_headers(), body=self._mfa_state or {})

    def mfa_verify_code(self, code: str) -> dict:
        """POST /v2/2fa/verify_code/check — verify the code, get tokens."""
        body = dict(self._mfa_state or {})
        body["code"] = code
        data = _curl("POST", API_BASE + "v2/2fa/verify_code/check",
                     self._base_headers(), body=body)
        payload = data.get("data") or data
        self.access_token = payload.get("access_token")
        self.refresh_token = payload.get("refresh_token")
        self.user_id = payload.get("user_id")
        self.email = payload.get("email")
        self._mfa_state = None
        return payload

    def refresh(self) -> None:
        """URL_GET_TOKEN / oauth token exchange (HL_API_URL: URL_WYZE_REFRESH_TOKEN,
        CLIENT_ID/CLIENT_SECRET/GRANT_TYPE_TAG=refresh_token)."""
        data = _curl("POST", OAUTH_TOKEN_URL, self._base_headers(), body={
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
        })
        payload = data.get("data") or data
        if payload.get("access_token"):
            self.access_token = payload["access_token"]
            self.refresh_token = payload.get("refresh_token", self.refresh_token)

    def _compose_head(self, sv: str, extra: dict | None = None) -> dict:
        """HLApi CloudProtocol.composeHead: old-style API request body."""
        body = {
            "sc": SC,
            "sv": sv,
            "app_ver": self.app_version,
            "ts": int(time.time() * 1000),
            "access_token": self.access_token,
            "phone_id": self.phone_id,
            "app_name": APP_NAME,
        }
        if extra:
            body.update(extra)
        return body

    # ---- devices -------------------------------------------------------
    def device_list(self) -> list[dict]:
        """GET device list — v2/device/get_device_list
        (SV_GET_DEVICE_LIST_V2). Returns the device array."""
        data = _curl("POST", API_BASE + "v2/device/get_device_list",
                     self._base_headers(),
                     body=self._compose_head(SV_GET_DEVICE_LIST_V2))
        payload = data.get("data") or data
        if isinstance(payload, dict):
            for key in ("device_list", "deviceList", "devices"):
                if key in payload:
                    return payload[key]
            return [payload]
        return payload or []

    # ---- live stream (KVS) ---------------------------------------------
    def kvs_live_url(self, device_id: str, product_model: str) -> str:
        """GET {kvs-service}/app/live_replay_url  (KvsAPI.getKinesisLiveReplayUrl)

        query: device_id, product_model, start_time, nonce, resource_version=2
        (WyzeEventPlatform.getEventAlphaLiveUrl + RemoteKvsRepo headers).
        Response {code, data, message}; data is a JSON string containing play_url
        (KVSReplayUrlOutPut -> Data.play_url).
        """
        params = {
            "device_id": device_id,
            "product_model": product_model,
            "start_time": int(time.time() * 1000),
            "resource_version": 2,
        }
        head = {
            "appid": SC_KVS,
            "access_token": self.access_token,
            "appinfo": f"{APP_NAME}_android_{self.app_version}",
            "app_version": f"android_{self.app_version}",
            "phoneid": self.phone_id,
            "requestid": request_id(),
            "Authorization": self.access_token,
            "appId": KVS_APP_ID,
        }
        head["Signature"] = sign(SC_KVS, {**head, **params})
        head["Signature2"] = old_signature(SC_KVS, {**head, **params})

        data = _curl("GET", KVS_BASE + "/app/live_replay_url", head, params=params)
        if str(data.get("code")) not in ("1", "200", "0"):
            raise RuntimeError(f"live_replay_url failed: {data}")
        inner = data.get("data")
        if isinstance(inner, str):
            inner = json.loads(inner)
        if isinstance(inner, dict):
            return inner.get("play_url") or inner.get("playUrl") or inner.get("url")
        if isinstance(inner, str) and inner.startswith("http"):
            return inner
        raise RuntimeError(f"no play_url in KVS response: {inner}")

    def wake_live_view(self, device_id: str) -> dict:
        """Wake the camera before live view — WpkIotCapabilityCloud.runAction:
        target(AN_RSCW/DEVICE), capability 'iot-device', function 'wakeup',
        params {"wakeup-live-view": 1}   (zh/a.smali)."""
        body = {
            "sc": SC,
            "sv": SV_GET_KVS_URL_LIVE,
            "app_ver": self.app_version,
            "ts": int(time.time() * 1000),
            "access_token": self.access_token,
            "phone_id": self.phone_id,
            "app_name": APP_NAME,
            "did": device_id,
            "target": "DEVICE",
            "capability": "iot-device",
            "function": "wakeup",
            "params": {"wakeup-live-view": 1},
        }
        return _curl("POST", IOT_BASE + "/device-management/api/action/run_action",
                     self._base_headers(), body=body)
