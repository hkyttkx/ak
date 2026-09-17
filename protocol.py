#!/usr/bin/env python3
"""Wire codecs for the two Stocks business routes.

``route=a`` is kept for compatibility with the earlier startup exchange.
``route=k`` is the card-activation protocol used by the visible license dialog.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from Crypto.Cipher import AES


IV = b"r/9^Ud]Dc7c%N;W@"
BLOCK_SIZE = 16

ROUTE_A = "//4.1/index.php?__route=a"
ROUTE_A_ALIASES = frozenset((ROUTE_A, "/4.1/index.php?__route=a"))
ROUTE_K = "/4.1/index.php?__route=k"
ROUTE_K_ALIASES = frozenset((ROUTE_K, "//4.1/index.php?__route=k"))

DEFAULT_ROUTE = ROUTE_A
DEFAULT_HOST_HEADER = "app.ioslan.cn"
DEFAULT_USER_AGENT = "LAN/IOS26.0"

ROUTE_K_USER_AGENT = "LANgege/1.0"
ROUTE_K_RC4_KEY = b"RC4key158"
ROUTE_K_AES_PREFIX = "9aG555uu5ZCI5L2c5Yqg6Kej5a+GcXNBGTg3ODIwODYw"
ROUTE_K_REQUEST_SIGN_PREFIX = "158KEY158"
ROUTE_K_RESPONSE_SIGN_PREFIX = "2449cff45b220e03"
ROUTE_K_REQUEST_WIRE_LENGTH = 560
ROUTE_K_MISSING_RESPONSE_WIRE_LENGTH = 256

# route=a response-seed construction recovered at the 0x1011c3878 callsite.
# The app builds this exact byte stream before entering its flattened MD5 VM:
#
#   SALT || decimal(minute_bucket) || UDID || "KEY158"
#
# ``SALT`` is 33 bytes (it is not a printable string).  The response path
# tries a minute window, with the previous minute bucket as its first
# candidate.  Keeping the bucket operation explicit makes the server work for
# arbitrary device identifiers instead of relying on a per-device lookup.
ROUTE_A_RESPONSE_SEED_SALT = bytes.fromhex(
    "23402164355957265e402167334f282a"
    "2655692129445d405321c3a5e28891c593"
)
ROUTE_A_RESPONSE_SEED_SUFFIX = "KEY158"
ROUTE_A_RESPONSE_SEED_BUCKET_OFFSET_MINUTES = -1


@dataclass(frozen=True)
class Profile:
    """Legacy route=a fixed profile."""

    fixed_epoch: int
    request_seed: str
    response_seed: str
    expected_appid: str
    expected_udid: str
    expected_h: str
    heartbeat: int
    marker_key: str
    marker_value: str
    payload_key: str
    payload_value: str
    haxi: str
    dynamic_key: str
    dynamic_value: str

    @classmethod
    def load(cls, path: str | Path) -> "Profile":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**raw["profile"])


@dataclass(frozen=True)
class RouteKSession:
    request: dict[str, Any]
    request_time: int
    expiry_bucket: int
    aes_seed: str
    aes_key: bytes
    sign_seed: str
    sign_clock_delta: int = 0

    @property
    def expected_request_sign(self) -> str:
        material = (
            ROUTE_K_REQUEST_SIGN_PREFIX
            + self.sign_seed
            + str(self.request["appid"])
            + str(self.request["udid"])
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @property
    def response_sign(self) -> str:
        material = ROUTE_K_RESPONSE_SIGN_PREFIX + self.sign_seed + str(self.request["udid"])
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


def validate_seed(seed: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{32}", seed):
        raise ValueError("seed must be 32 lowercase hexadecimal characters")
    return seed.encode("ascii")


def derive_key(seed: str) -> bytes:
    """Legacy route=a key derivation, also shared by route=k."""
    return hashlib.sha256(validate_seed(seed)).hexdigest()[:32].encode("ascii")


def pad(data: bytes) -> bytes:
    count = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([count]) * count


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("plaintext is not block aligned")
    count = data[-1]
    if not 1 <= count <= BLOCK_SIZE or data[-count:] != bytes([count]) * count:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-count]


def aes_encrypt_key(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    return AES.new(key, AES.MODE_CBC, IV).encrypt(pad(plaintext))


def aes_decrypt_key(key: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("ciphertext must be a non-empty multiple of 16")
    return unpad(AES.new(key, AES.MODE_CBC, IV).decrypt(ciphertext))


def encrypt(seed: str, plaintext: bytes) -> bytes:
    return aes_encrypt_key(derive_key(seed), plaintext)


def decrypt(seed: str, ciphertext: bytes) -> bytes:
    return aes_decrypt_key(derive_key(seed), ciphertext)


def compact_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def request_sign(appid: str, timestamp: str | int) -> str:
    """Legacy route=a request signature."""
    return hashlib.md5(f"{appid}{timestamp}langegeqq1587820860".encode("utf-8")).hexdigest()


def response_validation(plaintext: bytes) -> str:
    return hashlib.md5(plaintext).hexdigest()


def route_a_response_seed_bucket(
    request_time: int | str,
    *,
    offset_minutes: int = ROUTE_A_RESPONSE_SEED_BUCKET_OFFSET_MINUTES,
) -> int:
    """Return the minute candidate used by the first response decrypt try.

    Dynamic traces show candidates at ``floor(t/60)*60 - 60``, then each
    subsequent minute.  The fake server deliberately emits the first one so
    a client accepts the response without a retry.
    """
    timestamp = int(request_time)
    return (timestamp // 60) * 60 + int(offset_minutes) * 60


def route_a_response_seed_material(
    udid: str,
    request_time: int | str,
    *,
    offset_minutes: int = ROUTE_A_RESPONSE_SEED_BUCKET_OFFSET_MINUTES,
) -> tuple[int, bytes]:
    """Build the exact pre-MD5 material observed in the live VM."""
    if not isinstance(udid, str) or not udid:
        raise ValueError("udid must be a non-empty string")
    bucket = route_a_response_seed_bucket(request_time, offset_minutes=offset_minutes)
    material = (
        ROUTE_A_RESPONSE_SEED_SALT
        + f"{bucket}{udid}{ROUTE_A_RESPONSE_SEED_SUFFIX}".encode("utf-8")
    )
    return bucket, material


def route_a_response_seed(
    udid: str,
    request_time: int | str,
    *,
    offset_minutes: int = ROUTE_A_RESPONSE_SEED_BUCKET_OFFSET_MINUTES,
) -> str:
    """Derive the 32-character lowercase route=a response seed."""
    _bucket, material = route_a_response_seed_material(
        udid, request_time, offset_minutes=offset_minutes
    )
    return hashlib.md5(material).hexdigest()


def request_object(profile: Profile, token: str) -> dict[str, Any]:
    value: dict[str, Any] = {
        "time": str(profile.fixed_epoch),
        "appid": profile.expected_appid,
        "udid": profile.expected_udid,
        "H": profile.expected_h,
        "sing": "",
        "token": token,
    }
    value["sing"] = request_sign(value["appid"], value["time"])
    return value


def response_object(profile: Profile, request: dict[str, Any]) -> dict[str, Any]:
    return {
        "cnm": int(request["time"]) + 1,
        profile.marker_key: profile.marker_value,
        profile.payload_key: profile.payload_value,
        "haxi": profile.haxi,
        "xintiao": profile.heartbeat,
        profile.dynamic_key: profile.dynamic_value,
    }


def validate_request(
    profile: Profile,
    value: dict[str, Any],
    *,
    allow_any_udid: bool = False,
) -> list[str]:
    errors: list[str] = []
    required = ("time", "appid", "udid", "H", "sing", "token")
    for key in required:
        if key not in value:
            errors.append(f"missing:{key}")
    if errors:
        return errors
    if not re.fullmatch(r"[0-9]{10}", str(value["time"])):
        errors.append("time")
    if value["appid"] != profile.expected_appid:
        errors.append("appid")
    if not isinstance(value["udid"], str) or not value["udid"]:
        errors.append("udid")
    elif not allow_any_udid and value["udid"] != profile.expected_udid:
        errors.append("udid")
    if not isinstance(value["H"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["H"]):
        errors.append("H")
    if value["sing"] != request_sign(value["appid"], value["time"]):
        errors.append("sing")
    if not isinstance(value["token"], str) or len(value["token"]) != 35:
        errors.append("token")
    return errors


def rc4(data: bytes, key: bytes = ROUTE_K_RC4_KEY) -> bytes:
    """Small dependency-free RC4 implementation matching the app byte-for-byte."""
    if not key:
        raise ValueError("RC4 key is empty")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray(len(data))
    for index, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[index] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def routek_expiry_bucket(request_time: int | str) -> int:
    """Bucket observed in the AES key path: floor((time + 180) / 60) * 60."""
    return ((int(request_time) + 180) // 60) * 60


def routek_aes_seed_for_bucket(expiry_bucket: int | str) -> str:
    return hashlib.md5((ROUTE_K_AES_PREFIX + str(int(expiry_bucket))).encode("ascii")).hexdigest()


def routek_aes_key_for_bucket(expiry_bucket: int | str) -> bytes:
    return derive_key(routek_aes_seed_for_bucket(expiry_bucket))


def routek_sign_seed(request_time: int | str) -> str:
    """Independent signing seed: lowercase MD5(decimal request time + 180)."""
    return hashlib.md5(str(int(request_time) + 180).encode("ascii")).hexdigest()


def routek_request_sign(appid: str, udid: str, request_time: int | str) -> str:
    material = ROUTE_K_REQUEST_SIGN_PREFIX + routek_sign_seed(request_time) + appid + udid
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def routek_response_sign(udid: str, request_time: int | str) -> str:
    material = ROUTE_K_RESPONSE_SIGN_PREFIX + routek_sign_seed(request_time) + udid
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def routek_wrap(plaintext: bytes, aes_key: bytes) -> bytes:
    inner_cipher = aes_encrypt_key(aes_key, plaintext)
    inner_base64 = base64.b64encode(inner_cipher)
    outer_cipher = rc4(inner_base64)
    return outer_cipher.hex().encode("ascii")


def routek_unwrap(wire_body: bytes, aes_key: bytes) -> bytes:
    try:
        text = wire_body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("route=k body is not ASCII hex") from exc
    if len(text) % 2 or not re.fullmatch(r"[0-9a-f]+", text):
        raise ValueError("route=k body must be non-empty lowercase hexadecimal")
    try:
        inner_base64 = rc4(bytes.fromhex(text))
        inner_cipher = base64.b64decode(inner_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid route=k RC4/Base64 layer") from exc
    return aes_decrypt_key(aes_key, inner_cipher)


def routek_candidate_buckets(now: int | float | None = None, skew_minutes: int = 120) -> Iterable[int]:
    if skew_minutes < 0:
        raise ValueError("skew_minutes must be non-negative")
    center = routek_expiry_bucket(int(time.time() if now is None else now))
    yield center
    for distance in range(1, skew_minutes + 1):
        yield center - distance * 60
        yield center + distance * 60


def routek_match_request_sign(
    value: dict[str, Any], *, clock_skew_seconds: int = 5
) -> tuple[int, str] | None:
    request_time = int(value["time"])
    for distance in range(clock_skew_seconds + 1):
        deltas = (0,) if distance == 0 else (-distance, distance)
        for delta in deltas:
            seed = hashlib.md5(
                str(request_time + 180 + delta).encode("ascii")
            ).hexdigest()
            material = (
                ROUTE_K_REQUEST_SIGN_PREFIX
                + seed
                + str(value["appid"])
                + str(value["udid"])
            )
            if hashlib.sha256(material.encode("utf-8")).hexdigest() == value["sing"]:
                return delta, seed
    return None


def validate_routek_request(
    value: dict[str, Any], *, check_sign: bool = True
) -> list[str]:
    errors: list[str] = []
    for key in ("sing", "code", "udid", "appid", "time"):
        if key not in value:
            errors.append(f"missing:{key}")
    if errors:
        return errors
    if not isinstance(value["time"], str) or not re.fullmatch(r"[0-9]{10}", value["time"]):
        errors.append("time")
    if not isinstance(value["code"], str) or len(value["code"]) != 16:
        errors.append("code")
    if not isinstance(value["udid"], str) or not value["udid"]:
        errors.append("udid")
    if not isinstance(value["appid"], str) or not value["appid"]:
        errors.append("appid")
    if not isinstance(value["sing"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sing"]):
        errors.append("sing_format")
    elif check_sign and "time" not in errors and routek_match_request_sign(value) is None:
        errors.append("sing")
    return errors


def routek_decrypt_request(
    wire_body: bytes,
    *,
    now: int | float | None = None,
    skew_minutes: int = 120,
) -> RouteKSession:
    """Recover a live request by enumerating only nearby minute buckets.

    The timestamp is encrypted, so the receiver cannot select the AES key before
    decrypting.  The app's key has minute granularity; a bounded nearby-bucket
    search recovers it and the embedded timestamp then provides an exact check.
    """
    if len(wire_body) != ROUTE_K_REQUEST_WIRE_LENGTH:
        raise ValueError(
            f"route=k request wire length must be {ROUTE_K_REQUEST_WIRE_LENGTH}, got {len(wire_body)}"
        )
    last_error: Exception | None = None
    for bucket in routek_candidate_buckets(now, skew_minutes):
        seed = routek_aes_seed_for_bucket(bucket)
        key = derive_key(seed)
        try:
            plaintext = routek_unwrap(wire_body, key)
            value = json.loads(plaintext)
            if not isinstance(value, dict):
                continue
            request_time = int(value["time"])
            if routek_expiry_bucket(request_time) != bucket:
                continue
            errors = validate_routek_request(value, check_sign=False)
            if errors:
                raise ValueError("route=k request validation: " + ",".join(errors))
            sign_match = routek_match_request_sign(value)
            if sign_match is None:
                raise ValueError("route=k request validation: sing")
            sign_clock_delta, sign_seed = sign_match
            return RouteKSession(
                request=value,
                request_time=request_time,
                expiry_bucket=bucket,
                aes_seed=seed,
                aes_key=key,
                sign_seed=sign_seed,
                sign_clock_delta=sign_clock_delta,
            )
        except Exception as exc:
            last_error = exc
    detail = f": {last_error}" if last_error is not None else ""
    raise ValueError(f"no route=k AES minute bucket matched{detail}")


def routek_request_object(
    code: str,
    *,
    request_time: int,
    appid: str,
    udid: str,
) -> dict[str, str]:
    return {
        "sing": routek_request_sign(appid, udid, request_time),
        "code": code,
        "udid": udid,
        "appid": appid,
        "time": str(request_time),
    }


def routek_encrypt_request(value: dict[str, Any]) -> tuple[bytes, RouteKSession]:
    errors = validate_routek_request(value)
    if errors:
        raise ValueError("route=k request validation: " + ",".join(errors))
    request_time = int(value["time"])
    bucket = routek_expiry_bucket(request_time)
    seed = routek_aes_seed_for_bucket(bucket)
    key = derive_key(seed)
    session = RouteKSession(
        request=dict(value),
        request_time=request_time,
        expiry_bucket=bucket,
        aes_seed=seed,
        aes_key=key,
        sign_seed=routek_sign_seed(request_time),
    )
    return routek_wrap(compact_json(value), key), session


def routek_response_object(
    session: RouteKSession,
    *,
    success: bool,
    success_expiry: str = "2099-12-31 23:59:59",
    success_data: str = "qq1587820860",
) -> dict[str, Any]:
    if success:
        return {
            # The failure response captured from production intentionally leaves
            # this empty.  The success branch is different: the client derives
            # and verifies SHA256("2449cff45b220e03" + sign_seed + udid)
            # before it enables the protected kernel path.
            "sing": session.response_sign,
            # The client compares this marker after validating ``sing``.  It is
            # not a boolean success flag; ``"1"`` follows the failure alert
            # branch even when the response signature is correct.
            "data": success_data,
            "time": session.request_time + 1,
            "DQtime": success_expiry,
            "xintiao": "180",
        }
    return {
        "sing": "",
        "data": "0",
        "time": session.request_time + 1,
        "DQtime": "æ¿æ´»ç ä¸å­å¨",
        "xintiao": "180",
    }


def routek_encrypt_response(value: dict[str, Any], session: RouteKSession) -> bytes:
    return routek_wrap(compact_json(value), session.aes_key)


def routek_decrypt_response(wire_body: bytes, session: RouteKSession) -> dict[str, Any]:
    value = json.loads(routek_unwrap(wire_body, session.aes_key))
    if not isinstance(value, dict):
        raise ValueError("route=k response is not a JSON object")
    return value


def build_http_request(
    ciphertext: bytes,
    route: str = DEFAULT_ROUTE,
    *,
    user_agent: str | None = None,
) -> bytes:
    if user_agent is None:
        user_agent = ROUTE_K_USER_AGENT if route in ROUTE_K_ALIASES else DEFAULT_USER_AGENT
    head = (
        f"POST {route} HTTP/1.1\r\n"
        f"Host: {DEFAULT_HOST_HEADER}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Content-Length: {len(ciphertext)}\r\n\r\n"
    ).encode("ascii")
    return head + ciphertext
