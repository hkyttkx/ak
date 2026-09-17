#!/usr/bin/env python3
"""FastAPI implementation of the dynamic route=a and route=k protocols.

``route=a`` uses only the original client's dynamic next-minute seed algorithm;
there is no fixed profile or config.json dependency.  After a ``route=k``
request is decrypted and authenticated, its 16-character card code is submitted
to the local eruyi_kami ``/api/User/recharged`` endpoint.  Only a successful,
unexpired result is converted into a route=k success response.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from email.utils import formatdate
from typing import Any, AsyncIterator, Iterable, Protocol

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

try:  # Support both ``python fastapi_routek_server.py`` and package imports.
    from .protocol import (
        ROUTE_A_RESPONSE_SEED_SALT,
        ROUTE_A_RESPONSE_SEED_SUFFIX,
        ROUTE_K_REQUEST_WIRE_LENGTH,
        compact_json,
        decrypt,
        encrypt,
        request_sign,
        routek_decrypt_request,
        routek_encrypt_response,
    )
except ImportError:  # pragma: no cover - exercised when launched as a script.
    from protocol import (  # type: ignore[no-redef]
        ROUTE_A_RESPONSE_SEED_SALT,
        ROUTE_A_RESPONSE_SEED_SUFFIX,
        ROUTE_K_REQUEST_WIRE_LENGTH,
        compact_json,
        decrypt,
        encrypt,
        request_sign,
        routek_decrypt_request,
        routek_encrypt_response,
    )


LOGGER = logging.getLogger("routek_fastapi")

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 18080
DEFAULT_ERUYI_API_URL = "http://127.0.0.1/api/User/recharged"
DEFAULT_ERUYI_APP_NAME = "com.alq.sjz"
DEFAULT_ERUYI_TIMEOUT_SECONDS = 5.0
DEFAULT_ROUTE_K_SKEW_MINUTES = 120
DEFAULT_ROUTE_A_REQUEST_SKEW_MINUTES = 120
DEFAULT_SUCCESS_DATA = "qq1587820860"
DEFAULT_SUCCESS_HEARTBEAT = "86400"
DEFAULT_PERMANENT_END_TIME = 999_999_999
DEFAULT_PERMANENT_DQTIME = "2099-12-31 23:59:59"
CHINA_TIMEZONE = timezone(timedelta(hours=8), name="Asia/Shanghai")

ROUTE_A_REQUEST_WIRE_LENGTH = 256
ROUTE_A_RESPONSE_PLAIN_LENGTH = 422
ROUTE_A_RESPONSE_WIRE_LENGTH = 432
ROUTE_A_MARKER_KEY = "lan:qq1587820860"
ROUTE_A_MARKER_VALUE = "E585B0E4BA94E6|1|1"
ROUTE_A_PAYLOAD_KEY = "+W-xD="
ROUTE_A_HEARTBEAT = 43200
ROUTE_A_HAXI_KEY_PREFIX = b"M?C@x1B9"


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.getenv(name)
    value = default if raw is None or raw.strip() == "" else int(raw)
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    value = default if raw is None or raw.strip() == "" else float(raw)
    if value <= minimum:
        raise ValueError(f"{name} must be > {minimum}")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


@dataclass(frozen=True)
class Settings:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    eruyi_api_url: str = DEFAULT_ERUYI_API_URL
    eruyi_app_name: str = DEFAULT_ERUYI_APP_NAME
    eruyi_timeout_seconds: float = DEFAULT_ERUYI_TIMEOUT_SECONDS
    eruyi_verify_tls: bool = True
    routea_request_skew_minutes: int = DEFAULT_ROUTE_A_REQUEST_SKEW_MINUTES
    routek_skew_minutes: int = DEFAULT_ROUTE_K_SKEW_MINUTES
    success_data: str = DEFAULT_SUCCESS_DATA
    success_heartbeat: str = DEFAULT_SUCCESS_HEARTBEAT
    permanent_end_time: int = DEFAULT_PERMANENT_END_TIME
    permanent_dqtime: str = DEFAULT_PERMANENT_DQTIME
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(
            host=os.getenv("ROUTEK_HOST", DEFAULT_HOST).strip() or DEFAULT_HOST,
            port=_env_int("ROUTEK_PORT", DEFAULT_PORT, minimum=1),
            eruyi_api_url=(
                os.getenv("ERUYI_API_URL", DEFAULT_ERUYI_API_URL).strip()
                or DEFAULT_ERUYI_API_URL
            ),
            eruyi_app_name=(
                os.getenv("ERUYI_APP_NAME", DEFAULT_ERUYI_APP_NAME).strip()
                or DEFAULT_ERUYI_APP_NAME
            ),
            eruyi_timeout_seconds=_env_float(
                "ERUYI_TIMEOUT_SECONDS", DEFAULT_ERUYI_TIMEOUT_SECONDS
            ),
            eruyi_verify_tls=_env_bool("ERUYI_VERIFY_TLS", True),
            routea_request_skew_minutes=_env_int(
                "ROUTE_A_REQUEST_SKEW_MINUTES",
                DEFAULT_ROUTE_A_REQUEST_SKEW_MINUTES,
            ),
            routek_skew_minutes=_env_int(
                "ROUTE_K_SKEW_MINUTES", DEFAULT_ROUTE_K_SKEW_MINUTES
            ),
            success_data=(
                os.getenv("ROUTEK_SUCCESS_DATA", DEFAULT_SUCCESS_DATA).strip()
                or DEFAULT_SUCCESS_DATA
            ),
            success_heartbeat=(
                os.getenv("ROUTEK_SUCCESS_HEARTBEAT", DEFAULT_SUCCESS_HEARTBEAT).strip()
                or DEFAULT_SUCCESS_HEARTBEAT
            ),
            permanent_end_time=_env_int(
                "ERUYI_PERMANENT_END_TIME", DEFAULT_PERMANENT_END_TIME
            ),
            permanent_dqtime=(
                os.getenv("ERUYI_PERMANENT_DQTIME", DEFAULT_PERMANENT_DQTIME).strip()
                or DEFAULT_PERMANENT_DQTIME
            ),
            log_level=(os.getenv("LOG_LEVEL", "INFO").strip() or "INFO").upper(),
        )
        if not settings.success_heartbeat.isdigit():
            raise ValueError("ROUTEK_SUCCESS_HEARTBEAT must contain decimal digits")
        return settings


@dataclass(frozen=True)
class RouteARequestSession:
    request: dict[str, Any]
    plaintext: bytes
    request_seed: str
    request_seed_clock: int
    request_seed_bucket: int
    request_seed_material: bytes


def _routea_request_seed_bucket(request_time: int | str) -> int:
    timestamp = int(request_time)
    return (timestamp // 60) * 60 + 60


def _routea_request_seed_material(bucket: int | str) -> bytes:
    return ROUTE_A_RESPONSE_SEED_SALT + str(int(bucket)).encode("ascii")


def _routea_request_seed_for_bucket(bucket: int | str) -> str:
    return hashlib.md5(_routea_request_seed_material(bucket)).hexdigest()


def _routea_candidate_buckets(
    now: int | float | None,
    *,
    skew_minutes: int,
) -> Iterable[int]:
    center = _routea_request_seed_bucket(int(time.time() if now is None else now))
    yield center
    for distance in range(1, skew_minutes + 1):
        yield center - distance * 60
        yield center + distance * 60


def _decode_routea_candidate(
    body: bytes,
    seed: str,
) -> tuple[bytes, dict[str, Any]]:
    plaintext = decrypt(seed, body)
    value = json.loads(plaintext)
    if not isinstance(value, dict):
        raise ValueError("route=a plaintext is not a JSON object")
    errors: list[str] = []
    for key in ("time", "appid", "udid", "H", "sing", "token"):
        if key not in value:
            errors.append(f"missing:{key}")
    if errors:
        raise ValueError("route=a request validation: " + ",".join(errors))
    if not isinstance(value["time"], str) or not re.fullmatch(r"[0-9]{10}", value["time"]):
        errors.append("time")
    if not isinstance(value["appid"], str) or not value["appid"]:
        errors.append("appid")
    if not isinstance(value["udid"], str) or not value["udid"]:
        errors.append("udid")
    if not isinstance(value["H"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["H"]):
        errors.append("H")
    if (
        "time" not in errors
        and "appid" not in errors
        and value["sing"] != request_sign(value["appid"], value["time"])
    ):
        errors.append("sing")
    if not isinstance(value["token"], str) or len(value["token"]) != 35:
        errors.append("token")
    if errors:
        raise ValueError("route=a request validation: " + ",".join(errors))
    return plaintext, value


def _routea_decrypt_request(
    body: bytes,
    *,
    now: int | float | None = None,
    skew_minutes: int = DEFAULT_ROUTE_A_REQUEST_SKEW_MINUTES,
) -> RouteARequestSession:
    if skew_minutes < 0:
        raise ValueError("route=a request skew must be non-negative")
    last_error: Exception | None = None
    for bucket in _routea_candidate_buckets(now, skew_minutes=skew_minutes):
        seed = _routea_request_seed_for_bucket(bucket)
        try:
            plaintext, value = _decode_routea_candidate(body, seed)
            request_time = int(value["time"])
            if _routea_request_seed_bucket(request_time) != bucket:
                continue
            return RouteARequestSession(
                request=value,
                plaintext=plaintext,
                request_seed=seed,
                request_seed_clock=request_time,
                request_seed_bucket=bucket,
                request_seed_material=_routea_request_seed_material(bucket),
            )
        except Exception as exc:
            last_error = exc
    detail = f": {last_error}" if last_error is not None else ""
    raise ValueError(f"no dynamic route=a request seed matched{detail}")


def _rc4_xor(key: bytes, data: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key must not be empty")
    state = bytearray(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    i = j = 0
    output = bytearray(len(data))
    for offset, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def _routea_haxi(response_epoch: int | str, request_h: str) -> str:
    plaintext = str(request_h).encode("ascii")
    if len(plaintext) != 64:
        raise ValueError("route=a H must contain exactly 64 ASCII characters")
    key = ROUTE_A_HAXI_KEY_PREFIX + str(int(response_epoch)).encode("ascii")
    ciphertext = _rc4_xor(key, plaintext)
    return bytes(
        ((value << 4) & 0xF0) | (value >> 4) for value in ciphertext
    ).hex()


def _production_routea_response(
    request: dict[str, Any],
    *,
    response_epoch: int,
) -> dict[str, Any]:
    request_time = str(request["time"])
    udid = str(request["udid"])
    token = str(request["token"])
    payload_value = hmac.new(
        b"2449cff45b220e03",
        f"{udid}{request_time}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    dynamic_key = hmac.new(
        b"ios158",
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    dynamic_value = hmac.new(
        b"158ios",
        f"{token}{udid}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "cnm": response_epoch,
        ROUTE_A_MARKER_KEY: ROUTE_A_MARKER_VALUE,
        ROUTE_A_PAYLOAD_KEY: payload_value,
        "haxi": _routea_haxi(response_epoch, str(request["H"])),
        "xintiao": ROUTE_A_HEARTBEAT,
        dynamic_key: dynamic_value,
    }


def _routea_response_seed(
    session: RouteARequestSession,
) -> str:
    udid = str(session.request["udid"])
    bucket = session.request_seed_bucket
    material = (
        ROUTE_A_RESPONSE_SEED_SALT
        + f"{bucket}{udid}{ROUTE_A_RESPONSE_SEED_SUFFIX}".encode("utf-8")
    )
    return hashlib.md5(material).hexdigest()


@dataclass(frozen=True)
class KamiValidation:
    active: bool
    reason: str
    end_time: int | None = None
    dq_time: str | None = None
    permanent: bool = False
    upstream_code: str = ""


class KamiValidator(Protocol):
    async def validate(
        self,
        code: str,
        device_id: str,
        *,
        now: int | None = None,
    ) -> KamiValidation: ...


def _parse_epoch(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _format_dqtime(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=CHINA_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")


class EruyiKamiClient:
    """Client for eruyi_kami's local card recharge/validation API."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        settings: Settings,
    ) -> None:
        self._http = http_client
        self._settings = settings

    async def validate(
        self,
        code: str,
        device_id: str,
        *,
        now: int | None = None,
    ) -> KamiValidation:
        now_epoch = int(time.time() if now is None else now)
        app_name = self._settings.eruyi_app_name
        api_data = {
            "username": device_id,
            "device_id": device_id,
            "machine_code": device_id,
            "recharge_card": code,
            "kami": code,
            "card": code,
            "app_name": app_name,
            "app": app_name,
        }
        form_data = {
            "data": json.dumps(
                api_data,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            # These duplicates keep the request compatible with local wrappers
            # that read top-level POST fields instead of the JSON in ``data``.
            "recharge_card": code,
            "kami": code,
            "device_id": device_id,
            "app_name": app_name,
        }

        try:
            response = await self._http.post(
                self._settings.eruyi_api_url,
                data=form_data,
                headers={
                    "Accept": "application/json",
                    "X-App-Name": app_name,
                },
            )
        except httpx.HTTPError as exc:
            return KamiValidation(False, f"upstream_request_error:{type(exc).__name__}")

        if response.status_code < 200 or response.status_code >= 300:
            return KamiValidation(False, f"upstream_http_{response.status_code}")

        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError):
            return KamiValidation(False, "upstream_invalid_json")
        if not isinstance(payload, dict):
            return KamiValidation(False, "upstream_json_not_object")

        # Native /api/User/recharged response:
        # {"code":"306","data":{"endtime":178...}}
        upstream_code = str(payload.get("code", ""))
        data = payload.get("data")
        if upstream_code == "306" and isinstance(data, dict):
            return self._from_end_time(
                data.get("endtime"),
                now_epoch,
                upstream_code=upstream_code,
            )

        # Also accept a direct HTTP wrapper around eruyi_kami_query().  This is
        # useful if the local deployment exposes the project's richer query
        # result instead of the recharged controller.
        query_payload: dict[str, Any] | None = payload
        if isinstance(data, dict) and isinstance(data.get("card"), dict):
            query_payload = data
        card = query_payload.get("card") if query_payload is not None else None
        if isinstance(card, dict):
            exists = bool(card.get("exists"))
            active = bool(card.get("active"))
            expired = bool(card.get("expired"))
            permanent = bool(card.get("is_permanent"))
            end_time = _parse_epoch(
                card.get("card_end_time", card.get("end_time"))
            )
            if not exists:
                return KamiValidation(False, "card_not_found", upstream_code=upstream_code)
            if expired or not active:
                return KamiValidation(
                    False,
                    "card_expired_or_inactive",
                    end_time=end_time,
                    upstream_code=upstream_code,
                )
            if permanent:
                return KamiValidation(
                    True,
                    "permanent",
                    end_time=end_time,
                    dq_time=self._settings.permanent_dqtime,
                    permanent=True,
                    upstream_code=upstream_code,
                )
            return self._from_end_time(
                end_time,
                now_epoch,
                upstream_code=upstream_code,
            )

        return KamiValidation(
            False,
            "upstream_rejected",
            upstream_code=upstream_code,
        )

    def _from_end_time(
        self,
        raw_end_time: Any,
        now_epoch: int,
        *,
        upstream_code: str,
    ) -> KamiValidation:
        end_time = _parse_epoch(raw_end_time)
        if end_time is None or end_time <= 0:
            return KamiValidation(
                False,
                "invalid_end_time",
                end_time=end_time,
                upstream_code=upstream_code,
            )
        if end_time == self._settings.permanent_end_time:
            return KamiValidation(
                True,
                "permanent",
                end_time=end_time,
                dq_time=self._settings.permanent_dqtime,
                permanent=True,
                upstream_code=upstream_code,
            )
        if end_time <= now_epoch:
            return KamiValidation(
                False,
                "expired",
                end_time=end_time,
                upstream_code=upstream_code,
            )
        try:
            dq_time = _format_dqtime(end_time)
        except (OverflowError, OSError, ValueError):
            return KamiValidation(
                False,
                "invalid_end_time_range",
                end_time=end_time,
                upstream_code=upstream_code,
            )
        return KamiValidation(
            True,
            "active",
            end_time=end_time,
            dq_time=dq_time,
            upstream_code=upstream_code,
        )


def _routek_response_object(
    session: Any,
    validation: KamiValidation,
    settings: Settings,
) -> dict[str, Any]:
    if validation.active and validation.dq_time:
        return {
            "sing": session.response_sign,
            "data": settings.success_data,
            "time": session.request_time + 1,
            "DQtime": validation.dq_time,
            "xintiao": settings.success_heartbeat,
        }
    return {
        "sing": "",
        "data": "0",
        "time": session.request_time + 1,
        "DQtime": "æ¿æ´»ç ä¸å­å¨",
        "xintiao": "180",
    }


def _card_fingerprint(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()[:12]


async def _single_chunk(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _read_bounded_body(
    request: Request,
    *,
    expected_length: int,
    route_name: str,
) -> bytes:
    """Read at most one protocol request without buffering an arbitrary body."""
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > expected_length:
            raise ValueError(
                f"route={route_name} request wire length must be "
                f"{expected_length}, got more than {expected_length}"
            )
    return bytes(body)


def _encrypted_http_response(
    ciphertext: bytes,
    *,
    epoch: int,
    request_body: bytes,
) -> StreamingResponse:
    eo_uuid = str(int.from_bytes(hashlib.sha256(request_body).digest()[:8], "big"))
    return StreamingResponse(
        _single_chunk(ciphertext),
        status_code=200,
        headers={
            "Server": "nginx",
            "Content-Type": "text/html; charset=UTF-8",
            "Vary": "Accept-Encoding",
            "Connection": "close",
            "Date": formatdate(epoch, usegmt=True),
            "EO-LOG-UUID": eo_uuid,
            "EO-Cache-Status": "MISS",
        },
    )


def create_app(
    settings: Settings | None = None,
    *,
    kami_validator: KamiValidator | None = None,
) -> FastAPI:
    resolved = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if kami_validator is not None:
            application.state.kami_validator = kami_validator
            yield
            return

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(resolved.eruyi_timeout_seconds),
            verify=resolved.eruyi_verify_tls,
            trust_env=False,
            follow_redirects=False,
        ) as http_client:
            application.state.kami_validator = EruyiKamiClient(http_client, resolved)
            yield

    application = FastAPI(
        title="route=a/k FastAPI server",
        version="1.0.0",
        lifespan=lifespan,
    )
    application.state.settings = resolved

    @application.get("/health")
    @application.get("/healthz", include_in_schema=False)
    async def health() -> dict[str, Any]:
        return {
            "ok": True,
            "service": "route-a-k-fastapi",
            "port": resolved.port,
            "routes": ["a", "k"],
            "route_a_seed_mode": "dynamic_next_minute",
            "route_a_request_skew_minutes": resolved.routea_request_skew_minutes,
            "eruyi_api_url": resolved.eruyi_api_url,
            "eruyi_app_name": resolved.eruyi_app_name,
        }

    @application.post("/4.1/index.php")
    @application.post("//4.1/index.php", include_in_schema=False)
    async def business_route(request: Request):
        route_name = request.query_params.get("__route")
        if route_name not in {"a", "k"}:
            return JSONResponse(
                status_code=404,
                content={"ok": False, "error": "route"},
            )

        if route_name == "a":
            try:
                body = await _read_bounded_body(
                    request,
                    expected_length=ROUTE_A_REQUEST_WIRE_LENGTH,
                    route_name="a",
                )
            except Exception as exc:
                return JSONResponse(
                    status_code=400,
                    content={"ok": False, "error": "cipher_length", "detail": str(exc)},
                )
            if len(body) != ROUTE_A_REQUEST_WIRE_LENGTH:
                return JSONResponse(
                    status_code=400,
                    content={"ok": False, "error": "cipher_length"},
                )

            try:
                session_a = _routea_decrypt_request(
                    body,
                    now=time.time(),
                    skew_minutes=resolved.routea_request_skew_minutes,
                )
            except Exception as exc:
                LOGGER.info(
                    "route=a request rejected peer=%s detail=%s",
                    request.client.host if request.client else "unknown",
                    exc,
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "ok": False,
                        "error": "route_a_decrypt",
                        "detail": str(exc),
                    },
                )

            try:
                response_seed = _routea_response_seed(session_a)
                response_epoch = int(time.time())
                response_obj = _production_routea_response(
                    session_a.request,
                    response_epoch=response_epoch,
                )
                response_plain = compact_json(response_obj)
                response_cipher = encrypt(response_seed, response_plain)
                if (
                    len(response_plain) != ROUTE_A_RESPONSE_PLAIN_LENGTH
                    or len(response_cipher) != ROUTE_A_RESPONSE_WIRE_LENGTH
                ):
                    raise ValueError(
                        "route=a response must be 422/432 bytes, got "
                        f"{len(response_plain)}/{len(response_cipher)}"
                    )
            except Exception:
                LOGGER.exception("route=a response generation failed")
                return JSONResponse(
                    status_code=500,
                    content={"ok": False, "error": "route_a_response"},
                )

            LOGGER.info(
                "route=a success seed_mode=dynamic_next_minute "
                "device=%s request_bytes=%d response_bytes=%d",
                hashlib.sha256(
                    str(session_a.request["udid"]).encode("utf-8")
                ).hexdigest()[:12],
                len(body),
                len(response_cipher),
            )
            return _encrypted_http_response(
                response_cipher,
                epoch=response_epoch,
                request_body=body,
            )

        try:
            body = await _read_bounded_body(
                request,
                expected_length=ROUTE_K_REQUEST_WIRE_LENGTH,
                route_name="k",
            )
            session = routek_decrypt_request(
                body,
                now=time.time(),
                skew_minutes=resolved.routek_skew_minutes,
            )
        except Exception as exc:
            LOGGER.info(
                "route=k request rejected peer=%s detail=%s",
                request.client.host if request.client else "unknown",
                exc,
            )
            return JSONResponse(
                status_code=400,
                content={
                    "ok": False,
                    "error": "route_k_decrypt",
                    "detail": str(exc),
                },
            )

        code = str(session.request["code"])
        device_id = str(session.request["udid"])
        validator: KamiValidator = request.app.state.kami_validator
        try:
            validation = await validator.validate(code, device_id)
        except Exception:
            LOGGER.exception(
                "unexpected eruyi validation failure card=%s",
                _card_fingerprint(code),
            )
            validation = KamiValidation(False, "validator_exception")

        response_obj = _routek_response_object(session, validation, resolved)
        response_cipher = routek_encrypt_response(response_obj, session)
        LOGGER.info(
            "route=k activation active=%s reason=%s card=%s device=%s "
            "end_time=%s dqtime=%s response_bytes=%d",
            validation.active,
            validation.reason,
            _card_fingerprint(code),
            hashlib.sha256(device_id.encode("utf-8")).hexdigest()[:12],
            validation.end_time,
            validation.dq_time,
            len(response_cipher),
        )
        return _encrypted_http_response(
            response_cipher,
            epoch=session.request_time + 1,
            request_body=body,
        )

    return application


app = create_app()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--eruyi-api-url")
    parser.add_argument("--eruyi-app-name")
    parser.add_argument("--route-a-request-skew-minutes", type=int)
    parser.add_argument("--route-k-skew-minutes", type=int)
    parser.add_argument("--log-level")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    settings = Settings.from_env()
    overrides: dict[str, Any] = {}
    if args.host is not None:
        overrides["host"] = args.host
    if args.port is not None:
        if args.port <= 0 or args.port > 65535:
            raise ValueError("port must be between 1 and 65535")
        overrides["port"] = args.port
    if args.eruyi_api_url is not None:
        overrides["eruyi_api_url"] = args.eruyi_api_url
    if args.eruyi_app_name is not None:
        overrides["eruyi_app_name"] = args.eruyi_app_name
    if args.route_a_request_skew_minutes is not None:
        if args.route_a_request_skew_minutes < 0:
            raise ValueError("route-a request skew minutes must be non-negative")
        overrides["routea_request_skew_minutes"] = args.route_a_request_skew_minutes
    if args.route_k_skew_minutes is not None:
        if args.route_k_skew_minutes < 0:
            raise ValueError("route-k skew minutes must be non-negative")
        overrides["routek_skew_minutes"] = args.route_k_skew_minutes
    if args.log_level is not None:
        overrides["log_level"] = args.log_level.upper()
    settings = replace(settings, **overrides)

    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        server_header=False,
        date_header=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
