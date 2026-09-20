"""GRC 웹 콘솔 접근 인증 모듈입니다.

브라우저/사용자용 HTTP Basic Auth와 프로그래밍 클라이언트용
Bearer Token / X-API-Key 인증을 지원하는 미들웨어를 제공합니다.

환경 변수:
- GRC_WEB_AUTH: 인증 모드 (기본값 auto)
    - auto     : 로컬호스트(127.0.0.1, ::1) 접속은 인증 면제, 외부 접속은 인증 필요
    - required : 모든 접속에 인증 필요
    - disabled : 인증 비활성화 (로컬 개발 전용, 비권장)
- GRC_WEB_USERNAME: Basic Auth 사용자명 (기본값 admin)
- GRC_WEB_PASSWORD: Basic Auth 비밀번호.
    미설정 시 서버 시작 시점에 임시 비밀번호를 자동 생성하여 콘솔에 출력합니다.
- GRC_API_KEY: API 클라이언트용 키 (Authorization: Bearer / X-API-Key).
    미설정 시 GRC_WEB_PASSWORD와 동일한 자격증명으로 인증합니다.
"""

import base64
import binascii
import logging
import os
import secrets
from dataclasses import dataclass
from typing import Mapping, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

AUTH_MODES = ("auto", "required", "disabled")
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}
_BASIC_REALM = 'Basic realm="GRC-Agent", charset="UTF-8"'

logger = logging.getLogger("secgrc.web.auth")


@dataclass(frozen=True)
class WebAuthConfig:
    """웹 콘솔 인증 설정 (불변)."""

    mode: str = "auto"
    username: str = "admin"
    password: str = ""
    api_key: str = ""
    password_generated: bool = False


def resolve_auth_config(environ: Optional[Mapping[str, str]] = None) -> WebAuthConfig:
    """환경 변수로부터 웹 인증 설정을 해석합니다."""
    env = os.environ if environ is None else environ

    mode = (env.get("GRC_WEB_AUTH") or "auto").strip().lower()
    if mode not in AUTH_MODES:
        mode = "auto"

    username = (env.get("GRC_WEB_USERNAME") or "admin").strip() or "admin"

    password = (env.get("GRC_WEB_PASSWORD") or "").strip()
    generated = False
    if not password:
        password = secrets.token_urlsafe(18)
        generated = True

    api_key = (env.get("GRC_API_KEY") or "").strip() or password

    return WebAuthConfig(
        mode=mode,
        username=username,
        password=password,
        api_key=api_key,
        password_generated=generated,
    )


class AuthMiddleware(BaseHTTPMiddleware):
    """웹 콘솔 전체 엔드포인트에 대한 접근 인증 미들웨어.

    승인(approve), 조치 실행(execute) 등 상태 변경 엔드포인트를 포함한
    모든 라우트에 적용되며, 인증 실패 시 401과 Basic 챌린지를 반환합니다.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        config: WebAuthConfig = request.app.state.web_auth

        if config.mode == "disabled":
            return await call_next(request)

        if config.mode == "auto" and self._is_loopback(request):
            return await call_next(request)

        if self._is_authorized(request, config):
            return await call_next(request)

        client = request.client.host if request.client else "-"
        logger.warning(
            "인증 실패: client=%s method=%s path=%s",
            client,
            request.method,
            request.url.path,
        )
        return JSONResponse(
            {"detail": "Authentication required"},
            status_code=401,
            headers={"WWW-Authenticate": _BASIC_REALM},
        )

    @staticmethod
    def _is_loopback(request: Request) -> bool:
        host = request.client.host if request.client else ""
        return host in _LOOPBACK_HOSTS

    @staticmethod
    def _is_authorized(request: Request, config: WebAuthConfig) -> bool:
        auth_header = request.headers.get("authorization", "")
        scheme, _, credential = auth_header.partition(" ")
        scheme = scheme.lower()

        if scheme == "basic":
            return _check_basic_auth(credential.strip(), config)
        if scheme == "bearer":
            return _constant_time_eq(credential.strip(), config.api_key)

        api_key = request.headers.get("x-api-key", "")
        if api_key:
            return _constant_time_eq(api_key.strip(), config.api_key)

        return False


def _check_basic_auth(credential: str, config: WebAuthConfig) -> bool:
    """Basic 자격증명을 상수 시간 비교로 검증합니다."""
    try:
        decoded = base64.b64decode(credential).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False

    username, sep, password = decoded.partition(":")
    if not sep:
        return False

    return _constant_time_eq(username, config.username) and _constant_time_eq(
        password, config.password
    )


def _constant_time_eq(provided: str, expected: str) -> bool:
    """타이밍 공격을 방지하는 상수 시간 문자열 비교."""
    if not provided or not expected:
        return False
    return secrets.compare_digest(provided, expected)
