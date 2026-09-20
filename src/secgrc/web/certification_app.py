"""ISMS-P 인증심사 전용 FastAPI 애플리케이션 (v2).

기존 전체 GRC 콘솔(app.py, 포트 8000)과 완전히 분리된 별도 앱입니다.
인증심사 메뉴만 노출하며, routes.py의 광범위 라우터를 import하지 않습니다.
"""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from secgrc.web.auth import AuthMiddleware, resolve_auth_config
from secgrc.web.certification_routes import router

STATIC_DIR = Path(__file__).resolve().parent / "static"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """엔터프라이즈 보안 요구사항에 맞춘 HTTP 보안 응답 헤더 미들웨어.

    폰트/스타일 CDN(Pretendard, Google Fonts) 허용을 위해
    style-src/font-src만 해당 도메인으로 제한적으로 개방합니다.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        # HTML(심사 데이터)은 캐시하지 않음
        if "text/html" in response.headers.get("content-type", ""):
            response.headers["Cache-Control"] = "no-store"
        # 정적 자산(JS/CSS)은 매 요청 재검증 — 개발 중 stale 캐시 방지
        elif request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"
        return response


def create_certification_app() -> FastAPI:
    """인증심사 전용 FastAPI 애플리케이션 팩토리."""
    app = FastAPI(
        title="ISMS-P Certification Audit Console",
        description="ISMS-P 인증심사 전용 콘솔 — 6계층 아키텍처 (v2)",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.state.web_auth = resolve_auth_config()
    # Starlette는 마지막 등록 미들웨어가 최외곽 — 401에도 보안 헤더가
    # 적용되도록 Auth를 먼저 등록하고 SecurityHeaders를 최외곽에 둔다.
    app.add_middleware(AuthMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(router)

    return app


app = create_certification_app()
