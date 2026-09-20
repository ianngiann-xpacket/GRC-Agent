"""Compliance & Investigation Reporting Security & Sanitization (Step 23.6).

This module provides deterministic sanitization, secret redaction, and escaping
for reporting data to ensure no secret leakage, XSS, HTML injection, shell injection,
or prompt injection affects report presentation.
"""

from copy import deepcopy
import html
import re
from typing import Any, Dict, List, Union

SECRET_PATTERNS = [
    # Private Keys
    (re.compile(r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_-]+ PRIVATE KEY-----", re.IGNORECASE), "[REDACTED_PRIVATE_KEY]"),
    # Bearer tokens
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{12,}", re.IGNORECASE), r"\1[REDACTED]"),
    # AWS Access Key IDs
    (re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # Generic API Keys / Tokens (ak-..., sk-..., key-...)
    (re.compile(r"\b(ak|sk|pk|token|api_key|secret)[-_][A-Za-z0-9_\-]{16,}\b", re.IGNORECASE), "[REDACTED_TOKEN]"),
    # Google API Keys
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b"), "[REDACTED_GOOGLE_KEY]"),
    # Canary secrets
    (re.compile(r"\bCANARY_SECRET_[A-Za-z0-9_]+\b"), "[REDACTED_CANARY]"),
    # Common password assignments in strings: password=..., secret=...
    (re.compile(r"(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?([^\s,;'\"]+)['\"]?", re.IGNORECASE), r"\1=[REDACTED]"),
]

SENSITIVE_KEY_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "credential",
    "credentials",
    "auth_header",
    "authorization",
}


def redact_secrets(data: Any) -> Any:
    """원천 데이터 내 민감 정보(API 키, 토큰, 비밀번호, 개인키 등)를 결정론적으로 [REDACTED] 처리합니다."""
    if isinstance(data, str):
        result = data
        for pattern, replacement in SECRET_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    elif isinstance(data, dict):
        redacted_dict: Dict[str, Any] = {}
        for k, v in data.items():
            k_lower = str(k).lower().strip()
            if not isinstance(v, (dict, list)) and any(sens in k_lower for sens in SENSITIVE_KEY_NAMES):
                redacted_dict[k] = "[REDACTED]"
            else:
                redacted_dict[k] = redact_secrets(v)
        return redacted_dict

    elif isinstance(data, list):
        return [redact_secrets(item) for item in data]

    return data


def escape_report_text(text: str) -> str:
    """XSS 및 스크립트 인젝션, 프롬프트 인젝션을 무해화하기 위해 텍스트를 이스케이프합니다."""
    if not isinstance(text, str):
        return str(text)

    # HTML 이스케이프 (&, <, >, ", ')
    escaped = html.escape(text, quote=True)
    # 제어 문자 및 널 바이트 치환
    escaped = escaped.replace("\x00", "")
    return escaped


def escape_markdown(text: str) -> str:
    """마크다운 테이블 파이프(|) 및 포맷팅 파괴 요소를 이스케이프합니다."""
    if not isinstance(text, str):
        return str(text)

    sanitized = str(text).replace("|", "\\|")
    sanitized = sanitized.replace("\r\n", " ").replace("\n", " ")
    if "&lt;" not in sanitized and "<" in sanitized:
        sanitized = escape_report_text(sanitized)
    return sanitized

