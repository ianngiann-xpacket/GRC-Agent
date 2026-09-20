"""시크릿(API 키, 토큰, 비밀번호, 개인키 등) 전방위 탐지 및 마스킹(Secret Guard) 모듈입니다."""

import re
from typing import Any, Dict, List, Tuple

# 정밀 시크릿 정규식 패턴 사전
SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "google_api_key": re.compile(r"(AIza[0-9A-Za-z-_]{35})"),
    "github_token": re.compile(r"(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82})"),
    "oauth_access_token": re.compile(r"(ya29\.[0-9A-Za-z-_]+)"),
    "aws_access_key": re.compile(r"(AKIA[0-9A-Z]{16})"),
    "jwt_token": re.compile(r"(eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,})"),
    "private_key": re.compile(r"(-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----)"),
    "bearer_token": re.compile(r"(?i)(bearer\s+)([A-Za-z0-9_\-\.\/+=]{20,})"),
    "password_field": re.compile(r'(?i)("?(?:password|passwd|pwd|secret_key|client_secret)"?\s*[:=]\s*)"?([A-Za-z0-9_\-\.\/+=@!#$%^&*]{6,})"?'),
    "canary_token": re.compile(r"(canary_secgrc_token_[0-9A-Za-z_]{10,}|CANARY_SECRET_[0-9A-Za-z_]+)"),
}

REDACTION_MARK = "[REDACTED]"


class SecretGuard:
    """AI 입력, 출력, 로그에서 시크릿 노출을 방지하는 보안 가드 클래스입니다."""

    @classmethod
    def mask_secrets(cls, text: str) -> str:
        """문자열 내 시크릿을 마스킹한 결과를 반환합니다."""
        redacted, _, _ = cls.scan_and_redact(text)
        return redacted

    @classmethod
    def contains_secret(cls, text: str) -> bool:
        """문자열에 시크릿 패턴이 포함되어 있는지 검사합니다."""
        if not text or not isinstance(text, str):
            return False
        return any(pattern.search(text) is not None for pattern in SECRET_PATTERNS.values())

    @classmethod
    def scan_and_redact(cls, text: str) -> Tuple[str, bool, List[str]]:
        """문자열에서 시크릿을 스캔하고 [REDACTED]로 치환하며 발견된 시크릿 유형 목록을 반환합니다."""
        if not text or not isinstance(text, str):
            return text, False, []

        redacted_text = text
        detected_types: List[str] = []

        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(redacted_text):
                detected_types.append(name)
                if pattern.groups == 2:
                    redacted_text = pattern.sub(rf"\1{REDACTION_MARK}", redacted_text)
                else:
                    redacted_text = pattern.sub(REDACTION_MARK, redacted_text)

        return redacted_text, bool(detected_types), detected_types

    @classmethod
    def redact(cls, data: Any) -> Any:
        """문자열, 딕셔너리, 리스트 등 임의 데이터 구조에 대해 재귀적으로 시크릿을 마스킹합니다."""
        if isinstance(data, str):
            redacted, _, _ = cls.scan_and_redact(data)
            return redacted
        elif isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                lower_k = str(k).lower()
                if any(s in lower_k for s in ["secret", "password", "token", "api_key", "private_key", "passwd"]):
                    new_dict[k] = REDACTION_MARK
                else:
                    new_dict[k] = cls.redact(v)
            return new_dict
        elif isinstance(data, list):
            return [cls.redact(item) for item in data]
        return data
