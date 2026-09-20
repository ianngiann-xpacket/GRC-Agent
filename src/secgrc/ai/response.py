"""LLM 응답(Response) 데이터 모델 모듈 (Section 6)."""

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, Optional
from pydantic import Field, field_validator

from secgrc.ai.models import AIBaseModel, validate_id_str, CREDENTIAL_PATTERNS


class LLMResponse(AIBaseModel):
    """LLM 응답 모델 (Section 6). 민감정보 및 비밀키 저장을 영구 차단합니다."""
    response_id: str = Field(description="응답 고유 식별자")
    request_id: str = Field(description="요청 식별자")
    provider_id: str = Field(description="프로바이더 식별자")
    model_id: str = Field(description="모델 식별자")
    response_text: str = Field(description="원시 응답 텍스트")
    structured_output: Optional[Dict[str, Any]] = Field(default=None, description="구조화된 파싱 결과 딕셔너리")
    raw_output_hash: str = Field(default="", description="원시 출력 SHA-256 해시")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="응답 생성 일시 (ISO-8601)",
    )
    usage_metadata: Dict[str, Any] = Field(default_factory=dict, description="토큰 및 지연 시간 메타데이터")

    @field_validator("response_id", "request_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("response_text")
    @classmethod
    def sanitize_response_text(cls, v: str) -> str:
        # 응답 텍스트 내 비밀키/토큰 패턴 마스킹
        sanitized = re.sub(r"(?i)\b(bearer)\s+[A-Za-z0-9_\-\.]{12,}", r"\1 [REDACTED]", v)
        sanitized = re.sub(r"(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{12,}['\"]?", r"\1: [REDACTED]", sanitized)
        return sanitized

    @field_validator("usage_metadata")
    @classmethod
    def sanitize_usage(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        forbidden_keys = {"api_key", "apikey", "password", "secret", "private_key", "credentials", "access_token", "auth_token", "bearer_token"}
        cleaned = {}
        for k, val in v.items():
            k_lower = k.lower().replace("-", "_")
            if k_lower in forbidden_keys:
                continue
            cleaned[k] = val
        return cleaned

    def compute_raw_output_hash(self) -> str:
        """응답 텍스트 기반 SHA-256 해시를 계산합니다."""
        return hashlib.sha256(self.response_text.encode("utf-8")).hexdigest()
