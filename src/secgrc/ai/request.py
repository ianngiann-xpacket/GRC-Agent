"""LLM 요청(Request) 데이터 모델 모듈 (Section 5)."""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import ConfigDict, Field, field_validator

from secgrc.ai.models import AIBaseModel, validate_id_str, validate_id_list


class LLMRequest(AIBaseModel):
    """LLM 요청 모델 (Section 5). 범위가 한정된 바운디드 컨텍스트만을 전달합니다."""
    request_id: str = Field(description="요청 고유 식별자")
    investigation_id: str = Field(description="소속 조사 식별자")
    request_type: str = Field(description="추론 작업 유형")
    system_context: str = Field(description="시스템 지침 및 제약사항 컨텍스트")
    fact_context: List[Dict[str, Any]] = Field(default_factory=list, description="제공된 사실 컨텍스트")
    evidence_context: List[Dict[str, Any]] = Field(default_factory=list, description="제공된 증적 컨텍스트")
    relationship_context: List[Dict[str, Any]] = Field(default_factory=list, description="제공된 관계 컨텍스트")
    allowed_scope: str = Field(description="인가된 조사 스코프")
    allowed_entities: List[str] = Field(default_factory=list, description="인가된 엔티티 ID 목록")
    prompt_template_id: str = Field(description="프롬프트 템플릿 ID")
    prompt_template_version: str = Field(default="1.0.0", description="프롬프트 템플릿 버전")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="요청 생성 일시 (ISO-8601)",
    )
    request_hash: str = Field(default="", description="요청 내용 기반 무결성 해시")

    @field_validator("request_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("allowed_entities")
    @classmethod
    def check_entities_list(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    def compute_request_hash(self) -> str:
        """결정론적 해시를 계산합니다."""
        payload = {
            "request_id": self.request_id,
            "investigation_id": self.investigation_id,
            "request_type": self.request_type,
            "system_context": self.system_context,
            "fact_context": self.fact_context,
            "evidence_context": self.evidence_context,
            "relationship_context": self.relationship_context,
            "allowed_scope": self.allowed_scope,
            "allowed_entities": sorted(self.allowed_entities),
            "prompt_template_id": self.prompt_template_id,
            "prompt_template_version": self.prompt_template_version,
        }
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
