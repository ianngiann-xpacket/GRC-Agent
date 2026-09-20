"""매핑 신뢰도(Mapping Confidence) 및 AI 경계 가드레일 모듈입니다."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class MappingType(str, Enum):
    """매핑 출처 및 방식 분류"""
    EXPLICIT = "explicit"   # 표준 명세서 또는 법령/규정에 명시된 1:1 대응
    RULE = "rule"           # 결정론적 보안 규칙 및 어댑터 매핑
    KEYWORD = "keyword"     # 키워드/토큰 유사도 기반 매핑
    INFERRED = "inferred"   # AI/LLM 또는 그래프 추론 기반 매핑
    NONE = "none"           # 매핑 근거 없음


CONFIDENCE_SCORES = {
    MappingType.EXPLICIT: 1.0,
    MappingType.RULE: 0.9,
    MappingType.KEYWORD: 0.7,
    MappingType.INFERRED: 0.5,
    MappingType.NONE: 0.0,
}


class MappingConfidence(BaseModel):
    """매핑 신뢰도 및 출처 검증 모델"""
    mapping_type: MappingType = Field(default=MappingType.RULE, description="매핑 방식")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0, description="신뢰도 점수 (0.0 ~ 1.0)")
    source: str = Field(default="deterministic_rule", description="매핑 생성 주체/출처")
    rationale: Optional[str] = Field(default=None, description="매핑 근거 및 설명")

    def __init__(self, **data):
        if "score" in data and "confidence" not in data:
            data["confidence"] = data.pop("score")
        super().__init__(**data)

    @property
    def score(self) -> float:
        return self.confidence

    @field_validator("confidence")
    @classmethod
    def validate_confidence_ceiling(cls, v: float, info) -> float:
        """AI 추론(INFERRED) 매핑의 경우 결정론적 검증 없이 0.5를 초과할 수 없도록 강제합니다."""
        data = info.data
        m_type = data.get("mapping_type")
        if m_type == MappingType.INFERRED and v > 0.5:
            raise ValueError(f"AI inferred mapping confidence cannot exceed 0.5 without deterministic validation (got {v})")
        return round(float(v), 2)

    @classmethod
    def create_explicit(cls, source: str = "framework_spec", rationale: Optional[str] = None) -> "MappingConfidence":
        return cls(mapping_type=MappingType.EXPLICIT, confidence=1.0, source=source, rationale=rationale)

    @classmethod
    def create_rule(cls, source: str = "prowler_adapter", rationale: Optional[str] = None) -> "MappingConfidence":
        return cls(mapping_type=MappingType.RULE, confidence=0.9, source=source, rationale=rationale)

    @classmethod
    def create_keyword(cls, source: str = "keyword_matcher", rationale: Optional[str] = None) -> "MappingConfidence":
        return cls(mapping_type=MappingType.KEYWORD, confidence=0.7, source=source, rationale=rationale)

    @classmethod
    def create_inferred(cls, source: str = "ai_auditor", rationale: Optional[str] = None) -> "MappingConfidence":
        return cls(mapping_type=MappingType.INFERRED, confidence=0.5, source=source, rationale=rationale)
