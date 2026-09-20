"""Evidence Set Models (Step 23.5B).

This module defines composite evidence structures requiring multiple records to evaluate,
supporting logical combinations (ALL, ANY, AT_LEAST_N, CONDITIONAL).
"""

from enum import Enum
from typing import List, Optional
from pydantic import Field, field_validator, model_validator

from secgrc.compliance.applicability import EvidenceCondition
from secgrc.compliance.models import (
    ComplianceBaseModel,
    validate_identifier,
)


class EvidenceSetOperator(str, Enum):
    """증적 세트 논리 결합 연산자."""
    ALL = "ALL"
    ANY = "ANY"
    AT_LEAST_N = "AT_LEAST_N"
    CONDITIONAL = "CONDITIONAL"


class EvidenceSet(ComplianceBaseModel):
    """요구사항 평가에 필요한 복합 증적 세트 모델."""

    set_id: str = Field(description="증적 세트 식별자 (예: EV-SET-ISMS-P-2.5.2-01)")
    framework_id: str = Field(description="소속 프레임워크 식별자")
    framework_version: str = Field(description="소속 프레임워크 버전")
    requirement_id: str = Field(description="대상 요구사항 식별자")
    operator: EvidenceSetOperator = Field(
        default=EvidenceSetOperator.ALL,
        description="증적 결합 논리 연산자",
    )
    target_count: Optional[int] = Field(
        default=None,
        description="AT_LEAST_N 연산자 사용 시 최소 요구 충족 증적 수",
    )
    condition: Optional[EvidenceCondition] = Field(
        default=None,
        description="CONDITIONAL 연산자 사용 시 적용 조건",
    )
    required_evidence_ids: List[str] = Field(
        default_factory=list,
        description="필수 증적 ID 목록",
    )
    supporting_evidence_ids: List[str] = Field(
        default_factory=list,
        description="보조/보완 증적 ID 목록",
    )
    conditional_evidence_ids: List[str] = Field(
        default_factory=list,
        description="조건부 증적 ID 목록",
    )
    description: str = Field(
        default="",
        description="증적 세트 설명",
    )

    @field_validator("set_id", "framework_id", "framework_version", "requirement_id")
    @classmethod
    def check_set_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("required_evidence_ids", "supporting_evidence_ids", "conditional_evidence_ids")
    @classmethod
    def check_evidence_id_lists(cls, v: List[str], info) -> List[str]:
        cleaned = []
        for item in v:
            cleaned.append(validate_identifier(item, info.field_name))
        return cleaned

    @model_validator(mode="after")
    def validate_set_configuration(self) -> "EvidenceSet":
        if self.operator == EvidenceSetOperator.AT_LEAST_N:
            if self.target_count is None or self.target_count <= 0:
                raise ValueError("target_count must be a positive integer when operator is AT_LEAST_N")
        elif self.operator == EvidenceSetOperator.CONDITIONAL:
            if self.condition is None:
                raise ValueError("condition is required when operator is CONDITIONAL")
        return self
