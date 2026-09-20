"""Compliance Assessment Rules Models (Step 23.5C).

This module defines deterministic, declarative assessment rule models and rule types.
All assessment rules are static data specifications—no arbitrary user-supplied code is executed.
"""

from enum import Enum
from typing import List, Optional
from pydantic import Field, field_validator

from secgrc.compliance.applicability import EvidenceCondition, EvidenceScope
from secgrc.compliance.assessment_conditions import RuleCondition
from secgrc.compliance.freshness import EvidenceFreshness
from secgrc.compliance.models import (
    CanonicalDataType,
    ComplianceBaseModel,
    validate_identifier,
)
from secgrc.compliance.temporal import TemporalCoverage


class AssessmentStatus(str, Enum):
    """결정론적 컴플라이언스 평가 상태."""
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NO_EVIDENCE = "NO_EVIDENCE"
    MANUAL = "MANUAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    CONFLICTING = "CONFLICTING"
    UNDETERMINED = "UNDETERMINED"


class RuleType(str, Enum):
    """결정론적 평가 규칙 유형 분류."""
    EVIDENCE_PRESENCE = "EVIDENCE_PRESENCE"
    EVIDENCE_COMPLETENESS = "EVIDENCE_COMPLETENESS"
    DATA_ATTRIBUTE = "DATA_ATTRIBUTE"
    CONFIGURATION_STATE = "CONFIGURATION_STATE"
    EVENT_PATTERN = "EVENT_PATTERN"
    THRESHOLD = "THRESHOLD"
    COUNT = "COUNT"
    TEMPORAL_COVERAGE = "TEMPORAL_COVERAGE"
    FRESHNESS = "FRESHNESS"
    SCOPE = "SCOPE"
    CONSISTENCY = "CONSISTENCY"
    CONFLICT = "CONFLICT"
    COMPOSITE = "COMPOSITE"
    MANUAL = "MANUAL"


class ComplianceAssessmentRule(ComplianceBaseModel):
    """결정론적 컴플라이언스 평가 규칙 명세 모델."""

    rule_id: str = Field(description="규칙 고유 식별자 (예: RULE-IAM-MFA-001)")
    framework_id: str = Field(description="소속 프레임워크 식별자")
    framework_version: str = Field(description="프레임워크 버전")
    requirement_id: str = Field(description="대상 요구사항 식별자")
    rule_type: RuleType = Field(description="평가 규칙 유형")
    version: str = Field(default="1.0", description="규칙 버전")
    priority: int = Field(default=1, ge=1, description="규칙 평가 우선순위 (1이 최우선)")
    conditions: List[RuleCondition] = Field(
        default_factory=list,
        description="평가 조건 목록 (모두 만족 시 판정 연계)",
    )
    pass_state: AssessmentStatus = Field(
        default=AssessmentStatus.PASS,
        description="조건 충족 시 도출 상태 (통상 PASS)",
    )
    fail_state: AssessmentStatus = Field(
        default=AssessmentStatus.FAIL,
        description="위반 확인 시 도출 상태 (통상 FAIL)",
    )
    partial_state: Optional[AssessmentStatus] = Field(
        default=AssessmentStatus.PARTIAL,
        description="부분 충족 시 도출 상태",
    )
    required_evidence: List[str] = Field(
        default_factory=list,
        description="필수 증적 ID 목록",
    )
    required_data: List[CanonicalDataType] = Field(
        default_factory=list,
        description="필수 표준 정규 데이터 유형 목록",
    )
    applicability_conditions: List[EvidenceCondition] = Field(
        default_factory=list,
        description="규칙 적용 조건 목록",
    )
    freshness_requirements: Optional[EvidenceFreshness] = Field(
        default=None,
        description="신선도 제약 요건",
    )
    temporal_requirements: Optional[TemporalCoverage] = Field(
        default=None,
        description="시간적 보장 범위 요건",
    )
    scope_requirements: Optional[EvidenceScope] = Field(
        default=None,
        description="스코프 제약 요건",
    )
    conflict_policy: str = Field(
        default="CONFLICTING",
        description="상충 발생 시 처리 정책 (기본: CONFLICTING 상태 유지)",
    )
    manual_review: bool = Field(
        default=False,
        description="수동 심사 필요 여부",
    )
    source_reference: Optional[str] = Field(
        default=None,
        description="공식 지침/기준 출처 참조",
    )
    schema_version: str = Field(
        default="1.0",
        description="규칙 모델 스키마 버전",
    )

    @field_validator(
        "rule_id",
        "framework_id",
        "framework_version",
        "requirement_id",
        "version",
        "conflict_policy",
        "schema_version",
    )
    @classmethod
    def check_rule_identifiers(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("source_reference")
    @classmethod
    def check_rule_source_ref(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_identifier(v, "source_reference")
        return None
