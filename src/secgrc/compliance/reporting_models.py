"""Compliance & Investigation Reporting Layer Models (Step 23.6).

This module defines the deterministic data models for the 5 reporting views:
Executive, GRC Manager, Auditor, Technical, and Investigation.
All models strictly follow Pydantic v2 with extra='forbid' and preserve authoritative data.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import re
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secgrc.compliance.models import ComplianceBaseModel, validate_identifier, validate_iso8601_timestamp


class ReportType(str, Enum):
    """5종 준거성 및 조사 보고서 유형."""
    EXECUTIVE = "EXECUTIVE"
    GRC_MANAGER = "GRC_MANAGER"
    AUDITOR = "AUDITOR"
    TECHNICAL = "TECHNICAL"
    INVESTIGATION = "INVESTIGATION"


class ReportSortKey(str, Enum):
    """결정론적 보고서 정렬 키."""
    REQUIREMENT_ID = "requirement_id"
    STATUS = "status"
    SEVERITY = "severity"
    PRIORITY = "priority"
    ASSESSMENT_TIME = "assessment_time"
    RISK_SCORE = "risk_score"


class ReportFilter(ComplianceBaseModel):
    """결정론적 보고서 필터링 모델."""
    framework: Optional[str] = None
    framework_version: Optional[str] = None
    requirement: Optional[str] = None
    status: Optional[str] = None
    assessment_batch: Optional[str] = None
    scope: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    data_type: Optional[str] = None
    source_system: Optional[str] = None


class ReportMetric(ComplianceBaseModel):
    """보고서 단일 측정 지표 모델."""
    name: str = Field(description="지표 명칭")
    value: Union[int, float, str, bool] = Field(description="지표 값")
    unit: Optional[str] = Field(default=None, description="지표 단위 (예: %, 건, 점)")
    description: Optional[str] = Field(default=None, description="지표 설명")


class ReportFinding(ComplianceBaseModel):
    """보고서 기술 취약점/결함 항목."""
    finding_id: str = Field(description="결함 고유 식별자")
    title: str = Field(description="결함 제목")
    severity: str = Field(description="심각도 수준")
    status: str = Field(description="결함 상태")
    asset_id: Optional[str] = Field(default=None, description="연관 자산 식별자")
    description: str = Field(default="", description="결함 상세 설명")
    source: Optional[str] = Field(default=None, description="수집 소스 시스템")


class ReportEvidence(ComplianceBaseModel):
    """보고서 증적 레코드 항목."""
    evidence_id: str = Field(description="증적 고유 식별자")
    evidence_type: str = Field(description="증적 유형")
    requirement_id: str = Field(description="관련 요구사항 ID")
    status: str = Field(description="증적 상태 (AVAILABLE, MISSING, STALE 등)")
    source_system: str = Field(description="수집 소스 시스템")
    observed_at: Optional[str] = Field(default=None, description="관측 시각 (ISO 8601)")
    freshness: str = Field(default="NOT_SPECIFIED", description="신선도 검증 상태")
    valid_provenance: bool = Field(default=True, description="출처 유효성 여부")
    record_id: Optional[str] = Field(default=None, description="원본 데이터 레코드 식별자")


class ReportGap(ComplianceBaseModel):
    """요구사항 미충족 갭 항목."""
    requirement_id: str = Field(description="대상 요구사항 ID")
    assessment_id: str = Field(description="관련 평가 결과 ID")
    gap_type: str = Field(description="갭 유형 (EVIDENCE_MISSING, CONDITION_FAILED, SCOPE_MISMATCH 등)")
    status: str = Field(description="평가 상태 (FAIL, PARTIAL, NO_EVIDENCE 등)")
    description_code: str = Field(description="결정론적 사유 코드")
    missing_inputs: List[str] = Field(default_factory=list, description="누락된 입력 데이터 항목")
    missing_evidence: List[str] = Field(default_factory=list, description="누락된 증적 항목")
    source_refs: List[str] = Field(default_factory=list, description="참조 소스 목록")
    severity: str = Field(description="권위 있는 기존 심각도 (재계산 금지)")
    priority: str = Field(description="권위 있는 기존 우선순위 (재계산 금지)")


class ReportRisk(ComplianceBaseModel):
    """권위 있는 기존 리스크 데이터 표시 항목 (재계산 금지)."""
    risk_id: str = Field(description="리스크 고유 식별자")
    title: str = Field(description="리스크 명칭")
    score: float = Field(description="기존 권위 있는 리스크 점수")
    priority: str = Field(description="기존 권위 있는 리스크 우선순위")
    severity: str = Field(description="기존 권위 있는 리스크 심각도")
    requirement_id: Optional[str] = Field(default=None, description="매핑 요구사항 ID")
    affected_assets: List[str] = Field(default_factory=list, description="영향받는 자산 식별자 목록")

    @field_validator("score")
    @classmethod
    def validate_finite_score(cls, v: float) -> float:
        if math.isnan(v) or math.isinf(v):
            raise ValueError("Risk score must be a finite real number; NaN and Inf are forbidden")
        return v


class ReportConflict(ComplianceBaseModel):
    """증적 상충 표시 항목 (자동 해소 금지)."""
    conflict_id: str = Field(description="상충 고유 식별자")
    requirement_id: str = Field(description="관련 요구사항 ID")
    description: str = Field(description="상충 상세 설명")
    source_a: str = Field(description="상충 소스 A 정보")
    source_b: str = Field(description="상충 소스 B 정보")
    conflicting_values: Dict[str, Any] = Field(default_factory=dict, description="상충 값 상세")
    status: str = Field(default="UNRESOLVED", description="상충 상태")


class ReportManualReview(ComplianceBaseModel):
    """인간 심사관 수동 확인 필요 항목 (1급 상태 보존)."""
    requirement_id: str = Field(description="대상 요구사항 ID")
    required: bool = Field(default=True, description="수동 심사 필요 여부")
    reason: str = Field(default="", description="수동 심사 필요 사유")
    human_verification_required: str = Field(default="YES", description="인간 검증 플래그 (YES/NO)")
    scope: Optional[str] = Field(default=None, description="심사 대상 스코프")


class ReportProvenance(ComplianceBaseModel):
    """역방향 계보 추적 항목."""
    source_type: str = Field(description="소스 유형")
    source_id: str = Field(description="소스 식별자")
    assessment_id: Optional[str] = Field(default=None, description="평가 식별자")
    requirement_id: Optional[str] = Field(default=None, description="요구사항 식별자")
    rule_id: Optional[str] = Field(default=None, description="적용 규칙 식별자")
    evidence_refs: List[str] = Field(default_factory=list, description="증적 레퍼런스 목록")
    data_refs: List[str] = Field(default_factory=list, description="정규 데이터 레퍼런스 목록")
    observed_at: Optional[str] = Field(default=None, description="관측 시각 (ISO 8601)")


class ReportSection(ComplianceBaseModel):
    """보고서 독립 세션 모델."""
    section_id: str = Field(description="세션 식별자")
    title: str = Field(description="세션 제목")
    content: str = Field(default="", description="세션 본문 텍스트")
    order: int = Field(default=0, description="정렬 순서")
    metrics: List[ReportMetric] = Field(default_factory=list, description="세션 지표 목록")
    items: List[Dict[str, Any]] = Field(default_factory=list, description="세션 상세 항목 목록")


class ReportAssessmentSummary(ComplianceBaseModel):
    """평가 결과 집계 요약 (평가 계층 원천 데이터 기반)."""
    total: int = Field(default=0, ge=0, description="전체 평가 건수")
    pass_count: int = Field(default=0, ge=0, alias="pass", description="PASS 건수")
    fail_count: int = Field(default=0, ge=0, alias="fail", description="FAIL 건수")
    partial_count: int = Field(default=0, ge=0, alias="partial", description="PARTIAL 건수")
    no_evidence_count: int = Field(default=0, ge=0, alias="no_evidence", description="NO_EVIDENCE 건수")
    manual_count: int = Field(default=0, ge=0, alias="manual", description="MANUAL 건수")
    not_applicable_count: int = Field(default=0, ge=0, alias="not_applicable", description="N/A 건수")
    conflicting_count: int = Field(default=0, ge=0, alias="conflicting", description="CONFLICTING 건수")
    undetermined_count: int = Field(default=0, ge=0, alias="undetermined", description="UNDETERMINED 건수")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @property
    def pass_(self) -> int:
        return self.pass_count

    @property
    def fail(self) -> int:
        return self.fail_count

    @property
    def partial(self) -> int:
        return self.partial_count

    @property
    def no_evidence(self) -> int:
        return self.no_evidence_count

    @property
    def manual(self) -> int:
        return self.manual_count

    @property
    def not_applicable(self) -> int:
        return self.not_applicable_count

    @property
    def conflicting(self) -> int:
        return self.conflicting_count

    @property
    def undetermined(self) -> int:
        return self.undetermined_count


class ReportEvidenceSummary(ComplianceBaseModel):
    """증적 상태 집계 요약 (권위 있는 검증 불가능 시 'NOT_AVAILABLE' 표기)."""
    required: Union[int, str] = Field(default=0, description="요구 증적 건수 또는 NOT_AVAILABLE")
    available: Union[int, str] = Field(default=0, description="확보 증적 건수 또는 NOT_AVAILABLE")
    missing: Union[int, str] = Field(default=0, description="누락 증적 건수 또는 NOT_AVAILABLE")
    partial: Union[int, str] = Field(default=0, description="부분 충족 건수 또는 NOT_AVAILABLE")
    stale: Union[int, str] = Field(default=0, description="신선도 결함 건수 또는 NOT_AVAILABLE")
    conflicting: Union[int, str] = Field(default=0, description="상충 증적 건수 또는 NOT_AVAILABLE")
    manual: Union[int, str] = Field(default=0, description="수동 심사 증적 건수 또는 NOT_AVAILABLE")
    provenance_valid: Union[int, str] = Field(default=0, description="유효 계보 증적 건수 또는 NOT_AVAILABLE")
    provenance_invalid: Union[int, str] = Field(default=0, description="계보 결함 증적 건수 또는 NOT_AVAILABLE")


class ComplianceReport(ComplianceBaseModel):
    """최종 감사 가능 준거성 및 조사 보고서 모델."""
    report_id: str = Field(description="보고서 고유 식별자 (예: REP-ISMS-P-EXECUTIVE-<UUID>)")
    report_type: ReportType = Field(description="보고서 유형")
    framework_id: str = Field(description="대상 프레임워크 식별자")
    framework_version: str = Field(description="대상 프레임워크 버전")
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="보고서 생성 일시 (ISO 8601 UTC)",
    )
    assessment_batch_id: Optional[str] = Field(default=None, description="원천 평가 배치 식별자")
    title: str = Field(description="보고서 제목")
    summary: str = Field(description="보고서 요약 본문")
    assessment_summary: ReportAssessmentSummary = Field(description="평가 상태별 집계 요약")
    risk_summary: List[ReportRisk] = Field(default_factory=list, description="권위 있는 리스크 요약")
    evidence_summary: ReportEvidenceSummary = Field(default_factory=ReportEvidenceSummary, description="증적 요약")
    gap_summary: List[ReportGap] = Field(default_factory=list, description="미충족 갭 목록")
    conflict_summary: List[ReportConflict] = Field(default_factory=list, description="증적 상충 목록")
    manual_review_summary: List[ReportManualReview] = Field(default_factory=list, description="수동 심사 대상 목록")
    requirement_results: List[Dict[str, Any]] = Field(default_factory=list, description="개별 요구사항 평가 결과 목록")
    provenance_summary: List[ReportProvenance] = Field(default_factory=list, description="계보 추적 항목 목록")
    source_summary: List[Dict[str, Any]] = Field(default_factory=list, description="참조 소스 요약 목록")
    sections: List[ReportSection] = Field(default_factory=list, description="보고서 세션 목록")
    trend: str = Field(default="NOT_AVAILABLE", description="준거성 추세 (이력 부족 시 NOT_AVAILABLE)")
    integrity_hash: str = Field(default="", description="결정론적 내용 무결성 해시")
    report_version: str = Field(default="1.0", description="보고서 규격 버전")
    schema_version: str = Field(default="1.0", description="보고서 스키마 버전")

    @field_validator("report_id", "framework_id", "framework_version", "report_version", "schema_version")
    @classmethod
    def check_report_identifiers(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("generated_at")
    @classmethod
    def check_timestamp(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)

    @field_validator("report_version", "schema_version")
    @classmethod
    def check_version_str(cls, v: str, info) -> str:
        if v != "1.0":
            raise ValueError(f"{info.field_name} must be '1.0', got '{v}'")
        return v
