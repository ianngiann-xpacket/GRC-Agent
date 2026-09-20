"""Continuous GRC / Continuous Compliance의 핵심 데이터 모델 및 열거형 정의 모듈입니다.

Step 25: Continuous Compliance & Change Impact Engine 데이터 모델.
Pydantic v2 기반 extra="forbid" 엄격 모델링 및 이전 하위 호환 모델 완벽 유지.
"""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


def validate_identifier(v: str, field_name: str = "identifier") -> str:
    """식별자 문자열 검증: 경로 조작, 인젝션, 위험 특수문자 차단."""
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    clean = v.strip()
    if any(pt in clean for pt in ("../", "..\\", "/..", "\\..")):
        raise ValueError(f"Path traversal characters forbidden in {field_name}: '{v}'")
    if any(c in clean for c in ("\x00", "\n", "\r", "<", ">", ";", "'", '"', "`")):
        raise ValueError(f"Invalid character in {field_name}: '{v}'")
    return clean


def validate_iso8601_timestamp(v: str, field_name: str = "timestamp") -> str:
    """ISO 8601 타임스탬프 유효성 검증."""
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"{field_name} must be a non-empty ISO 8601 string")
    clean = v.strip()
    try:
        # Allow trailing Z
        norm = clean.replace("Z", "+00:00")
        datetime.fromisoformat(norm)
    except Exception as e:
        raise ValueError(f"Invalid ISO 8601 timestamp in {field_name}: '{v}'") from e
    return clean


class ContinuousBaseModel(BaseModel):
    """Step 25 전용 엄격 Pydantic 기본 모델 (extra='forbid')."""
    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        populate_by_name=True,
    )


class ChangeType(str, Enum):
    """자산 및 환경 변경 유형 (Step 25 Section 6)."""
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    STATUS_CHANGE = "STATUS_CHANGE"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    CONFIG_CHANGE = "CONFIG_CHANGE"  # 하위 호환성 유지
    POLICY_CHANGE = "POLICY_CHANGE"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    IDENTITY_CHANGE = "IDENTITY_CHANGE"
    ASSET_CHANGE = "ASSET_CHANGE"
    VULNERABILITY_CHANGE = "VULNERABILITY_CHANGE"
    EVIDENCE_CHANGE = "EVIDENCE_CHANGE"
    DOCUMENT_CHANGE = "DOCUMENT_CHANGE"
    PROCESSING_CHANGE = "PROCESSING_CHANGE"


class ImpactLevel(str, Enum):
    """변경 영향 심각도 수준 (Section 40)."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class ImpactType(str, Enum):
    """영향 분석 유형."""
    DIRECT_REQUIREMENT = "DIRECT_REQUIREMENT"
    EVIDENCE_AVAILABILITY = "EVIDENCE_AVAILABILITY"
    EVIDENCE_FRESHNESS = "EVIDENCE_FRESHNESS"
    SECURITY_CONTROL = "SECURITY_CONTROL"
    VULNERABILITY_STATE = "VULNERABILITY_STATE"
    PRIVACY_OBLIGATION = "PRIVACY_OBLIGATION"


class FieldChange(ContinuousBaseModel):
    """필드 단위 변경 상세 모델 (Section 8)."""
    field_name: str = Field(description="변경된 필드 명칭")
    old_value: Any = Field(default=None, description="이전 값")
    new_value: Any = Field(default=None, description="변경된 새 값")
    change_type: ChangeType = Field(default=ChangeType.UPDATE, description="변경 유형")


class ChangeEvent(ContinuousBaseModel):
    """엔터프라이즈 정규 데이터 변경 이벤트 모델 (Section 5)."""
    change_id: str = Field(description="변경 고유 식별자 (예: CHG-2026-001)")
    tenant_id: str = Field(default="default", description="테넌트 격리 식별자")
    source_system: str = Field(description="소스 시스템 (aws, gcp, k8s, prowler, nessus, iam)")
    source_record_id: str = Field(description="소스 레코드 ID")
    entity_type: str = Field(description="정규 엔티티 유형 (IAMPolicy, FirewallRule, Asset, Finding 등)")
    entity_id: str = Field(description="엔티티 식별자")
    change_type: ChangeType = Field(description="변경 유형")
    occurred_at: str = Field(description="변경 발생 일시 (ISO 8601)")
    observed_at: str = Field(description="변경 관측 일시 (ISO 8601)")
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="엔진 탐지 일시 (ISO 8601)",
    )
    previous_hash: str = Field(default="", description="이전 상태 해시")
    new_hash: str = Field(description="신규 상태 해시")
    previous_version: Optional[str] = Field(default=None, description="이전 버전")
    new_version: Optional[str] = Field(default=None, description="신규 버전")
    scope: str = Field(default="GLOBAL", description="적용 스코프")
    changed_fields: List[FieldChange] = Field(default_factory=list, description="변경된 필드 목록")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="변경 출처 계보 메타데이터")
    integrity_hash: str = Field(default="", description="논리 변경 무결성 해시")
    schema_version: str = Field(default="1.0", description="스키마 버전")

    @field_validator("change_id", "tenant_id", "source_system", "source_record_id", "entity_type", "entity_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("occurred_at", "observed_at", "detected_at")
    @classmethod
    def check_times(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)


class ImpactRule(ContinuousBaseModel):
    """결정론적 컴플라이언스 영향 분석 규칙 모델 (Section 16)."""
    rule_id: str = Field(description="규칙 고유 식별자")
    rule_version: str = Field(default="1.0", description="규칙 버전")
    source_data_type: str = Field(description="소스 정규 데이터 유형")
    changed_field: Optional[str] = Field(default=None, description="영향 받는 특정 필드 (선택)")
    target_framework: str = Field(description="대상 프레임워크 (ISMS-P, ISO-27001, GDPR 등)")
    target_requirement: str = Field(description="대상 요구사항 ID")
    impact_type: ImpactType = Field(default=ImpactType.DIRECT_REQUIREMENT, description="영향 유형")
    priority: str = Field(default="P1", description="우선순위")
    source_reference: str = Field(default="RULE", description="규칙 근거")
    impact_level: ImpactLevel = Field(default=ImpactLevel.HIGH, description="영향 수준")

    @field_validator("rule_id", "rule_version", "source_data_type", "target_framework", "target_requirement")
    @classmethod
    def check_rule_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class ImpactAnalysis(ContinuousBaseModel):
    """결정론적 변경 영향 분석 결과 모델 (Section 14)."""
    impact_id: str = Field(description="영향 분석 고유 식별자")
    change_id: str = Field(description="원인 변경 이벤트 ID")
    tenant_id: str = Field(default="default", description="테넌트 격리 식별자")
    affected_entities: List[str] = Field(default_factory=list, description="영향 받는 엔티티 목록")
    affected_data_types: List[str] = Field(default_factory=list, description="영향 받는 정규 데이터 유형")
    affected_frameworks: List[str] = Field(default_factory=list, description="영향 받는 프레임워크 목록")
    affected_requirements: List[str] = Field(default_factory=list, description="영향 받는 요구사항 목록")
    affected_evidence_requirements: List[str] = Field(default_factory=list, description="영향 받는 증적 요구사항 목록")
    affected_assessments: List[str] = Field(default_factory=list, description="재평가 대상 평가 ID 목록")
    affected_risks: List[str] = Field(default_factory=list, description="연계 위험 목록")
    affected_investigations: List[str] = Field(default_factory=list, description="연계 조사 목록")
    impact_scope: str = Field(default="GLOBAL", description="영향 스코프")
    impact_reason_codes: List[str] = Field(default_factory=list, description="결정론적 영향 사유 코드 목록")
    analysis_version: str = Field(default="1.0", description="분석 엔진 버전")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="영향 분석 계보")
    impact_level: ImpactLevel = Field(default=ImpactLevel.HIGH, description="최대 영향 수준")

    @field_validator("impact_id", "change_id", "tenant_id")
    @classmethod
    def check_impact_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class ComplianceDelta(ContinuousBaseModel):
    """재평가 전후 컴플라이언스 델타 모델 (Section 31)."""
    delta_id: str = Field(description="델타 고유 식별자 (예: DLT-ISMS-P-2.7.1-001)")
    requirement_id: str = Field(description="요구사항 식별자")
    previous_assessment_id: Optional[str] = Field(default=None, description="이전 평가 ID")
    current_assessment_id: str = Field(description="신규 재평가 ID")
    previous_status: Optional[str] = Field(default=None, description="이전 평가 상태")
    current_status: str = Field(description="신규 평가 상태 (PASS, FAIL, PARTIAL, NO_EVIDENCE 등)")
    status_changed: bool = Field(description="상태 전이 여부")
    changed_fields: List[str] = Field(default_factory=list, description="변동된 평가 필드 목록")
    change_ids: List[str] = Field(default_factory=list, description="원인 변경 이벤트 ID 목록")
    reason_codes: List[str] = Field(default_factory=list, description="결정론적 상태 전이 사유 코드")
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="델타 생성 일시 (ISO 8601)",
    )
    provenance: Dict[str, Any] = Field(default_factory=dict, description="델타 계보 메타데이터")

    @field_validator("delta_id", "requirement_id", "current_assessment_id")
    @classmethod
    def check_delta_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("detected_at")
    @classmethod
    def check_time(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)


class ComplianceTimelineEntry(ContinuousBaseModel):
    """컴플라이언스 타임라인 단일 이벤트 항목 (Section 35)."""
    timestamp: str = Field(description="타임스탬프 (ISO 8601)")
    event_type: str = Field(description="이벤트 유형 (CHANGE, REASSESSMENT, DELTA 등)")
    status: Optional[str] = Field(default=None, description="평가 상태")
    change_id: Optional[str] = Field(default=None, description="관련 변경 ID")
    assessment_id: Optional[str] = Field(default=None, description="관련 평가 ID")
    delta_id: Optional[str] = Field(default=None, description="관련 델타 ID")
    summary: str = Field(default="", description="이벤트 요약")

    @field_validator("timestamp")
    @classmethod
    def check_time(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)


class ComplianceTimeline(ContinuousBaseModel):
    """요구사항별 컴플라이언스 변동 타임라인 모델 (Section 35)."""
    requirement_id: str = Field(description="요구사항 ID")
    framework_id: str = Field(default="ISMS-P", description="프레임워크 ID")
    entries: List[ComplianceTimelineEntry] = Field(default_factory=list, description="시간순 항목 목록")

    @field_validator("requirement_id", "framework_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class InvestigationTriggerCandidate(ContinuousBaseModel):
    """조사 트리거 후보 모델 (Section 37, 자동 실행 없음)."""
    candidate_id: str = Field(description="트리거 후보 ID")
    requirement_id: str = Field(description="요구사항 ID")
    change_id: str = Field(description="원인 변경 ID")
    trigger_reason: str = Field(description="트리거 사유")
    severity: str = Field(default="HIGH", description="심각도")
    status: str = Field(default="CANDIDATE", description="상태 (CANDIDATE, DISMISSED, QUEUED)")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="생성 일시",
    )

    @field_validator("candidate_id", "requirement_id", "change_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class StateSnapshot(ContinuousBaseModel):
    """엔진 전후 상태 스냅샷 해시 모델 (Section 52)."""
    snapshot_id: str = Field(description="스냅샷 식별자")
    created_at: str = Field(description="생성 일시 (ISO 8601)")
    entities_hash: str = Field(default="", description="엔티티 해시")
    relationships_hash: str = Field(default="", description="관계 해시")
    assessment_hash: str = Field(default="", description="평가 해시")
    risk_hash: str = Field(default="", description="위험 해시")
    control_hash: str = Field(default="", description="통제 해시")
    evidence_hash: str = Field(default="", description="증적 해시")

    @field_validator("snapshot_id")
    @classmethod
    def check_id(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("created_at")
    @classmethod
    def check_time(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)


class ContinuousComplianceState(ContinuousBaseModel):
    """지속적 컴플라이언스 엔진 런타임 상태 모델 (Section 53)."""
    last_processed_change: Optional[str] = Field(default=None, description="마지막 처리된 변경 ID")
    current_repository_snapshot: Optional[str] = Field(default=None, description="현재 저장소 스냅샷 ID")
    pending_reassessments: List[str] = Field(default_factory=list, description="대기 중인 재평가 요구사항 목록")
    last_assessment_run: Optional[str] = Field(default=None, description="마지막 재평가 실행 시각")
    last_delta: Optional[str] = Field(default=None, description="마지막 도출된 델타 ID")
    engine_version: str = Field(default="1.0", description="엔진 버전")


class ChangeBatch(ContinuousBaseModel):
    """일괄 처리 변경 묶음 모델 (Section 41)."""
    batch_id: str = Field(description="배치 식별자")
    change_ids: List[str] = Field(default_factory=list, description="포함된 변경 ID 목록")
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="배치 감지 시각",
    )
    source_window: Optional[str] = Field(default=None, description="수집 윈도우")

    @field_validator("batch_id")
    @classmethod
    def check_id(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


# ---------------------------------------------------------------------------
# 기존 하위 호환성 유지 모델 (Step 6 및 기존 테스트 보존)
# ---------------------------------------------------------------------------

class ChangeClassification(str, Enum):
    """변경사항의 보안/컴플라이언스 영향 분류"""
    SECURITY_RELEVANT = "SECURITY_RELEVANT"
    COMPLIANCE_RELEVANT = "COMPLIANCE_RELEVANT"
    NON_SECURITY = "NON_SECURITY"
    UNKNOWN = "UNKNOWN"


class RiskChangeType(str, Enum):
    """재평가 결과 위험 변동 유형"""
    RISK_INCREASED = "RISK_INCREASED"
    RISK_DECREASED = "RISK_DECREASED"
    RISK_UNCHANGED = "RISK_UNCHANGED"
    NEW_RISK = "NEW_RISK"
    RISK_RESOLVED = "RISK_RESOLVED"


class ContinuousStatus(str, Enum):
    """지속적 컴플라이언스 모니터링 수명주기 상태"""
    MONITORING = "MONITORING"
    CHANGE_DETECTED = "CHANGE_DETECTED"
    IMPACT_ANALYZED = "IMPACT_ANALYZED"
    REASSESSMENT_REQUIRED = "REASSESSMENT_REQUIRED"
    REASSESSING = "REASSESSING"
    RISK_CHANGED = "RISK_CHANGED"
    ALERTED = "ALERTED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"
    RESOLVED = "RESOLVED"


class TrendDirection(str, Enum):
    """컴플라이언스 건전성 추세 방향"""
    IMPROVING = "IMPROVING"
    STABLE = "STABLE"
    DEGRADING = "DEGRADING"
    VOLATILE = "VOLATILE"


class NormalizedChangeEvent(BaseModel):
    """다양한 클라우드 및 소스로부터 정규화된 변경 이벤트 모델"""
    event_id: str = Field(..., description="이벤트 고유 식별자 (Deduplication 기준)")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = Field(..., description="이벤트 소스 (gcp, aws, azure, github, iam)")
    event_type: str = Field(..., description="이벤트 유형 (FIREWALL_CHANGED, IAM_CHANGED 등)")
    resource_type: str = Field(..., description="리소스 유형 (firewall_rule, service_account, bucket)")
    resource_id: str = Field(..., description="리소스 고유 ID/이름")
    change_type: ChangeType = Field(default=ChangeType.UPDATE, description="변경 유형")
    actor: str = Field(default="system", description="변경 수행 주체")
    environment: str = Field(default="production", description="배포 환경")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="추가 상세 메타데이터")
    classification: ChangeClassification = Field(default=ChangeClassification.UNKNOWN, description="보안/컴플라이언스 영향 분류")


class ControlImpactMapping(BaseModel):
    """이벤트 유형과 ISMS-P 통제항목 간의 영향 매핑 규칙"""
    event_type: str
    control_id: str
    mapping_type: str = "RULE"
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    base_impact_score: float = Field(default=75.0, ge=0.0, le=100.0)
    impact_level: str = "HIGH"


class ControlSnapshot(BaseModel):
    """통제항목별 과거 상태 및 위험 스냅샷 (Before/After 비교용)"""
    control_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = Field(..., description="감사 판정 상태 (PASS, FAIL, PARTIAL, NO_EVIDENCE)")
    risk_score: float = Field(..., description="정량적 위험 점수 (0-100)")
    evidence_hash: str = Field(default="", description="증적 데이터 해시값")
    evidence_ids: List[str] = Field(default_factory=list, description="연계된 증적 ID 목록")


class ContinuousAlert(BaseModel):
    """위험 급증 또는 신규 위험 발생 시 보안 담당자에게 전달되는 알림 모델"""
    alert_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    control_id: str
    change_event_id: str
    risk_before: float
    risk_after: float
    risk_delta: float
    priority: str
    message: str
    action_required: str
    status: str = "OPEN"


class ComplianceHealthSnapshot(BaseModel):
    """시계열 컴플라이언스 건전성 스냅샷"""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    health_score: float = Field(..., ge=0.0, le=100.0)
    average_risk: float
    total_controls: int
    failing_controls: int
