"""Closed-loop Security의 핵심 데이터 모델 및 상태 열거형 정의 모듈입니다."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ClosedLoopStatus(str, Enum):
    """Closed-loop 전체 프로세스 상태"""
    OPEN = "OPEN"
    REMEDIATION_PLANNED = "REMEDIATION_PLANNED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REMEDIATED = "REMEDIATED"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    VERIFIED = "VERIFIED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    RISK_REMAINING = "RISK_REMAINING"
    VERIFIED_WITH_RESIDUAL_RISK = "VERIFIED_WITH_RESIDUAL_RISK"


class VerificationStatus(str, Enum):
    """조치 후 재검증 결과 상태"""
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    FAILED = "FAILED"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"
    VERIFIED_WITH_RESIDUAL_RISK = "VERIFIED_WITH_RESIDUAL_RISK"
    RISK_REMAINING = "RISK_REMAINING"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"


class RemediationActionModel(BaseModel):
    """시정조치 액션 모델 (Remediation Action Model)"""
    action_id: str = Field(..., description="멱등성 보장을 위한 고유 조치 ID")
    risk_id: str = Field(..., description="연관된 위험 ID")
    control_id: str = Field(..., description="연관된 ISMS-P 통제 항목 ID")
    action_type: str = Field(..., description="조치 유형 (예: RESTRICT_PUBLIC_ACCESS)")
    target: str = Field(..., description="조치 대상 리소스 식별자")
    reason: str = Field(..., description="조치 사유 및 근거")
    expected_result: str = Field(..., description="조치 성공 시 기대 결과")
    impact: str = Field(default="", description="서비스 영향도 평가")
    rollback_plan: str = Field(default="", description="장애 발생 시 롤백 방안")
    required_approval: bool = Field(default=True, description="휴먼 승인 필요 여부")
    status: str = Field(default="PLANNED", description="조치 상태 (PLANNED, APPROVED, REJECTED, EXECUTED, SKIPPED, FAILED)")
    executed_at: Optional[str] = Field(default=None, description="실행 일시 (ISO-8601)")


class RemediationResult(BaseModel):
    """조치 실행 결과 모델"""
    action_id: str
    status: str  # SUCCESS, FAILED, ALREADY_REMEDIATED, SKIPPED, POLICY_DENIED, APPROVAL_REJECTED
    execution_mode: str  # DRY_RUN, SIMULATED, BLOCKED
    details: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    changes: Dict[str, Any] = Field(default_factory=dict)


class EvidenceDiffResult(BaseModel):
    """조치 전후 개별 증적 비교(Diff) 결과 모델"""
    finding_id: str
    resource_id: str = ""
    control_id: str = ""
    before_status: str
    after_status: str
    severity_before: str = ""
    severity_after: str = ""
    changed: bool = False
    change_type: str = "UNCHANGED"  # RESOLVED, UNRESOLVED, DEGRADED, UNCHANGED


class RiskDelta(BaseModel):
    """조치 전후 위험도 비교 및 감축률 모델"""
    risk_before: float = Field(..., description="조치 전 종합 위험 점수")
    risk_after: float = Field(..., description="조치 후 종합 위험 점수")
    risk_delta: float = Field(..., description="위험 점수 변화량 (risk_after - risk_before)")
    risk_reduction_pct: float = Field(..., description="위험 감축률 (%)")
    residual_risk_level: str = Field(..., description="잔여 위험 등급 (NONE, LOW, MEDIUM, HIGH, CRITICAL)")
