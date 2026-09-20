"""Closed-loop Security 워크플로우 상태(State) 정의 모듈입니다."""

from typing import Any, Dict, List, Optional, TypedDict
from secgrc.audit.models import AuditResult
from secgrc.closed_loop.models import (
    ClosedLoopStatus,
    EvidenceDiffResult,
    RemediationActionModel,
    RemediationResult,
    RiskDelta,
    VerificationStatus,
)
from secgrc.models.evidence import NormalizedEvidence
from secgrc.risk.models import RiskAssessment


class ClosedLoopState(TypedDict, total=False):
    """Closed-loop Security의 전체 수명주기 상태를 유지하는 State Dict입니다."""

    # 1. 스캔 식별자 및 메타데이터
    scan_id: str
    framework: str
    provider: str
    evidence_path: str

    # 2. 초기 스캔 및 분석 계층 (Before)
    initial_evidence: List[NormalizedEvidence]
    initial_audit: List[AuditResult]
    initial_risk: List[RiskAssessment]

    # 3. 조치 계획 및 휴먼 승인 계층
    remediation_plan: List[RemediationActionModel]
    approval_status: str  # PENDING, APPROVED, REJECTED, NOT_REQUIRED
    approval_details: Dict[str, Any]
    remediation_result: List[RemediationResult]

    # 4. 재스캔 및 재검증 계층 (After)
    verification_evidence: List[NormalizedEvidence]
    verification_audit: List[AuditResult]
    verification_risk: List[RiskAssessment]

    # 5. 전후 비교 및 정량 위험 지표 (Risk Delta & Diff)
    evidence_diff: List[EvidenceDiffResult]
    risk_before: float
    risk_after: float
    risk_delta: float
    risk_reduction_pct: float
    residual_risk_level: str

    # 6. 최종 검증 및 Closed-loop 상태
    verification_status: VerificationStatus
    closed_loop_status: ClosedLoopStatus

    # 7. 제어 및 이력 관리
    cycle_count: int
    max_cycles: int
    execution_mode: str  # DRY_RUN, SIMULATED
    synthetic_state: Dict[str, Any]
    remediated_actions: List[str]
    history: List[Dict[str, Any]]
    errors: List[str]
    report: Dict[str, Any]
