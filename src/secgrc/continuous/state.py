"""Continuous GRC Workflow & Step 25 Engine State Management.

Maintains runtime state and cryptographic state snapshots for continuous compliance.
"""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, TypedDict

from secgrc.audit.models import AuditResult
from secgrc.continuous.models import (
    ChangeClassification,
    ContinuousAlert,
    ContinuousComplianceState,
    ContinuousStatus,
    ControlImpactMapping,
    NormalizedChangeEvent,
    RiskChangeType,
    StateSnapshot,
)
from secgrc.models.evidence import NormalizedEvidence
from secgrc.risk.models import RiskAssessment


# ---------------------------------------------------------------------------
# Step 25 Continuous Compliance State & Snapshot Manager
# ---------------------------------------------------------------------------

class ContinuousComplianceStateManager:
    """Step 25 지속적 컴플라이언스 엔진 상태 및 스냅샷 관리자 (Section 52, 53)."""

    def __init__(self) -> None:
        self._state = ContinuousComplianceState(
            last_processed_change=None,
            current_repository_snapshot=None,
            pending_reassessments=[],
            last_assessment_run=None,
            last_delta=None,
            engine_version="1.0",
        )
        self._snapshots: Dict[str, StateSnapshot] = {}

    def get_state(self) -> ContinuousComplianceState:
        """현재 엔진 상태를 반환합니다."""
        return deepcopy(self._state)

    def update_state(
        self,
        last_processed_change: Optional[str] = None,
        pending_reassessments: Optional[List[str]] = None,
        last_assessment_run: Optional[str] = None,
        last_delta: Optional[str] = None,
    ) -> ContinuousComplianceState:
        """엔진 상태를 갱신합니다."""
        updates: Dict[str, Any] = {}
        if last_processed_change is not None:
            updates["last_processed_change"] = last_processed_change
        if pending_reassessments is not None:
            updates["pending_reassessments"] = pending_reassessments
        if last_assessment_run is not None:
            updates["last_assessment_run"] = last_assessment_run
        if last_delta is not None:
            updates["last_delta"] = last_delta

        self._state = self._state.model_copy(update=updates)
        return deepcopy(self._state)

    def create_snapshot(
        self,
        snapshot_id: str,
        entities: Optional[List[Any]] = None,
        assessments: Optional[List[Any]] = None,
        risks: Optional[List[Any]] = None,
        controls: Optional[List[Any]] = None,
        evidences: Optional[List[Any]] = None,
    ) -> StateSnapshot:
        """엔진 전후 무결성 검증을 위한 해시 스냅샷을 생성합니다 (Section 52)."""
        now_iso = datetime.now(timezone.utc).isoformat()
        
        def _hash_list(items: Optional[List[Any]]) -> str:
            if not items:
                return hashlib.sha256(b"empty").hexdigest()[:16]
            str_items = sorted([str(i) for i in items])
            return hashlib.sha256("".join(str_items).encode("utf-8")).hexdigest()[:16]

        snap = StateSnapshot(
            snapshot_id=snapshot_id,
            created_at=now_iso,
            entities_hash=_hash_list(entities),
            relationships_hash=hashlib.sha256(b"relationships").hexdigest()[:16],
            assessment_hash=_hash_list(assessments),
            risk_hash=_hash_list(risks),
            control_hash=_hash_list(controls),
            evidence_hash=_hash_list(evidences),
        )
        self._snapshots[snap.snapshot_id] = deepcopy(snap)
        self._state = self._state.model_copy(update={"current_repository_snapshot": snap.snapshot_id})
        return snap

    def get_snapshot(self, snapshot_id: str) -> Optional[StateSnapshot]:
        """스냅샷을 조회합니다."""
        s = self._snapshots.get(snapshot_id)
        return deepcopy(s) if s else None

    def clear(self) -> None:
        """테스트 격리용 초기화."""
        self._snapshots.clear()
        self._state = ContinuousComplianceState()


default_state_manager = ContinuousComplianceStateManager()


# ---------------------------------------------------------------------------
# 기존 하위 호환성 유지 (Step 6 LangGraph 워크플로우 상태)
# ---------------------------------------------------------------------------

class ContinuousState(TypedDict, total=False):
    """Continuous GRC 에이전트 워크플로우의 수명주기 상태를 유지하는 TypedDict입니다."""
    event_raw: Dict[str, Any]
    event: NormalizedChangeEvent
    classification: ChangeClassification
    affected_controls: List[ControlImpactMapping]
    impact_score: float
    impact_level: str
    targeted_evidence: List[NormalizedEvidence]
    targeted_audit: List[AuditResult]
    targeted_risk: List[RiskAssessment]
    risk_before: float
    risk_after: float
    risk_delta: float
    risk_change_type: RiskChangeType
    alert: Optional[ContinuousAlert]
    ai_analysis: Dict[str, Any]
    routing_decision: str
    continuous_status: ContinuousStatus
    history: List[Dict[str, Any]]
    errors: List[str]
