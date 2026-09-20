"""Before/After 스냅샷 비교, 위험 변동 감지 및 상관분석(Correlation)을 수행하는 ContinuousRiskMonitor 모듈입니다."""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from secgrc.audit.models import AuditResult
from secgrc.continuous.alert import AlertManager
from secgrc.continuous.models import (
    ContinuousAlert,
    ControlSnapshot,
    NormalizedChangeEvent,
    RiskChangeType,
)
from secgrc.risk.models import RiskAssessment, RiskLevel


class ContinuousRiskMonitor:
    """통제항목별 과거 스냅샷 관리, 실시간 위험 변동 감지, 임계치 초과 시 경보 생성 및 다중 이벤트 상관분석을 담당합니다."""

    def __init__(self, alert_manager: Optional[AlertManager] = None):
        self.alert_manager = alert_manager or AlertManager()
        # control_id별 스냅샷 이력
        self._snapshots: Dict[str, List[ControlSnapshot]] = {}
        self._seed_default_snapshots()

    def _seed_default_snapshots(self):
        """기본 베이스라인 스냅샷 초기화"""
        now = datetime.now(timezone.utc).isoformat()
        self.save_snapshot("ISMS-P-2.6.3", "PASS", 22.0, "hash-fw-init", ["init-fw"])
        self.save_snapshot("ISMS-P-2.5.2", "PASS", 18.0, "hash-iam-init", ["init-iam"])
        self.save_snapshot("ISMS-P-2.7.1", "PASS", 15.0, "hash-gcs-init", ["init-gcs"])
        self.save_snapshot("ISMS-P-2.9.2", "PASS", 20.0, "hash-log-init", ["init-log"])

    def save_snapshot(
        self,
        control_id: str,
        status: str,
        risk_score: float,
        evidence_hash: str = "",
        evidence_ids: Optional[List[str]] = None,
    ) -> ControlSnapshot:
        """통제항목의 현재 평가 상태를 스냅샷으로 영속 저장합니다."""
        snap = ControlSnapshot(
            control_id=control_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status=status.upper(),
            risk_score=round(float(risk_score), 2),
            evidence_hash=evidence_hash or hashlib.md5(f"{control_id}:{status}:{risk_score}".encode()).hexdigest(),
            evidence_ids=evidence_ids or [],
        )
        if control_id not in self._snapshots:
            self._snapshots[control_id] = []
        self._snapshots[control_id].append(snap)
        return snap

    def get_latest_snapshot(self, control_id: str) -> Optional[ControlSnapshot]:
        """해당 통제항목의 가장 최근 스냅샷을 반환합니다."""
        history = self._snapshots.get(control_id, [])
        return history[-1] if history else None

    def get_history(self, control_id: str) -> List[ControlSnapshot]:
        """해당 통제항목의 스냅샷 이력을 시간순으로 반환합니다."""
        return list(self._snapshots.get(control_id, []))

    @staticmethod
    def classify_risk_change(
        before_status: str,
        after_status: str,
        risk_before: float,
        risk_after: float,
    ) -> RiskChangeType:
        """이전 상태와 비교하여 위험 변동 유형을 분류합니다.
        
        - NEW_RISK: 과거 PASS/NO_EVIDENCE 였으나 현재 고위험(>=40) 또는 결함 발생
        - RISK_RESOLVED: 과거 FAIL 이었으나 현재 PASS
        - RISK_INCREASED: risk_after > risk_before
        - RISK_DECREASED: risk_after < risk_before
        - RISK_UNCHANGED: risk_after == risk_before
        """
        b_st = before_status.upper()
        a_st = after_status.upper()
        b_risk = round(risk_before, 2)
        a_risk = round(risk_after, 2)

        # 1. 완전 해결 검증 (결정론적 Re-audit 결과 기준)
        if b_st in ("FAIL", "NON_COMPLIANT") and a_st in ("PASS", "COMPLIANT"):
            return RiskChangeType.RISK_RESOLVED

        # 2. 신규 위험 탐지
        if b_risk < 30.0 and a_risk >= 40.0:
            return RiskChangeType.NEW_RISK

        # 3. 위험 점수 증감 비교
        if a_risk > b_risk:
            return RiskChangeType.RISK_INCREASED
        elif a_risk < b_risk:
            return RiskChangeType.RISK_DECREASED
        return RiskChangeType.RISK_UNCHANGED

    def evaluate_change_and_alert(
        self,
        event: NormalizedChangeEvent,
        control_id: str,
        after_status: str,
        after_risk_score: float,
    ) -> Tuple[RiskChangeType, Optional[ContinuousAlert], float]:
        """단일 통제항목의 Before 스냅샷과 비교하여 변동을 감지하고, 임계치 초과 시 알림을 생성합니다."""
        before_snap = self.get_latest_snapshot(control_id)
        if before_snap:
            b_st = before_snap.status
            b_risk = before_snap.risk_score
        else:
            b_st = "PASS"
            b_risk = 22.0

        change_type = self.classify_risk_change(
            before_status=b_st,
            after_status=after_status,
            risk_before=b_risk,
            risk_after=after_risk_score,
        )

        delta = round(after_risk_score - b_risk, 2)

        # 임계치 검사: 20점 이상 급증하거나 고위험군 진입 시 알림 생성
        alert: Optional[ContinuousAlert] = None
        should_alert = (
            delta >= 20.0
            or (b_risk < 40.0 and after_risk_score >= 40.0)
            or (b_risk < 70.0 and after_risk_score >= 70.0)
            or change_type == RiskChangeType.NEW_RISK
        )

        if should_alert:
            priority = "P1" if after_risk_score >= 80.0 else ("P2" if after_risk_score >= 60.0 else "P3")
            msg = (
                f"Continuous GRC Alert: Risk increased on {control_id} "
                f"({b_risk} -> {after_risk_score}, Delta: +{delta}) due to {event.event_type} on {event.resource_id}."
            )
            action = "Immediate human review & mitigation required" if priority == "P1" else "Human review required"
            alert = self.alert_manager.create_alert(
                control_id=control_id,
                change_event_id=event.event_id,
                risk_before=b_risk,
                risk_after=after_risk_score,
                message=msg,
                priority=priority,
                action_required=action,
            )

        # 새로운 After 상태를 스냅샷으로 기록
        self.save_snapshot(control_id, after_status, after_risk_score, evidence_hash=event.event_id)

        return change_type, alert, b_risk

    @staticmethod
    def correlate_events(events: List[NormalizedChangeEvent]) -> Dict[str, Any]:
        """여러 이벤트가 복합적으로 보안 위험을 야기하는지 상관분석(Correlation)합니다.
        
        보안 가드레일:
        - AI 또는 시스템은 침해 사고(Compromise)를 단정하지 않고,
        - OBSERVED (관찰된 사실) vs INFERRED (추론된 노출도) vs NOT OBSERVED (관찰되지 않은 침해)를 엄격히 분리합니다.
        """
        sec_events = [e for e in events if e.classification != "NON_SECURITY"]

        types = {e.event_type for e in sec_events}
        has_fw = any("FIREWALL" in t for t in types)
        has_iam = any("IAM" in t for t in types)
        has_log = any("LOGGING" in t for t in types)

        is_coordinated = (len(sec_events) >= 2) and (has_fw or has_iam)

        observed_facts = [
            f"Event {e.event_id}: {e.event_type} on resource {e.resource_id} by {e.actor}"
            for e in sec_events
        ]

        if is_coordinated:
            inference = (
                "Multiple security-relevant configuration changes occurred concurrently. "
                "The combined changes (e.g. access expansion with privilege modifications) may increase attack surface exposure."
            )
        else:
            inference = "Isolated configuration change observed. Routine administrative review recommended."

        return {
            "correlated_event_count": len(sec_events),
            "is_potential_coordinated_degradation": is_coordinated,
            "OBSERVED": observed_facts,
            "INFERRED": inference,
            "NOT_OBSERVED": "No evidence of active exploit or adversarial compromise.",
        }
