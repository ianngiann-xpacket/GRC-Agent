"""영향받는 통제항목(Affected Controls)만을 선별하여 선택적으로 재평가하는 TargetedEvaluator 모듈입니다."""

import copy
from typing import Any, Dict, List, Optional, Tuple
from secgrc.audit.engine import AuditEngine
from secgrc.audit.models import AuditResult
from secgrc.continuous.models import NormalizedChangeEvent
from secgrc.models.evidence import NormalizedEvidence
from secgrc.risk.engine import RiskEngine
from secgrc.risk.models import RiskAssessment


class TargetedEvaluator:
    """전체 통제를 매번 전수 감사하지 않고, 이벤트에 의해 영향받는 통제 및 자산만을 결정론적으로 재평가합니다."""

    def __init__(
        self,
        audit_engine: Optional[AuditEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
    ):
        self.audit_engine = audit_engine or AuditEngine()
        self.risk_engine = risk_engine or RiskEngine()

    def generate_targeted_evidence(
        self,
        event: NormalizedChangeEvent,
        existing_evidence: List[NormalizedEvidence],
    ) -> List[NormalizedEvidence]:
        """변경 이벤트의 최신 상태를 반영하여 증적 목록을 갱신 또는 추가합니다."""
        evidence_list = [copy.deepcopy(e) for e in existing_evidence]

        # 이벤트의 리소스 ID와 일치하는 증적 찾기
        matched = False
        meta = event.metadata

        # 보안 상태 판정 (public_access, allUsers 등)
        is_failing = (
            meta.get("public_access") is True
            or meta.get("allUsers") is True
            or "0.0.0.0/0" in str(meta)
            or meta.get("uniform_bucket_level_access") is False
        )
        status_str = "FAIL" if is_failing else "PASS"
        severity_str = "HIGH" if is_failing else "LOW"

        default_ctrl = "ISMS-P-2.6.3"
        default_check = "compute_firewall_ssh_public"
        e_type_up = event.event_type.upper()
        if "IAM" in e_type_up:
            default_ctrl = "ISMS-P-2.5.3"
            default_check = "iam_sa_no_admin_privileges"
        elif "STORAGE" in e_type_up or "BUCKET" in e_type_up:
            default_ctrl = "ISMS-P-2.7.1"
            default_check = "storage_bucket_public_access"
        elif "LOGGING" in e_type_up or "AUDIT" in e_type_up:
            default_ctrl = "ISMS-P-2.9.2"
            default_check = "logging_bucket_retention"

        for ev in evidence_list:
            r_name = str(ev.get("resource_name") or "")
            r_uid = str(ev.get("resource_uid") or "")
            ch_id = str(ev.get("check_id") or "")
            if event.resource_id in (r_name, r_uid) or (default_check == ch_id):
                matched = True
                ev["status"] = status_str
                ev["severity"] = severity_str
                ev["description"] = f"{event.event_type} applied: {meta}"
                break

        # 기존 증적에 없는 신규 자산 생성(CREATE)인 경우 새 증적 생성
        if not matched:
            new_ev = NormalizedEvidence(
                finding_uid=f"dyn-{event.event_id}",
                resource_uid=event.resource_id,
                resource_name=event.resource_id,
                check_id=default_check,
                control_id=default_ctrl,
                status=status_str,
                severity=severity_str,
                description=f"Dynamically generated from {event.event_type}: {meta}",
            )
            evidence_list.append(new_ev)

        return evidence_list

    def evaluate_targeted(
        self,
        affected_control_ids: List[str],
        evidence_list: List[NormalizedEvidence],
    ) -> Tuple[List[AuditResult], List[RiskAssessment]]:
        """영향받는 통제 ID 목록에 대해서만 AuditEngine 및 RiskEngine을 실행합니다."""
        # 1. 전체 증적으로부터 감사 평가
        all_audits = self.audit_engine.assess(evidence_list)
        all_risks = self.risk_engine.assess(all_audits, evidence_list)

        # 2. affected_control_ids만 선별 필터링
        if not affected_control_ids:
            return [], []

        targeted_audits = [a for a in all_audits if a.control_id in affected_control_ids]
        targeted_risks = [r for r in all_risks if r.control_id in affected_control_ids]

        return targeted_audits, targeted_risks
