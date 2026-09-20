"""Closed-loop 시정조치 오케스트레이션(Remediation Orchestrator) 모듈입니다."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from secgrc.agent_security.audit import SecurityAuditLogger
from secgrc.closed_loop.models import (
    ClosedLoopStatus,
    RemediationActionModel,
    RemediationResult,
)
from secgrc.closed_loop.providers import MockRemediationProvider, RemediationProvider


class RemediationOrchestrator:
    """시정조치 계획, 승인 정책 검사, 안전 실행(DRY-RUN / SIMULATED)을 총괄하는 오케스트레이터입니다."""

    def __init__(
        self,
        provider: Optional[RemediationProvider] = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
    ):
        self.provider = provider or MockRemediationProvider()
        self.audit_logger = audit_logger or SecurityAuditLogger()

    def determine_approval_policy(self, risk_level: str) -> str:
        """위험도 등급에 따른 승인 요구 정책을 판정합니다.
        
        - CRITICAL / HIGH: REQUIRE_APPROVAL (CISO/보안관리자 결재 필수)
        - MEDIUM: POLICY_BASED (사전 정의된 화이트리스트 정책 기반)
        - LOW / INFO: REPORT_ONLY (결재 없이 조치 또는 리포트 전용)
        """
        lvl = str(risk_level).upper()
        if lvl in ("CRITICAL", "HIGH"):
            return "REQUIRE_APPROVAL"
        elif lvl == "MEDIUM":
            return "POLICY_BASED"
        else:
            return "REPORT_ONLY"

    def plan_remediations(
        self,
        findings: List[Any],
        risks: List[Any],
        scan_id: str = "SCAN-001",
    ) -> List[RemediationActionModel]:
        """발견된 보안 취약점과 위험 평가 결과를 매핑하여 종합 조치 계획을 수립합니다."""
        actions: List[RemediationActionModel] = []
        risk_map: Dict[str, Any] = {}
        for r in risks:
            cid = getattr(r, "control_id", "") if hasattr(r, "control_id") else r.get("control_id", "")
            if cid:
                risk_map[cid] = r

        for f in findings:
            cid = f.get("control_id") if isinstance(f, dict) else getattr(f, "control_id", "ISMS-P-UNKNOWN")
            r_obj = risk_map.get(cid)

            risk_id = "RSK-DEFAULT"
            risk_level = "HIGH"
            if r_obj:
                risk_id = getattr(r_obj, "risk_id", "RSK-001") if hasattr(r_obj, "risk_id") else r_obj.get("risk_id", "RSK-001")
                risk_level = getattr(r_obj, "severity", "HIGH") if hasattr(r_obj, "severity") else r_obj.get("severity", "HIGH")

            # Provider를 통한 표준 조치 계획 도출
            action = self.provider.plan(f, scan_id=scan_id, risk_id=risk_id)
            policy = self.determine_approval_policy(risk_level)
            action.required_approval = (policy in ("REQUIRE_APPROVAL", "POLICY_BASED"))
            actions.append(action)

        return actions

    def execute_actions(
        self,
        actions: List[RemediationActionModel],
        approval_status: str,
        execution_mode: str = "DRY_RUN",
        scan_id: str = "SCAN-001",
    ) -> Tuple[List[RemediationResult], ClosedLoopStatus]:
        """승인 상태와 실행 모드(DRY_RUN vs SIMULATED)를 검증한 후 조치를 실행합니다."""
        results: List[RemediationResult] = []

        # 전체 승인 상태 검사
        requires_approval = any(a.required_approval for a in actions)
        if requires_approval and approval_status == "REJECTED":
            self.audit_logger.log_event(
                event="APPROVAL_REJECTED",
                agent_id="closed-loop-agent",
                details={"scan_id": scan_id, "reason": "Human approval was rejected"},
            )
            for a in actions:
                a.status = "REJECTED"
                results.append(
                    RemediationResult(
                        action_id=a.action_id,
                        status="APPROVAL_REJECTED",
                        execution_mode="BLOCKED",
                        details="Action blocked: human approval was rejected",
                    )
                )
            return results, ClosedLoopStatus.REMEDIATION_FAILED

        if requires_approval and approval_status != "APPROVED":
            self.audit_logger.log_event(
                event="APPROVAL_REQUIRED",
                agent_id="closed-loop-agent",
                details={"scan_id": scan_id, "status": "Pending approval for critical/high actions"},
            )
            for a in actions:
                a.status = "PENDING_APPROVAL"
                results.append(
                    RemediationResult(
                        action_id=a.action_id,
                        status="SKIPPED",
                        execution_mode="BLOCKED",
                        details="Action pending: awaiting human approval",
                    )
                )
            return results, ClosedLoopStatus.AWAITING_APPROVAL

        # 승인 완료 또는 승인 불필요 항목 실행
        all_succeeded = True
        for a in actions:
            # 개별 실행
            res = self.provider.execute(a, mode=execution_mode)
            results.append(res)
            if res.status == "FAILED":
                all_succeeded = False
                self.audit_logger.log_event(
                    event="REMEDIATION_FAILED",
                    agent_id="closed-loop-agent",
                    details={"action_id": a.action_id, "error": res.details},
                )

        final_status = ClosedLoopStatus.REMEDIATED if all_succeeded else ClosedLoopStatus.REMEDIATION_FAILED
        return results, final_status
