"""Closed-loop 재검증 및 잔여 위험 평가 엔진(VerificationEngine) 모듈입니다."""

import copy
from typing import Any, Dict, List, Optional

from secgrc.audit.engine import AuditEngine
from secgrc.audit.models import AuditResult, AuditSeverity, AuditStatus
from secgrc.closed_loop.models import (
    RiskDelta,
    VerificationStatus,
)
from secgrc.closed_loop.providers import MockRemediationProvider
from secgrc.models.evidence import NormalizedEvidence
from secgrc.risk.engine import RiskEngine
from secgrc.risk.models import RiskAssessment, RiskLevel


class VerificationEngine:
    """조치 후 수집된 증적을 기반으로 결정론적 재감사, 재위험평가, 5대 검증 규칙을 평가하는 엔진입니다."""

    def __init__(
        self,
        audit_engine: Optional[AuditEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
    ):
        self.audit_engine = audit_engine or AuditEngine()
        self.risk_engine = risk_engine or RiskEngine()

    @staticmethod
    def evaluate_verification_case(
        before_status: str,
        after_status: str,
        severity_before: str = "",
        severity_after: str = "",
    ) -> VerificationStatus:
        """5대 핵심 검증 규칙에 따라 단일 통제/항목의 검증 상태를 결정론적으로 판정합니다.

        규칙 1: Before FAIL -> After PASS ===> VERIFIED
        규칙 2: Before PARTIAL -> After PARTIAL ===> RISK_REMAINING
        규칙 3: Before FAIL -> After FAIL ===> REMEDIATION_FAILED
        규칙 4: Before NO_EVIDENCE -> After NO_EVIDENCE ===> NOT_VERIFIABLE
        규칙 5: Before CRITICAL -> After LOW ===> VERIFIED_WITH_RESIDUAL_RISK
        """
        b_st = str(before_status).upper()
        a_st = str(after_status).upper()
        b_sev = str(severity_before).upper()
        a_sev = str(severity_after).upper()

        # Case 4: 증적 부재 유지
        if b_st in ("NO_EVIDENCE", "NOT_FOUND", "NONE") and a_st in ("NO_EVIDENCE", "NOT_FOUND", "NONE"):
            return VerificationStatus.NOT_VERIFIABLE

        # Case 3: 실패 상태 유지
        if b_st in ("FAIL", "NON_COMPLIANT") and a_st in ("FAIL", "NON_COMPLIANT"):
            return VerificationStatus.REMEDIATION_FAILED

        # Case 2: 부분 준수 상태 유지 (위험 잔존)
        if b_st in ("PARTIAL", "MANUAL") and a_st in ("PARTIAL", "MANUAL"):
            return VerificationStatus.RISK_REMAINING

        # Case 5: 심각도가 CRITICAL에서 LOW/INFO로 대폭 완화되었으나 잔여 위험 존재
        if b_sev == "CRITICAL" and a_sev in ("LOW", "INFO", "NONE"):
            return VerificationStatus.VERIFIED_WITH_RESIDUAL_RISK

        # Case 1: 결함 해결 및 준수 달성
        if b_st in ("FAIL", "NON_COMPLIANT", "PARTIAL") and a_st in ("PASS", "COMPLIANT"):
            # 준수 달성되었으나 After 심각도가 MEDIUM 이상이면 잔여 위험 포함
            if a_sev in ("MEDIUM", "HIGH", "CRITICAL"):
                return VerificationStatus.VERIFIED_WITH_RESIDUAL_RISK
            return VerificationStatus.VERIFIED

        if a_st in ("PASS", "COMPLIANT"):
            return VerificationStatus.VERIFIED

        return VerificationStatus.PARTIALLY_VERIFIED

    @staticmethod
    def calculate_risk_delta(risk_before: float, risk_after: float) -> RiskDelta:
        """위험 점수 변화량 및 감축률, 잔여 위험 등급을 산출합니다."""
        b = round(float(risk_before), 2)
        a = round(float(risk_after), 2)
        delta = round(a - b, 2)

        if b > 0:
            reduction_pct = round(((b - a) / b) * 100.0, 1)
        else:
            reduction_pct = 0.0

        if a >= 80.0:
            res_level = "CRITICAL"
        elif a >= 60.0:
            res_level = "HIGH"
        elif a >= 40.0:
            res_level = "MEDIUM"
        elif a > 0.0:
            res_level = "LOW"
        else:
            res_level = "NONE"

        return RiskDelta(
            risk_before=b,
            risk_after=a,
            risk_delta=delta,
            risk_reduction_pct=reduction_pct,
            residual_risk_level=res_level,
        )

    def generate_verification_evidence(
        self,
        before_evidence: List[NormalizedEvidence],
        provider: MockRemediationProvider,
    ) -> List[NormalizedEvidence]:
        """MockRemediationProvider의 Synthetic State에 맞추어 Re-scan 증적을 생성합니다."""
        after_evidence: List[NormalizedEvidence] = []

        for ev in before_evidence:
            ev_copy = copy.deepcopy(ev)
            t_name = str(ev.get("resource_name") or "")
            t_uid = str(ev.get("resource_uid") or "")
            t_id = str(ev.get("resource_id") or "")

            st = None
            for candidate in (t_name, t_uid, t_id):
                if candidate and candidate in provider.synthetic_state:
                    st = provider.synthetic_state[candidate]
                    break

            # Synthetic 상태가 업데이트된 경우
            if st is not None:
                # 보안 설정이 준수(compliant) 상태로 변경되었는지 판정
                is_compliant = (
                    st.get("compliant") is True
                    or st.get("public_access") is False
                    or st.get("auto_rotate") is True
                    or st.get("uniform_bucket_level_access") is True
                    or st.get("require_ssl") is True
                    or st.get("allUsers") is False
                )
                if is_compliant:
                    ev_copy["status"] = "PASS"
                    ev_copy["severity"] = "LOW"
                    desc = ev_copy.get("description") or ev_copy.get("finding") or ""
                    ev_copy["description"] = f"{desc} [REMEDIATED & VERIFIED: Synthetic state compliant]"
                    ev_copy["status_extended"] = "Remediated by mock provider"
                    if "raw" in ev_copy and isinstance(ev_copy["raw"], dict):
                        ev_copy["raw"]["Status"] = "PASS"
                        ev_copy["raw"]["Severity"] = "low"

            after_evidence.append(ev_copy)

        return after_evidence

    def verify(
        self,
        before_evidence: List[NormalizedEvidence],
        after_evidence: List[NormalizedEvidence],
        initial_risk: Optional[List[RiskAssessment]] = None,
    ) -> Dict[str, Any]:
        """결정론적 재감사(Re-audit) 및 재위험평가(Recalculate Risk)를 수행하고 종합 판정을 도출합니다."""
        # 1. 결정론적 Re-audit 수행 (Prowler PASS != Automatically ISMS-P PASS 규칙 유지)
        verification_audit: List[AuditResult] = self.audit_engine.assess(after_evidence)

        # 2. 결정론적 Recalculate Risk 수행
        verification_risk: List[RiskAssessment] = self.risk_engine.assess(verification_audit, after_evidence)

        # 3. Before/After 점수 집계
        def _compute_max_or_top_risk(r_list: List[RiskAssessment]) -> float:
            if not r_list:
                return 0.0
            return max(r.risk_score for r in r_list)

        r_before = _compute_max_or_top_risk(initial_risk) if initial_risk else 0.0
        r_after = _compute_max_or_top_risk(verification_risk)

        risk_delta = self.calculate_risk_delta(r_before, r_after)

        # 4. 전체 검증 상태 종합 판정
        audit_statuses = [a.status for a in verification_audit]
        has_fail = any(s == AuditStatus.FAIL for s in audit_statuses)
        has_partial = any(s in (AuditStatus.PARTIAL, AuditStatus.MANUAL) for s in audit_statuses)
        all_pass = all(s in (AuditStatus.PASS, AuditStatus.NO_EVIDENCE) for s in audit_statuses)

        if has_fail:
            overall_status = VerificationStatus.REMEDIATION_FAILED
        elif has_partial or risk_delta.residual_risk_level in ("MEDIUM", "HIGH", "CRITICAL"):
            overall_status = VerificationStatus.VERIFIED_WITH_RESIDUAL_RISK
        elif all_pass:
            overall_status = VerificationStatus.VERIFIED
        else:
            overall_status = VerificationStatus.PARTIALLY_VERIFIED

        # 5. AI 감사관 역할 제한 설명 생성 (수치 결정 배제, 해설 및 다음 권고만)
        ai_explanation = {
            "why_risk_changed": f"Risk score changed from {risk_delta.risk_before} to {risk_delta.risk_after} (Delta: {risk_delta.risk_delta}, Reduction: {risk_delta.risk_reduction_pct}%).",
            "remaining_gaps": [
                f"{a.control_id} ({a.control_title}): {a.status.value}"
                for a in verification_audit
                if a.status != AuditStatus.PASS
            ],
            "next_remediation_recommendation": (
                "Review residual risks and schedule secondary audit approval."
                if risk_delta.residual_risk_level != "NONE"
                else "All identified controls are compliant. Ready to close."
            ),
        }

        return {
            "verification_audit": verification_audit,
            "verification_risk": verification_risk,
            "risk_delta": risk_delta,
            "verification_status": overall_status,
            "ai_explanation": ai_explanation,
        }
