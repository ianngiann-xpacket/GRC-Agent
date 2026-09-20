"""결정론적 컴플라이언스 감사 엔진(AuditEngine) 모듈입니다.

LLM을 배제하고 엄격한 규칙 기반(Rule-based) 알고리즘으로
Prowler 증적(Evidence)을 ISMS-P 통제항목에 대조하여 객관적 감사 결과를 도출합니다.
"""

from typing import Any, Dict, List, Optional

from secgrc.audit.mapper import EvidenceMapper
from secgrc.audit.models import AuditResult, AuditSeverity, AuditStatus
from secgrc.knowledge.repository import ControlRepository
from secgrc.models.evidence import NormalizedEvidence

SEVERITY_ORDER = {
    AuditSeverity.CRITICAL: 5,
    AuditSeverity.HIGH: 4,
    AuditSeverity.MEDIUM: 3,
    AuditSeverity.LOW: 2,
    AuditSeverity.INFO: 1,
    AuditSeverity.UNKNOWN: 0,
}


class AuditEngine:
    """결정론적(Rule-based) ISMS-P 컴플라이언스 평가 엔진."""

    def __init__(
        self,
        repo: Optional[ControlRepository] = None,
        mapper: Optional[EvidenceMapper] = None,
    ):
        """감사 엔진 초기화."""
        self.repo = repo if repo is not None else ControlRepository()
        self.mapper = mapper if mapper is not None else EvidenceMapper(self.repo)

    def _determine_max_severity(self, severities: List[str]) -> AuditSeverity:
        """문자열 리스트에서 가장 높은 AuditSeverity를 결정합니다."""
        max_sev = AuditSeverity.UNKNOWN
        max_weight = -1

        for s in severities:
            norm = str(s).strip().upper()
            try:
                candidate = AuditSeverity(norm)
            except ValueError:
                candidate = AuditSeverity.UNKNOWN

            weight = SEVERITY_ORDER.get(candidate, 0)
            if weight > max_weight:
                max_weight = weight
                max_sev = candidate

        return max_sev

    def assess_control(
        self, control_id: str, control_title: str, evidence_list: List[NormalizedEvidence]
    ) -> AuditResult:
        """단일 통제항목에 대해 매핑된 증적들을 기반으로 상태, 심각도, Rationale을 평가합니다.

        감사 원칙:
          - NO_EVIDENCE != PASS
          - MANUAL != PASS
          - Prowler PASS != ISMS-P 최종 확정
        """
        evidence_ids = [ev.get("finding_uid") or ev.get("evidence_id") for ev in evidence_list]

        # 1. 증거가 전혀 없는 경우 -> NO_EVIDENCE
        if not evidence_list:
            return AuditResult(
                control_id=control_id,
                control_title=control_title,
                framework="ISMS-P",
                evidence_ids=[],
                status=AuditStatus.NO_EVIDENCE,
                severity=AuditSeverity.UNKNOWN,
                mapping_type="none",
                mapping_confidence=0.0,
                rationale=(
                    f"Control {control_id} ({control_title}) is assessed as NO_EVIDENCE "
                    f"because no normalized evidence was mapped to the control."
                ),
                gaps=["No automated cloud evidence found for this control."],
                recommendations=[
                    "Collect manual evidence (e.g. policy document, approval history, audit report) for review."
                ],
            )

        # 매핑 신뢰도 결정 (증적들의 매핑 메타데이터 기반)
        has_explicit = any(
            ev.get("compliance") and ("isms" in str(ev.get("compliance")).lower() or "cis" in str(ev.get("compliance")).lower())
            for ev in evidence_list
        )
        if has_explicit:
            mapping_type = "explicit"
            mapping_confidence = 1.0
        elif any(ev.get("check_id") in self.mapper.CHECK_ID_HEURISTICS for ev in evidence_list):
            mapping_type = "rule"
            mapping_confidence = 0.9
        else:
            mapping_type = "keyword"
            mapping_confidence = 0.7

        pass_findings = [ev for ev in evidence_list if str(ev.get("status", "")).upper() == "PASS"]
        fail_findings = [ev for ev in evidence_list if str(ev.get("status", "")).upper() == "FAIL"]
        manual_findings = [
            ev for ev in evidence_list if str(ev.get("status", "")).upper() in ("MANUAL", "MUTED")
        ]

        # 2. 모든 증적이 PASS인 경우 -> PASS
        if pass_findings and not fail_findings and not manual_findings:
            return AuditResult(
                control_id=control_id,
                control_title=control_title,
                framework="ISMS-P",
                evidence_ids=evidence_ids,
                status=AuditStatus.PASS,
                severity=AuditSeverity.INFO,
                mapping_type=mapping_type,
                mapping_confidence=mapping_confidence,
                rationale=(
                    f"Control {control_id} ({control_title}) is assessed as PASS "
                    f"because all {len(pass_findings)} mapped Prowler finding(s) reported PASS. "
                    f"(Note: Prowler PASS verifies technical configuration, but administrative policy controls still apply.)"
                ),
                gaps=[],
                recommendations=["Maintain current technical baseline and continuous evidence monitoring."],
            )

        # 3. PASS와 FAIL이 혼재하는 경우 -> PARTIAL
        if pass_findings and fail_findings:
            fail_sevs = [ev.get("severity", "unknown") for ev in fail_findings]
            max_sev = self._determine_max_severity(fail_sevs)
            gaps = [
                f"[{ev.get('check_id')}]: {ev.get('description') or ev.get('title')}"
                for ev in fail_findings
            ]
            recomms = [
                ev.get("remediation")
                for ev in fail_findings
                if ev.get("remediation")
            ]

            return AuditResult(
                control_id=control_id,
                control_title=control_title,
                framework="ISMS-P",
                evidence_ids=evidence_ids,
                status=AuditStatus.PARTIAL,
                severity=max_sev,
                mapping_type=mapping_type,
                mapping_confidence=mapping_confidence,
                rationale=(
                    f"Control {control_id} ({control_title}) is assessed as PARTIAL "
                    f"because findings are mixed ({len(pass_findings)} PASS, {len(fail_findings)} FAIL with highest severity: {max_sev.value})."
                ),
                gaps=gaps,
                recommendations=recomms if recomms else ["Remediate failing resources to achieve full compliance."],
            )

        # 4. FAIL만 존재하는 경우 (또는 FAIL과 MANUAL 혼재) -> FAIL
        if fail_findings:
            fail_sevs = [ev.get("severity", "unknown") for ev in fail_findings]
            max_sev = self._determine_max_severity(fail_sevs)
            gaps = [
                f"[{ev.get('check_id')}]: {ev.get('description') or ev.get('title')}"
                for ev in fail_findings
            ]
            recomms = [
                ev.get("remediation")
                for ev in fail_findings
                if ev.get("remediation")
            ]

            return AuditResult(
                control_id=control_id,
                control_title=control_title,
                framework="ISMS-P",
                evidence_ids=evidence_ids,
                status=AuditStatus.FAIL,
                severity=max_sev,
                mapping_type=mapping_type,
                mapping_confidence=mapping_confidence,
                rationale=(
                    f"Control {control_id} ({control_title}) is assessed as FAIL "
                    f"because {len(fail_findings)} Prowler finding(s) reported FAIL with highest severity: {max_sev.value}."
                ),
                gaps=gaps,
                recommendations=recomms if recomms else ["Implement technical and administrative remediation."],
            )

        # 5. MANUAL 또는 MUTED 증적만 있는 경우 -> MANUAL
        manual_sevs = [ev.get("severity", "unknown") for ev in manual_findings]
        max_sev = self._determine_max_severity(manual_sevs)
        if max_sev == AuditSeverity.UNKNOWN:
            max_sev = AuditSeverity.MEDIUM

        gaps = [
            f"[{ev.get('check_id')}]: {ev.get('description') or ev.get('title')}"
            for ev in manual_findings
        ]
        recomms = [
            ev.get("remediation")
            for ev in manual_findings
            if ev.get("remediation")
        ]

        return AuditResult(
            control_id=control_id,
            control_title=control_title,
            framework="ISMS-P",
            evidence_ids=evidence_ids,
            status=AuditStatus.MANUAL,
            severity=max_sev,
            mapping_type=mapping_type,
            mapping_confidence=mapping_confidence,
            rationale=(
                f"Control {control_id} ({control_title}) is assessed as MANUAL "
                f"because {len(manual_findings)} finding(s) require manual review or are muted."
            ),
            gaps=gaps,
            recommendations=recomms if recomms else ["Perform manual audit inspection of the referenced resources."],
        )


    def assess(self, evidence_list: List[NormalizedEvidence]) -> List[AuditResult]:
        """정규화된 증적 리스트를 바탕으로 모든 통제항목을 평가합니다.

        Args:
            evidence_list: Prowler 증적 목록

        Returns:
            List[AuditResult]: 통제항목별 감사 결과 목록
        """
        grouped = self.mapper.group_by_control(evidence_list)
        results: List[AuditResult] = []

        for ctrl in self.repo.controls:
            ctrl_evidence = grouped.get(ctrl.control_id, [])
            audit_res = self.assess_control(ctrl.control_id, ctrl.title, ctrl_evidence)
            results.append(audit_res)

        return results

    def summary(self, results: List[AuditResult]) -> Dict[str, Any]:
        """감사 결과 집계 통계를 산출합니다.

        Args:
            results: 통제항목별 감사 결과 목록

        Returns:
            Dict[str, Any]: 요약 통계 딕셔너리
        """
        stats: Dict[str, Any] = {
            "total_controls": len(results),
            "pass": sum(1 for r in results if r.status == AuditStatus.PASS),
            "fail": sum(1 for r in results if r.status == AuditStatus.FAIL),
            "partial": sum(1 for r in results if r.status == AuditStatus.PARTIAL),
            "manual": sum(1 for r in results if r.status == AuditStatus.MANUAL),
            "no_evidence": sum(1 for r in results if r.status == AuditStatus.NO_EVIDENCE),
            "critical": sum(1 for r in results if r.severity == AuditSeverity.CRITICAL),
            "high": sum(1 for r in results if r.severity == AuditSeverity.HIGH),
            "medium": sum(1 for r in results if r.severity == AuditSeverity.MEDIUM),
            "low": sum(1 for r in results if r.severity == AuditSeverity.LOW),
        }
        return stats
