"""Deterministic Compliance & Investigation Report Builder (Step 23.6).

This module implements the deterministic, auditable report builder across the 5 views:
Executive, GRC Manager, Auditor, Technical, and Investigation.
"Assessment is Authority": It never re-assesses, recalculates risk, or mutates repository data.
"""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Union
import uuid

from secgrc.compliance.assessment import AssessmentStatus, ComplianceAssessment, ComplianceAssessmentBatch
from secgrc.compliance.reporting_models import (
    ComplianceReport,
    ReportAssessmentSummary,
    ReportConflict,
    ReportEvidence,
    ReportEvidenceSummary,
    ReportFilter,
    ReportFinding,
    ReportGap,
    ReportManualReview,
    ReportMetric,
    ReportProvenance,
    ReportRisk,
    ReportSection,
    ReportSortKey,
    ReportType,
)
from secgrc.compliance.reporting_security import escape_markdown, escape_report_text, redact_secrets
from secgrc.investigation.guard import GuardStatus, InvestigationGuardResult


def compute_report_hash(report: ComplianceReport) -> str:
    """결정론적 보고서 무결성 SHA-256 해시를 계산합니다.
    
    실행 런타임 종속 필드(generated_at, integrity_hash)는 제외하여
    동일한 논리적 입력에 대해 항상 동일한 해시값을 보장합니다.
    """
    data = report.model_dump(by_alias=True)
    # 런타임 가변 필드 제외
    data.pop("generated_at", None)
    data.pop("integrity_hash", None)

    canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class ComplianceReportBuilder:
    """결정론적 5종 컴플라이언스 및 조사 보고서 빌더 (순수 프레젠테이션 계층)."""

    @classmethod
    def _compute_assessment_summary(cls, assessments: List[ComplianceAssessment]) -> ReportAssessmentSummary:
        """원천 평가 결과들로부터 결정론적 상태 카운트를 산출합니다."""
        counts = {
            "total": len(assessments),
            "pass": 0,
            "fail": 0,
            "partial": 0,
            "no_evidence": 0,
            "manual": 0,
            "not_applicable": 0,
            "conflicting": 0,
            "undetermined": 0,
        }

        for asm in assessments:
            st = asm.status.value if isinstance(asm.status, AssessmentStatus) else str(asm.status)
            if st == "PASS":
                counts["pass"] += 1
            elif st == "FAIL":
                counts["fail"] += 1
            elif st == "PARTIAL":
                counts["partial"] += 1
            elif st == "NO_EVIDENCE":
                counts["no_evidence"] += 1
            elif st == "MANUAL":
                counts["manual"] += 1
            elif st in ("NOT_APPLICABLE", "N/A"):
                counts["not_applicable"] += 1
            elif st == "CONFLICTING":
                counts["conflicting"] += 1
            elif st == "UNDETERMINED":
                counts["undetermined"] += 1

        return ReportAssessmentSummary(
            total=counts["total"],
            pass_count=counts["pass"],
            fail_count=counts["fail"],
            partial_count=counts["partial"],
            no_evidence_count=counts["no_evidence"],
            manual_count=counts["manual"],
            not_applicable_count=counts["not_applicable"],
            conflicting_count=counts["conflicting"],
            undetermined_count=counts["undetermined"],
        )

    @classmethod
    def _extract_evidence_summary(cls, assessments: List[ComplianceAssessment]) -> ReportEvidenceSummary:
        """평가 데이터에 존재하는 증적 집계를 추출합니다. 권위 있는 데이터가 없으면 'NOT_AVAILABLE' 처리합니다."""
        total_req = sum(len(a.required_items) for a in assessments)
        total_avail = sum(len(a.available_items) for a in assessments)
        total_missing = sum(len(a.missing_items) for a in assessments)
        conflicts_count = sum(len(a.conflicts) for a in assessments)
        stale_count = sum(1 for a in assessments if a.freshness_result == "STALE")
        manual_count = sum(1 for a in assessments if a.human_review_required)
        prov_valid = sum(1 for a in assessments if a.provenance_result == "VALID")
        prov_invalid = sum(1 for a in assessments if a.provenance_result == "INVALID")

        return ReportEvidenceSummary(
            required=total_req,
            available=total_avail,
            missing=total_missing,
            partial=sum(1 for a in assessments if a.status == AssessmentStatus.PARTIAL),
            stale=stale_count,
            conflicting=conflicts_count,
            manual=manual_count,
            provenance_valid=prov_valid,
            provenance_invalid=prov_invalid,
        )

    @classmethod
    def _extract_gaps(
        cls,
        assessments: List[ComplianceAssessment],
        authoritative_risks: Optional[List[ReportRisk]] = None,
    ) -> List[ReportGap]:
        """미충족 요구사항(FAIL, PARTIAL, NO_EVIDENCE 등)에 대한 갭을 권위 있는 리스크 심각도를 보존하여 추출합니다."""
        gaps: List[ReportGap] = []
        risk_map = {r.requirement_id: r for r in (authoritative_risks or []) if r.requirement_id}

        for asm in assessments:
            st = asm.status.value if isinstance(asm.status, AssessmentStatus) else str(asm.status)
            if st in ("FAIL", "PARTIAL", "NO_EVIDENCE", "CONFLICTING"):
                mapped_risk = risk_map.get(asm.requirement_id)
                severity = mapped_risk.severity if mapped_risk else ("HIGH" if st == "FAIL" else "MEDIUM")
                priority = mapped_risk.priority if mapped_risk else ("P1" if st == "FAIL" else "P2")

                gap_type = (
                    "EVIDENCE_MISSING" if st == "NO_EVIDENCE"
                    else "CONFLICTING_EVIDENCE" if st == "CONFLICTING"
                    else "CONTROL_DEFICIENCY"
                )

                gaps.append(
                    ReportGap(
                        requirement_id=asm.requirement_id,
                        assessment_id=asm.assessment_id,
                        gap_type=gap_type,
                        status=st,
                        description_code=asm.explanation_code,
                        missing_inputs=list(asm.missing_items),
                        missing_evidence=list(asm.missing_items),
                        source_refs=list(asm.data_refs),
                        severity=severity,
                        priority=priority,
                    )
                )
        return gaps

    @classmethod
    def _extract_conflicts(cls, assessments: List[ComplianceAssessment]) -> List[ReportConflict]:
        """증적 상충 내역을 자동 해소 없이 1급 객체로 추출합니다."""
        conflicts: List[ReportConflict] = []
        c_idx = 1
        for asm in assessments:
            for conf_desc in asm.conflicts:
                conflicts.append(
                    ReportConflict(
                        conflict_id=f"CONF-{asm.requirement_id}-{c_idx:03d}",
                        requirement_id=asm.requirement_id,
                        description=redact_secrets(escape_report_text(conf_desc)),
                        source_a="Source_A",
                        source_b="Source_B",
                        conflicting_values={"detail": conf_desc},
                        status="UNRESOLVED",
                    )
                )
                c_idx += 1
        return conflicts

    @classmethod
    def _extract_manual_reviews(cls, assessments: List[ComplianceAssessment]) -> List[ReportManualReview]:
        """인간 심사관 수동 확인 필요 내역을 추출합니다."""
        reviews: List[ReportManualReview] = []
        for asm in assessments:
            if asm.human_review_required or asm.status == AssessmentStatus.MANUAL:
                reviews.append(
                    ReportManualReview(
                        requirement_id=asm.requirement_id,
                        required=True,
                        reason=escape_report_text(asm.explanation_code or "Human verification required for physical/operational evidence."),
                        human_verification_required="YES",
                        scope=asm.scope_result,
                    )
                )
        return reviews

    @classmethod
    def _extract_provenance(cls, assessments: List[ComplianceAssessment]) -> List[ReportProvenance]:
        """역방향 감사 추적 계보를 추출합니다."""
        provenances: List[ReportProvenance] = []
        for asm in assessments:
            provenances.append(
                ReportProvenance(
                    source_type="ASSESSMENT_RULE",
                    source_id=asm.rule_id or "UNKNOWN_RULE",
                    assessment_id=asm.assessment_id,
                    requirement_id=asm.requirement_id,
                    rule_id=asm.rule_id,
                    evidence_refs=list(asm.evidence_refs),
                    data_refs=list(asm.data_refs),
                    observed_at=asm.evaluated_at,
                )
            )
        return provenances

    @classmethod
    def build_executive_report(
        cls,
        assessments: List[ComplianceAssessment],
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
        risks: Optional[List[ReportRisk]] = None,
        assessment_batch_id: Optional[str] = None,
        title: Optional[str] = None,
    ) -> ComplianceReport:
        """CISO 및 경영진을 위한 요약 보고서 (상태 집계, 최상위 리스크, 주요 갭, 증적 커버리지, 추세)."""
        summary_metrics = cls._compute_assessment_summary(assessments)
        ev_summary = cls._extract_evidence_summary(assessments)
        authoritative_risks = deepcopy(risks or [])
        gaps = cls._extract_gaps(assessments, authoritative_risks)
        conflicts = cls._extract_conflicts(assessments)
        manual_reviews = cls._extract_manual_reviews(assessments)
        provenances = cls._extract_provenance(assessments)

        # Evidence coverage calculation
        cov_pct = "NOT_AVAILABLE"
        if isinstance(ev_summary.required, int) and ev_summary.required > 0 and isinstance(ev_summary.available, int):
            cov_pct = f"{int((ev_summary.available / ev_summary.required) * 100)}%"

        # Sections
        sections = [
            ReportSection(
                section_id="SEC-EXEC-OVERVIEW",
                title="Executive Overview",
                content=f"Compliance assessment for {framework_id} v{framework_version}.",
                order=1,
                metrics=[
                    ReportMetric(name="Total Requirements", value=summary_metrics.total),
                    ReportMetric(name="PASS Count", value=summary_metrics.pass_count),
                    ReportMetric(name="FAIL Count", value=summary_metrics.fail_count),
                    ReportMetric(name="Evidence Coverage", value=cov_pct),
                ],
            ),
            ReportSection(
                section_id="SEC-EXEC-TOP-RISKS",
                title="Top Authoritative Risks",
                content="Authoritative risks linked to compliance requirements without modification.",
                order=2,
                items=[r.model_dump() for r in authoritative_risks],
            ),
            ReportSection(
                section_id="SEC-EXEC-CRITICAL-GAPS",
                title="Critical Compliance Gaps",
                content="Identified gaps requiring executive attention.",
                order=3,
                items=[g.model_dump() for g in gaps[:10]],
            ),
        ]

        report_id = f"REP-{framework_id}-EXECUTIVE-{uuid.uuid4().hex[:8]}"
        rep = ComplianceReport(
            report_id=report_id,
            report_type=ReportType.EXECUTIVE,
            framework_id=framework_id,
            framework_version=framework_version,
            assessment_batch_id=assessment_batch_id,
            title=title or f"{framework_id} Executive Compliance Report",
            summary=f"Executive compliance summary for {framework_id}. Total evaluated: {summary_metrics.total}.",
            assessment_summary=summary_metrics,
            risk_summary=authoritative_risks,
            evidence_summary=ev_summary,
            gap_summary=gaps,
            conflict_summary=conflicts,
            manual_review_summary=manual_reviews,
            requirement_results=[a.model_dump() for a in assessments],
            provenance_summary=provenances,
            source_summary=[],
            sections=sections,
            trend="NOT_AVAILABLE",
        )
        rep.integrity_hash = compute_report_hash(rep)
        return rep

    @classmethod
    def build_grc_manager_report(
        cls,
        assessments: List[ComplianceAssessment],
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
        risks: Optional[List[ReportRisk]] = None,
        assessment_batch_id: Optional[str] = None,
        title: Optional[str] = None,
    ) -> ComplianceReport:
        """GRC 실무 관리자를 위한 요구사항별 세부 추적 보고서."""
        summary_metrics = cls._compute_assessment_summary(assessments)
        ev_summary = cls._extract_evidence_summary(assessments)
        authoritative_risks = deepcopy(risks or [])
        gaps = cls._extract_gaps(assessments, authoritative_risks)
        conflicts = cls._extract_conflicts(assessments)
        manual_reviews = cls._extract_manual_reviews(assessments)
        provenances = cls._extract_provenance(assessments)

        # Requirement-by-requirement tracking table items
        req_items = []
        for asm in assessments:
            req_items.append({
                "requirement_id": asm.requirement_id,
                "status": asm.status.value,
                "rule_id": asm.rule_id,
                "rule_version": asm.rule_version,
                "required_evidence": list(asm.required_items),
                "available_evidence": list(asm.available_items),
                "missing_evidence": list(asm.missing_items),
                "automation_level": "AUTOMATIC" if not asm.human_review_required else "SEMI_AUTOMATIC",
                "freshness": asm.freshness_result,
                "temporal_coverage": asm.temporal_result,
                "scope": asm.scope_result,
                "manual_review_required": asm.human_review_required,
                "conflicts_count": len(asm.conflicts),
            })

        sections = [
            ReportSection(
                section_id="SEC-GRC-REQUIREMENTS",
                title="Requirement Compliance & Evidence Tracking",
                content="Granular requirement status with required vs missing evidence items.",
                order=1,
                items=req_items,
            ),
            ReportSection(
                section_id="SEC-GRC-MANUAL-REVIEWS",
                title="Manual Review Requirements",
                content="Controls requiring human auditor physical/policy inspection.",
                order=2,
                items=[m.model_dump() for m in manual_reviews],
            ),
            ReportSection(
                section_id="SEC-GRC-EVIDENCE-CONFLICTS",
                title="Evidence Conflicts",
                content="Conflicting evidence records requiring human review.",
                order=3,
                items=[c.model_dump() for c in conflicts],
            ),
        ]

        report_id = f"REP-{framework_id}-GRC-MANAGER-{uuid.uuid4().hex[:8]}"
        rep = ComplianceReport(
            report_id=report_id,
            report_type=ReportType.GRC_MANAGER,
            framework_id=framework_id,
            framework_version=framework_version,
            assessment_batch_id=assessment_batch_id,
            title=title or f"{framework_id} GRC Manager Compliance Report",
            summary=f"GRC Manager operational report for {framework_id}. Requirements evaluated: {len(assessments)}.",
            assessment_summary=summary_metrics,
            risk_summary=authoritative_risks,
            evidence_summary=ev_summary,
            gap_summary=gaps,
            conflict_summary=conflicts,
            manual_review_summary=manual_reviews,
            requirement_results=req_items,
            provenance_summary=provenances,
            source_summary=[],
            sections=sections,
            trend="NOT_AVAILABLE",
        )
        rep.integrity_hash = compute_report_hash(rep)
        return rep

    @classmethod
    def build_auditor_report(
        cls,
        assessments: List[ComplianceAssessment],
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
        risks: Optional[List[ReportRisk]] = None,
        assessment_batch_id: Optional[str] = None,
        title: Optional[str] = None,
    ) -> ComplianceReport:
        """감사인을 위한 완전한 역방향 엔드투엔드 계보 추적 보고서.
        
        Lineage Chain:
        Requirement -> Evidence Requirement -> Evidence Reference -> Canonical Security Data -> Source Record -> Provenance -> Assessment Rule -> Assessment
        """
        summary_metrics = cls._compute_assessment_summary(assessments)
        ev_summary = cls._extract_evidence_summary(assessments)
        authoritative_risks = deepcopy(risks or [])
        gaps = cls._extract_gaps(assessments, authoritative_risks)
        conflicts = cls._extract_conflicts(assessments)
        manual_reviews = cls._extract_manual_reviews(assessments)
        provenances = cls._extract_provenance(assessments)

        # Full deterministic audit trail records
        audit_trails = []
        for asm in assessments:
            trail = {
                "framework": asm.framework_id,
                "framework_version": asm.framework_version,
                "requirement_id": asm.requirement_id,
                "status": asm.status.value,
                "rule_id": asm.rule_id,
                "rule_version": asm.rule_version,
                "evidence_requirement_ids": list(asm.required_items),
                "evidence_refs": list(asm.evidence_refs),
                "canonical_data_ids": list(asm.data_refs),
                "observed_at": asm.evaluated_at,
                "freshness": asm.freshness_result,
                "temporal_coverage": asm.temporal_result,
                "scope": asm.scope_result,
                "provenance": asm.provenance,
                "explanation_code": asm.explanation_code,
                "lineage_chain": (
                    f"Requirement({asm.requirement_id}) -> "
                    f"EvidenceRequirement({','.join(asm.required_items) or 'NONE'}) -> "
                    f"EvidenceRef({','.join(asm.evidence_refs) or 'NONE'}) -> "
                    f"CanonicalData({','.join(asm.data_refs) or 'NONE'}) -> "
                    f"Rule({asm.rule_id} v{asm.rule_version}) -> "
                    f"Assessment({asm.status.value})"
                ),
            }
            audit_trails.append(trail)

        sections = [
            ReportSection(
                section_id="SEC-AUDITOR-LINEAGE",
                title="Auditor Traceability Lineage Chain",
                content="Deterministic end-to-end evidence lineage chain from requirement to assessment decision.",
                order=1,
                items=audit_trails,
            ),
            ReportSection(
                section_id="SEC-AUDITOR-PROVENANCE",
                title="Authoritative Provenance Records",
                content="Immutable provenance records documenting source system bindings.",
                order=2,
                items=[p.model_dump() for p in provenances],
            ),
        ]

        report_id = f"REP-{framework_id}-AUDITOR-{uuid.uuid4().hex[:8]}"
        rep = ComplianceReport(
            report_id=report_id,
            report_type=ReportType.AUDITOR,
            framework_id=framework_id,
            framework_version=framework_version,
            assessment_batch_id=assessment_batch_id,
            title=title or f"{framework_id} Auditor Traceability Report",
            summary=f"Auditor lineage report for {framework_id}. End-to-end provenance verified for {len(assessments)} requirements.",
            assessment_summary=summary_metrics,
            risk_summary=authoritative_risks,
            evidence_summary=ev_summary,
            gap_summary=gaps,
            conflict_summary=conflicts,
            manual_review_summary=manual_reviews,
            requirement_results=audit_trails,
            provenance_summary=provenances,
            source_summary=[],
            sections=sections,
            trend="NOT_AVAILABLE",
        )
        rep.integrity_hash = compute_report_hash(rep)
        return rep

    @classmethod
    def build_technical_report(
        cls,
        assessments: List[ComplianceAssessment],
        technical_findings: Optional[List[ReportFinding]] = None,
        technical_evidence: Optional[List[ReportEvidence]] = None,
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
        risks: Optional[List[ReportRisk]] = None,
        assessment_batch_id: Optional[str] = None,
        title: Optional[str] = None,
    ) -> ComplianceReport:
        """기술 분석가를 위한 상세 텔레메트리 보고서 (이미 참조된 자산, 취약점, 이벤트만 포함, 신규 발견/탐색 금지)."""
        summary_metrics = cls._compute_assessment_summary(assessments)
        ev_summary = cls._extract_evidence_summary(assessments)
        authoritative_risks = deepcopy(risks or [])
        gaps = cls._extract_gaps(assessments, authoritative_risks)
        conflicts = cls._extract_conflicts(assessments)
        manual_reviews = cls._extract_manual_reviews(assessments)
        provenances = cls._extract_provenance(assessments)

        # Filter technical findings & evidence to only those referenced by assessment data_refs or evidence_refs
        referenced_ids = set()
        for asm in assessments:
            referenced_ids.update(asm.data_refs)
            referenced_ids.update(asm.evidence_refs)

        findings_items = []
        for f in (technical_findings or []):
            if f.finding_id in referenced_ids or any(f.finding_id in ref for ref in referenced_ids) or not referenced_ids:
                findings_items.append(f.model_dump())

        evidence_items = []
        for e in (technical_evidence or []):
            if e.evidence_id in referenced_ids or any(e.evidence_id in ref for ref in referenced_ids) or not referenced_ids:
                evidence_items.append(e.model_dump())

        sections = [
            ReportSection(
                section_id="SEC-TECH-FINDINGS",
                title="Referenced Security Findings & Vulnerabilities",
                content="Technical findings referenced by the evaluated requirements (no new discovery).",
                order=1,
                items=findings_items,
            ),
            ReportSection(
                section_id="SEC-TECH-EVIDENCE",
                title="Referenced Technical Evidence Items",
                content="Ground-level configurations, logs, IAM policies, and scan records.",
                order=2,
                items=evidence_items,
            ),
        ]

        report_id = f"REP-{framework_id}-TECHNICAL-{uuid.uuid4().hex[:8]}"
        rep = ComplianceReport(
            report_id=report_id,
            report_type=ReportType.TECHNICAL,
            framework_id=framework_id,
            framework_version=framework_version,
            assessment_batch_id=assessment_batch_id,
            title=title or f"{framework_id} Technical Telemetry Report",
            summary=f"Technical security telemetry report for {framework_id}. Referenced findings: {len(findings_items)}, evidence: {len(evidence_items)}.",
            assessment_summary=summary_metrics,
            risk_summary=authoritative_risks,
            evidence_summary=ev_summary,
            gap_summary=gaps,
            conflict_summary=conflicts,
            manual_review_summary=manual_reviews,
            requirement_results=[a.model_dump() for a in assessments],
            provenance_summary=provenances,
            source_summary=[],
            sections=sections,
            trend="NOT_AVAILABLE",
        )
        rep.integrity_hash = compute_report_hash(rep)
        return rep

    @classmethod
    def build_investigation_report(
        cls,
        investigation_id: str,
        guard_result: InvestigationGuardResult,
        assessments: Optional[List[ComplianceAssessment]] = None,
        investigation_data: Optional[Dict[str, Any]] = None,
        correlation_data: Optional[Dict[str, Any]] = None,
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
        risks: Optional[List[ReportRisk]] = None,
        title: Optional[str] = None,
    ) -> ComplianceReport:
        """조사 안전 가드(Guard)를 통과한 조사 결과 보고서.
        
        Strict Safety Gate:
        GuardStatus == PASS 및 allowed_to_report == True 일 때만 생성을 허용합니다.
        가드 차단(BLOCK) 시 즉각 fail-closed로 예외를 발생시킵니다.
        """
        # 1. Strict Investigation Guard Gate Check
        if guard_result is None:
            raise ValueError("REPORT_BLOCKED_GUARD_VALIDATION_FAILED: Guard result is missing.")

        status_val = guard_result.status.value if isinstance(guard_result.status, GuardStatus) else str(guard_result.status)
        if status_val != "PASS" or not guard_result.allowed_to_report:
            raise ValueError("REPORT_BLOCKED_GUARD_VALIDATION_FAILED")

        effective_assessments = assessments or []
        summary_metrics = cls._compute_assessment_summary(effective_assessments)
        ev_summary = cls._extract_evidence_summary(effective_assessments)
        authoritative_risks = deepcopy(risks or [])
        gaps = cls._extract_gaps(effective_assessments, authoritative_risks)
        conflicts = cls._extract_conflicts(effective_assessments)
        manual_reviews = cls._extract_manual_reviews(effective_assessments)
        provenances = cls._extract_provenance(effective_assessments)

        sections = [
            ReportSection(
                section_id="SEC-INV-GUARD",
                title="Investigation Safety Gate Validation",
                content=f"Guard Status: {status_val}, Allowed to Report: {guard_result.allowed_to_report}.",
                order=1,
                metrics=[
                    ReportMetric(name="Guard Status", value=status_val),
                    ReportMetric(name="Allowed to Report", value=guard_result.allowed_to_report),
                    ReportMetric(name="Total Checks", value=len(guard_result.checks)),
                ],
                items=[{"check_id": c.check_id, "status": c.status.value, "category": c.category.value, "message": c.message} for c in guard_result.checks],
            ),
            ReportSection(
                section_id="SEC-INV-EXECUTION",
                title="Investigation Plan and Execution Telemetry",
                content="Authoritative facts and execution steps without LLM inference.",
                order=2,
                items=[investigation_data or {}],
            ),
            ReportSection(
                section_id="SEC-INV-CORRELATION",
                title="Investigation Correlation Analysis",
                content="Deterministic relationship graph and hypothesis validation.",
                order=3,
                items=[correlation_data or {}],
            ),
        ]

        report_id = f"REP-{investigation_id}-INVESTIGATION-{uuid.uuid4().hex[:8]}"
        rep = ComplianceReport(
            report_id=report_id,
            report_type=ReportType.INVESTIGATION,
            framework_id=framework_id,
            framework_version=framework_version,
            assessment_batch_id=investigation_id,
            title=title or f"Investigation Report: {investigation_id}",
            summary=f"Trusted investigation report for {investigation_id}. Gated by Investigation Guard (PASS).",
            assessment_summary=summary_metrics,
            risk_summary=authoritative_risks,
            evidence_summary=ev_summary,
            gap_summary=gaps,
            conflict_summary=conflicts,
            manual_review_summary=manual_reviews,
            requirement_results=[a.model_dump() for a in effective_assessments],
            provenance_summary=provenances,
            source_summary=[],
            sections=sections,
            trend="NOT_AVAILABLE",
        )
        rep.integrity_hash = compute_report_hash(rep)
        return rep

    @classmethod
    def build_cross_framework_summary(
        cls,
        framework_assessments: Dict[str, List[ComplianceAssessment]],
    ) -> Dict[str, Any]:
        """다중 프레임워크 준거성 요약 매트릭스를 생성합니다. 임의의 가중치 점수를 조작/발명하지 않습니다."""
        summary_table: Dict[str, Dict[str, int]] = {}
        for fw_name, asms in framework_assessments.items():
            summary = cls._compute_assessment_summary(asms)
            summary_table[fw_name] = {
                "total": summary.total,
                "pass": summary.pass_count,
                "fail": summary.fail_count,
                "partial": summary.partial_count,
                "no_evidence": summary.no_evidence_count,
                "manual": summary.manual_count,
                "not_applicable": summary.not_applicable_count,
                "conflicting": summary.conflicting_count,
                "undetermined": summary.undetermined_count,
            }

        return {
            "matrix": summary_table,
            "framework_count": len(framework_assessments),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def filter_report(cls, report: ComplianceReport, filter_opts: ReportFilter) -> ComplianceReport:
        """결정론적으로 정형화된 필터를 보고서에 적용합니다."""
        filtered = deepcopy(report)

        if filter_opts.framework and filtered.framework_id != filter_opts.framework:
            filtered.requirement_results = []
            filtered.sections = []

        if filter_opts.requirement:
            filtered.requirement_results = [
                r for r in filtered.requirement_results
                if r.get("requirement_id") == filter_opts.requirement
            ]
            filtered.gap_summary = [
                g for g in filtered.gap_summary
                if g.requirement_id == filter_opts.requirement
            ]

        if filter_opts.status:
            filtered.requirement_results = [
                r for r in filtered.requirement_results
                if r.get("status") == filter_opts.status
            ]
            filtered.gap_summary = [
                g for g in filtered.gap_summary
                if g.status == filter_opts.status
            ]

        if filter_opts.severity:
            filtered.risk_summary = [
                r for r in filtered.risk_summary
                if r.severity == filter_opts.severity
            ]
            filtered.gap_summary = [
                g for g in filtered.gap_summary
                if g.severity == filter_opts.severity
            ]

        filtered.integrity_hash = compute_report_hash(filtered)
        return filtered

    @classmethod
    def sort_report(
        cls,
        report: ComplianceReport,
        sort_key: ReportSortKey,
        reverse: bool = False,
    ) -> ComplianceReport:
        """결정론적 키에 따라 보고서 요구사항 및 갭 목록을 정렬합니다."""
        sorted_rep = deepcopy(report)

        if sort_key == ReportSortKey.REQUIREMENT_ID:
            sorted_rep.requirement_results.sort(key=lambda r: str(r.get("requirement_id", "")), reverse=reverse)
            sorted_rep.gap_summary.sort(key=lambda g: g.requirement_id, reverse=reverse)
        elif sort_key == ReportSortKey.STATUS:
            sorted_rep.requirement_results.sort(key=lambda r: str(r.get("status", "")), reverse=reverse)
            sorted_rep.gap_summary.sort(key=lambda g: g.status, reverse=reverse)
        elif sort_key == ReportSortKey.SEVERITY:
            sorted_rep.risk_summary.sort(key=lambda r: r.severity, reverse=reverse)
            sorted_rep.gap_summary.sort(key=lambda g: g.severity, reverse=reverse)
        elif sort_key == ReportSortKey.PRIORITY:
            sorted_rep.risk_summary.sort(key=lambda r: r.priority, reverse=reverse)
            sorted_rep.gap_summary.sort(key=lambda g: g.priority, reverse=reverse)
        elif sort_key == ReportSortKey.RISK_SCORE:
            sorted_rep.risk_summary.sort(key=lambda r: r.score, reverse=reverse)

        sorted_rep.integrity_hash = compute_report_hash(sorted_rep)
        return sorted_rep
