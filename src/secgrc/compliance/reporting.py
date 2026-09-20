"""Compliance & Investigation Reporting Public APIs (Step 23.6).

This module provides high-level, read-only public functions to generate, query,
export (JSON / Markdown), and inspect compliance and investigation reports.
"""

from copy import deepcopy
import json
from typing import Any, Dict, List, Optional, Union

from secgrc.compliance.assessment import ComplianceAssessment
from secgrc.compliance.reporting_builder import ComplianceReportBuilder, compute_report_hash
from secgrc.compliance.reporting_history import ReportHistoryStore, default_report_history
from secgrc.compliance.reporting_models import (
    ComplianceReport,
    ReportEvidence,
    ReportFilter,
    ReportFinding,
    ReportRisk,
    ReportSortKey,
    ReportType,
)
from secgrc.compliance.reporting_security import escape_markdown, escape_report_text, redact_secrets
from secgrc.investigation.guard import InvestigationGuardResult


def generate_compliance_report(
    report_type: Union[ReportType, str],
    framework_id: str = "ISMS-P",
    framework_version: str = "2024-07",
    assessments: Optional[List[ComplianceAssessment]] = None,
    risks: Optional[List[ReportRisk]] = None,
    technical_findings: Optional[List[ReportFinding]] = None,
    technical_evidence: Optional[List[ReportEvidence]] = None,
    assessment_batch_id: Optional[str] = None,
    title: Optional[str] = None,
    history_store: Optional[ReportHistoryStore] = None,
) -> ComplianceReport:
    """컴플라이언스 평가 결과를 바탕으로 지정된 유형의 보고서를 결정론적으로 생성하고 이력에 불변 기록합니다."""
    type_val = report_type.value if isinstance(report_type, ReportType) else str(report_type).upper()
    effective_asms = assessments or []
    store = history_store or default_report_history

    if type_val == ReportType.EXECUTIVE.value:
        report = ComplianceReportBuilder.build_executive_report(
            assessments=effective_asms,
            framework_id=framework_id,
            framework_version=framework_version,
            risks=risks,
            assessment_batch_id=assessment_batch_id,
            title=title,
        )
    elif type_val == ReportType.GRC_MANAGER.value:
        report = ComplianceReportBuilder.build_grc_manager_report(
            assessments=effective_asms,
            framework_id=framework_id,
            framework_version=framework_version,
            risks=risks,
            assessment_batch_id=assessment_batch_id,
            title=title,
        )
    elif type_val == ReportType.AUDITOR.value:
        report = ComplianceReportBuilder.build_auditor_report(
            assessments=effective_asms,
            framework_id=framework_id,
            framework_version=framework_version,
            risks=risks,
            assessment_batch_id=assessment_batch_id,
            title=title,
        )
    elif type_val == ReportType.TECHNICAL.value:
        report = ComplianceReportBuilder.build_technical_report(
            assessments=effective_asms,
            technical_findings=technical_findings,
            technical_evidence=technical_evidence,
            framework_id=framework_id,
            framework_version=framework_version,
            risks=risks,
            assessment_batch_id=assessment_batch_id,
            title=title,
        )
    else:
        raise ValueError(f"Unsupported compliance report type: {report_type}. Use generate_investigation_report() for INVESTIGATION reports.")

    # Record in history store
    store.record(report)
    return report


def generate_investigation_report(
    investigation_id: str,
    guard_result: InvestigationGuardResult,
    assessments: Optional[List[ComplianceAssessment]] = None,
    investigation_data: Optional[Dict[str, Any]] = None,
    correlation_data: Optional[Dict[str, Any]] = None,
    framework_id: str = "ISMS-P",
    framework_version: str = "2024-07",
    risks: Optional[List[ReportRisk]] = None,
    title: Optional[str] = None,
    history_store: Optional[ReportHistoryStore] = None,
) -> ComplianceReport:
    """조사 가드 심사를 통과(PASS)한 조사 결과 보고서를 생성하고 이력에 기록합니다. 가드 차단 시 fail-closed로 예외가 발생합니다."""
    store = history_store or default_report_history

    report = ComplianceReportBuilder.build_investigation_report(
        investigation_id=investigation_id,
        guard_result=guard_result,
        assessments=assessments,
        investigation_data=investigation_data,
        correlation_data=correlation_data,
        framework_id=framework_id,
        framework_version=framework_version,
        risks=risks,
        title=title,
    )

    store.record(report)
    return report


def get_report(report_id: str, history_store: Optional[ReportHistoryStore] = None) -> Optional[ComplianceReport]:
    """이력 저장소에서 고유 식별자로 보고서를 조회합니다."""
    store = history_store or default_report_history
    return store.get(report_id)


def list_reports(
    report_type: Optional[Union[ReportType, str]] = None,
    framework_id: Optional[str] = None,
    history_store: Optional[ReportHistoryStore] = None,
) -> List[ComplianceReport]:
    """이력 저장소의 보고서 목록을 조건에 따라 조회합니다."""
    store = history_store or default_report_history
    reports = store.list_all()

    if report_type:
        type_val = report_type.value if isinstance(report_type, ReportType) else str(report_type).upper()
        reports = [r for r in reports if r.report_type == type_val]

    if framework_id:
        reports = [r for r in reports if r.framework_id == framework_id]

    return reports


def export_report_json(report: ComplianceReport, indent: int = 2) -> str:
    """보고서 객체를 안전한 JSON 형식 문자열로 직렬화합니다."""
    data = report.model_dump(by_alias=True)
    sanitized_data = redact_secrets(data)
    return json.dumps(sanitized_data, indent=indent, ensure_ascii=False)


def export_report_markdown(report: ComplianceReport) -> str:
    """보고서 객체를 표준 마크다운 형식으로 직렬화합니다."""
    asm_sum = report.assessment_summary
    lines = [
        f"# {escape_markdown(report.title)}",
        "",
        f"- **Report ID**: `{report.report_id}`",
        f"- **Report Type**: `{report.report_type.value}`",
        f"- **Framework**: `{report.framework_id}` (v`{report.framework_version}`)",
        f"- **Generated At**: `{report.generated_at}`",
        f"- **Integrity Hash**: `{report.integrity_hash}`",
        "",
        "## Assessment Summary",
        "",
        "| Status | Count |",
        "|---|---:|",
        f"| PASS | {asm_sum.pass_count} |",
        f"| FAIL | {asm_sum.fail_count} |",
        f"| PARTIAL | {asm_sum.partial_count} |",
        f"| NO_EVIDENCE | {asm_sum.no_evidence_count} |",
        f"| MANUAL | {asm_sum.manual_count} |",
        f"| N/A | {asm_sum.not_applicable_count} |",
        f"| CONFLICTING | {asm_sum.conflicting_count} |",
        f"| UNDETERMINED | {asm_sum.undetermined_count} |",
        f"| **TOTAL** | **{asm_sum.total}** |",
        "",
    ]

    # Authoritative Top Risks
    if report.risk_summary:
        lines.extend([
            "## Authoritative Risks",
            "",
            "| Risk ID | Title | Score | Priority | Severity |",
            "|---|---|---:|---|---|",
        ])
        for r in report.risk_summary:
            lines.append(
                f"| `{escape_markdown(r.risk_id)}` | {escape_markdown(r.title)} | {r.score:.1f} | {escape_markdown(r.priority)} | {escape_markdown(r.severity)} |"
            )
        lines.append("")

    # Critical Gaps
    if report.gap_summary:
        lines.extend([
            "## Critical Gaps",
            "",
            "| Requirement | Status | Severity | Priority | Description Code |",
            "|---|---|---|---|---|",
        ])
        for g in report.gap_summary:
            lines.append(
                f"| `{escape_markdown(g.requirement_id)}` | `{g.status}` | {g.severity} | {g.priority} | `{g.description_code}` |"
            )
        lines.append("")

    # Evidence Gaps
    evidence_gaps = [g for g in report.gap_summary if g.missing_evidence]
    if evidence_gaps:
        lines.extend([
            "## Evidence Gaps",
            "",
            "| Requirement | Missing Evidence Items |",
            "|---|---|",
        ])
        for eg in evidence_gaps:
            missing_str = ", ".join(eg.missing_evidence) or "None"
            lines.append(f"| `{escape_markdown(eg.requirement_id)}` | {escape_markdown(missing_str)} |")
        lines.append("")

    # Conflicting Evidence
    if report.conflict_summary:
        lines.extend([
            "## Conflicting Evidence",
            "",
            "| Conflict ID | Requirement | Description | Status |",
            "|---|---|---|---|",
        ])
        for c in report.conflict_summary:
            lines.append(
                f"| `{escape_markdown(c.conflict_id)}` | `{escape_markdown(c.requirement_id)}` | {escape_markdown(c.description)} | {c.status} |"
            )
        lines.append("")

    # Auditor Lineage / Traceability
    if report.report_type == ReportType.AUDITOR and report.requirement_results:
        lines.extend([
            "## Auditor Traceability",
            "",
            "| Requirement | Status | Rule | Lineage Chain |",
            "|---|---|---|---|",
        ])
        for res in report.requirement_results:
            chain = res.get("lineage_chain", "")
            lines.append(
                f"| `{escape_markdown(str(res.get('requirement_id')))}` | `{res.get('status')}` | `{res.get('rule_id')} v{res.get('rule_version')}` | {escape_markdown(chain)} |"
            )
        lines.append("")

    # Sections
    for sec in report.sections:
        lines.extend([
            f"## {escape_markdown(sec.title)}",
            "",
            escape_markdown(sec.content),
            "",
        ])
        if sec.metrics:
            lines.extend([
                "| Metric | Value |",
                "|---|---|",
            ])
            for m in sec.metrics:
                lines.append(f"| {escape_markdown(m.name)} | {escape_markdown(str(m.value))} |")
            lines.append("")

    return "\n".join(lines)
