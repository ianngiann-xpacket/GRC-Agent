"""인증심사 웹 페이지 데이터 조립 모듈.

6계층 아키텍처(통제 온톨로지, 증적 원장, 수집 커넥터, 정합성 엔진,
심사 워크스페이스, 결함 생명주기)의 상태를 대시보드용 컨텍스트로 집계합니다.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List

from secgrc.audit_findings.manager import (
    AuditFindingsManager,
    CorrectiveActionType,
    FindingCategory,
    FindingSeverity,
    audit_findings_manager,
)
from secgrc.audit_workspace.workspace import AuditWorkspace, audit_workspace
from secgrc.certification.workflow import (
    AuditStage,
    AuditType,
    CertificationAuditWorkflow,
    CertificationTier,
    certification_audit_workflow,
)
from secgrc.control_engine.engine import ControlEngine, control_engine
from secgrc.evidence.ledger import EvidenceLedger, EvidenceRecordType, evidence_ledger
from secgrc.gap_analysis.engine import GapAnalysisEngine, gap_analysis_engine
from secgrc.reconciliation.engine import ReconciliationEngine, reconciliation_engine

_DEMO_AUDIT_ID = "AUDIT-DEMO-001"


def _seed_demo_data() -> str:
    """데모용 인증심사 데이터가 없으면 시드합니다."""
    audit = certification_audit_workflow.get_audit(_DEMO_AUDIT_ID)
    if audit is None:
        audit = certification_audit_workflow.create_audit(
            organization_id="ORG-001",
            scope="전사 정보시스템 및 개인정보처리시스템",
            lead_auditor="김심사",
            audit_type=AuditType.INITIAL,
            certification_tier=CertificationTier.STANDARD,
            target_date=datetime.now() + timedelta(days=90),
        )
        audit.audit_id = _DEMO_AUDIT_ID
        certification_audit_workflow._audits[_DEMO_AUDIT_ID] = audit

        # 준비 단계 일부 완료 처리
        for item in audit.checklist:
            if item.item_id in ("PREP-001", "PREP-002", "PREP-003"):
                item.completed = True
        certification_audit_workflow.update_audit_stage(_DEMO_AUDIT_ID, AuditStage.DOCUMENT_REVIEW)

    # 증적 원장 데모 데이터
    if not evidence_ledger._records:
        evidence_ledger.append_record(
            evidence_id="EV-IAM-001",
            control_id="ISMS-P-2.5.2",
            content={
                "type": "IAM_CONFIGURATION",
                "system": "Active Directory",
                "mfa_enabled": True,
                "admin_accounts": ["admin", "administrator"],
            },
            record_type=EvidenceRecordType.EVIDENCE,
            created_by="SYSTEM",
            source_system="IAM_CONNECTOR",
            collection_method="AUTOMATIC",
            retention_period=365,
        )
        evidence_ledger.append_record(
            evidence_id="EV-PWD-001",
            control_id="ISMS-P-2.5.4",
            content={
                "type": "PASSWORD_POLICY",
                "system": "Active Directory",
                "min_length": 8,
                "max_age_days": 90,
                "complexity_required": True,
            },
            record_type=EvidenceRecordType.EVIDENCE,
            created_by="SYSTEM",
            source_system="IAM_CONNECTOR",
            collection_method="AUTOMATIC",
            retention_period=365,
        )

    # 정합성 엔진 데모 데이터
    if not reconciliation_engine.results:
        reconciliation_engine.add_config_observation(
            system_id="AD-PROD",
            config_key="password_min_length",
            actual_value=8,
            source_query="Get-ADDefaultDomainPasswordPolicy",
        )
        reconciliation_engine.add_config_observation(
            system_id="AD-PROD",
            config_key="password_max_age",
            actual_value=0,  # 무제한 — 정책(90일)과 불일치 유도
            source_query="Get-ADDefaultDomainPasswordPolicy",
        )
        reconciliation_engine.reconcile_policy_to_config("ISMS-P-2.5.4")
        reconciliation_engine.reconcile_requirement_to_evidence(
            "ISMS-P-2.5.2",
            ["account_list", "mfa_status", "password_policy_config"],
            ["mfa_status", "password_policy_config"],
        )

    # 심사 워크스페이스 데모 세션
    if not audit_workspace._sessions:
        session = audit_workspace.create_audit_session(
            audit_id=_DEMO_AUDIT_ID,
            auditor_name="김심사",
            audit_date=datetime.now() + timedelta(days=7),
            requested_items=["ISMS-P-2.5.2", "ISMS-P-2.5.4", "ISMS-P-2.9.4"],
        )
        req = audit_workspace.request_sample(
            session_id=session.session_id,
            control_id="ISMS-P-2.5.4",
            request_description="비밀번호 정책 설정값 및 적용 계정 목록",
            requested_by="김심사",
            due_date=datetime.now() + timedelta(days=5),
        )
        audit_workspace.assign_sample_request(req.request_id, "보안팀원")
        audit_workspace.submit_sample_evidence(
            request_id=req.request_id,
            evidence_ids=["EV-PWD-001"],
            submission_notes="비밀번호 정책 설정 증적 제출",
        )

    # 지적사항 데모 데이터
    if not audit_findings_manager._findings:
        finding = audit_findings_manager.create_finding(
            audit_id=_DEMO_AUDIT_ID,
            control_id="ISMS-P-2.5.2",
            control_name="사용자 인증",
            severity=FindingSeverity.MAJOR,
            title="관리자 계정 MFA 미적용",
            description="일부 관리자 계정에 MFA가 적용되지 않아 무단 접근 위험이 있습니다.",
            auditor="김심사",
            defect_number="DEF-2024-001",
            category=FindingCategory.ACCESS_CONTROL,
            confirmed_facts="관리자 계정 5개 중 2개에 MFA 미적용 확인",
            target="IT 인프라 관리자 계정",
            sample="admin01, admin02",
            judgment_basis="IAM 시스템 설정 및 계정 목록 확인",
            occurrence_period="2024-01-01 ~ 현재",
            impact="기밀성/무결성 침해 가능성",
            current_controls="기본 인증만 적용",
            additional_checks="전체 관리자 계정 모집단 점검 필요",
            assignee="보안팀장",
            evidence=["EV-IAM-001"],
            recommendation="모든 관리자 계정에 MFA 즉시 적용",
        )
        audit_findings_manager.add_corrective_action(
            finding_id=finding.finding_id,
            description="모든 관리자 계정에 MFA 설정 적용",
            assignee="보안팀원",
            assignee_email="security@company.com",
            due_date=datetime.now() + timedelta(days=14),
            action_type=CorrectiveActionType.CORRECTIVE,
            population_scope="모집단",
        )

    return _DEMO_AUDIT_ID


def build_certification_context() -> Dict[str, Any]:
    """인증심사 페이지 렌더링용 컨텍스트를 구축합니다."""
    audit_id = _seed_demo_data()

    audit = certification_audit_workflow.get_audit(audit_id)
    audit_summary = certification_audit_workflow.get_audit_summary(audit_id)

    # 단계별 진행 상황
    stage_progress: List[Dict[str, Any]] = []
    stage_names = {
        AuditStage.PREPARATION: "준비",
        AuditStage.DOCUMENT_REVIEW: "문서 심사",
        AuditStage.ON_SITE_AUDIT: "현장 심사",
        AuditStage.FINDINGS: "지적사항",
        AuditStage.CORRECTIVE_ACTION: "보완조치",
        AuditStage.VERIFICATION: "확인 심사",
        AuditStage.CERTIFICATION: "인증 발급",
    }
    for stage in AuditStage:
        prog = certification_audit_workflow.get_stage_progress(audit_id, stage)
        stage_progress.append({
            "name": stage_names.get(stage, stage.value),
            "value": stage.value,
            "is_current": audit.current_stage == stage if audit else False,
            "total": prog.get("total_items", 0),
            "completed": prog.get("completed_items", 0),
            "completion_rate": prog.get("completion_rate", 0.0),
        })

    # 정합성 결과
    recon_results = [
        {
            "control_id": r.control_id,
            "type": r.reconciliation_type.value,
            "status": r.status.value,
            "severity": r.severity,
            "description": r.description,
        }
        for r in reconciliation_engine.results
    ]
    mismatch_count = len(reconciliation_engine.get_mismatched_controls())

    # 지적사항
    findings = [
        {
            "finding_id": f.finding_id,
            "defect_number": f.defect_number,
            "control_id": f.control_id,
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status.value,
            "independent_reviewer": f.independent_reviewer,
        }
        for f in audit_findings_manager._findings.values()
    ]
    findings_summary = audit_findings_manager.get_finding_summary()

    # 심사 세션
    sessions = []
    for s in audit_workspace._sessions.values():
        summary = audit_workspace.get_session_summary(s.session_id)
        if summary:
            sessions.append({
                "session_id": summary["session_id"],
                "auditor": summary["auditor"],
                "audit_date": summary["audit_date"].strftime("%Y-%m-%d"),
                "status": summary["status"],
                "progress": summary["progress"],
            })

    # 증적 원장
    ledger_records = [
        {
            "record_id": r.record_id,
            "control_id": r.control_id,
            "type": r.record_type.value,
            "method": r.collection_method,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M"),
            "hash": r.hash[:16] + "...",
        }
        for r in evidence_ledger._records
    ]
    chain_valid = evidence_ledger.verify_chain_integrity()

    # GAP 분석
    gap_result = gap_analysis_engine.analyze_gaps(organization_id="ORG-001")

    summary = {
        "readiness_score": gap_result.overall_score,
        "total_controls": len(control_engine._controls),
        "ledger_records": len(evidence_ledger._records),
        "chain_valid": chain_valid,
        "mismatch_count": mismatch_count,
        "open_findings": findings_summary.get("open_findings", 0)
        + findings_summary.get("in_progress_findings", 0),
        "overdue_actions": findings_summary.get("corrective_actions", {}).get("overdue", 0),
    }

    audit_meta = {
        "audit_id": audit_id,
        "audit_type": audit.audit_type.value if audit else "INITIAL",
        "tier": audit.certification_tier.value if audit else "STANDARD",
        "current_stage": audit.current_stage.value if audit else "PREPARATION",
        "overall_progress": audit_summary.get("overall_progress", 0.0),
        "total_items": audit_summary.get("total_items", 0),
        "completed_items": audit_summary.get("completed_items", 0),
    }

    return {
        "summary": summary,
        "audit_meta": audit_meta,
        "stage_progress": stage_progress,
        "reconciliation_results": recon_results,
        "findings": findings,
        "sessions": sessions,
        "ledger_records": ledger_records,
    }
