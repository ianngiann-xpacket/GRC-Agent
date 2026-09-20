"""Closed-loop Security LangGraph 워크플로우 정의 및 실행 엔진 모듈입니다."""

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from secgrc.ai.auditor import AIAuditor
from secgrc.audit.engine import AuditEngine
from secgrc.closed_loop.diff import EvidenceDiffEngine
from secgrc.closed_loop.models import (
    ClosedLoopStatus,
    RemediationActionModel,
    RemediationResult,
    RiskDelta,
    VerificationStatus,
)
from secgrc.closed_loop.providers import MockRemediationProvider
from secgrc.closed_loop.remediation import RemediationOrchestrator
from secgrc.closed_loop.state import ClosedLoopState
from secgrc.closed_loop.verification import VerificationEngine
from secgrc.evidence.prowler_adapter import ProwlerEvidenceAdapter
from secgrc.risk.engine import RiskEngine

MAX_REMEDIATION_CYCLES = 3


# --- 노드 함수들 (Node Functions) ---


def node_load_evidence(state: ClosedLoopState) -> Dict[str, Any]:
    """1. 증적 로드 노드: 초기 Prowler CSV 증적을 파싱 및 정규화합니다."""
    ev_path = state.get("evidence_path", "")
    if ev_path and os.path.exists(ev_path):
        adapter = ProwlerEvidenceAdapter()
        evidence_list = adapter.load_findings(ev_path)
    else:
        evidence_list = state.get("initial_evidence", [])

    return {
        "initial_evidence": evidence_list,
        "history": state.get("history", []) + [{"step": "load_evidence", "count": len(evidence_list)}],
    }


def node_audit(state: ClosedLoopState) -> Dict[str, Any]:
    """2. 초기 감사 노드: 결정론적 ISMS-P 감사 엔진을 실행합니다."""
    engine = AuditEngine()
    audit_results = engine.assess(state.get("initial_evidence", []))
    return {
        "initial_audit": audit_results,
        "history": state.get("history", []) + [{"step": "audit", "evaluated": len(audit_results)}],
    }


def node_risk(state: ClosedLoopState) -> Dict[str, Any]:
    """3. 초기 위험 분석 노드: 정량적 위험 점수를 산출합니다."""
    engine = RiskEngine()
    risk_results = engine.assess(state.get("initial_audit", []), state.get("initial_evidence", []))
    max_risk = max((r.risk_score for r in risk_results), default=0.0)
    return {
        "initial_risk": risk_results,
        "risk_before": max_risk,
        "history": state.get("history", []) + [{"step": "risk", "risk_before": max_risk}],
    }


def node_ai_analysis(state: ClosedLoopState) -> Dict[str, Any]:
    """4. AI 분석 노드: 심층 위험 맥락 및 조치 권고사항을 생성합니다."""
    auditor = AIAuditor()
    analyses = auditor.analyze_all(
        audit_results=state.get("initial_audit", []),
        evidence_list=state.get("initial_evidence", []),
        risk_assessments=state.get("initial_risk", []),
    )
    return {
        "history": state.get("history", []) + [{"step": "ai_analysis", "analyses": len(analyses)}],
    }


def node_remediation_plan(state: ClosedLoopState) -> Dict[str, Any]:
    """5. 조치 계획 수립 노드: 위험 항목별 RemediationActionModel을 수립합니다."""
    orch = RemediationOrchestrator()
    actions = orch.plan_remediations(
        findings=state.get("initial_evidence", []),
        risks=state.get("initial_risk", []),
        scan_id=state.get("scan_id", "SCAN-DEFAULT"),
    )
    return {
        "remediation_plan": actions,
        "closed_loop_status": ClosedLoopStatus.REMEDIATION_PLANNED,
        "history": state.get("history", []) + [{"step": "remediation_plan", "actions": len(actions)}],
    }


def node_approval(state: ClosedLoopState) -> Dict[str, Any]:
    """6. 승인 게이트 노드: 결재 상태를 평가합니다."""
    actions = state.get("remediation_plan", [])
    current_status = state.get("approval_status")

    # 이미 명시적으로 APPROVED 또는 REJECTED가 설정된 경우 유지
    if current_status in ("APPROVED", "REJECTED"):
        status = current_status
    elif any(a.required_approval for a in actions):
        # 실행 모드가 SIMULATED이고 사전 승인 파라미터가 부여되지 않았다면 승인 필요 상태
        status = "APPROVED" if state.get("execution_mode") == "SIMULATED" and current_status != "REJECTED" else "PENDING"
    else:
        status = "NOT_REQUIRED"

    closed_status = (
        ClosedLoopStatus.AWAITING_APPROVAL
        if status == "PENDING"
        else (ClosedLoopStatus.REMEDIATION_FAILED if status == "REJECTED" else ClosedLoopStatus.REMEDIATION_PLANNED)
    )

    return {
        "approval_status": status,
        "closed_loop_status": closed_status,
        "history": state.get("history", []) + [{"step": "approval", "status": status}],
    }


def node_remediation(state: ClosedLoopState) -> Dict[str, Any]:
    """7. 조치 실행 노드: 결재 검증 후 Provider(DRY_RUN 또는 SIMULATED)를 통해 조치를 수행합니다."""
    provider = MockRemediationProvider()
    if state.get("synthetic_state"):
        provider.synthetic_state.update(state.get("synthetic_state", {}))
    if state.get("remediated_actions"):
        provider.remediated_actions.update(state.get("remediated_actions", []))

    orch = RemediationOrchestrator(provider=provider)

    mode = state.get("execution_mode", "DRY_RUN")
    app_status = state.get("approval_status", "PENDING")

    results, closed_status = orch.execute_actions(
        actions=state.get("remediation_plan", []),
        approval_status=app_status,
        execution_mode=mode,
        scan_id=state.get("scan_id", "SCAN-DEFAULT"),
    )

    return {
        "remediation_result": results,
        "closed_loop_status": closed_status,
        "synthetic_state": provider.synthetic_state,
        "remediated_actions": list(provider.remediated_actions),
        "history": state.get("history", []) + [{"step": "remediation", "results": len(results), "mode": mode}],
    }


def node_collect_verification_evidence(state: ClosedLoopState) -> Dict[str, Any]:
    """8. 재스캔 증적 수집 노드: 조치 결과(Synthetic State)가 반영된 Re-scan Evidence를 생성합니다."""
    provider = MockRemediationProvider()
    if state.get("synthetic_state"):
        provider.synthetic_state.update(state.get("synthetic_state", {}))
    if state.get("remediated_actions"):
        provider.remediated_actions.update(state.get("remediated_actions", []))

    verifier = VerificationEngine()

    v_evidence = verifier.generate_verification_evidence(
        before_evidence=state.get("initial_evidence", []),
        provider=provider,
    )

    return {
        "verification_evidence": v_evidence,
        "closed_loop_status": ClosedLoopStatus.VERIFICATION_PENDING,
        "history": state.get("history", []) + [{"step": "collect_verification_evidence", "evidence_count": len(v_evidence)}],
    }


def node_re_audit(state: ClosedLoopState) -> Dict[str, Any]:
    """9. 재감사 노드: Re-scan 증적을 대상으로 결정론적 ISMS-P 감사를 재수행합니다."""
    engine = AuditEngine()
    v_audit = engine.assess(state.get("verification_evidence", []))
    return {
        "verification_audit": v_audit,
        "history": state.get("history", []) + [{"step": "re_audit", "audit_count": len(v_audit)}],
    }


def node_recalculate_risk(state: ClosedLoopState) -> Dict[str, Any]:
    """10. 위험 재계산 노드: 재감사 결과를 바탕으로 정량적 위험을 재산출합니다."""
    engine = RiskEngine()
    v_risk = engine.assess(state.get("verification_audit", []), state.get("verification_evidence", []))
    max_risk = max((r.risk_score for r in v_risk), default=0.0)
    return {
        "verification_risk": v_risk,
        "risk_after": max_risk,
        "history": state.get("history", []) + [{"step": "recalculate_risk", "risk_after": max_risk}],
    }


def node_compare(state: ClosedLoopState) -> Dict[str, Any]:
    """11. 증적 Diff 비교 노드: 조치 전후 증적 상태 변화를 1:1 비교합니다."""
    diff_results = EvidenceDiffEngine.compare(
        before_evidence=state.get("initial_evidence", []),
        after_evidence=state.get("verification_evidence", []),
    )
    return {
        "evidence_diff": diff_results,
        "history": state.get("history", []) + [{"step": "compare", "diffs": len(diff_results)}],
    }


def node_verification(state: ClosedLoopState) -> Dict[str, Any]:
    """12. 종합 검증 판정 노드: Case 1~5 평가 및 위험 감축률을 산출하고 사이클을 갱신합니다."""
    r_before = state.get("risk_before", 0.0)
    r_after = state.get("risk_after", 0.0)
    delta_obj = VerificationEngine.calculate_risk_delta(r_before, r_after)

    cycles = state.get("cycle_count", 0) + 1
    v_audit = state.get("verification_audit", [])

    # 전반적 검증 판정
    has_fail = any(a.status.value == "FAIL" for a in v_audit)
    has_partial = any(a.status.value in ("PARTIAL", "MANUAL") for a in v_audit)

    if has_fail:
        v_status = VerificationStatus.FAILED
        cl_status = ClosedLoopStatus.REMEDIATION_FAILED
    elif has_partial or delta_obj.residual_risk_level in ("MEDIUM", "HIGH", "CRITICAL"):
        v_status = VerificationStatus.VERIFIED_WITH_RESIDUAL_RISK
        cl_status = ClosedLoopStatus.VERIFIED_WITH_RESIDUAL_RISK
    else:
        v_status = VerificationStatus.VERIFIED
        cl_status = ClosedLoopStatus.VERIFIED

    return {
        "verification_status": v_status,
        "closed_loop_status": cl_status,
        "risk_delta": delta_obj.risk_delta,
        "risk_reduction_pct": delta_obj.risk_reduction_pct,
        "residual_risk_level": delta_obj.residual_risk_level,
        "cycle_count": cycles,
        "history": state.get("history", []) + [
            {
                "step": "verification",
                "status": v_status.value,
                "reduction_pct": delta_obj.risk_reduction_pct,
                "cycle": cycles,
            }
        ],
    }


def node_report(state: ClosedLoopState) -> Dict[str, Any]:
    """13. 최종 보고서 생성 노드: 종합 Closed-loop 실행 결과 리포트를 집계합니다."""
    rep = {
        "scan_id": state.get("scan_id", "SCAN-001"),
        "closed_loop_status": state.get("closed_loop_status", ClosedLoopStatus.OPEN).value,
        "verification_status": state.get("verification_status", VerificationStatus.FAILED).value,
        "risk_before": state.get("risk_before", 0.0),
        "risk_after": state.get("risk_after", 0.0),
        "risk_delta": state.get("risk_delta", 0.0),
        "risk_reduction_pct": state.get("risk_reduction_pct", 0.0),
        "residual_risk_level": state.get("residual_risk_level", "NONE"),
        "cycle_count": state.get("cycle_count", 1),
        "execution_mode": state.get("execution_mode", "DRY_RUN"),
        "approval_status": state.get("approval_status", "NOT_REQUIRED"),
    }
    return {
        "report": rep,
        "history": state.get("history", []) + [{"step": "report", "summary": rep}],
    }


# --- 조건부 라우터 함수들 (Conditional Routers) ---


def router_approval(state: ClosedLoopState) -> str:
    """승인 결과에 따른 분기 라우터"""
    app_status = state.get("approval_status")
    if app_status == "REJECTED":
        return "report"
    if app_status == "PENDING" and state.get("execution_mode") == "DRY_RUN":
        return "remediation"
    if app_status == "PENDING":
        return "report"
    return "remediation"


def router_remediation(state: ClosedLoopState) -> str:
    """조치 실행 후 분기 라우터"""
    cl_status = state.get("closed_loop_status")
    if cl_status == ClosedLoopStatus.REMEDIATION_FAILED:
        return "report"
    return "collect_verification_evidence"


def router_verification(state: ClosedLoopState) -> str:
    """검증 완료 후 루프 제어 및 종료 라우터 (MAX_REMEDIATION_CYCLES 제한)"""
    v_status = state.get("verification_status")
    cycles = state.get("cycle_count", 0)
    max_c = state.get("max_cycles", MAX_REMEDIATION_CYCLES)

    # 위험 잔존 상태이고 루프 한도 미만인 경우 재조치 루프로 복귀
    if v_status in (VerificationStatus.RISK_REMAINING, VerificationStatus.PARTIALLY_VERIFIED) and cycles < max_c:
        return "remediation_plan"

    return "report"


# --- 그래프 빌더 (Graph Builder) ---


def build_closed_loop_graph(checkpointer: Optional[Any] = None) -> Any:
    """Closed-loop Security의 StateGraph를 조립하고 컴파일합니다."""
    builder = StateGraph(ClosedLoopState)

    # 1. 노드 등록
    builder.add_node("load_evidence", node_load_evidence)
    builder.add_node("audit", node_audit)
    builder.add_node("risk", node_risk)
    builder.add_node("ai_analysis", node_ai_analysis)
    builder.add_node("remediation_plan", node_remediation_plan)
    builder.add_node("approval", node_approval)
    builder.add_node("remediation", node_remediation)
    builder.add_node("collect_verification_evidence", node_collect_verification_evidence)
    builder.add_node("re_audit", node_re_audit)
    builder.add_node("recalculate_risk", node_recalculate_risk)
    builder.add_node("compare", node_compare)
    builder.add_node("verification", node_verification)
    builder.add_node("report", node_report)

    # 2. 순차 엣지 연결
    builder.add_edge(START, "load_evidence")
    builder.add_edge("load_evidence", "audit")
    builder.add_edge("audit", "risk")
    builder.add_edge("risk", "ai_analysis")
    builder.add_edge("ai_analysis", "remediation_plan")
    builder.add_edge("remediation_plan", "approval")

    # 3. 승인 조건부 엣지
    builder.add_conditional_edges(
        "approval",
        router_approval,
        {
            "remediation": "remediation",
            "report": "report",
        },
    )

    # 4. 조치 결과 조건부 엣지
    builder.add_conditional_edges(
        "remediation",
        router_remediation,
        {
            "collect_verification_evidence": "collect_verification_evidence",
            "report": "report",
        },
    )

    # 5. 재검증 파이프라인 순차 엣지
    builder.add_edge("collect_verification_evidence", "re_audit")
    builder.add_edge("re_audit", "recalculate_risk")
    builder.add_edge("recalculate_risk", "compare")
    builder.add_edge("compare", "verification")

    # 6. 검증 후 루프 조건부 엣지 (루프 한도 방어)
    builder.add_conditional_edges(
        "verification",
        router_verification,
        {
            "remediation_plan": "remediation_plan",
            "report": "report",
        },
    )

    builder.add_edge("report", END)

    return builder.compile(checkpointer=checkpointer)
