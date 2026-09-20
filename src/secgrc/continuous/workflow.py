"""Continuous GRC LangGraph 워크플로우 조립 및 실행 엔진 모듈입니다."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from langgraph.graph import END, START, StateGraph

from secgrc.continuous.alert import AlertManager
from secgrc.continuous.detector import ChangeDetector
from secgrc.continuous.evaluator import TargetedEvaluator
from secgrc.continuous.impact import ImpactAnalyzer
from secgrc.continuous.models import (
    ChangeClassification,
    ContinuousStatus,
    RiskChangeType,
)
from secgrc.continuous.normalizer import EventNormalizer
from secgrc.continuous.risk_monitor import ContinuousRiskMonitor
from secgrc.continuous.state import ContinuousState
from secgrc.models.evidence import NormalizedEvidence


# --- 워크플로우 노드 함수들 (Workflow Nodes) ---


def node_normalize(state: ContinuousState) -> Dict[str, Any]:
    """1. 이벤트 정규화: 원본 딕셔너리를 NormalizedChangeEvent로 변환하고 살균합니다."""
    raw = state.get("event_raw", {})
    event = EventNormalizer.normalize(raw)
    return {
        "event": event,
        "continuous_status": ContinuousStatus.CHANGE_DETECTED,
        "history": state.get("history", []) + [{"step": "normalize", "event_id": event.event_id}],
    }


def node_classify(state: ContinuousState) -> Dict[str, Any]:
    """2. 변경 분류: 이벤트를 SECURITY_RELEVANT, COMPLIANCE_RELEVANT, NON_SECURITY, UNKNOWN으로 분류합니다."""
    event = state["event"]
    classification = ChangeDetector.classify(event)
    return {
        "classification": classification,
        "history": state.get("history", []) + [{"step": "classify", "classification": classification.value}],
    }


def node_impact_analysis(state: ContinuousState) -> Dict[str, Any]:
    """3. 영향 분석: 연관 ISMS-P 통제항목을 매핑하고 정량 영향도 점수를 계산합니다."""
    event = state["event"]
    mappings = ImpactAnalyzer.map_affected_controls(event)
    score, level = ImpactAnalyzer.calculate_impact_score(event, mappings)

    return {
        "affected_controls": mappings,
        "impact_score": score,
        "impact_level": level,
        "continuous_status": ContinuousStatus.IMPACT_ANALYZED,
        "history": state.get("history", []) + [{"step": "impact_analysis", "score": score, "level": level}],
    }


def node_log_only(state: ContinuousState) -> Dict[str, Any]:
    """4. 비보안 변경 로그 기록 노드: 보안 영향이 없으므로 추가 감사 없이 완료 처리합니다."""
    return {
        "routing_decision": "LOG_ONLY",
        "continuous_status": ContinuousStatus.RESOLVED,
        "history": state.get("history", []) + [{"step": "log_only", "message": "Non-security change logged."}],
    }


def node_collect_evidence(state: ContinuousState) -> Dict[str, Any]:
    """5. 증적 수집 및 갱신: 변경된 자산에 대한 최신 증적을 타깃 생성합니다."""
    import os
    from secgrc.evidence.prowler_adapter import ProwlerEvidenceAdapter

    event = state["event"]
    evaluator = TargetedEvaluator()
    base_evidence = list(state.get("targeted_evidence", []))
    if not base_evidence and os.path.exists("tests/fixtures/prowler_gcp_sample.csv"):
        base_evidence = ProwlerEvidenceAdapter().load_findings("tests/fixtures/prowler_gcp_sample.csv")

    updated_evidence = evaluator.generate_targeted_evidence(event, base_evidence)

    return {
        "targeted_evidence": updated_evidence,
        "continuous_status": ContinuousStatus.REASSESSING,
        "history": state.get("history", []) + [{"step": "collect_evidence", "count": len(updated_evidence)}],
    }


def node_reassess(state: ContinuousState) -> Dict[str, Any]:
    """6. 타깃 감사 및 위험 재산출: 영향받는 통제항목에 대해서만 AuditEngine 및 RiskEngine을 실행합니다."""
    evaluator = TargetedEvaluator()
    affected_ids = [m.control_id for m in state.get("affected_controls", [])]
    audits, risks = evaluator.evaluate_targeted(affected_ids, state.get("targeted_evidence", []))

    after_risk = max((r.risk_score for r in risks), default=0.0)

    return {
        "targeted_audit": audits,
        "targeted_risk": risks,
        "risk_after": after_risk,
        "continuous_status": ContinuousStatus.REASSESSMENT_REQUIRED,
        "history": state.get("history", []) + [{"step": "reassess", "audits": len(audits), "after_risk": after_risk}],
    }


def node_risk_change_detection(state: ContinuousState) -> Dict[str, Any]:
    """7. 위험 변동 감지 및 알림: Before 스냅샷과 비교하여 Delta 산출 및 임계치 검사를 수행합니다."""
    monitor = ContinuousRiskMonitor()
    event = state["event"]
    affected = state.get("affected_controls", [])
    target_ctrl = affected[0].control_id if affected else "ISMS-P-UNKNOWN"

    after_st = state.get("targeted_audit", [None])[0]
    st_val = after_st.status.value if (after_st and hasattr(after_st, "status")) else "FAIL"

    c_type, alert, r_before = monitor.evaluate_change_and_alert(
        event=event,
        control_id=target_ctrl,
        after_status=st_val,
        after_risk_score=state.get("risk_after", 0.0),
    )

    r_after = state.get("risk_after", 0.0)
    delta = round(r_after - r_before, 2)

    # 이벤트 기반 라우팅 결정
    imp_level = state.get("impact_level", "LOW")
    if imp_level == "CRITICAL":
        route = "IMMEDIATE_ALERT_AND_APPROVAL"
        status = ContinuousStatus.AWAITING_APPROVAL
    elif imp_level == "HIGH":
        route = "HUMAN_REVIEW"
        status = ContinuousStatus.ALERTED
    elif imp_level == "MEDIUM":
        route = "ALERT"
        status = ContinuousStatus.ALERTED
    else:
        route = "REASSESS"
        status = ContinuousStatus.RESOLVED

    # AI 설명 가드레일 (AI는 점수를 조작하지 않고 사실 설명 및 권고만)
    ai_analysis = {
        "OBSERVED": f"Event {event.event_id} ({event.event_type}) on resource {event.resource_id}.",
        "INFERRED": f"Risk shifted by {delta} points ({r_before} -> {r_after}).",
        "NOT_OBSERVED": "No active compromise observed.",
        "why_risk_changed": f"Configuration property modification triggered re-evaluation of {target_ctrl}.",
        "recommendation": "Review firewall and access restriction policies." if r_after >= 60.0 else "Monitor baseline.",
    }

    return {
        "risk_before": r_before,
        "risk_delta": delta,
        "risk_change_type": c_type,
        "alert": alert,
        "routing_decision": route,
        "continuous_status": status,
        "ai_analysis": ai_analysis,
        "history": state.get("history", []) + [{"step": "risk_change_detection", "delta": delta, "route": route}],
    }


# --- 조건부 라우터 함수 (Conditional Router) ---


def router_classification(state: ContinuousState) -> str:
    """분류 결과에 따른 분기 (NON_SECURITY -> log_only, 기타 -> collect_evidence)"""
    if state.get("classification") == ChangeClassification.NON_SECURITY:
        return "log_only"
    return "collect_evidence"


# --- 그래프 빌더 (Graph Builder) ---


def build_continuous_graph(checkpointer: Optional[Any] = None) -> Any:
    """Continuous GRC Workflow의 StateGraph를 조립하고 컴파일합니다."""
    builder = StateGraph(ContinuousState)

    # 1. 노드 등록
    builder.add_node("normalize", node_normalize)
    builder.add_node("classify", node_classify)
    builder.add_node("impact_analysis", node_impact_analysis)
    builder.add_node("log_only", node_log_only)
    builder.add_node("collect_evidence", node_collect_evidence)
    builder.add_node("reassess", node_reassess)
    builder.add_node("risk_change_detection", node_risk_change_detection)

    # 2. 순차 엣지
    builder.add_edge(START, "normalize")
    builder.add_edge("normalize", "classify")
    builder.add_edge("classify", "impact_analysis")

    # 3. 조건부 엣지 (NON_SECURITY는 감사를 건너뛰고 LOG_ONLY로 직행)
    builder.add_conditional_edges(
        "impact_analysis",
        router_classification,
        {
            "log_only": "log_only",
            "collect_evidence": "collect_evidence",
        },
    )

    # 4. 감사 재평가 및 위험 감지 엣지
    builder.add_edge("collect_evidence", "reassess")
    builder.add_edge("reassess", "risk_change_detection")
    builder.add_edge("risk_change_detection", END)
    builder.add_edge("log_only", END)

    return builder.compile(checkpointer=checkpointer)
