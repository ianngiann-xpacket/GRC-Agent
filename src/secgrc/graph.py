"""LangGraph 기반의 GRC Agent 워크플로우를 정의하는 모듈입니다.

ISMS-P Knowledge Base 및 Retriever와 연동되어 지식 기반의 보안 감사를 수행합니다.
"""

from typing import TypedDict
from langgraph.graph import StateGraph, START, END

from secgrc.knowledge.retriever import KnowledgeRetriever
from secgrc.llm import audit_with_llm


# [1] State (상태 정의): RAG 검색 결과와 감사 판정 데이터를 담는 공유 메모장
class ComplianceState(TypedDict):
    query: str             # 사용자가 입력한 현재 보안 현황 또는 질의
    control_id: str        # 검색된 ISMS-P 통제항목 번호 (예: '2.7.1')
    control_name: str      # 검색된 ISMS-P 통제항목명 (예: '암호정책 적용')
    requirements: str      # 해당 통제항목 요구사항 본문
    is_compliant: bool     # 컴플라이언스 기준 충족(적합) 여부
    findings: str          # 감사 점검 결과 (Finding)
    recommendation: str    # 개선 권고 조치안 (Remediation)


# [2] Node 1: RAG 검색 노드 (Retrieve)
def retrieve_control(state: ComplianceState) -> dict:
    """사용자의 질의와 가장 관련된 ISMS-P 통제항목을 검색하여 State에 증강(Augment)합니다."""
    query = state.get("query", "")
    retriever = KnowledgeRetriever()
    retrieved = retriever.retrieve(query)

    if retrieved:
        control, score = retrieved
        return {
            "control_id": control.control_id,
            "control_name": control.name,
            "requirements": control.requirements,
        }
    else:
        return {
            "control_id": "미식별",
            "control_name": "해당 통제항목 없음",
            "requirements": "일치하는 ISMS-P 통제항목을 찾을 수 없습니다.",
        }


# [3] Node 2: 보안 규칙 평가 노드 (Evaluate with LLM)
def evaluate_rule(state: ComplianceState) -> dict:
    """검색된 통제항목 기준에 비추어 LLM(또는 규칙 폴백)을 통해 보안 적합/부적합 여부를 판정합니다."""
    query = state.get("query", "")
    ctrl_id = state.get("control_id", "")
    ctrl_name = state.get("control_name", "")
    requirements = state.get("requirements", "")

    # LLM 감사 추론 호출 (API 키가 없으면 규칙 기반 시뮬레이션 모드로 자동 대체)
    return audit_with_llm(
        query=query,
        control_id=ctrl_id,
        control_name=ctrl_name,
        requirements=requirements,
    )


# [4] Node 3: 적합(Pass) 처리 노드
def pass_node(state: ComplianceState) -> dict:
    """적합 판정 시 증적 관리 및 유지 가이드를 확정합니다."""
    ctrl_id = state.get("control_id", "")
    recom = state.get("recommendation")
    if not recom:
        recom = f"[적합 유지 권고] ISMS-P {ctrl_id} 인증 유지를 위해 관련 보안 정책 및 설정 증적을 주기적으로 검토하세요."
    return {"recommendation": recom}


# [5] Node 4: 시정조치(Remediation) 권고 노드
def remediation_node(state: ComplianceState) -> dict:
    """부적합 판정 시 구체적인 시정조치 가이드를 확정합니다."""
    ctrl_id = state.get("control_id", "")
    ctrl_name = state.get("control_name", "")
    recom = state.get("recommendation")
    if not recom:
        recom = f"[시정조치 권고] ISMS-P {ctrl_id}({ctrl_name}) 결함 사항에 대해 즉시 보호대책을 수립하고 재발 방지 조치를 이행하세요."
    return {"recommendation": recom}



# [6] Router: 조건부 분기 함수
def route_compliance(state: ComplianceState) -> str:
    """적합 여부에 따라 적합 노드 또는 시정조치 노드로 라우팅합니다."""
    if state.get("is_compliant"):
        return "pass_node"
    return "remediation_node"


# [7] Graph 빌드 및 컴파일
def build_graph():
    """RAG 검색 -> 평가 -> 조건부 분기 -> 보고서 작성을 수행하는 그래프를 빌드합니다."""
    builder = StateGraph(ComplianceState)

    # 1. 노드 등록
    builder.add_node("retrieve_control", retrieve_control)
    builder.add_node("evaluate_rule", evaluate_rule)
    builder.add_node("pass_node", pass_node)
    builder.add_node("remediation_node", remediation_node)

    # 2. 고정 엣지 연결: 시작(START) -> RAG 검색 -> 평가 노드
    builder.add_edge(START, "retrieve_control")
    builder.add_edge("retrieve_control", "evaluate_rule")

    # 3. 조건부 엣지 연결: 평가 노드 -> 분기(적합 vs 시정조치)
    builder.add_conditional_edges(
        "evaluate_rule",
        route_compliance,
        {
            "pass_node": "pass_node",
            "remediation_node": "remediation_node",
        },
    )

    # 4. 종료 엣지 연결
    builder.add_edge("pass_node", END)
    builder.add_edge("remediation_node", END)

    return builder.compile()
