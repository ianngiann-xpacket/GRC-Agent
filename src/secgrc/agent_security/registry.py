"""에이전트 및 도구 등록소(Agent Registry & Tool Registry) 모듈입니다."""

from typing import Dict, List, Optional
from secgrc.agent_security.identity import DEFAULT_AUDITOR_AGENT, DEFAULT_REMEDIATION_AGENT
from secgrc.agent_security.models import AgentIdentity, AgentStatus, ToolMetadata, ToolType


class AgentRegistry:
    """인가된 AI 에이전트의 등록, 상태 조회 및 수명주기(ACTIVE, SUSPENDED, REVOKED)를 관리합니다."""

    def __init__(self):
        self._agents: Dict[str, AgentIdentity] = {}
        # 기본 에이전트 등록
        self.register(DEFAULT_AUDITOR_AGENT)
        self.register(DEFAULT_REMEDIATION_AGENT)

    def register(self, agent: AgentIdentity) -> AgentIdentity:
        self._agents[agent.agent_id] = agent
        return agent

    def get(self, agent_id: str) -> Optional[AgentIdentity]:
        return self._agents.get(agent_id)

    def list_all(self) -> List[AgentIdentity]:
        return list(self._agents.values())

    def update_status(self, agent_id: str, status: AgentStatus) -> bool:
        agent = self.get(agent_id)
        if agent:
            agent.status = status
            return True
        return False

    def is_active(self, agent_id: str) -> bool:
        """에이전트가 활성(ACTIVE) 상태인지 확인합니다. REVOKED 또는 SUSPENDED면 False를 반환합니다."""
        agent = self.get(agent_id)
        return bool(agent and agent.status == AgentStatus.ACTIVE)


class ToolRegistry:
    """인가된 보안 도구 및 각 도구별 실행 권한을 가진 에이전트 목록을 관리합니다."""

    def __init__(self):
        self._tools: Dict[str, ToolMetadata] = {}
        self._initialize_default_tools()

    def _initialize_default_tools(self):
        default_tools = [
            ToolMetadata(
                tool_name="read_evidence",
                tool_type=ToolType.READ,
                risk_level="LOW",
                requires_approval=False,
                allowed_agents=["grc-auditor-001"],
                description="Prowler 보안 진단 결과 CSV 증적 로딩 및 정규화",
            ),
            ToolMetadata(
                tool_name="run_audit",
                tool_type=ToolType.ANALYZE,
                risk_level="LOW",
                requires_approval=False,
                allowed_agents=["grc-auditor-001"],
                description="결정론적 ISMS-P 통제항목 규칙 기반 적합성 평가",
            ),
            ToolMetadata(
                tool_name="calculate_risk",
                tool_type=ToolType.ANALYZE,
                risk_level="LOW",
                requires_approval=False,
                allowed_agents=["grc-auditor-001"],
                description="결정론적 GRC Risk Score 및 우선순위(P1~P5) 산출",
            ),
            ToolMetadata(
                tool_name="run_ai_audit",
                tool_type=ToolType.ANALYZE,
                risk_level="LOW",
                requires_approval=False,
                allowed_agents=["grc-auditor-001"],
                description="AI Auditor 심층 보안 추론 및 교정 권고 생성",
            ),
            ToolMetadata(
                tool_name="create_remediation_plan",
                tool_type=ToolType.PLAN,
                risk_level="MEDIUM",
                requires_approval=False,
                allowed_agents=["grc-auditor-001"],
                description="발견된 위험 통제에 대한 멱등 시정조치 계획 생성",
            ),
            ToolMetadata(
                tool_name="generate_report",
                tool_type=ToolType.READ,
                risk_level="LOW",
                requires_approval=False,
                allowed_agents=["grc-auditor-001"],
                description="종합 GRC 감사 보고서 생성 및 브라우저/파일 렌더링",
            ),
            ToolMetadata(
                tool_name="execute_action",
                tool_type=ToolType.ACTION,
                risk_level="CRITICAL",
                requires_approval=True,
                allowed_agents=["grc-remediation-001"],
                description="승인된 교정 조치 시뮬레이션 및 실행",
            ),
        ]
        for t in default_tools:
            self.register(t)

    def register(self, tool: ToolMetadata) -> ToolMetadata:
        self._tools[tool.tool_name] = tool
        return tool

    def get(self, tool_name: str) -> Optional[ToolMetadata]:
        return self._tools.get(tool_name)

    def list_all(self) -> List[ToolMetadata]:
        return list(self._tools.values())

    def is_agent_authorized_for_tool(self, agent_id: str, tool_name: str) -> bool:
        """해당 에이전트가 대상 도구를 실행할 인가를 받았는지 검증합니다."""
        tool = self.get(tool_name)
        if not tool:
            return False
        return agent_id in tool.allowed_agents


# 전역 기본 레지스트리 인스턴스
global_agent_registry = AgentRegistry()
global_tool_registry = ToolRegistry()
