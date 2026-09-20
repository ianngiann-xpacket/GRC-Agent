"""MCP 도구 정책 평가 엔진(MCP Tool Policy Engine) 모듈입니다."""

from typing import Any, Dict, Optional, Tuple
from secgrc.agent_security.models import AgentStatus, PolicyDecision
from secgrc.agent_security.registry import AgentRegistry
from secgrc.mcp.models import MCPToolMetadata, MCPToolStatus
from secgrc.mcp.registry import MCPToolRegistry


class MCPPolicyEngine:
    """에이전트 신원, 도구 속성, 권한 수준 및 거버넌스 원칙에 따라 호출을 평가합니다."""

    def __init__(self, agent_registry: AgentRegistry, tool_registry: MCPToolRegistry):
        self.agent_registry = agent_registry
        self.tool_registry = tool_registry

    def evaluate_tool_call(
        self, agent_id: str, tool_id: str, arguments: Dict[str, Any]
    ) -> Tuple[PolicyDecision, str]:
        """도구 호출에 대한 정책 결정을 내립니다.
        
        반환값: (PolicyDecision, 사유 문자열)
        - ALLOW: 실행 허가
        - DENY: 정책 위반으로 즉시 차단
        - REQUIRE_APPROVAL: 사람의 승인 필요
        """
        # 1. 에이전트 신원 및 상태 확인
        agent = self.agent_registry.get(agent_id)
        if not agent:
            return PolicyDecision.DENY, f"Unregistered agent identity: {agent_id}"

        if agent.status == AgentStatus.REVOKED:
            return PolicyDecision.DENY, f"Agent {agent_id} has been REVOKED and is blocked from tool execution."
        if agent.status == AgentStatus.SUSPENDED:
            return PolicyDecision.DENY, f"Agent {agent_id} is SUSPENDED and cannot execute tools."

        # 2. 도구 등록 상태 확인
        tool: Optional[MCPToolMetadata] = self.tool_registry.get_tool(tool_id)
        if not tool:
            return PolicyDecision.DENY, f"Tool '{tool_id}' is not registered in MCPToolRegistry."

        if tool.status != MCPToolStatus.ACTIVE:
            return PolicyDecision.DENY, f"Tool '{tool_id}' is disabled or deprecated (status: {tool.status})."

        # 3. 최소 권한 원칙 (Least Privilege) & 인가 확인
        if agent_id not in tool.allowed_agents:
            return (
                PolicyDecision.DENY,
                f"Agent '{agent_id}' does not have permission to execute tool '{tool_id}' (allowed: {tool.allowed_agents}).",
            )

        # 4. Excessive Agency Guard: 프로덕션 변경 및 파괴적 Action 통제
        if tool.production_change or tool.requires_approval:
            # GRC Auditor 에이전트는 프로덕션 변경 도구를 실행할 수 없음
            if "auditor" in agent_id.lower():
                return (
                    PolicyDecision.DENY,
                    f"Auditor agents are strictly prohibited from invoking mutating action '{tool_id}'.",
                )
            return (
                PolicyDecision.REQUIRE_APPROVAL,
                f"Tool '{tool_id}' requires explicit human approval before execution (production_change=True).",
            )

        return PolicyDecision.ALLOW, f"Tool '{tool_id}' authorized for agent '{agent_id}'."
