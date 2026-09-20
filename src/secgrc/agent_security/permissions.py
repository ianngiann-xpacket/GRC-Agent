"""최소 권한 원칙(Least Privilege) 및 도구 인가 권한 매트릭스 모듈입니다."""

from typing import Tuple
from secgrc.agent_security.models import AgentIdentity, AgentRiskLevel, ToolMetadata, ToolType


class PermissionChecker:
    """에이전트의 역할과 자율 등급에 따라 도구 실행 권한을 엄격하게 제한합니다."""

    @classmethod
    def check_permission(cls, agent: AgentIdentity, tool: ToolMetadata) -> Tuple[bool, str]:
        """에이전트가 해당 도구를 실행할 수 있는지 검사합니다.
        
        규칙:
        1. 감사관 에이전트(L2 이하)는 ACTION 유형 도구(프로덕션 변경)를 실행할 수 없음.
        2. 도구의 allowed_agents 목록에 agent_id가 포함되어 있어야 함.
        3. 에이전트의 allowed_tools 목록에 tool_name이 포함되어 있어야 함.
        """
        # 1. ACTION 타입 도구는 최소 L4 이상의 Controlled Action 권한 요구
        if tool.tool_type == ToolType.ACTION:
            if agent.risk_level in (AgentRiskLevel.L0, AgentRiskLevel.L1, AgentRiskLevel.L2, AgentRiskLevel.L3):
                return False, f"최소 권한 위반: {agent.agent_id} (위험등급: {agent.risk_level.value})는 ACTION 도구를 실행할 수 없습니다."

        # 2. 도구의 허용 에이전트 목록 확인
        if agent.agent_id not in tool.allowed_agents:
            return False, f"도구 인가 실패: 에이전트 '{agent.agent_id}'는 도구 '{tool.tool_name}'의 인가 목록에 없습니다."

        # 3. 에이전트 자체 허용 도구 목록 확인
        if tool.tool_name not in agent.allowed_tools:
            return False, f"권한 부재: 에이전트 '{agent.agent_id}'의 인가 도구 목록에 '{tool.tool_name}'가 포함되어 있지 않습니다."

        return True, "Authorized"
