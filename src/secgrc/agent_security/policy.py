"""보안 정책 결정 엔진(Policy Engine) 모듈입니다."""

from secgrc.agent_security.models import (
    AgentStatus,
    PolicyDecision,
    PolicyDecisionResult,
    PolicyEvaluationRequest,
    ToolType,
)
from secgrc.agent_security.permissions import PermissionChecker
from secgrc.agent_security.registry import global_agent_registry, global_tool_registry


class PolicyEngine:
    """에이전트 신원, 도구 인가, 위험 등급, 리소스 접근 권한을 종합 평가하여 최종 정책 결정을 내립니다."""

    def __init__(self, agent_reg=None, tool_reg=None):
        self.agent_registry = agent_reg or global_agent_registry
        self.tool_registry = tool_reg or global_tool_registry

    def evaluate(self, request: PolicyEvaluationRequest) -> PolicyDecisionResult:
        """단일 요청에 대해 ALLOW, DENY, REQUIRE_APPROVAL 중 하나를 결정합니다."""
        agent_id = request.agent_id
        tool_name = request.tool_name
        risk_level = (request.risk_level or "LOW").upper()

        # 1. 에이전트 존재 여부 확인
        agent = self.agent_registry.get(agent_id)
        if not agent:
            return PolicyDecisionResult(
                decision=PolicyDecision.DENY,
                agent_id=agent_id,
                tool_name=tool_name,
                risk_level=risk_level,
                reason=f"미등록 에이전트: 식별자 '{agent_id}'를 찾을 수 없습니다.",
            )

        # 2. 에이전트 수명주기 상태 확인 (REVOKED / SUSPENDED 차단)
        if agent.status == AgentStatus.REVOKED:
            return PolicyDecisionResult(
                decision=PolicyDecision.DENY,
                agent_id=agent_id,
                tool_name=tool_name,
                risk_level=risk_level,
                reason=f"차단된 에이전트: '{agent_id}'는 폐기(REVOKED) 상태이므로 일체의 도구 실행이 금지됩니다.",
            )
        elif agent.status == AgentStatus.SUSPENDED:
            return PolicyDecisionResult(
                decision=PolicyDecision.DENY,
                agent_id=agent_id,
                tool_name=tool_name,
                risk_level=risk_level,
                reason=f"일시 정지된 에이전트: '{agent_id}'는 정지(SUSPENDED) 상태입니다.",
            )

        # 3. 도구 등록 여부 확인
        tool = self.tool_registry.get(tool_name)
        if not tool:
            return PolicyDecisionResult(
                decision=PolicyDecision.DENY,
                agent_id=agent_id,
                tool_name=tool_name,
                risk_level=risk_level,
                reason=f"미등록 도구: 도구 '{tool_name}'는 시스템 도구 레지스트리에 존재하지 않습니다.",
            )

        # 4. 최소 권한(Least Privilege) 및 도구 인가 검사
        is_authorized, perm_reason = PermissionChecker.check_permission(agent, tool)
        if not is_authorized:
            return PolicyDecisionResult(
                decision=PolicyDecision.DENY,
                agent_id=agent_id,
                tool_name=tool_name,
                risk_level=risk_level,
                reason=perm_reason,
            )

        # 5. ACTION 도구이거나 CRITICAL/HIGH 위험 수준인 경우 휴먼 승인 요구
        if tool.tool_type == ToolType.ACTION or tool.requires_approval or risk_level in ("CRITICAL", "HIGH"):
            return PolicyDecisionResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                agent_id=agent_id,
                tool_name=tool_name,
                risk_level=risk_level,
                requires_human_approval=True,
                reason=f"고위험 조치 승인 필수: 도구 '{tool_name}' (위험도: {risk_level}) 실행 전 CISO/보안관리자 승인이 요구됩니다.",
            )

        # 6. 모든 보안 정책 통과
        return PolicyDecisionResult(
            decision=PolicyDecision.ALLOW,
            agent_id=agent_id,
            tool_name=tool_name,
            risk_level=risk_level,
            requires_human_approval=False,
            reason="정책 검증 통과: 인가된 도구 호출입니다.",
        )


global_policy_engine = PolicyEngine()
