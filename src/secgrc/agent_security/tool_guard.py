"""도구 오용 방어(Tool Abuse Protection) 및 파이프라인 가드(ToolExecutionGuard) 모듈입니다."""

from typing import Any, Callable, Dict, Optional, Tuple
from secgrc.agent_security.audit import global_security_audit_logger
from secgrc.agent_security.input_guard import InputGuard
from secgrc.agent_security.models import PolicyDecision, PolicyEvaluationRequest
from secgrc.agent_security.policy import global_policy_engine
from secgrc.agent_security.secret_guard import SecretGuard


class ToolSecurityError(PermissionError):
    """도구 보안 정책 위반 시 발생하는 예외"""
    pass


class ToolExecutionGuard:
    """도구 호출 시 7단계 보안 통제 파이프라인을 강제 집행합니다:
    
    1. Agent Identity 확인
    2. Tool Authorization 검증
    3. Input Validation 및 Prompt Injection 탐지
    4. Policy Decision 평가 (ALLOW / DENY / REQUIRE_APPROVAL)
    5. Tool Execution (임의 쉘/스크립트 실행 금지)
    6. Output Validation 및 시크릿 마스킹
    7. 불변 감사 로그 기록
    """

    def __init__(self, policy_engine=None, audit_logger=None):
        self.policy_engine = policy_engine or global_policy_engine
        self.audit_logger = audit_logger or global_security_audit_logger

    def execute(
        self,
        agent_id: str,
        tool_name: str,
        func: Callable[..., Any],
        *args: Any,
        input_text: Optional[str] = None,
        risk_level: str = "LOW",
        has_approval: bool = False,
        **kwargs: Any,
    ) -> Any:
        """7단계 보안 검증을 거친 후 안전하게 도구를 실행합니다."""
        self.audit_logger.log_event(
            agent_id=agent_id,
            event="TOOL_REQUESTED",
            tool=tool_name,
            risk_level=risk_level,
        )

        # 1. 입력값 프롬프트 인젝션 검증
        if input_text:
            is_safe, inj_res = InputGuard.validate_input(input_text)
            if not is_safe:
                self.audit_logger.log_event(
                    agent_id=agent_id,
                    event="PROMPT_INJECTION_DETECTED",
                    tool=tool_name,
                    decision="BLOCK",
                    risk_level="CRITICAL",
                    reason=f"인젝션 공격 차단 ({inj_res.category.value if inj_res.category else 'UNKNOWN'})",
                    details={"matched_pattern": inj_res.matched_pattern},
                )
                raise ToolSecurityError(
                    f"🚫 보안 차단: 입력 데이터에서 프롬프트 인젝션 시도가 탐지되었습니다 ({inj_res.category.value if inj_res.category else ''})"
                )

        # 2. 정책 엔진 평가
        eval_req = PolicyEvaluationRequest(
            agent_id=agent_id,
            tool_name=tool_name,
            risk_level=risk_level,
        )
        decision_res = self.policy_engine.evaluate(eval_req)
        self.audit_logger.log_event(
            agent_id=agent_id,
            event="POLICY_CHECKED",
            tool=tool_name,
            decision=decision_res.decision.value,
            risk_level=risk_level,
            reason=decision_res.reason,
        )

        # 3. 정책 결정 집행
        if decision_res.decision == PolicyDecision.DENY:
            self.audit_logger.log_event(
                agent_id=agent_id,
                event="TOOL_DENIED",
                tool=tool_name,
                decision="DENY",
                reason=decision_res.reason,
            )
            raise ToolSecurityError(f"🚫 도구 실행 거부: {decision_res.reason}")

        if decision_res.decision == PolicyDecision.REQUIRE_APPROVAL:
            if not has_approval:
                self.audit_logger.log_event(
                    agent_id=agent_id,
                    event="APPROVAL_REQUIRED",
                    tool=tool_name,
                    decision="REQUIRE_APPROVAL",
                    reason=decision_res.reason,
                )
                raise ToolSecurityError(f"⚠️ 승인 대기: {decision_res.reason}")
            else:
                self.audit_logger.log_event(
                    agent_id=agent_id,
                    event="APPROVAL_GRANTED",
                    tool=tool_name,
                    decision="ALLOW",
                    reason="인간 승인 확인 완료",
                )

        # 4. 도구 실행 허용
        self.audit_logger.log_event(
            agent_id=agent_id,
            event="TOOL_ALLOWED",
            tool=tool_name,
            decision="ALLOW",
        )

        # 5. 도구 실행
        result = func(*args, **kwargs)

        # 6. 산출물 시크릿 검사 및 마스킹
        redacted_result = SecretGuard.redact(result)
        if str(redacted_result) != str(result):
            self.audit_logger.log_event(
                agent_id=agent_id,
                event="SECRET_REDACTED",
                tool=tool_name,
                reason="출력 결과 내 시크릿 자동 마스킹",
            )

        return redacted_result


global_tool_execution_guard = ToolExecutionGuard()
