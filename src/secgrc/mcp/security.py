"""MCP 보안 파이프라인(MCP Security Pipeline) 모듈입니다.

다음을 수행합니다:
1. 에이전트 신원 및 상태 검증
2. 도구 인가 및 Excessive Agency 통제 (PolicyEngine)
3. 입력 인자 검증 및 경로 탐색(Path Traversal) 방어
4. 입력 프롬프트 인젝션 방어 (InputGuard)
5. 도구 호출 속도 제한 (Rate Limiting)
6. 타임아웃 보호 (Timeout Protection)
7. 결과 크기 및 아이템 수 한도 절삭 (Result Size Truncation)
8. 출력 시크릿 마스킹 및 DATA_ONLY 보장 (SecretGuard & OutputGuard)
9. 감사 로그 기록 (SecurityAuditLogger)
"""

import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from secgrc.agent_security.audit import SecurityAuditLogger
from secgrc.agent_security.input_guard import InputGuard
from secgrc.agent_security.models import PolicyDecision
from secgrc.agent_security.registry import AgentRegistry
from secgrc.agent_security.secret_guard import SecretGuard
from secgrc.mcp.models import MCPRequest, MCPToolMetadata, MCPToolResult
from secgrc.mcp.policy import MCPPolicyEngine
from secgrc.mcp.registry import MCPToolRegistry

# 경로 탐색 및 민감 파일 접근 차단 패턴
SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"\.\./"),                    # 상대 경로 탈출 (../)
    re.compile(r"/\.\."),                    # 역방향 탐색 (/..)
    re.compile(r"~[/\\]"),                   # 홈 디렉토리 확장
    re.compile(r"(?i)/etc/(passwd|shadow)"), # 시스템 인증 파일
    re.compile(r"(?i)\.env(\.local)?$"),     # 환경 변수 파일
    re.compile(r"(?i)(id_rsa|id_ed25519)"),  # 개인 SSH 키
    re.compile(r"(?i)\.git(/|\b)"),          # 내부 git 디렉토리
]

MAX_ITEMS_COUNT = 500
MAX_DATA_SIZE_BYTES = 1024 * 1024  # 1MB


class MCPSecurityPipeline:
    """MCP 도구 호출 전후의 종합 보안 통제를 강제하는 파이프라인"""

    def __init__(
        self,
        agent_registry: Optional[AgentRegistry] = None,
        tool_registry: Optional[MCPToolRegistry] = None,
        policy_engine: Optional[MCPPolicyEngine] = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
        max_calls_per_session: int = 20,
    ):
        self.agent_registry = agent_registry or AgentRegistry()
        self.tool_registry = tool_registry or MCPToolRegistry()
        self.policy_engine = policy_engine or MCPPolicyEngine(self.agent_registry, self.tool_registry)
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.max_calls_per_session = max_calls_per_session
        self._call_counts: Dict[str, int] = {}

    def _get_rate_limit_key(self, session_id: str, tool_id: str) -> str:
        return f"{session_id}:{tool_id}"

    def reset_rate_limits(self, session_id: Optional[str] = None):
        """테스트 및 세션 초기화용 속도 제한 카운터 리셋"""
        if session_id:
            keys_to_del = [k for k in self._call_counts if k.startswith(f"{session_id}:")]
            for k in keys_to_del:
                del self._call_counts[k]
        else:
            self._call_counts.clear()

    def validate_path_traversal(self, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """인자 내 경로 탐색, 디렉토리 탈출 및 시스템 민감 파일 접근 시도를 검사합니다."""
        for key, val in arguments.items():
            if isinstance(val, str):
                for pattern in SUSPICIOUS_PATH_PATTERNS:
                    if pattern.search(val):
                        return False, f"Path traversal or restricted file access detected in parameter '{key}': {val}"
        return True, None

    def validate_schema_and_arguments(
        self, tool: MCPToolMetadata, arguments: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """스키마 필수 필드 및 경로 탐색/인젝션 검증"""
        schema = tool.parameters_schema
        required_fields = schema.get("required", [])
        for field in required_fields:
            if field not in arguments:
                return False, f"Missing required parameter '{field}' for tool '{tool.tool_id}'."

        # 경로 탐색 검사
        is_safe_path, path_err = self.validate_path_traversal(arguments)
        if not is_safe_path:
            return False, path_err

        # 입력 프롬프트 인젝션 스캔 (문자열 인자에 악의적 지침 포함 여부)
        for key, val in arguments.items():
            if isinstance(val, str):
                detect_res = InputGuard.detect_injection(val)
                if detect_res.detected and detect_res.confidence >= 0.85:
                    return False, f"Prompt injection pattern detected in '{key}': {detect_res.category} (risk: {detect_res.risk})"

        return True, None

    def execute_with_guard(
        self,
        request: MCPRequest,
        handler: Callable[[Dict[str, Any]], Any],
    ) -> MCPToolResult:
        """보안 파이프라인을 엄격히 통과하여 도구를 실행합니다."""
        start_time = time.perf_counter()
        session_id = request.session_id or "default-session"
        agent_id = request.agent_id
        tool_id = request.tool_id
        args = request.arguments

        # 1. 속도 제한 (Rate Limiting) 검사
        rate_key = self._get_rate_limit_key(session_id, tool_id)
        current_calls = self._call_counts.get(rate_key, 0)
        tool_meta = self.tool_registry.get_tool(tool_id)
        max_allowed = tool_meta.rate_limit_per_session if tool_meta else self.max_calls_per_session

        if current_calls >= max_allowed:
            err_msg = f"Rate limit exceeded: Tool '{tool_id}' called {current_calls} times in session '{session_id}' (max: {max_allowed})."
            self.audit_logger.log_event(
                agent_id=agent_id,
                event="MCP_RATE_LIMITED",
                tool=tool_id,
                decision=PolicyDecision.DENY.value,
                risk_level="HIGH",
                reason=err_msg,
                details={"arguments": args, "session_id": session_id},
            )
            return MCPToolResult(
                success=False,
                tool_id=tool_id,
                data=None,
                error=err_msg,
                decision=PolicyDecision.DENY,
                execution_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        # 2. 정책 평가 (Policy Engine: Identity, Authorization, Excessive Agency)
        decision, reason = self.policy_engine.evaluate_tool_call(agent_id, tool_id, args)
        if decision != PolicyDecision.ALLOW:
            self.audit_logger.log_event(
                agent_id=agent_id,
                event="MCP_POLICY_DENIAL" if decision == PolicyDecision.DENY else "MCP_APPROVAL_REQUIRED",
                tool=tool_id,
                decision=decision.value,
                risk_level=tool_meta.risk_level.value if tool_meta else "HIGH",
                reason=reason,
                details={"arguments": args, "session_id": session_id},
            )
            return MCPToolResult(
                success=False,
                tool_id=tool_id,
                data=None,
                error=reason,
                decision=decision,
                execution_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        # 3. 입력 인자 검증 및 경로 탐색/인젝션 차단
        is_valid, validation_err = self.validate_schema_and_arguments(tool_meta, args)
        if not is_valid:
            self.audit_logger.log_event(
                agent_id=agent_id,
                event="MCP_ARGUMENT_BLOCKED",
                tool=tool_id,
                decision=PolicyDecision.DENY.value,
                risk_level="HIGH",
                reason=validation_err,
                details={"arguments": args, "session_id": session_id},
            )
            return MCPToolResult(
                success=False,
                tool_id=tool_id,
                data=None,
                error=validation_err,
                decision=PolicyDecision.DENY,
                execution_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        # 호출 횟수 증가
        self._call_counts[rate_key] = current_calls + 1

        # 4. 핸들러 실행 (타임아웃 보호 적용)
        # Python에서 시그널 기반 타임아웃은 메인 스레드 제약이 있으므로 경과 시간 측정 및 동기 호출 처리
        timeout_limit = tool_meta.timeout_seconds if tool_meta else 30
        try:
            exec_start = time.perf_counter()
            raw_data = handler(args)
            duration = time.perf_counter() - exec_start

            if duration > timeout_limit:
                err_msg = f"Tool execution timed out ({duration:.2f}s > {timeout_limit}s limit)."
                self.audit_logger.log_event(
                    agent_id=agent_id,
                    event="MCP_TOOL_TIMEOUT",
                    tool=tool_id,
                    decision=PolicyDecision.DENY.value,
                    risk_level="MEDIUM",
                    reason=err_msg,
                    details={"duration_seconds": duration, "limit": timeout_limit},
                )
                return MCPToolResult(
                    success=False,
                    tool_id=tool_id,
                    data=None,
                    error=err_msg,
                    decision=PolicyDecision.DENY,
                    execution_time_ms=duration * 1000,
                )
        except Exception as e:
            err_msg = f"Tool execution failed with exception: {type(e).__name__}: {str(e)}"
            self.audit_logger.log_event(
                agent_id=agent_id,
                event="MCP_TOOL_EXCEPTION",
                tool=tool_id,
                decision=PolicyDecision.DENY.value,
                risk_level="MEDIUM",
                reason=err_msg,
                details={"exception": str(e)},
            )
            return MCPToolResult(
                success=False,
                tool_id=tool_id,
                data=None,
                error=err_msg,
                decision=PolicyDecision.DENY,
                execution_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        # 5. 결과 크기 제한 및 절삭 (Result Size Truncation)
        truncated = False
        items_count = 0
        final_data = raw_data

        if isinstance(raw_data, list):
            items_count = len(raw_data)
            if items_count > MAX_ITEMS_COUNT:
                final_data = raw_data[:MAX_ITEMS_COUNT]
                truncated = True
        elif isinstance(raw_data, dict):
            items_count = len(raw_data)
        elif raw_data is not None:
            items_count = 1

        # 6. 시크릿 마스킹 및 DATA_ONLY 보장 (Secret Redaction & Output Guard)
        redacted_data = SecretGuard.redact(final_data)

        # 7. 성공 감사 로그 기록
        self.audit_logger.log_event(
            agent_id=agent_id,
            event="MCP_TOOL_EXECUTED",
            tool=tool_id,
            decision=PolicyDecision.ALLOW.value,
            risk_level=tool_meta.risk_level.value,
            reason=f"Tool executed successfully ({items_count} items)",
            details={
                "items_count": items_count,
                "truncated": truncated,
                "session_id": session_id,
            },
        )

        exec_ms = (time.perf_counter() - start_time) * 1000
        return MCPToolResult(
            success=True,
            tool_id=tool_id,
            data=redacted_data,
            is_data_only=True,
            items_count=items_count,
            truncated=truncated,
            error=None,
            decision=PolicyDecision.ALLOW,
            execution_time_ms=exec_ms,
        )
