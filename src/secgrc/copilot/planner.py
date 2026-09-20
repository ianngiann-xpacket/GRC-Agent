"""Copilot 질의 계획 수립기(CopilotQueryPlanner) 모듈입니다."""

import uuid
from typing import Any, Dict, List
from pydantic import BaseModel, Field

from secgrc.copilot.intents import IntentCategory, IntentResult

# 명시적 읽기 전용 허용 목록 (Read-Only Allowlist)
ALLOWED_OPERATIONS = {
    "GET_RISKS",
    "GET_CONTROLS",
    "GET_EVIDENCE",
    "GET_FINDINGS",
    "GET_ASSETS",
    "GET_REMEDIATIONS",
    "GET_FRAMEWORKS",
    "GET_RELATIONSHIPS",
    "GET_LINEAGE",
    "GET_COVERAGE",
    "GET_REDTEAM_SUMMARY",
    "GET_AGENT_SECURITY_STATUS",
}

# 엄격히 금지된 변경/실행 키워드 목록
FORBIDDEN_OPERATIONS = {
    "EXECUTE", "REMEDIATE", "APPLY", "MODIFY", "DELETE", "WRITE",
    "MUTATE", "UPDATE", "BYPASS", "GRANT", "INVOKE_TOOL"
}


class QueryPlan(BaseModel):
    """결정론적 실행 계획 모델"""
    plan_id: str = Field(default_factory=lambda: f"PLAN-{uuid.uuid4().hex[:8]}")
    intent: IntentCategory
    operations: List[str] = Field(default_factory=list)
    entities: Dict[str, Any] = Field(default_factory=dict)
    parameters: Dict[str, Any] = Field(default_factory=dict)


class CopilotQueryPlanner:
    """분류된 의도와 엔티티를 안전한 읽기 전용 실행 계획으로 변환하는 플래너"""

    def create_plan(self, intent_res: IntentResult) -> QueryPlan:
        """IntentResult를 바탕으로 검증된 QueryPlan을 생성합니다."""
        operations = intent_res.allowed_operations

        # 1. 안전성 검증: 금지된 변조 작업 포함 여부
        for op in operations:
            if any(forbidden in op for forbidden in FORBIDDEN_OPERATIONS):
                raise PermissionError(f"Security Violation: Unauthorized mutating operation detected: {op}")
            if op not in ALLOWED_OPERATIONS:
                raise ValueError(f"Security Violation: Operation '{op}' is not in the read-only query allowlist")

        # 2. 의도별 파라미터 보정
        parameters: Dict[str, Any] = {}
        if intent_res.intent == IntentCategory.RISK_OVERVIEW:
            parameters["top_k"] = 1
            parameters["sort_by"] = "risk_score"
        elif intent_res.intent == IntentCategory.FRAMEWORK_MAPPING:
            if intent_res.entities.get("unknown_framework"):
                parameters["target_framework"] = "NONEXISTENT_FRAMEWORK_UNKNOWN"
            else:
                parameters["target_framework"] = intent_res.entities.get("framework_id", "NIST-CSF")
        elif intent_res.intent in (IntentCategory.CONTROL_GAP, IntentCategory.CONTROL_EFFECTIVENESS):
            parameters["framework_id"] = "ISMS-P"

        return QueryPlan(
            intent=intent_res.intent,
            operations=operations,
            entities=intent_res.entities,
            parameters=parameters,
        )
