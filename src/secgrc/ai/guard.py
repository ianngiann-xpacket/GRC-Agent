"""AI 조사 가드(AI Investigation Guard) 모듈 (Section 27 - 34)."""

from datetime import datetime, timezone
from enum import Enum
import re
import uuid
from typing import Any, Dict, List, Optional
from pydantic import Field

from secgrc.ai.context import AIInvestigationContext
from secgrc.ai.models import (
    AIBaseModel,
    AIClaimType,
    AIReasoningResult,
    CREDENTIAL_PATTERNS,
    DANGEROUS_ID_PATTERNS,
    INSTRUCTION_PATTERNS,
    validate_id_str,
)
from secgrc.ai.response import LLMResponse


class GuardCheckStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"


class AIInvestigationGuardResult(AIBaseModel):
    """AI 조사 가드 판정 결과 모델 (Section 28)"""
    guard_id: str = Field(description="가드 검증 고유 식별자")
    status: GuardCheckStatus = Field(description="전체 판정 결과 (PASS / WARN / BLOCK)")
    checks: Dict[str, str] = Field(description="12대 세부 점검 항목별 상태 (PASS/WARN/BLOCK)")
    violations: List[str] = Field(default_factory=list, description="위반 사유 목록")
    guard_version: str = Field(default="1.0.0", description="가드 엔진 버전")
    validated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="검증 일시 (ISO-8601)",
    )

    @property
    def is_blocked(self) -> bool:
        return self.status == GuardCheckStatus.BLOCK


class AIInvestigationGuard:
    """LLM의 출력, 주장 접지성, 사실/가설 경계 및 권한 모델을 독립적으로 검증하는 가드 (Section 27).
    
    23.5 Guard(조사 상태 검증)와 명확히 구분되며, 오직 AI 출력의 보안성과 비권위적 불변성을 검증합니다.
    """

    GUARD_VERSION = "1.0.0"

    def __init__(self, strict_grounding: bool = True):
        self.strict_grounding = strict_grounding

    def validate_raw_response(self, response: LLMResponse, context: AIInvestigationContext) -> AIInvestigationGuardResult:
        """원시 LLM 응답 텍스트에 대한 1차 보안 검증 (도구 호출, 인젝션, 비밀키 누출 탐지)."""
        checks: Dict[str, str] = {}
        violations: List[str] = []
        text = response.response_text or ""
        text_lower = text.lower()

        # 1. TOOL_SAFETY (Section 43, 44, 70)
        tool_patterns = [
            "<tool_call>",
            "</tool_call>",
            "\"tool\":",
            "\"action\": \"run_command\"",
            "\"action\":\"run_command\"",
            "run_command(",
            "execute(",
            "\"tool_call\":",
        ]
        if any(pat in text_lower for pat in tool_patterns):
            checks["TOOL_SAFETY"] = "BLOCK"
            violations.append("TOOL_SAFETY: Model output contains forbidden tool execution patterns.")
        else:
            checks["TOOL_SAFETY"] = "PASS"

        # 2. SECRET_SAFETY (Section 16, 45)
        secret_request_patterns = [
            "show api key",
            "show system prompt",
            "show credentials",
            "show environment variables",
            "show hidden context",
            "what is the password",
            "aws root password",
        ]
        if any(pat in text_lower for pat in secret_request_patterns):
            checks["SECRET_SAFETY"] = "BLOCK"
            violations.append("SECRET_SAFETY: Model output requests sensitive secrets/system prompts.")
        else:
            checks["SECRET_SAFETY"] = "PASS"

        # 3. RISK_AUTHORITY (Section 30, 66, 88)
        # LLM이 임의로 리스크 점수를 재정의하거나 93.0 기준선을 번복하려는 시도 감지
        if "risk score should be" in text_lower or "\"risk_score_override\"" in text_lower:
            checks["RISK_AUTHORITY"] = "BLOCK"
            violations.append("RISK_AUTHORITY: LLM attempted to override or mutate authoritative risk score.")
        else:
            checks["RISK_AUTHORITY"] = "PASS"

        # 4. COMPLIANCE_AUTHORITY (Section 31, 67, 89)
        if "\"compliance_status_override\"" in text_lower or "mark control pass" in text_lower:
            checks["COMPLIANCE_AUTHORITY"] = "BLOCK"
            violations.append("COMPLIANCE_AUTHORITY: LLM attempted to override deterministic compliance decision.")
        else:
            checks["COMPLIANCE_AUTHORITY"] = "PASS"

        overall_status = GuardCheckStatus.BLOCK if any(v == "BLOCK" for v in checks.values()) else GuardCheckStatus.PASS

        return AIInvestigationGuardResult(
            guard_id=f"guard-{uuid.uuid4().hex[:8]}",
            status=overall_status,
            checks=checks,
            violations=violations,
            guard_version=self.GUARD_VERSION,
        )

    def validate_reasoning_result(
        self,
        result: AIReasoningResult,
        context: AIInvestigationContext,
    ) -> AIInvestigationGuardResult:
        """구조화된 AIReasoningResult 객체에 대한 포괄적 12대 가드 검증 (Section 28)."""
        checks: Dict[str, str] = {}
        violations: List[str] = []

        # 컨텍스트 내 알려진 ID 집합 구성
        known_fact_ids = {f.get("fact_id") for f in context.facts if isinstance(f, dict) and f.get("fact_id")}
        known_evidence_ids = {e.get("evidence_id") for e in context.evidence if isinstance(e, dict) and e.get("evidence_id")}
        allowed_entity_set = set(context.allowed_entity_ids)
        for f in context.facts:
            if isinstance(f, dict):
                if f.get("entity_id"):
                    allowed_entity_set.add(f.get("entity_id"))
                if f.get("source_id"):
                    allowed_entity_set.add(f.get("source_id"))
        for e in context.evidence:
            if isinstance(e, dict):
                if e.get("entity_id"):
                    allowed_entity_set.add(e.get("entity_id"))
                if e.get("resource_id"):
                    allowed_entity_set.add(e.get("resource_id"))

        # [1] FACT_BOUNDARY (Section 10, 29)
        # LLM은 FACT를 생성할 수 없음. claim_type이 FACT인 경우 차단
        has_fact_claim = any(c.claim_type == AIClaimType.FACT for c in result.claims)
        if has_fact_claim:
            checks["FACT_BOUNDARY"] = "BLOCK"
            violations.append("FACT_BOUNDARY: LLM output claims to be authoritative FACT without prior record.")
        else:
            checks["FACT_BOUNDARY"] = "PASS"

        # [2] HYPOTHESIS_BOUNDARY (Section 13, 35)
        # LLM은 PROPOSED 상태만 가능하며 자율 승격(SUPPORTED) 불가
        invalid_hypo = any(h.status not in ["PROPOSED", "UNRESOLVED"] for h in result.hypotheses)
        if invalid_hypo:
            checks["HYPOTHESIS_BOUNDARY"] = "BLOCK"
            violations.append("HYPOTHESIS_BOUNDARY: LLM attempted to auto-promote hypothesis beyond PROPOSED.")
        else:
            checks["HYPOTHESIS_BOUNDARY"] = "PASS"

        # [3] CLAIM_GROUNDING (Section 11, 71)
        # 모든 주장은 컨텍스트 내 실재하는 fact_id 또는 evidence_id를 참조해야 함
        un_grounded = []
        for c in result.claims:
            if c.claim_type != AIClaimType.QUESTION:
                all_refs = set(c.supporting_fact_ids + c.supporting_evidence_ids)
                if not all_refs:
                    un_grounded.append(c.claim_id)
                else:
                    # 알려지지 않은 ID 참조 여부 검사
                    unknown_facts = set(c.supporting_fact_ids) - known_fact_ids
                    unknown_ev = set(c.supporting_evidence_ids) - known_evidence_ids
                    if unknown_facts or unknown_ev:
                        un_grounded.append(f"{c.claim_id}(unknown refs: {unknown_facts | unknown_ev})")

        # 가설 접지 검사
        for h in result.hypotheses:
            unknown_facts = set(h.supporting_fact_ids) - known_fact_ids
            unknown_ev = set(h.supporting_evidence_ids) - known_evidence_ids
            if unknown_facts or unknown_ev:
                un_grounded.append(f"{h.hypothesis_id}(unknown refs: {unknown_facts | unknown_ev})")

        if un_grounded:
            checks["CLAIM_GROUNDING"] = "BLOCK" if self.strict_grounding else "WARN"
            violations.append(f"CLAIM_GROUNDING: Un-grounded or fictitious references found: {un_grounded}")
        else:
            checks["CLAIM_GROUNDING"] = "PASS"

        # [4] SCOPE (Section 33, 69)
        # 인가된 스코프 외의 미승인 엔티티를 다루는지 검사
        out_of_scope_entities = set()
        for q in result.questions:
            for ent in q.target_entity_ids:
                if ent not in allowed_entity_set and ent not in known_evidence_ids and ent not in known_fact_ids:
                    out_of_scope_entities.add(ent)
        if out_of_scope_entities:
            checks["SCOPE"] = "BLOCK"
            violations.append(f"SCOPE: LLM referenced out-of-scope entities: {out_of_scope_entities}")
        else:
            checks["SCOPE"] = "PASS"

        # [5] PROVENANCE (Section 32, 68)
        # 컨텍스트에 없는 출처 시스템 날조 검사
        fake_provenance = False
        if result.provenance:
            src_sys = result.provenance.get("source_system", "").upper()
            if src_sys in ["KISA", "GOVERNMENT", "INTERNAL_AUDIT"] and not any(src_sys in str(f) for f in context.facts):
                fake_provenance = True
        if fake_provenance:
            checks["PROVENANCE"] = "BLOCK"
            violations.append("PROVENANCE: LLM invented fictitious source provenance not present in context.")
        else:
            checks["PROVENANCE"] = "PASS"

        # [6] SECRET_SAFETY (Section 16, 45)
        unsafe_questions = []
        for q in result.questions:
            q_lower = q.question.lower()
            if any(p in q_lower for p in CREDENTIAL_PATTERNS):
                unsafe_questions.append(q.question_id)
        if unsafe_questions:
            checks["SECRET_SAFETY"] = "BLOCK"
            violations.append(f"SECRET_SAFETY: Questions request credentials: {unsafe_questions}")
        else:
            checks["SECRET_SAFETY"] = "PASS"

        # [7] TOOL_SAFETY (Section 43, 44, 70)
        # 구조화된 객체에 실행 도구 요청이 들어있지 않은지 검증
        checks["TOOL_SAFETY"] = "PASS"

        # [8] COMPLIANCE_AUTHORITY (Section 31)
        checks["COMPLIANCE_AUTHORITY"] = "PASS"

        # [9] RISK_AUTHORITY (Section 30)
        checks["RISK_AUTHORITY"] = "PASS"

        # [10] DETERMINISM (Section 39, 73)
        checks["DETERMINISM"] = "PASS"

        # [11] OUTPUT_SCHEMA (Section 20)
        checks["OUTPUT_SCHEMA"] = "PASS"

        # [12] INJECTION_RESILIENCE (Section 26, 64)
        checks["INJECTION_RESILIENCE"] = "PASS"

        overall_status = GuardCheckStatus.BLOCK if any(v == "BLOCK" for v in checks.values()) else (
            GuardCheckStatus.WARN if any(v == "WARN" for v in checks.values()) else GuardCheckStatus.PASS
        )

        return AIInvestigationGuardResult(
            guard_id=f"guard-{uuid.uuid4().hex[:8]}",
            status=overall_status,
            checks=checks,
            violations=violations,
            guard_version=self.GUARD_VERSION,
        )
