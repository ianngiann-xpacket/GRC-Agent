"""AI 조사 및 보안 추론 메인 엔진(Reasoning Engine) 모듈."""

import copy
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple

from secgrc.ai.context import AIContextBuilder, AIInvestigationContext
from secgrc.ai.guard import AIInvestigationGuard, AIInvestigationGuardResult, GuardCheckStatus
from secgrc.ai.history import AIReasoningHistoryStore, AIReasoningRecord, default_ai_history_store
from secgrc.ai.hypotheses import HypothesisValidator
from secgrc.ai.models import (
    AIClaim,
    AIClaimType,
    AIExplanation,
    AIReasoningResult,
    AIReasoningStatus,
    InvestigationHypothesisAI,
    InvestigationQuestion,
    ReasoningType,
    RootCauseCandidate,
)
from secgrc.ai.policy import AIInvestigationPolicy, DEFAULT_AI_POLICY
from secgrc.ai.prompts import PromptTemplate, TEMPLATE_HYPOTHESIS_V1
from secgrc.ai.provider import LLMProvider, MockLLMProvider
from secgrc.ai.questions import QuestionValidator
from secgrc.ai.registry import default_prompt_registry, default_provider_registry
from secgrc.ai.request import LLMRequest
from secgrc.ai.response import LLMResponse
from secgrc.ai.tasks import AIInvestigationTask


class AIReasoningEngine:
    """결정론적 입력 데이터만을 바탕으로 비권위적 추론(가설, 질문, 설명, 원인 후보)을 도출하는 핵심 엔진 (Step 27).
    
    절대 원칙:
    - LLM은 권위 있는 사실(Fact)을 생성할 수 없음 (자동 변환 또는 거부).
    - LLM은 리스크, 통제, 컴플라이언스 판정을 수정할 수 없음.
    - 모든 추론 결과는 비권위적(is_authoritative=False)이며 AIInvestigationGuard 검증을 통과해야 함.
    - 실패 시에도 기존 결정론적 GRC 상태에 영향을 주지 않음 (Safe Failure).
    """

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        guard: Optional[AIInvestigationGuard] = None,
        history_store: Optional[AIReasoningHistoryStore] = None,
        policy: Optional[AIInvestigationPolicy] = None,
        context_builder: Optional[AIContextBuilder] = None,
    ):
        self.provider = provider or default_provider_registry.get_default()
        self.guard = guard or AIInvestigationGuard()
        self.history_store = history_store or default_ai_history_store
        self.policy = policy or DEFAULT_AI_POLICY
        self.context_builder = context_builder or AIContextBuilder(self.policy)

    def reason(
        self,
        task: AIInvestigationTask,
        context: AIInvestigationContext,
        template: Optional[PromptTemplate] = None,
    ) -> Tuple[Optional[AIReasoningResult], AIInvestigationGuardResult]:
        """단일 바운디드 조사 작업에 대해 AI 추론을 실행하고 가드 검증을 거친 결과를 반환합니다."""
        inv_id = task.investigation_id
        tpl = template or default_prompt_registry.get(f"TPL-{task.required_output_type.value}-V1") or TEMPLATE_HYPOTHESIS_V1

        # 1. LLMRequest 생성
        req_id = f"req-{uuid.uuid4().hex[:8]}"
        llm_request = LLMRequest(
            request_id=req_id,
            investigation_id=inv_id,
            request_type=task.required_output_type.value,
            system_context=tpl.system_instruction,
            fact_context=context.facts,
            evidence_context=context.evidence,
            relationship_context=context.relationships,
            allowed_scope=context.scope,
            allowed_entities=context.allowed_entity_ids,
            prompt_template_id=tpl.template_id,
            prompt_template_version=tpl.template_version,
        )
        llm_request.request_hash = llm_request.compute_request_hash()

        # 2. LLM 호출 (에러 격리 및 비저하 보장)
        try:
            llm_response = self.provider.generate(llm_request)
        except Exception as err:
            # 프로바이더 장애 시 GRC 상태 저하 없이 안전 실패 반환 (Section 61, 74)
            failed_guard = AIInvestigationGuardResult(
                guard_id=f"guard-err-{uuid.uuid4().hex[:6]}",
                status=GuardCheckStatus.BLOCK,
                checks={"PROVIDER_EXECUTION": "BLOCK"},
                violations=[f"Provider error: {str(err)}"],
            )
            rec = AIReasoningRecord(
                record_id=f"rec-{uuid.uuid4().hex[:8]}",
                request_id=req_id,
                response_id=f"resp-err-{uuid.uuid4().hex[:6]}",
                investigation_id=inv_id,
                provider_id=self.provider.provider_id,
                model_id=self.provider.model_id,
                prompt_template_id=tpl.template_id,
                prompt_template_version=tpl.template_version,
                context_hash=context.context_hash,
                output_hash="",
                guard_result=failed_guard,
                reasoning_result=None,
            )
            self.history_store.append_record(rec)
            return None, failed_guard

        # 3. 1차 원시 응답 보안 검증 (도구 호출, 비밀키 추출, 권한 오버라이드 탐지)
        raw_guard_result = self.guard.validate_raw_response(llm_response, context)
        if raw_guard_result.is_blocked:
            rec = AIReasoningRecord(
                record_id=f"rec-{uuid.uuid4().hex[:8]}",
                request_id=req_id,
                response_id=llm_response.response_id,
                investigation_id=inv_id,
                provider_id=self.provider.provider_id,
                model_id=self.provider.model_id,
                prompt_template_id=tpl.template_id,
                prompt_template_version=tpl.template_version,
                context_hash=context.context_hash,
                output_hash=llm_response.raw_output_hash,
                guard_result=raw_guard_result,
                reasoning_result=None,
            )
            self.history_store.append_record(rec)
            return None, raw_guard_result

        # 4. 구조화된 출력 파싱 및 객체화
        structured_data = llm_response.structured_output or {}
        if not structured_data and llm_response.response_text:
            try:
                structured_data = json.loads(llm_response.response_text)
            except Exception:
                structured_data = {}

        # 5. 사실 생성 방지 변환 (Section 10: FACT -> HYPOTHESIS/INFERENCE 강제 다운그레이드)
        parsed_claims: List[AIClaim] = []
        for raw_c in structured_data.get("claims", []):
            c_type = raw_c.get("claim_type", "HYPOTHESIS")
            if c_type == "FACT":
                # LLM이 자율적으로 FACT를 주장한 경우 HYPOTHESIS로 강제 변환
                c_type = "HYPOTHESIS"
            parsed_claims.append(
                AIClaim(
                    claim_id=raw_c.get("claim_id", f"claim-{uuid.uuid4().hex[:6]}"),
                    claim_type=AIClaimType(c_type),
                    statement=raw_c.get("statement", ""),
                    supporting_fact_ids=raw_c.get("supporting_fact_ids", []),
                    supporting_evidence_ids=raw_c.get("supporting_evidence_ids", []),
                    contradicting_fact_ids=raw_c.get("contradicting_fact_ids", []),
                    confidence=float(raw_c.get("confidence", 0.7)),
                    grounded=bool(raw_c.get("grounded", True)),
                )
            )

        # 6. 가설 파싱 및 결정론적 지지 수준 평가 (Section 13, 35, 36)
        parsed_hypotheses: List[InvestigationHypothesisAI] = []
        for raw_h in structured_data.get("hypotheses", []):
            h_obj = InvestigationHypothesisAI(
                hypothesis_id=raw_h.get("hypothesis_id", f"hypo-{uuid.uuid4().hex[:6]}"),
                investigation_id=inv_id,
                statement=raw_h.get("statement", ""),
                supporting_fact_ids=raw_h.get("supporting_fact_ids", []),
                supporting_evidence_ids=raw_h.get("supporting_evidence_ids", []),
                contradicting_fact_ids=raw_h.get("contradicting_fact_ids", []),
                status="PROPOSED",  # 자율 승격 원천 차단
                validation_required=True,
                created_by="LLM",
            )
            # 결정론적 증적 대조 및 주석 부여
            annotated_h = HypothesisValidator.validate_and_annotate(h_obj, context)
            parsed_hypotheses.append(annotated_h)

        # 7. 질문 파싱 및 자격증명 추출 차단 (Section 15, 16)
        parsed_questions: List[InvestigationQuestion] = []
        for raw_q in structured_data.get("questions", []):
            try:
                q_obj = InvestigationQuestion(
                    question_id=raw_q.get("question_id", f"q-{uuid.uuid4().hex[:6]}"),
                    investigation_id=inv_id,
                    question=raw_q.get("question", ""),
                    reason=raw_q.get("reason", ""),
                    target_data_type=raw_q.get("target_data_type", "Telemetry"),
                    target_entity_ids=raw_q.get("target_entity_ids", []),
                    priority=raw_q.get("priority", "P2"),
                    created_by="LLM",
                )
                parsed_questions.append(q_obj)
            except ValueError:
                # 비밀키/토큰 요청 질문은 pydantic validator에서 자동 거부됨
                continue

        # 8. 설명 및 근본 원인 후보 파싱 (Section 14, 17)
        parsed_explanations: List[AIExplanation] = []
        for raw_e in structured_data.get("explanations", []):
            parsed_explanations.append(
                AIExplanation(
                    explanation_id=raw_e.get("explanation_id", f"exp-{uuid.uuid4().hex[:6]}"),
                    target_type=raw_e.get("target_type", "FINDING"),
                    target_id=raw_e.get("target_id", "TARGET-001"),
                    summary=raw_e.get("summary", ""),
                    reasoning_points=raw_e.get("reasoning_points", []),
                    supporting_refs=raw_e.get("supporting_refs", []),
                    uncertainty_points=raw_e.get("uncertainty_points", ["Uncertainty structurally preserved."]),
                    created_by="LLM",
                )
            )

        parsed_root_causes: List[RootCauseCandidate] = []
        for raw_rc in structured_data.get("root_causes", []):
            parsed_root_causes.append(
                RootCauseCandidate(
                    candidate_id=raw_rc.get("candidate_id", f"rc-{uuid.uuid4().hex[:6]}"),
                    investigation_id=inv_id,
                    candidate=raw_rc.get("candidate", ""),
                    supporting_fact_ids=raw_rc.get("supporting_fact_ids", []),
                    contradicting_fact_ids=raw_rc.get("contradicting_fact_ids", []),
                    status="PROPOSED",
                    created_by="LLM",
                )
            )

        # 인간 검토 필수 트리거 판정 (Section 37, 72)
        human_review_required = (
            task.human_review_required
            or len(parsed_root_causes) > 0
            or any(h.support_level == "CONTRADICTED" for h in parsed_hypotheses)
        )

        # 9. AIReasoningResult 객체 조립
        result_id = f"reasoning-{uuid.uuid4().hex[:8]}"
        res = AIReasoningResult(
            reasoning_id=result_id,
            investigation_id=inv_id,
            reasoning_type=task.required_output_type,
            claims=parsed_claims[:self.policy.max_hypotheses * 2],
            hypotheses=parsed_hypotheses[:self.policy.max_hypotheses],
            questions=parsed_questions[:self.policy.max_questions],
            explanations=parsed_explanations,
            root_causes=parsed_root_causes,
            supporting_fact_ids=[f.get("fact_id") for f in context.facts if isinstance(f, dict) and f.get("fact_id")],
            supporting_evidence_ids=[e.get("evidence_id") for e in context.evidence if isinstance(e, dict) and e.get("evidence_id")],
            supporting_relationship_ids=[],
            contradicting_fact_ids=[],
            uncertainties=structured_data.get("uncertainties", []),
            provider_id=self.provider.provider_id,
            model_id=self.provider.model_id,
            prompt_template_id=tpl.template_id,
            prompt_template_version=tpl.template_version,
            provenance={"source": "AIReasoningEngine", "context_hash": context.context_hash},
            human_review_required=human_review_required,
            is_authoritative=False,
        )
        res.integrity_hash = res.compute_integrity_hash()

        # 10. 2차 포괄적 가드 검증 (Section 28)
        full_guard_result = self.guard.validate_reasoning_result(res, context)

        # 11. 불변 이력 저장소 기록 (Section 38)
        rec = AIReasoningRecord(
            record_id=f"rec-{uuid.uuid4().hex[:8]}",
            request_id=req_id,
            response_id=llm_response.response_id,
            investigation_id=inv_id,
            provider_id=self.provider.provider_id,
            model_id=self.provider.model_id,
            prompt_template_id=tpl.template_id,
            prompt_template_version=tpl.template_version,
            context_hash=context.context_hash,
            output_hash=llm_response.raw_output_hash,
            guard_result=full_guard_result,
            reasoning_result=res if not full_guard_result.is_blocked else None,
        )
        self.history_store.append_record(rec)

        return res, full_guard_result
