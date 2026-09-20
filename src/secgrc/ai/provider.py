"""LLM 프로바이더 추상화 및 결정론적 목(Mock) 프로바이더 모듈 (Section 4)."""

import hashlib
import json
import uuid
from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable

from secgrc.ai.models import (
    AIClaim,
    AIClaimType,
    AIExplanation,
    InvestigationHypothesisAI,
    InvestigationQuestion,
    ReasoningType,
    RootCauseCandidate,
)
from secgrc.ai.request import LLMRequest
from secgrc.ai.response import LLMResponse


@runtime_checkable
class LLMProvider(Protocol):
    """LLM 프로바이더 인터페이스 규약 (Section 4)"""
    provider_id: str
    model_id: str

    def generate(self, request: LLMRequest) -> LLMResponse:
        """주어진 요청에 대해 LLM 응답을 생성합니다."""
        ...


class MockLLMProvider:
    """테스트 및 결정론적 오프라인 추론을 위한 Mock LLM 프로바이더.
    
    외부 네트워크 호출 없이, 입력 컨텍스트와 태스크에 맞추어 검증된 구조화된 JSON 출력을 생성합니다.
    테스트를 위한 커스텀 응답 오버라이드 및 시나리오 주입 기능을 지원합니다.
    """

    def __init__(
        self,
        provider_id: str = "mock-provider",
        model_id: str = "deterministic-security-reasoner-v1",
        custom_generator: Optional[Callable[[LLMRequest], Dict[str, Any]]] = None,
    ):
        self.provider_id = provider_id
        self.model_id = model_id
        self.custom_generator = custom_generator
        self._preset_responses: Dict[str, Dict[str, Any]] = {}
        self._inject_tool_call = False
        self._inject_secret_request = False
        self._inject_fact_claim = False
        self._inject_risk_override = False
        self._inject_compliance_override = False

    def preset_response(self, request_type: str, structured_data: Dict[str, Any]) -> None:
        """특정 요청 유형에 대한 반환 데이터를 사전 설정합니다."""
        self._preset_responses[request_type] = structured_data

    def set_adversarial_flags(
        self,
        inject_tool_call: bool = False,
        inject_secret_request: bool = False,
        inject_fact_claim: bool = False,
        inject_risk_override: bool = False,
        inject_compliance_override: bool = False,
    ) -> None:
        """가드 검증 테스트를 위한 이상 출력 플래그를 설정합니다."""
        self._inject_tool_call = inject_tool_call
        self._inject_secret_request = inject_secret_request
        self._inject_fact_claim = inject_fact_claim
        self._inject_risk_override = inject_risk_override
        self._inject_compliance_override = inject_compliance_override

    def generate(self, request: LLMRequest) -> LLMResponse:
        """요청을 받아 결정론적 응답을 생성합니다."""
        # 1. 사전 주입 플래그 검사 (적대적 테스트용)
        if self._inject_tool_call:
            raw_text = json.dumps({
                "type": "tool_call",
                "tool": "nmap",
                "target": "10.0.0.1",
            })
            return LLMResponse(
                response_id=f"resp-{uuid.uuid4().hex[:8]}",
                request_id=request.request_id,
                provider_id=self.provider_id,
                model_id=self.model_id,
                response_text=raw_text,
                structured_output={"tool_call": {"name": "nmap", "args": {"target": "10.0.0.1"}}},
                raw_output_hash=hashlib.sha256(raw_text.encode()).hexdigest(),
                usage_metadata={"input_tokens": 100, "output_tokens": 50, "latency_ms": 10.0},
            )

        if self._inject_risk_override:
            raw_text = json.dumps({
                "reasoning_type": "EXPLANATION",
                "claims": [{"type": "INFERENCE", "statement": "Risk score should be 98", "supporting_fact_ids": []}],
                "risk_score_override": 98.0,
            })
            return LLMResponse(
                response_id=f"resp-{uuid.uuid4().hex[:8]}",
                request_id=request.request_id,
                provider_id=self.provider_id,
                model_id=self.model_id,
                response_text=raw_text,
                structured_output=json.loads(raw_text),
                raw_output_hash=hashlib.sha256(raw_text.encode()).hexdigest(),
                usage_metadata={"input_tokens": 100, "output_tokens": 50, "latency_ms": 10.0},
            )

        if self._inject_compliance_override:
            raw_text = json.dumps({
                "reasoning_type": "EXPLANATION",
                "claims": [{"type": "INFERENCE", "statement": "ISMS-P requirement is failed without assessment reference", "supporting_fact_ids": []}],
                "compliance_status_override": "FAIL",
            })
            return LLMResponse(
                response_id=f"resp-{uuid.uuid4().hex[:8]}",
                request_id=request.request_id,
                provider_id=self.provider_id,
                model_id=self.model_id,
                response_text=raw_text,
                structured_output=json.loads(raw_text),
                raw_output_hash=hashlib.sha256(raw_text.encode()).hexdigest(),
                usage_metadata={"input_tokens": 100, "output_tokens": 50, "latency_ms": 10.0},
            )

        # 2. 사용자 정의 생성기 또는 사전 설정 응답 확인
        if self.custom_generator:
            data = self.custom_generator(request)
        elif request.request_type in self._preset_responses:
            data = self._preset_responses[request.request_type]
        else:
            data = self._default_deterministic_response(request)

        # 3. 사실 사칭 플래그 주입 시
        if self._inject_fact_claim:
            data.setdefault("claims", []).append({
                "claim_id": f"claim-fact-{uuid.uuid4().hex[:6]}",
                "claim_type": "FACT",
                "statement": "Administrator account was compromised.",
                "supporting_fact_ids": [],
            })

        # 4. 비밀키 요청 주입 시
        if self._inject_secret_request:
            data.setdefault("questions", []).append({
                "question_id": f"q-secret-{uuid.uuid4().hex[:6]}",
                "investigation_id": request.investigation_id,
                "question": "What is the AWS root password and API secret token?",
                "reason": "Need password for validation",
                "target_data_type": "Credentials",
                "target_entity_ids": [],
                "priority": "P1",
                "created_by": "LLM",
            })

        raw_text = json.dumps(data, indent=2, default=str)
        raw_hash = hashlib.sha256(raw_text.encode()).hexdigest()

        return LLMResponse(
            response_id=f"resp-{uuid.uuid4().hex[:8]}",
            request_id=request.request_id,
            provider_id=self.provider_id,
            model_id=self.model_id,
            response_text=raw_text,
            structured_output=data,
            raw_output_hash=raw_hash,
            usage_metadata={"input_tokens": 150, "output_tokens": 120, "latency_ms": 15.5},
        )

    def _default_deterministic_response(self, request: LLMRequest) -> Dict[str, Any]:
        """컨텍스트에 기반하여 기본적이고 접지된(Grounded) 추론 응답을 생성합니다."""
        inv_id = request.investigation_id
        fact_ids = [f.get("fact_id", "FACT-001") for f in request.fact_context if isinstance(f, dict)]
        evidence_ids = [e.get("evidence_id", "EV-001") for e in request.evidence_context if isinstance(e, dict)]

        # 기본 사실 ID가 없는 경우 접지용
        if not fact_ids:
            fact_ids = ["FACT-001"] if request.fact_context else []
        if not evidence_ids:
            evidence_ids = ["EV-001"] if request.evidence_context else []

        # 태스크별 응답 구조화
        return {
            "reasoning_type": request.request_type if request.request_type in ReasoningType.__members__ else "HYPOTHESIS",
            "claims": [
                {
                    "claim_id": f"claim-{inv_id}-1",
                    "claim_type": "HYPOTHESIS",
                    "statement": "Configuration drift in cloud storage access control may be a contributing factor.",
                    "supporting_fact_ids": fact_ids[:2],
                    "supporting_evidence_ids": evidence_ids[:2],
                    "contradicting_fact_ids": [],
                    "confidence": 0.85,
                    "grounded": True,
                }
            ],
            "hypotheses": [
                {
                    "hypothesis_id": f"hypo-{inv_id}-1",
                    "investigation_id": inv_id,
                    "statement": "Configuration drift in access permissions resulted in unexpected exposure.",
                    "supporting_fact_ids": fact_ids[:2],
                    "supporting_evidence_ids": evidence_ids[:2],
                    "contradicting_fact_ids": [],
                    "status": "PROPOSED",
                    "validation_required": True,
                    "created_by": "LLM",
                }
            ],
            "questions": [
                {
                    "question_id": f"q-{inv_id}-1",
                    "investigation_id": inv_id,
                    "question": "Was the privileged access review completed after the IAM policy change?",
                    "reason": "Verify whether unauthorized policy drift occurred without prior approval",
                    "target_data_type": "AccessReview",
                    "target_entity_ids": request.allowed_entities[:2],
                    "priority": "P2",
                    "created_by": "LLM",
                }
            ],
            "explanations": [
                {
                    "explanation_id": f"exp-{inv_id}-1",
                    "target_type": "RISK",
                    "target_id": "RSK-ISMS-P-2.7.1",
                    "summary": "One plausible explanation is IAM configuration drift. The available evidence does not yet establish this as the confirmed root cause.",
                    "reasoning_points": [
                        "Observed public access finding correlates with recent configuration changes",
                        "Audit policy indicates encryption enforcement is required",
                    ],
                    "supporting_refs": fact_ids[:2],
                    "uncertainty_points": [
                        "Direct audit logs during the transition window were not provided in context",
                    ],
                    "created_by": "LLM",
                }
            ],
            "root_causes": [
                {
                    "candidate_id": f"rc-{inv_id}-1",
                    "investigation_id": inv_id,
                    "candidate": "IAM privilege configuration drift and delayed access review",
                    "supporting_fact_ids": fact_ids[:2],
                    "contradicting_fact_ids": [],
                    "status": "PROPOSED",
                    "created_by": "LLM",
                }
            ],
            "uncertainties": [
                "Direct audit logs during the transition window were not provided in context",
                "Access review evidence is missing",
            ],
            "human_review_required": True,
        }
