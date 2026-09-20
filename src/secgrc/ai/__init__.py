"""AI 감사관 및 보안 추론(AI Reasoning) 레이어 패키지입니다."""

from secgrc.ai.auditor import AIAuditor
from secgrc.ai.context import AIContextBuilder, AIInvestigationContext
from secgrc.ai.explanations import ExplanationBuilder
from secgrc.ai.guard import AIInvestigationGuard, AIInvestigationGuardResult, GuardCheckStatus
from secgrc.ai.history import AIReasoningHistoryStore, AIReasoningRecord, default_ai_history_store
from secgrc.ai.hypotheses import HypothesisValidator
from secgrc.ai.models import (
    AIAnalysis,
    AIClaim,
    AIClaimType,
    AIExplanation,
    AIInvestigationTaskType,
    AIReasoningResult,
    AIReasoningStatus,
    ClaimSupport,
    ClaimSupportType,
    EvidenceBasis,
    HypothesisStatus,
    HypothesisSupport,
    InvestigationHypothesisAI,
    InvestigationQuestion,
    ReasoningRunMetadata,
    ReasoningType,
    RemediationItem,
    RootCauseCandidate,
    validate_id_str,
    validate_id_list,
)
from secgrc.ai.policy import AIInvestigationPolicy, DEFAULT_AI_POLICY
from secgrc.ai.prompts import (
    AI_INVESTIGATION_SYSTEM_INSTRUCTION,
    PromptTemplate,
    STANDARD_REASONING_TEMPLATES,
    TEMPLATE_EXPLAIN_V1,
    TEMPLATE_HYPOTHESIS_V1,
    TEMPLATE_QUESTION_V1,
    TEMPLATE_ROOT_CAUSE_V1,
)
from secgrc.ai.provider import LLMProvider, MockLLMProvider
from secgrc.ai.questions import QuestionValidator
from secgrc.ai.reasoning import AIReasoningEngine
from secgrc.ai.registry import (
    AIPromptRegistry,
    AIProviderRegistry,
    default_prompt_registry,
    default_provider_registry,
)
from secgrc.ai.request import LLMRequest
from secgrc.ai.response import LLMResponse
from secgrc.ai.retriever import AIInvestigationRetriever
from secgrc.ai.tasks import AIInvestigationTask

__all__ = [
    # v1.1.0 하위 호환
    "AIAuditor",
    "AIAnalysis",
    "EvidenceBasis",
    "RemediationItem",
    # Step 27 열거형 및 도메인 모델
    "ReasoningType",
    "AIClaimType",
    "ClaimSupportType",
    "HypothesisStatus",
    "HypothesisSupport",
    "AIReasoningStatus",
    "AIInvestigationTaskType",
    "ClaimSupport",
    "AIClaim",
    "InvestigationHypothesisAI",
    "RootCauseCandidate",
    "InvestigationQuestion",
    "AIExplanation",
    "ReasoningRunMetadata",
    "AIReasoningResult",
    "validate_id_str",
    "validate_id_list",
    # 요청 / 응답 / 컨텍스트 / 정책
    "LLMRequest",
    "LLMResponse",
    "AIInvestigationContext",
    "AIContextBuilder",
    "AIInvestigationPolicy",
    "DEFAULT_AI_POLICY",
    "AIInvestigationTask",
    # 프로바이더 및 템플릿
    "LLMProvider",
    "MockLLMProvider",
    "PromptTemplate",
    "AI_INVESTIGATION_SYSTEM_INSTRUCTION",
    "STANDARD_REASONING_TEMPLATES",
    "TEMPLATE_HYPOTHESIS_V1",
    "TEMPLATE_QUESTION_V1",
    "TEMPLATE_EXPLAIN_V1",
    "TEMPLATE_ROOT_CAUSE_V1",
    # 가드 / 검증기 / 빌더
    "AIInvestigationGuard",
    "AIInvestigationGuardResult",
    "GuardCheckStatus",
    "HypothesisValidator",
    "QuestionValidator",
    "ExplanationBuilder",
    "AIInvestigationRetriever",
    # 엔진 및 이력 저장소
    "AIReasoningEngine",
    "AIReasoningHistoryStore",
    "AIReasoningRecord",
    "default_ai_history_store",
    "AIProviderRegistry",
    "AIPromptRegistry",
    "default_provider_registry",
    "default_prompt_registry",
]

