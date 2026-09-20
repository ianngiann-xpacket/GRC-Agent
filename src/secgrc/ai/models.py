"""AI 감사관 및 AI 추론(AI Reasoning) 데이터 모델 모듈입니다.

Step 27: AI-Assisted Investigation & Security Reasoning Layer의 모든 데이터 모델을 정의합니다.
기존 v1.1.0 모델(EvidenceBasis, RemediationItem, AIAnalysis)과의 완전한 하위 호환성을 유지합니다.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secgrc.audit.models import AuditSeverity, AuditStatus
from secgrc.risk.models import RiskLevel, RiskPriority


# ==============================================================================
# 0. 보안 검증 상수 및 헬퍼 함수
# ==============================================================================

DANGEROUS_ID_PATTERNS = [
    "..",
    "/etc",
    ".env",
    "passwd",
    ";",
    "|",
    "&",
    "$",
    "`",
    "\n",
    "\r",
    "<",
    ">",
    "https://",
    "http://",
    "ftp://",
    "file://",
    "ssh://",
    "data:",
]

INSTRUCTION_PATTERNS = [
    "ignore previous",
    "system:",
    "sudo ",
    "rm -rf",
    "drop table",
    "chmod ",
    "eval(",
    "exec(",
    "curl ",
    "wget ",
    "bash -c",
    "sh -c",
]

CREDENTIAL_PATTERNS = [
    "api_key",
    "apikey",
    "password",
    "secret",
    "token",
    "private_key",
    "credentials",
    "bearer ",
    "access_token",
    "auth_token",
]


def validate_id_str(val: str, field_name: str = "ID") -> str:
    """식별자(ID)의 공백, 비인가 문자, 경로 조작 및 셸 주입 패턴을 엄격히 검증합니다."""
    if not isinstance(val, str):
        raise ValueError(f"{field_name} must be a string, got {type(val).__name__}")
    cleaned = val.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty or whitespace only")
    cleaned_lower = cleaned.lower()
    for pat in DANGEROUS_ID_PATTERNS:
        if pat.lower() in cleaned_lower:
            raise ValueError(f"{field_name} contains dangerous pattern: '{pat}'")
    if cleaned.startswith("/") or cleaned.startswith("\\"):
        raise ValueError(f"{field_name} cannot start with path separator")
    return cleaned


def validate_id_list(vals: List[str], field_name: str = "IDs") -> List[str]:
    """식별자 리스트의 각 항목에 대해 안전성을 검증합니다."""
    if not isinstance(vals, list):
        raise ValueError(f"{field_name} must be a list")
    return [validate_id_str(v, field_name) for v in vals]


# ==============================================================================
# 1. 기존 v1.1.0 하위 호환 모델 (AIAuditor 호환)
# ==============================================================================

class EvidenceBasis(BaseModel):
    """핵심 주장 및 소견에 대한 증적 출처 추적 모델"""

    evidence_id: str = Field(..., description="연관 증적 ID (예: Prowler Finding UID 또는 통제 ID)")
    claim: str = Field(..., description="증적에 기반한 핵심 관측 또는 소견")
    basis: str = Field(
        ...,
        description="근거 유형 ('direct': 직접 관측, 'inferred': 보안 추론, 'recommendation': 조치 권고)",
    )


class RemediationItem(BaseModel):
    """출처가 명시된 시정조치 권고 모델"""

    action: str = Field(..., description="구체적 시정조치 내용")
    source: str = Field(
        default="evidence",
        description="권고 출처 ('evidence': 점검 도구 직접 제시, 'ai_generated': AI 심층 제안)",
    )
    reference_url: Optional[str] = Field(default=None, description="참조 가이드 또는 공식 문서 URL")


class AIAnalysis(BaseModel):
    """결정론적 평가 결과에 대한 AI Auditor의 심층 분석 및 소견 레코드"""

    # 1. 권위 있는 결정론적 입력값 (AI가 절대 수정할 수 없음 - Immutable)
    risk_id: str = Field(..., description="연관 위험 평가 식별자")
    control_id: str = Field(..., description="통제항목 번호 (예: 'ISMS-P-2.7.1')")
    control_title: str = Field(..., description="통제항목 명칭")
    audit_status: str = Field(..., description="권위 있는 결정론적 컴플라이언스 판정 상태")
    risk_level: str = Field(..., description="권위 있는 결정론적 위험 등급")
    priority: str = Field(..., description="권위 있는 결정론적 대응 우선순위")
    risk_score: float = Field(..., description="권위 있는 결정론적 위험 점수 (0~100)")

    # 2. AI 심층 분석 및 설명 필드
    executive_summary: str = Field(..., description="경영진/CISO를 위한 비즈니스 관점의 핵심 요약")
    technical_summary: str = Field(..., description="보안 엔지니어를 위한 기술적 발견 요약")
    root_cause: str = Field(..., description="설정 미흡, 프로세스 부재 등 근본 원인 분석")
    business_impact: str = Field(..., description="침해 발생 시 재무, 규제 과징금, 신뢰도 등 비즈니스 영향")
    attack_scenario: str = Field(
        ...,
        description="Observed Evidence / Potential Attack Path / Limitations 형식의 공격 시나리오",
    )
    remediation: List[str] = Field(default_factory=list, description="우선순위화된 기술적/관리적 시정조치 권고 문자열 목록")
    remediation_items: List[RemediationItem] = Field(
        default_factory=list,
        description="출처(evidence/ai_generated)가 구분된 구조화된 시정조치 목록",
    )
    auditor_questions: List[str] = Field(default_factory=list, description="현장 심사원이 추가 확인해야 할 질의 목록")

    # 3. 근거 추적 및 신뢰성 메타데이터
    evidence_basis: List[EvidenceBasis] = Field(
        default_factory=list,
        description="소견 및 주장에 대한 증적 출처 추적 (direct/inferred/recommendation)",
    )
    confidence: float = Field(default=0.9, ge=0.0, le=1.0, description="AI 분석 신뢰도 (0.0~1.0, AI analysis confidence)")
    evidence_ids: List[str] = Field(default_factory=list, description="분석에 활용된 증적 ID 목록")
    assumptions: List[str] = Field(default_factory=list, description="분석에 적용된 주요 전제조건")
    limitations: List[str] = Field(default_factory=list, description="클라우드 점검 증적의 한계점 및 수동 검토 필요 항목")
    source_references: List[str] = Field(default_factory=list, description="참조한 보안 표준 및 가이드라인")
    model_name: str = Field(default="gemini-2.5-flash", description="추론에 사용된 AI 모델")
    prompt_version: str = Field(default="1.1.0", description="감사관 프롬프트 버전")
    llm_used: bool = Field(default=False, description="실제 LLM API 호출 성공 여부")
    fallback_reason: Optional[str] = Field(default=None, description="폴백 동작 사유 (비밀키/토큰 등 민감정보 제외)")
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="분석 생성 일시 (ISO-8601)",
    )


# ==============================================================================
# 2. Step 27 열거형 (Enums)
# ==============================================================================

class ReasoningType(str, Enum):
    """Step 27 허용 추론 유형. COMPLIANCE_DECISION, RISK_DECISION, REMEDIATION_ACTION 절대 불포함."""
    HYPOTHESIS = "HYPOTHESIS"
    QUESTION = "QUESTION"
    EXPLANATION = "EXPLANATION"
    ROOT_CAUSE_CANDIDATE = "ROOT_CAUSE_CANDIDATE"
    CONTRIBUTING_FACTOR_CANDIDATE = "CONTRIBUTING_FACTOR_CANDIDATE"
    ANOMALY_INTERPRETATION = "ANOMALY_INTERPRETATION"
    EVIDENCE_GAP_ANALYSIS = "EVIDENCE_GAP_ANALYSIS"
    INVESTIGATION_SUMMARY = "INVESTIGATION_SUMMARY"


class AIClaimType(str, Enum):
    """주장의 성격 분류. LLM은 FACT를 생성할 수 없음."""
    FACT = "FACT"
    OBSERVATION = "OBSERVATION"
    HYPOTHESIS = "HYPOTHESIS"
    INFERENCE = "INFERENCE"
    RECOMMENDATION = "RECOMMENDATION"
    QUESTION = "QUESTION"


class ClaimSupportType(str, Enum):
    """주장과 근거 간의 지지 관계 유형"""
    SUPPORTING = "SUPPORTING"
    CONTRADICTING = "CONTRADICTING"
    CONTEXT = "CONTEXT"
    UNKNOWN = "UNKNOWN"


class HypothesisStatus(str, Enum):
    """가설의 생명주기 상태. LLM은 PROPOSED만 제안 가능하며 자동 승격 불가."""
    PROPOSED = "PROPOSED"
    TESTING = "TESTING"
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    REJECTED = "REJECTED"
    UNRESOLVED = "UNRESOLVED"


class HypothesisSupport(str, Enum):
    """결정론적 증적 관계에 기반한 가설 지지 수준 (LLM 신뢰도 점수가 아님)"""
    NO_SUPPORT = "NO_SUPPORT"
    WEAK_SUPPORT = "WEAK_SUPPORT"
    PARTIAL_SUPPORT = "PARTIAL_SUPPORT"
    STRONG_SUPPORT = "STRONG_SUPPORT"
    CONTRADICTED = "CONTRADICTED"


class AIReasoningStatus(str, Enum):
    """AI 추론 작업 상태"""
    REQUESTED = "REQUESTED"
    COMPLETED = "COMPLETED"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    GUARD_BLOCKED = "GUARD_BLOCKED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    TIMEOUT = "TIMEOUT"
    CONTEXT_TOO_LARGE = "CONTEXT_TOO_LARGE"
    UNSUPPORTED_TASK = "UNSUPPORTED_TASK"


class AIInvestigationTaskType(str, Enum):
    """Step 27 허용 조사 작업 유형 (Section 50)"""
    EXPLAIN_FINDING = "EXPLAIN_FINDING"
    ANALYZE_RISK_CAUSE = "ANALYZE_RISK_CAUSE"
    ANALYZE_CONTROL_GAP = "ANALYZE_CONTROL_GAP"
    ANALYZE_EVIDENCE_GAP = "ANALYZE_EVIDENCE_GAP"
    ANALYZE_CHANGE = "ANALYZE_CHANGE"
    GENERATE_INVESTIGATION_QUESTIONS = "GENERATE_INVESTIGATION_QUESTIONS"
    COMPARE_EVIDENCE = "COMPARE_EVIDENCE"
    SUMMARIZE_INVESTIGATION = "SUMMARIZE_INVESTIGATION"
    IDENTIFY_PLAUSIBLE_CAUSES = "IDENTIFY_PLAUSIBLE_CAUSES"


# ==============================================================================
# 3. Step 27 핵심 도메인 모델 (Pydantic v2 extra="forbid")
# ==============================================================================

class AIBaseModel(BaseModel):
    """모든 Step 27 AI 모델의 베이스 클래스"""
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        return cls.model_validate(data)


class ClaimSupport(AIBaseModel):
    """주장에 대한 구체적 지지/반박 출처 매트릭스 (Section 12)"""
    claim_id: str = Field(description="연관 주장 ID")
    support_type: ClaimSupportType = Field(default=ClaimSupportType.SUPPORTING, description="지지 관계 유형")
    source_id: str = Field(description="근거 출처 ID (fact_id, evidence_id 등)")
    source_type: str = Field(description="근거 출처 유형 ('FACT', 'EVIDENCE', 'RELATIONSHIP', 'CHANGE')")
    relationship: str = Field(default="DIRECT", description="관계 설명")

    @field_validator("claim_id", "source_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)


class AIClaim(AIBaseModel):
    """LLM이 도출한 개별 주장 모델 (Section 9-11)"""
    claim_id: str = Field(description="주장 고유 식별자")
    claim_type: AIClaimType = Field(description="주장 분류 (FACT 불가 - 자동 변환)")
    statement: str = Field(description="주장 명제")
    supporting_fact_ids: List[str] = Field(default_factory=list, description="근거 사실 ID 목록")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="근거 증적 ID 목록")
    contradicting_fact_ids: List[str] = Field(default_factory=list, description="반박 사실 ID 목록")
    confidence: float = Field(default=0.7, ge=0.0, le=1.0, description="추론 신뢰도")
    grounded: bool = Field(default=True, description="공급된 사실/증적에 접지(grounded)되었는지 여부")

    @field_validator("claim_id")
    @classmethod
    def check_claim_id(cls, v: str) -> str:
        return validate_id_str(v, "claim_id")

    @field_validator("supporting_fact_ids", "supporting_evidence_ids", "contradicting_fact_ids")
    @classmethod
    def check_ids_list(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)


class InvestigationHypothesisAI(AIBaseModel):
    """AI 제안 조사 가설 모델 (Section 13)"""
    hypothesis_id: str = Field(description="가설 식별자")
    investigation_id: str = Field(description="연관 조사 식별자")
    statement: str = Field(description="가설 명제")
    supporting_fact_ids: List[str] = Field(default_factory=list, description="지지 사실 ID 목록")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="지지 증적 ID 목록")
    contradicting_fact_ids: List[str] = Field(default_factory=list, description="반박 사실 ID 목록")
    status: HypothesisStatus = Field(default=HypothesisStatus.PROPOSED, description="가설 상태 (LLM은 PROPOSED만 가능)")
    validation_required: bool = Field(default=True, description="검증 필요 플래그")
    created_by: str = Field(default="LLM", description="생성 주체 (항상 'LLM')")
    support_level: Optional[HypothesisSupport] = Field(default=None, description="결정론적 지지 수준")

    @field_validator("hypothesis_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("supporting_fact_ids", "supporting_evidence_ids", "contradicting_fact_ids")
    @classmethod
    def check_ids_list(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("created_by")
    @classmethod
    def check_creator(cls, v: str) -> str:
        return "LLM"


class RootCauseCandidate(AIBaseModel):
    """AI 제안 근본 원인 후보 모델 (Section 14). 결코 ROOT_CAUSE_CONFIRMED로 자동 승격되지 않음."""
    candidate_id: str = Field(description="후보 식별자")
    investigation_id: str = Field(description="연관 조사 식별자")
    candidate: str = Field(description="원인 후보 설명")
    supporting_fact_ids: List[str] = Field(default_factory=list, description="지지 사실 ID 목록")
    contradicting_fact_ids: List[str] = Field(default_factory=list, description="반박 사실 ID 목록")
    status: str = Field(default="PROPOSED", description="상태 (항상 'PROPOSED')")
    created_by: str = Field(default="LLM", description="생성 주체")

    @field_validator("candidate_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("supporting_fact_ids", "contradicting_fact_ids")
    @classmethod
    def check_ids_list(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("status")
    @classmethod
    def check_status(cls, v: str) -> str:
        if v.upper() == "ROOT_CAUSE_CONFIRMED":
            raise ValueError("Root cause cannot be confirmed autonomously by LLM.")
        return "PROPOSED"


class InvestigationQuestion(AIBaseModel):
    """AI 제안 추가 조사 질문 모델 (Section 15, 16). 비밀정보/크리덴셜 요청 엄격 차단."""
    question_id: str = Field(description="질문 식별자")
    investigation_id: str = Field(description="연관 조사 식별자")
    question: str = Field(description="질문 내용")
    reason: str = Field(description="질문 사유")
    target_data_type: str = Field(description="확인 필요 데이터 유형")
    target_entity_ids: List[str] = Field(default_factory=list, description="대상 엔티티 ID 목록")
    priority: str = Field(default="P2", description="우선순위 (P1, P2, P3)")
    created_by: str = Field(default="LLM", description="생성 주체")

    @field_validator("question_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("target_entity_ids")
    @classmethod
    def check_ids_list(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("question")
    @classmethod
    def check_question_safety(cls, v: str) -> str:
        lower = v.lower()
        for pat in CREDENTIAL_PATTERNS:
            if pat in lower:
                raise ValueError(f"Investigation question cannot request secrets/credentials: '{pat}'")
        return v


class AIExplanation(AIBaseModel):
    """AI 설명 모델 (Section 17, 18). 불확실성을 구조적으로 보존."""
    explanation_id: str = Field(description="설명 식별자")
    target_type: str = Field(description="설명 대상 유형 ('FINDING', 'ASSESSMENT', 'RISK', 'CHANGE')")
    target_id: str = Field(description="설명 대상 식별자")
    summary: str = Field(description="요약 설명")
    reasoning_points: List[str] = Field(default_factory=list, description="추론 논점 목록")
    supporting_refs: List[str] = Field(default_factory=list, description="뒷받침하는 참조 ID 목록")
    uncertainty_points: List[str] = Field(default_factory=list, description="보존된 불확실성 항목 목록")
    created_by: str = Field(default="LLM", description="생성 주체")

    @field_validator("explanation_id", "target_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("supporting_refs")
    @classmethod
    def check_refs_list(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)


class ReasoningRunMetadata(AIBaseModel):
    """모델 추론 런타임 메타데이터 (Section 40, 41)"""
    provider_id: str = Field(description="프로바이더 식별자")
    model_id: str = Field(description="모델 식별자")
    model_version: str = Field(default="1.0.0", description="모델 버전")
    prompt_template_id: str = Field(description="프롬프트 템플릿 ID")
    prompt_template_version: str = Field(description="프롬프트 템플릿 버전")
    guard_version: str = Field(default="1.0.0", description="가드 버전")
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="온도")
    top_p: float = Field(default=1.0, ge=0.0, le=1.0, description="Top-P")
    seed: Optional[int] = Field(default=42, description="시드")
    context_hash: str = Field(description="컨텍스트 SHA-256 해시")
    input_tokens: Optional[int] = Field(default=None, description="입력 토큰 수")
    output_tokens: Optional[int] = Field(default=None, description="출력 토큰 수")
    latency_ms: Optional[float] = Field(default=None, description="지연 시간(ms)")


class AIReasoningResult(AIBaseModel):
    """최종 비권위적 AI 추론 결과 객체 (Section 7)"""
    reasoning_id: str = Field(description="추론 결과 식별자")
    investigation_id: str = Field(description="연관 조사 식별자")
    reasoning_type: ReasoningType = Field(description="추론 유형")
    claims: List[AIClaim] = Field(default_factory=list, description="도출된 주장 목록")
    hypotheses: List[InvestigationHypothesisAI] = Field(default_factory=list, description="도출된 가설 목록")
    questions: List[InvestigationQuestion] = Field(default_factory=list, description="도출된 질문 목록")
    explanations: List[AIExplanation] = Field(default_factory=list, description="도출된 설명 목록")
    root_causes: List[RootCauseCandidate] = Field(default_factory=list, description="도출된 근본원인 후보 목록")
    supporting_fact_ids: List[str] = Field(default_factory=list, description="활용된 사실 ID 목록")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="활용된 증적 ID 목록")
    supporting_relationship_ids: List[str] = Field(default_factory=list, description="활용된 관계 ID 목록")
    contradicting_fact_ids: List[str] = Field(default_factory=list, description="식별된 모순/반박 사실 ID 목록")
    uncertainties: List[str] = Field(default_factory=list, description="식별된 불확실성 및 결측 정보 목록")
    provider_id: str = Field(description="LLM 프로바이더 ID")
    model_id: str = Field(description="LLM 모델 ID")
    prompt_template_id: str = Field(description="프롬프트 템플릿 ID")
    prompt_template_version: str = Field(description="프롬프트 템플릿 버전")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="생성 일시 (ISO-8601)",
    )
    provenance: Dict[str, Any] = Field(default_factory=dict, description="추적 메타데이터")
    integrity_hash: str = Field(default="", description="결과 SHA-256 무결성 해시")
    human_review_required: bool = Field(default=False, description="인간 검토 필수 여부")
    is_authoritative: bool = Field(default=False, description="권위 여부 (항상 False)")

    @field_validator("reasoning_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("is_authoritative")
    @classmethod
    def check_non_authoritative(cls, v: bool) -> bool:
        if v:
            raise ValueError("AIReasoningResult cannot be marked authoritative.")
        return False

    @field_validator("supporting_fact_ids", "supporting_evidence_ids", "supporting_relationship_ids", "contradicting_fact_ids")
    @classmethod
    def check_ids_list(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    def compute_integrity_hash(self) -> str:
        """논리적 결과 내용을 기반으로 SHA-256 무결성 해시를 계산합니다."""
        payload = {
            "reasoning_id": self.reasoning_id,
            "investigation_id": self.investigation_id,
            "reasoning_type": self.reasoning_type.value,
            "claims": [c.model_dump() for c in self.claims],
            "hypotheses": [h.model_dump() for h in self.hypotheses],
            "questions": [q.model_dump() for q in self.questions],
            "explanations": [e.model_dump() for e in self.explanations],
            "root_causes": [r.model_dump() for r in self.root_causes],
            "supporting_fact_ids": sorted(self.supporting_fact_ids),
            "supporting_evidence_ids": sorted(self.supporting_evidence_ids),
            "contradicting_fact_ids": sorted(self.contradicting_fact_ids),
            "uncertainties": self.uncertainties,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "prompt_template_id": self.prompt_template_id,
            "prompt_template_version": self.prompt_template_version,
            "human_review_required": self.human_review_required,
        }
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

