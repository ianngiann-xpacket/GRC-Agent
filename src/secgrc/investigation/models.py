"""GRC Investigation 데이터 모델 모듈입니다.

자율 조사 에이전트(Autonomous GRC Investigation Agent)를 위한 안정적인
도메인 데이터 모델을 정의합니다.
결정론적 GRC(RiskEngine, AuditEngine, OntologyRepository)가 단일 진실 공급원이며,
본 조사 모델은 기존 엔티티를 고유 ID로만 참조하며 변경하거나 점수를 재정의하지 않습니다.
"""

from datetime import datetime, timezone
import math
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secgrc.copilot.models import FactType, UserRole
from secgrc.copilot.planner import ALLOWED_OPERATIONS
from secgrc.investigation.enums import (
    EvidenceRole,
    FindingType,
    HypothesisStatus,
    InvestigationScopeType,
    InvestigationStatus,
    InvestigationStepStatus,
    InvestigationType,
)

# 보안 위협 및 비인가 주입 패턴 목록
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
    # URL schemes and protocol hardening
    "https://",
    "http://",
    "ftp://",
    "file://",
    "ssh://",
    "data:",
]

# 증적 ID 내 실행 명령형 패턴 (Instruction Separation)
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

# 엄격히 금지된 변경/실행 작업 키워드 목록
FORBIDDEN_STEP_OPERATIONS = [
    "DELETE",
    "UPDATE",
    "MODIFY",
    "MUTATE",
    "EXECUTE",
    "REMEDIATE",
    "REMEDIATION",
    "APPLY",
    "BYPASS",
    "GRANT",
    "INVOKE_TOOL",
    "SHELL",
    "MCP",
    "WRITE",
    "DROP",
    "ALTER",
    "CREATE",
    "KILL",
    "CISO",
    "DASHBOARD",
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
            raise ValueError(f"{field_name} contains dangerous or invalid pattern: '{pat}'")
    if cleaned.startswith("/") or cleaned.startswith("\\"):
        raise ValueError(f"{field_name} cannot start with path separator")
    return cleaned


def validate_id_list(vals: List[str], field_name: str = "IDs") -> List[str]:
    """식별자 리스트의 각 항목에 대해 안전성을 검증합니다."""
    if not isinstance(vals, list):
        raise ValueError(f"{field_name} must be a list")
    return [validate_id_str(v, field_name) for v in vals]


def validate_confidence_val(v: Optional[float], field_name: str = "confidence") -> Optional[float]:
    """신뢰도(confidence) 값이 [0.0, 1.0] 범위의 유효한 실수인지 검증합니다 (NaN, Inf 차단)."""
    if v is None:
        return None
    try:
        val = float(v)
    except (ValueError, TypeError):
        raise ValueError(f"{field_name} must be a valid float")
    if math.isnan(val) or math.isinf(val):
        raise ValueError(f"{field_name} cannot be NaN or Infinite")
    if not (0.0 <= val <= 1.0):
        raise ValueError(f"{field_name} must be between 0.0 and 1.0 (got {val})")
    return round(val, 4)


def validate_evidence_id_str(val: str) -> str:
    """증적 ID의 형식과 명령어 주입 패턴을 엄밀히 검증합니다."""
    cleaned = validate_id_str(val, "evidence_id")
    lower = cleaned.lower()
    for pat in INSTRUCTION_PATTERNS:
        if pat in lower:
            raise ValueError(f"Evidence ID contains suspicious instruction pattern: '{pat}'")
    # 증적 ID 포맷 검증: 일반적인 영숫자, 하이픈, 언더스코어, 점, 콜론만 허용
    if not re.match(r"^[A-Za-z0-9_.:-]+$", cleaned):
        raise ValueError(f"Evidence ID contains invalid characters: '{cleaned}'")
    return cleaned


class InvestigationBaseModel(BaseModel):
    """모든 조사 데이터 모델의 기본 클래스 (임의 필드 주입 차단 및 직렬화 지원)."""
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    def to_dict(self) -> Dict[str, Any]:
        """모델을 딕셔너리로 직렬화합니다."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """딕셔너리로부터 모델을 역직렬화합니다."""
        return cls.model_validate(data)


class InvestigationStep(InvestigationBaseModel):
    """조사 실행 단위 단계 모델 (결정론적 단일 읽기 전용 작업)."""
    step_id: str = Field(description="단계 고유 식별자")
    investigation_id: str = Field(description="소속 조사 식별자")
    sequence: int = Field(default=1, ge=1, description="실행 순서 (1 이상)")
    name: str = Field(description="단계 명칭")
    description: str = Field(default="", description="단계 상세 설명")
    status: InvestigationStepStatus = Field(
        default=InvestigationStepStatus.PENDING,
        description="단계 진행 상태",
    )
    operation: Optional[str] = Field(
        default=None,
        description="수행할 읽기 전용 작업 (ALLOWED_OPERATIONS)",
    )
    target_ids: List[str] = Field(default_factory=list, description="대상 엔티티 식별자 목록")
    depends_on_step_ids: List[str] = Field(default_factory=list, description="선행 의존 단계 ID 목록")
    output_fact_ids: List[str] = Field(default_factory=list, description="산출된 사실 ID 목록")
    output_evidence_ids: List[str] = Field(default_factory=list, description="산출된 증적 ID 목록")
    read_only: bool = Field(default=True, description="읽기 전용 강제 플래그 (반드시 True)")

    @field_validator("step_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("target_ids", "depends_on_step_ids", "output_fact_ids", "output_evidence_ids")
    @classmethod
    def check_id_lists(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("read_only")
    @classmethod
    def check_read_only(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Investigation steps must strictly be read-only (read_only=True).")
        return True

    @field_validator("operation")
    @classmethod
    def check_operation(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        op_clean = str(v).strip().upper()
        # 변경/실행 금지 키워드 검증
        for kw in FORBIDDEN_STEP_OPERATIONS:
            if kw in op_clean:
                raise ValueError(f"Mutation/Execution operation '{v}' is strictly forbidden.")
        # 파일시스템 경로 및 셸 주입 검증
        if "/" in op_clean or "\\" in op_clean or ".." in op_clean:
            raise ValueError(f"Filesystem path operations are forbidden: '{v}'")
        if op_clean not in ALLOWED_OPERATIONS:
            raise ValueError(
                f"Operation '{v}' is not in the read-only ALLOWED_OPERATIONS list: {sorted(ALLOWED_OPERATIONS)}"
            )
        return op_clean

    @model_validator(mode="after")
    def validate_step_consistency(self) -> "InvestigationStep":
        if self.step_id in self.depends_on_step_ids:
            raise ValueError(
                f"Step '{self.step_id}' cannot depend on itself (self-dependency detected)."
            )
        if len(self.depends_on_step_ids) != len(set(self.depends_on_step_ids)):
            raise ValueError(
                f"Step '{self.step_id}' contains duplicate dependencies in depends_on_step_ids."
            )
        if self.sequence < 1:
            raise ValueError("sequence must be >= 1")
        return self


class InvestigationHypothesis(InvestigationBaseModel):
    """조사 가설 모델 (검증 대상 명제)."""
    hypothesis_id: str = Field(description="가설 고유 식별자")
    investigation_id: str = Field(description="소속 조사 식별자")
    statement: str = Field(description="가설 명제 본문")
    status: HypothesisStatus = Field(
        default=HypothesisStatus.PROPOSED,
        description="가설 검증 상태",
    )
    confidence: float = Field(default=0.0, description="가설 신뢰도 (0.0~1.0)")
    supporting_fact_ids: List[str] = Field(default_factory=list, description="지지하는 사실 ID 목록")
    contradicting_fact_ids: List[str] = Field(default_factory=list, description="반박하는 사실 ID 목록")
    evidence_ids: List[str] = Field(default_factory=list, description="연관 증적 ID 목록")
    related_risk_ids: List[str] = Field(default_factory=list, description="연관 위험 ID 목록")
    related_control_ids: List[str] = Field(default_factory=list, description="연관 통제 ID 목록")
    related_finding_ids: List[str] = Field(default_factory=list, description="연관 결함 ID 목록")
    rationale: Optional[str] = Field(default=None, description="가설 수립 및 평가 근거")

    @field_validator("hypothesis_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator(
        "supporting_fact_ids",
        "contradicting_fact_ids",
        "evidence_ids",
        "related_risk_ids",
        "related_control_ids",
        "related_finding_ids",
    )
    @classmethod
    def check_id_lists(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, v: float) -> float:
        res = validate_confidence_val(v, "confidence")
        return res if res is not None else 0.0


class InvestigationFact(InvestigationBaseModel):
    """조사 과정에서 관찰되거나 확인된 사실 모델."""
    fact_id: str = Field(description="사실 고유 식별자")
    investigation_id: str = Field(description="소속 조사 식별자")
    fact_type: FactType = Field(description="사실 분류 (OBSERVED_FACT, INFERENCE, RECOMMENDATION)")
    statement: str = Field(description="사실 명제 본문")
    source_type: str = Field(description="출처 개체 유형 (Risk, Control, Evidence, Finding 등)")
    source_id: str = Field(description="출처 개체 식별자")
    source_path: Optional[str] = Field(default=None, description="출처 상세 경로")
    entity_type: Optional[str] = Field(default=None, description="연관 도메인 엔티티 유형")
    entity_id: Optional[str] = Field(default=None, description="연관 도메인 엔티티 식별자")
    confidence: float = Field(default=1.0, description="사실 신뢰도 (0.0~1.0)")
    step_id: Optional[str] = Field(default=None, description="산출 조사 단계 ID")
    evidence_ids: List[str] = Field(default_factory=list, description="뒷받침하는 증적 ID 목록")
    provenance_ids: List[str] = Field(default_factory=list, description="출처 근거(Provenance) ID 목록")

    @field_validator("fact_id", "investigation_id", "source_id")
    @classmethod
    def check_mandatory_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("entity_id", "step_id")
    @classmethod
    def check_optional_ids(cls, v: Optional[str], info) -> Optional[str]:
        if v is None:
            return None
        return validate_id_str(v, info.field_name)

    @field_validator("evidence_ids", "provenance_ids")
    @classmethod
    def check_id_lists(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, v: float) -> float:
        res = validate_confidence_val(v, "confidence")
        return res if res is not None else 1.0


class InvestigationFinding(InvestigationBaseModel):
    """조사 과정에서 도출된 결함/발견사항 모델."""
    finding_id: str = Field(description="발견사항 고유 식별자")
    investigation_id: str = Field(description="소속 조사 식별자")
    finding_type: FindingType = Field(description="발견사항 유형")
    title: str = Field(description="발견사항 제목")
    description: str = Field(default="", description="발견사항 상세 설명")
    severity: Optional[str] = Field(default=None, description="심각도 수준 (LOW, MEDIUM, HIGH, CRITICAL)")
    priority: Optional[str] = Field(default=None, description="조치 우선순위 (P1, P2, P3 등)")
    status: str = Field(default="OPEN", description="상태 (OPEN, RESOLVED 등)")
    root_cause: Optional[str] = Field(default=None, description="식별된 근본 원인")
    fact_ids: List[str] = Field(default_factory=list, description="근거 사실 ID 목록")
    hypothesis_ids: List[str] = Field(default_factory=list, description="연관 가설 ID 목록")
    evidence_ids: List[str] = Field(default_factory=list, description="연관 증적 ID 목록")
    risk_ids: List[str] = Field(default_factory=list, description="연관 위험 ID 목록")
    control_ids: List[str] = Field(default_factory=list, description="연관 통제 ID 목록")
    asset_ids: List[str] = Field(default_factory=list, description="연관 자산 ID 목록")
    source_finding_ids: List[str] = Field(default_factory=list, description="연관 원천 결함 ID 목록")
    confidence: float = Field(default=1.0, description="결함 신뢰도 (0.0~1.0)")
    provenance_ids: List[str] = Field(default_factory=list, description="출처 근거 ID 목록")

    @field_validator("finding_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator(
        "fact_ids",
        "hypothesis_ids",
        "evidence_ids",
        "risk_ids",
        "control_ids",
        "asset_ids",
        "source_finding_ids",
        "provenance_ids",
    )
    @classmethod
    def check_id_lists(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, v: float) -> float:
        res = validate_confidence_val(v, "confidence")
        return res if res is not None else 1.0


class EvidenceChain(InvestigationBaseModel):
    """결론 또는 가설을 뒷받침하는 증적 체인 모델."""
    chain_id: str = Field(description="증적 체인 고유 식별자")
    investigation_id: str = Field(description="소속 조사 식별자")
    evidence_ids: List[str] = Field(default_factory=list, description="체인 구성 증적 ID 목록")
    fact_ids: List[str] = Field(default_factory=list, description="연관 사실 ID 목록")
    hypothesis_ids: List[str] = Field(default_factory=list, description="연관 가설 ID 목록")
    finding_ids: List[str] = Field(default_factory=list, description="연관 결함 ID 목록")
    evidence_roles: Dict[str, EvidenceRole] = Field(
        default_factory=dict,
        description="증적별 역할 맵 (PRIMARY, SUPPORTING, CONTRADICTING, CONTEXT)",
    )
    completeness: Optional[float] = Field(default=None, description="증적 완전성 점수 (0.0~1.0)")
    confidence: Optional[float] = Field(default=None, description="체인 종합 신뢰도 (0.0~1.0)")
    provenance_ids: List[str] = Field(default_factory=list, description="출처 근거 ID 목록")

    @field_validator("chain_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("evidence_ids")
    @classmethod
    def check_evidence_ids(cls, v: List[str]) -> List[str]:
        return [validate_evidence_id_str(item) for item in v]

    @field_validator("fact_ids", "hypothesis_ids", "finding_ids", "provenance_ids")
    @classmethod
    def check_id_lists(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("completeness", "confidence")
    @classmethod
    def check_metrics(cls, v: Optional[float], info) -> Optional[float]:
        return validate_confidence_val(v, info.field_name)

    @field_validator("evidence_roles")
    @classmethod
    def check_roles_keys(cls, v: Dict[str, EvidenceRole]) -> Dict[str, EvidenceRole]:
        for k in v:
            validate_evidence_id_str(k)
        return v


class InvestigationResult(InvestigationBaseModel):
    """조사 완료 후 산출되는 표준 정형 결과 모델."""
    investigation_id: str = Field(description="소속 조사 식별자")
    status: InvestigationStatus = Field(description="최종 조사 상태")
    fact_ids: List[str] = Field(default_factory=list, description="산출된 사실 ID 목록")
    hypothesis_ids: List[str] = Field(default_factory=list, description="검증된 가설 ID 목록")
    finding_ids: List[str] = Field(default_factory=list, description="도출된 결함 ID 목록")
    evidence_chain_ids: List[str] = Field(default_factory=list, description="연계된 증적 체인 ID 목록")
    conclusion: Optional[str] = Field(default=None, description="조사 최종 결론")
    confidence: Optional[float] = Field(default=None, description="결론 신뢰도 (0.0~1.0)")
    limitations: List[str] = Field(default_factory=list, description="조사 한계점 및 제약사항 목록")
    provenance_ids: List[str] = Field(default_factory=list, description="출처 근거 ID 목록")
    deterministic_integrity_verified: bool = Field(
        default=True,
        description="결정론적 GRC 무결성(원천 데이터 불변) 검증 여부",
    )
    provenance_integrity_verified: bool = Field(
        default=True,
        description="출처 근거 무결성 검증 여부",
    )
    secret_scan_passed: bool = Field(
        default=True,
        description="시크릿 및 민감정보 유출 여부 검증",
    )

    @field_validator("investigation_id")
    @classmethod
    def check_investigation_id(cls, v: str) -> str:
        return validate_id_str(v, "investigation_id")

    @field_validator("fact_ids", "hypothesis_ids", "finding_ids", "evidence_chain_ids", "provenance_ids")
    @classmethod
    def check_id_lists(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, v: Optional[float]) -> Optional[float]:
        return validate_confidence_val(v, "confidence")


class Investigation(InvestigationBaseModel):
    """GRC 조사 상위 오케스트레이션 모델."""
    investigation_id: str = Field(description="조사 고유 식별자")
    investigation_type: InvestigationType = Field(description="조사 유형")
    status: InvestigationStatus = Field(
        default=InvestigationStatus.CREATED,
        description="조사 진행 상태",
    )
    title: str = Field(description="조사 제목")
    question: str = Field(description="조사 핵심 질의")
    requested_by_role: UserRole = Field(
        default=UserRole.ANALYST,
        description="조사 요청자 역할",
    )
    language: str = Field(default="ko", description="조사 언어 ('ko' 또는 'en')")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="생성 일시 (ISO 8601 UTC)",
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="최종 갱신 일시 (ISO 8601 UTC)",
    )
    scope_type: InvestigationScopeType = Field(
        default=InvestigationScopeType.GLOBAL,
        description="조사 범위 유형",
    )
    scope_id: Optional[str] = Field(
        default=None,
        description="조사 대상 고유 식별자 (scope_type != GLOBAL 시 필수)",
    )
    # 기존 결정론적 GRC 엔티티 참조 (ID 목록만 유지하여 원본 불변성 보장)
    related_risk_ids: List[str] = Field(default_factory=list, description="연관 위험 ID 목록")
    related_control_ids: List[str] = Field(default_factory=list, description="연관 통제 ID 목록")
    related_evidence_ids: List[str] = Field(default_factory=list, description="연관 증적 ID 목록")
    related_finding_ids: List[str] = Field(default_factory=list, description="연관 결함 ID 목록")
    related_asset_ids: List[str] = Field(default_factory=list, description="연관 자산 ID 목록")
    related_framework_ids: List[str] = Field(default_factory=list, description="연관 프레임워크 ID 목록")

    # 조사 구성요소 참조
    hypothesis_ids: List[str] = Field(default_factory=list, description="연계된 가설 ID 목록")
    fact_ids: List[str] = Field(default_factory=list, description="수집된 사실 ID 목록")
    investigation_step_ids: List[str] = Field(default_factory=list, description="수행 조사 단계 ID 목록")
    finding_ids: List[str] = Field(default_factory=list, description="도출된 결함 ID 목록")
    evidence_chain_ids: List[str] = Field(default_factory=list, description="증적 체인 ID 목록")

    # 종합 결과 및 신뢰도
    conclusion: Optional[str] = Field(default=None, description="조사 최종 결론")
    confidence: Optional[float] = Field(default=None, description="결론 종합 신뢰도 (0.0~1.0)")

    # 안전성 및 제약
    blocked_reason: Optional[str] = Field(default=None, description="차단 사유 (차단 시)")
    limitations: List[str] = Field(default_factory=list, description="조사 한계점 목록")

    # 출처 근거 추적
    provenance_ids: List[str] = Field(default_factory=list, description="출처 근거 ID 목록")

    @field_validator("investigation_id")
    @classmethod
    def check_investigation_id(cls, v: str) -> str:
        return validate_id_str(v, "investigation_id")

    @field_validator("scope_id")
    @classmethod
    def check_scope_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return validate_id_str(v, "scope_id")

    @field_validator(
        "related_risk_ids",
        "related_control_ids",
        "related_evidence_ids",
        "related_finding_ids",
        "related_asset_ids",
        "related_framework_ids",
        "hypothesis_ids",
        "fact_ids",
        "investigation_step_ids",
        "finding_ids",
        "evidence_chain_ids",
        "provenance_ids",
    )
    @classmethod
    def check_id_lists(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, v: Optional[float]) -> Optional[float]:
        return validate_confidence_val(v, "confidence")

    @model_validator(mode="after")
    def validate_investigation_scope(self) -> "Investigation":
        if self.scope_type != InvestigationScopeType.GLOBAL:
            if not self.scope_id or not str(self.scope_id).strip():
                raise ValueError(
                    f"scope_id is required when scope_type is {self.scope_type.value}"
                )
            validate_id_str(self.scope_id, "scope_id")
        return self


__all__ = [
    "validate_id_str",
    "validate_id_list",
    "validate_confidence_val",
    "validate_evidence_id_str",
    "InvestigationBaseModel",
    "InvestigationStep",
    "InvestigationHypothesis",
    "InvestigationFact",
    "InvestigationFinding",
    "EvidenceChain",
    "InvestigationResult",
    "Investigation",
]
