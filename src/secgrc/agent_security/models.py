"""AI 에이전트 보안 및 거버넌스(Agent Security & Governance) 데이터 모델 모듈입니다."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentStatus(str, Enum):
    """에이전트 수명주기 상태"""
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class AgentRiskLevel(str, Enum):
    """에이전트 자체의 자율성/위험 등급 분류"""
    L0 = "L0"  # Informational (설명/조회 전용)
    L1 = "L1"  # Read Only (읽기 전용 증적 수집)
    L2 = "L2"  # Analysis (감사 규칙 평가 및 AI 추론) - 현재 GRC Auditor
    L3 = "L3"  # Planning (조치 계획 및 로드맵 수립)
    L4 = "L4"  # Controlled Action (사람의 명시적 승인 후 시뮬레이션/제어 실행)
    L5 = "L5"  # Autonomous Production Action (인간 개입 없는 완전 자율 실행 - 기본 금지)


class ToolType(str, Enum):
    """도구 행위 유형"""
    READ = "READ"
    ANALYZE = "ANALYZE"
    PLAN = "PLAN"
    ACTION = "ACTION"


class PolicyDecision(str, Enum):
    """정책 결정 결과"""
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class DataTrustLevel(str, Enum):
    """데이터 및 증적 신뢰 경계 분류"""
    TRUSTED_SYSTEM_DATA = "TRUSTED_SYSTEM_DATA"
    TRUSTED_TOOL_OUTPUT = "TRUSTED_TOOL_OUTPUT"
    UNTRUSTED_EXTERNAL_DATA = "UNTRUSTED_EXTERNAL_DATA"
    UNTRUSTED_USER_INPUT = "UNTRUSTED_USER_INPUT"
    UNTRUSTED_DOCUMENT = "UNTRUSTED_DOCUMENT"


class FactType(str, Enum):
    """AI Auditor 소견의 사실성/추론 구분"""
    OBSERVED = "OBSERVED"          # 증적에서 직접 확인된 불변 사실
    INFERRED = "INFERRED"          # 보안 위험 및 공격 시나리오 추론
    RECOMMENDED = "RECOMMENDED"    # 개선 조치 권고안
    NOT_ASSESSABLE = "NOT_ASSESSABLE"  # 증거 불충분으로 평가 불가


class InjectionCategory(str, Enum):
    """프롬프트 인젝션 공격 카테고리 (7대 유형)"""
    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"            # 기존 지침 무시/재정의
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"    # 시스템 프롬프트 탈취
    ROLE_MANIPULATION = "ROLE_MANIPULATION"                  # 권한자/관리자 역할 사칭
    FAKE_AUTHORITY = "FAKE_AUTHORITY"                        # 가짜 상위 명령/우회 암호
    TOOL_INVOCATION_REQUEST = "TOOL_INVOCATION_REQUEST"      # 임의 명령어/쉘 실행 강제
    SECRET_EXTRACTION = "SECRET_EXTRACTION"                  # API 키/자격증명 노출 유도
    POLICY_OVERRIDE = "POLICY_OVERRIDE"                      # 보안 감사 정책 무효화


class AgentIdentity(BaseModel):
    """보안 에이전트의 공식 등록 식별자 및 거버넌스 메타데이터"""
    agent_id: str = Field(..., description="에이전트 고유 식별자 (예: 'grc-auditor-001')")
    agent_name: str = Field(..., description="에이전트 명칭")
    agent_type: str = Field(default="security_grc", description="에이전트 유형")
    version: str = Field(default="1.0.0", description="에이전트 버전")
    model: str = Field(default="gemini-2.5-flash", description="탑재된 LLM 모델명")
    prompt_version: str = Field(default="1.0.0", description="적용된 시스템 프롬프트 버전")
    owner: str = Field(default="security_team", description="책임 관리 조직/담당자")
    purpose: str = Field(default="ISMS-P Compliance Audit & Risk Analysis", description="에이전트 목적")
    risk_level: AgentRiskLevel = Field(default=AgentRiskLevel.L2, description="에이전트 위험/자율 등급")
    allowed_tools: List[str] = Field(default_factory=list, description="인가된 도구 목록")
    data_sources: List[str] = Field(default_factory=list, description="접근 허용된 데이터 출처")
    environment: str = Field(default="development", description="운영 환경 (development, staging, production)")
    approval_policy: str = Field(default="HIGH_RISK_REQUIRED", description="승인 정책")
    status: AgentStatus = Field(default=AgentStatus.ACTIVE, description="현재 상태")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ToolMetadata(BaseModel):
    """등록된 보안 도구의 메타데이터"""
    tool_name: str = Field(..., description="도구 식별 명칭 (예: 'run_audit')")
    tool_type: ToolType = Field(..., description="도구 유형 (READ, ANALYZE, PLAN, ACTION)")
    risk_level: str = Field(default="LOW", description="도구 잠재 위험도 (LOW, MEDIUM, HIGH, CRITICAL)")
    requires_approval: bool = Field(default=False, description="실행 시 휴먼 결재 필수 여부")
    allowed_agents: List[str] = Field(default_factory=list, description="도구 실행 권한이 부여된 에이전트 ID 목록")
    description: str = Field(default="", description="도구 상세 설명")


class PolicyEvaluationRequest(BaseModel):
    """정책 결정 엔진 평가 요청"""
    agent_id: str
    tool_name: str
    target_resource: Optional[str] = None
    risk_level: Optional[str] = None
    action_type: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class PolicyDecisionResult(BaseModel):
    """정책 결정 엔진의 판단 결과"""
    decision: PolicyDecision
    agent_id: str
    tool_name: str
    risk_level: str = "LOW"
    reason: str
    requires_human_approval: bool = False
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InjectionDetectionResult(BaseModel):
    """프롬프트 인젝션 탐지 결과"""
    detected: bool
    category: Optional[InjectionCategory] = None
    severity: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float = 0.0  # 0.0 ~ 1.0
    action: str = "ALLOW"    # ALLOW, NEUTRALIZE, BLOCK
    matched_pattern: Optional[str] = None
    sanitized_text: str = ""


class OutputValidationResult(BaseModel):
    """AI Auditor 출력 검증 결과"""
    valid: bool
    violations: List[str] = Field(default_factory=list)
    redacted_output: Any = None
    facts_classified: Dict[str, List[str]] = Field(default_factory=dict)


class SecurityAuditEvent(BaseModel):
    """보안 거버넌스 감사 로그 레코드"""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent_id: str
    agent_version: str = "1.0.0"
    event: str  # AGENT_STARTED, TOOL_REQUESTED, TOOL_ALLOWED, TOOL_DENIED, etc.
    tool: Optional[str] = None
    decision: Optional[str] = None
    risk_level: Optional[str] = None
    reason: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
