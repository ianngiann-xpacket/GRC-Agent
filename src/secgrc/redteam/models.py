"""AI Agent Red Team / Purple Team 보안 검증 데이터 모델 모듈입니다."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RedTeamCategory(str, Enum):
    """Red Team 10대 공격 검증 카테고리"""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    TOOL_ABUSE = "TOOL_ABUSE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    EXCESSIVE_AGENCY = "EXCESSIVE_AGENCY"
    POLICY_BYPASS = "POLICY_BYPASS"
    SECRET_LEAKAGE = "SECRET_LEAKAGE"
    OUTPUT_MANIPULATION = "OUTPUT_MANIPULATION"
    TRUST_BOUNDARY = "TRUST_BOUNDARY"
    APPROVAL_BYPASS = "APPROVAL_BYPASS"
    LOOP_ABUSE = "LOOP_ABUSE"


class RedTeamScenario(BaseModel):
    """결정론적 Red Team 공격 시나리오 모델"""
    scenario_id: str = Field(description="시나리오 고유 식별자 (예: RT-INJ-001)")
    category: RedTeamCategory = Field(description="공격 카테고리")
    name: str = Field(description="시나리오 명칭")
    description: str = Field(description="공격 벡터 및 목적 설명")
    attack_input: Any = Field(description="공격 입력 페이로드 (문자열 또는 구조화 딕셔너리)")
    expected_control: str = Field(description="방어 및 탐지를 담당해야 할 보안 통제 컴포넌트")
    expected_decision: str = Field(description="기대되는 최종 정책 결정 (예: BLOCKED, DENIED, SANITIZED)")
    severity: str = Field(default="HIGH", description="취약점 심각도 (LOW, MEDIUM, HIGH, CRITICAL)")
    requires_tool: bool = Field(default=False, description="도구 호출을 수반하는지 여부")
    requires_approval: bool = Field(default=False, description="인간 승인이 필수적인 시나리오인지 여부")
    synthetic_only: bool = Field(default=True, description="100% 가상 합성 환경에서만 실행 보장")
    tags: List[str] = Field(default_factory=list, description="분류 태그 목록")
    target_tool: Optional[str] = Field(default=None, description="공격 대상 도구 명칭")
    target_agent: Optional[str] = Field(default="grc-auditor-agent", description="공격 대상 에이전트 ID")
    context: Dict[str, Any] = Field(default_factory=dict, description="시나리오 실행용 추가 컨텍스트")


class RedTeamResult(BaseModel):
    """단일 시나리오 Red Team 실행 결과 모델"""
    scenario_id: str
    category: RedTeamCategory
    detected: bool = Field(description="보안 가드레일이 공격을 탐지했는지 여부")
    blocked: bool = Field(description="공격 실행이 차단되었는지 여부")
    executed: bool = Field(default=False, description="공격 행위가 실제 실행되었는지 여부")
    approval_bypassed: bool = Field(default=False, description="승인 게이트 우회가 발생했는지 여부")
    secret_leaked: bool = Field(default=False, description="카나리 또는 민감 시크릿이 유출되었는지 여부")
    policy_violated: bool = Field(default=False, description="에이전트 보안 정책이 위반되었는지 여부")
    expected_decision: str
    actual_decision: str
    severity: str
    evidence: Any = Field(default=None, description="차단 또는 실행 관련 증적")
    explanation: str = Field(default="", description="결과 상세 설명")
    remediation: str = Field(default="", description="방어 실패 시 Purple Team 권고 조치")
    timestamp: str


class RedTeamSummary(BaseModel):
    """전체 Red Team 검증 요약 및 복원력 점수 모델"""
    total_scenarios: int
    detected: int
    blocked: int
    allowed: int
    policy_violations: int
    approval_bypasses: int
    secret_leakages: int
    unauthorized_tool_executions: int
    detection_rate: float = Field(description="탐지율 (%)")
    block_rate: float = Field(description="차단율 (%)")
    resilience_score: float = Field(description="보안 복원력 점수 (0-100)")
    overall_status: str = Field(description="종합 상태 (EXCELLENT, GOOD, NEEDS_IMPROVEMENT, FAIL)")
    critical_findings: List[Dict[str, Any]] = Field(default_factory=list, description="주요 위험 발견사항")
