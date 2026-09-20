"""AI GRC Copilot 데이터 모델 모듈입니다."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class UserRole(str, Enum):
    """Copilot 질의 사용자 역할"""
    EXECUTIVE = "EXECUTIVE"
    CISO = "CISO"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    ANALYST = "ANALYST"

    @classmethod
    def from_str(cls, value: Any) -> "UserRole":
        if isinstance(value, cls):
            return value
        val = getattr(value, "value", str(value)).strip().upper()
        if "." in val:
            val = val.split(".")[-1]
        if val in ("EXECUTIVE", "EXEC"):
            return cls.EXECUTIVE
        elif val in ("CISO",):
            return cls.CISO
        elif val in ("MANAGER", "SECURITY_MANAGER", "MGR"):
            return cls.SECURITY_MANAGER
        return cls.ANALYST


class FactType(str, Enum):
    """답변 구성 요소의 사실성 및 권고 분류"""
    OBSERVED_FACT = "OBSERVED_FACT"  # 수집된 증적 및 결정론적 판정 불변 사실
    INFERENCE = "INFERENCE"          # 인과관계 및 공격 시나리오 추론
    RECOMMENDATION = "RECOMMENDATION"  # 후속 개선 및 조치 권고


class Provenance(BaseModel):
    """증적 및 데이터 근거 출처 모델 (Provenance)"""
    source_type: str = Field(description="출처 개체 유형 (Risk, Control, Evidence, Finding, Asset, Remediation)")
    source_id: str = Field(description="출처 개체 ID (예: 'ISMS-P-2.7.1', 'EV-001')")
    source_path: str = Field(default="", description="상세 출처 파일 또는 시스템 경로")
    relationship: str = Field(default="", description="연계 관계 유형 (예: 'SUPPORTED_BY', 'CREATES_RISK')")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="출처 신뢰도 점수 (0.0~1.0)")


class CopilotFact(BaseModel):
    """검증된 단일 사실/추론/권고 항목"""
    fact_type: FactType = Field(description="사실성 분류")
    statement: str = Field(description="명제 본문")
    source_reference: Optional[str] = Field(default=None, description="연관 출처 참조 ID")


class CopilotQuery(BaseModel):
    """Copilot 자연어 질의 모델"""
    query_id: str = Field(description="질의 고유 식별자")
    question: str = Field(description="자연어 질의 원문")
    language: str = Field(default="ko", description="질의 응답 언어 ('ko' 또는 'en')")
    user_role: UserRole = Field(default=UserRole.ANALYST, description="사용자 역할 (Executive, CISO, Manager, Analyst)")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="질의 접수 시각")
    requested_scope: Optional[str] = Field(default=None, description="특정 프레임워크 또는 통제 영역 범위")


class CopilotAnswer(BaseModel):
    """Copilot 최종 구조화 응답 모델"""
    answer_id: str = Field(description="응답 고유 식별자")
    question: str = Field(description="원본 질문")
    intent: str = Field(description="분류된 의도 (IntentCategory)")
    answer: str = Field(description="사용자 제공 최종 설명 및 답변 요약")
    facts: List[CopilotFact] = Field(default_factory=list, description="분리된 사실/추론/권고 목록")
    reasoning: List[str] = Field(default_factory=list, description="단계별 논리 전개 과정")
    recommendations: List[str] = Field(default_factory=list, description="실무 개선 권고 사항")
    provenance: List[Provenance] = Field(default_factory=list, description="증적 근거 출처 체인")
    confidence: float = Field(default=1.0, description="응답 전체 신뢰도")
    limitations: List[str] = Field(default_factory=list, description="답변의 한계점 또는 수동 검토 필요 사항")
    generated_by: str = Field(default="deterministic_copilot", description="답변 생성 엔진 (deterministic 또는 llm_grounded)")
