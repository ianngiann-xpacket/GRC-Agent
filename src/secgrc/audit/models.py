"""Audit 결과 및 상태 모델을 정의하는 모듈입니다."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class AuditStatus(str, Enum):
    """컴플라이언스 감사 평가 판정 상태"""
    PASS = "PASS"                  # 모든 증적이 적합(Pass)
    FAIL = "FAIL"                  # 명확한 부적합(결함) 발견
    PARTIAL = "PARTIAL"            # 통과 증적과 결함 증적이 혼재 (부분 준수)
    MANUAL = "MANUAL"              # 자동 점검 불가, 사람의 수동 검토 필요
    NO_EVIDENCE = "NO_EVIDENCE"    # 매핑된 증적이 존재하지 않음


class AuditSeverity(str, Enum):
    """감사 결함 위험 심각도"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class AuditResult(BaseModel):
    """통제항목 단위의 최종 컴플라이언스 평가 결과 레코드"""

    control_id: str = Field(..., description="통제항목 번호 (예: 'ISMS-P-2.5.2')")
    control_title: str = Field(..., description="통제항목명 (예: '사용자 식별 및 인증')")
    framework: str = Field(default="ISMS-P", description="규제 프레임워크 명칭")
    evidence_ids: List[str] = Field(default_factory=list, description="연관된 증적 ID 목록")
    status: AuditStatus = Field(..., description="최종 판정 상태")
    severity: AuditSeverity = Field(default=AuditSeverity.UNKNOWN, description="위험 심각도")
    mapping_type: str = Field(default="explicit", description="매핑 방식 (explicit, rule, keyword, inferred, none)")
    mapping_confidence: float = Field(default=1.0, description="증적 매핑 신뢰도 (0.0 ~ 1.0)")
    rationale: str = Field(default="", description="판정 근거 및 결정 사유 (Explainability)")
    gaps: List[str] = Field(default_factory=list, description="식별된 결함 및 갭(Gap) 목록")
    recommendations: List[str] = Field(default_factory=list, description="시정조치 권고안 목록")

