"""GRC 위험 평가(Risk Assessment) 데이터 모델 모듈입니다."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field

from secgrc.audit.models import AuditSeverity, AuditStatus


class RiskLevel(str, Enum):
    """위험도 레벨 분류"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskPriority(str, Enum):
    """시정조치 대응 우선순위"""
    P1 = "P1"  # 즉각 조치 필요 (Critical 위험)
    P2 = "P2"  # 단기 조치 필요 (High 위험)
    P3 = "P3"  # 중기 관리 대상 (Medium 위험)
    P4 = "P4"  # 모니터링 및 주기 점검 (Low 위험)
    P5 = "P5"  # 정보성 / 양호 (Info)


class RiskAssessment(BaseModel):
    """통제항목 단위의 최종 보안 위험 평가 결과 레코드"""

    risk_id: str = Field(..., description="위험 평가 고유 식별자 (예: 'RSK-ISMS-P-2.7.1')")
    control_id: str = Field(..., description="연관 통제항목 번호")
    control_title: str = Field(..., description="통제항목 명칭")
    audit_status: AuditStatus = Field(..., description="컴플라이언스 판정 상태")
    severity: AuditSeverity = Field(..., description="감사 결함 심각도")
    asset_criticality: float = Field(..., ge=0.0, le=100.0, description="영향받는 자산 중요도 (0~100)")
    evidence_confidence: float = Field(..., ge=0.0, le=1.0, description="증적 매핑 신뢰도 (0.0~1.0)")
    control_impact: float = Field(..., ge=0.0, le=100.0, description="통제항목 비즈니스 영향도 (0~100)")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="정규화된 종합 위험 점수 (0~100)")
    risk_level: RiskLevel = Field(..., description="산출된 위험도 등급 (CRITICAL~INFO)")
    priority: RiskPriority = Field(..., description="대응 우선순위 (P1~P5)")
    rationale: str = Field(default="", description="위험 점수 산출 사유 및 설명 (Explainability)")
    evidence_ids: List[str] = Field(default_factory=list, description="연관 증적 ID 목록")
    recommendations: List[str] = Field(default_factory=list, description="위험 완화 권고안 목록")
