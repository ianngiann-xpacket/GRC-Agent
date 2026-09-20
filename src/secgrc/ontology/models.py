"""온톨로지 핵심 열거형 및 커버리지 요약 모델 모듈입니다."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ControlEffectiveness(str, Enum):
    """결정론적 통제 유효성 판정 분류"""
    EFFECTIVE = "EFFECTIVE"                      # PASS -> 결함 없음, 통제 완전 작동
    PARTIALLY_EFFECTIVE = "PARTIALLY_EFFECTIVE"  # PARTIAL -> 일부 결함 존재
    INEFFECTIVE = "INEFFECTIVE"                  # FAIL -> 통제 미작동 또는 중대 결함
    NOT_ASSESSED = "NOT_ASSESSED"                # MANUAL / NO_EVIDENCE -> 증적 불충분 또는 수동 검토 대기

    @classmethod
    def from_audit_status(cls, status: str) -> "ControlEffectiveness":
        """AuditEngine의 판정 문자열로부터 통제 유효성을 결정론적으로 변환합니다."""
        st = str(status).upper()
        if st in ("PASS", "COMPLIANT"):
            return cls.EFFECTIVE
        elif st in ("PARTIAL", "PARTIALLY_COMPLIANT"):
            return cls.PARTIALLY_EFFECTIVE
        elif st in ("FAIL", "NON_COMPLIANT"):
            return cls.INEFFECTIVE
        return cls.NOT_ASSESSED


class AutomationLevel(str, Enum):
    """통제항목의 자동화 평가 수준"""
    FULLY_AUTOMATED = "FULLY_AUTOMATED"          # 클라우드 API/도구 기반 100% 자동 진단
    PARTIALLY_AUTOMATED = "PARTIALLY_AUTOMATED"  # 기술 증적 수집 + 관리적 검토 병행
    MANUAL = "MANUAL"                            # 정책 문서, 면담, 수동 확인 필요


class RelationshipType(str, Enum):
    """온톨로지 지식 그래프 16대 관계 유형"""
    CONTAINS = "CONTAINS"                    # Framework -> Control, Control -> Requirement
    MAPS_TO = "MAPS_TO"                      # Control -> Control (Cross-framework), Evidence -> Control
    REQUIRES = "REQUIRES"                    # Control -> Requirement
    SUPPORTED_BY = "SUPPORTED_BY"            # Control -> Evidence
    DERIVED_FROM = "DERIVED_FROM"            # Evidence -> Finding / Raw Source
    AFFECTS = "AFFECTS"                      # Finding -> Asset
    PROTECTED_BY = "PROTECTED_BY"            # Asset -> Control
    CONTRIBUTES_TO = "CONTRIBUTES_TO"        # Asset / Finding -> Risk
    CREATES_RISK = "CREATES_RISK"            # Finding -> Risk
    MITIGATED_BY = "MITIGATED_BY"            # Risk -> Remediation
    REMEDIATES = "REMEDIATES"                # Remediation -> Finding / Asset
    VERIFIED_BY = "VERIFIED_BY"              # Remediation -> Evidence
    USES = "USES"                            # Agent -> Tool
    GOVERNED_BY = "GOVERNED_BY"              # Agent -> Policy
    PRODUCES = "PRODUCES"                    # Agent -> Evidence / AuditResult
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"  # Remediation -> Policy / Human Gate


class FrameworkCoverage(BaseModel):
    """컴플라이언스 프레임워크 온톨로지 커버리지 통계 모델"""
    framework_id: str = Field(description="프레임워크 식별자 (예: 'ISMS-P')")
    total_controls: int = Field(description="전체 통제항목 수")
    assessed_controls: int = Field(description="실제 평가가 수행된 통제항목 수")
    effective_controls: int = Field(description="효과적인(PASS) 통제항목 수")
    partially_effective_controls: int = Field(description="부분 효과적(PARTIAL) 통제항목 수")
    ineffective_controls: int = Field(description="비효과적(FAIL) 통제항목 수")
    not_assessed_controls: int = Field(description="미평가(MANUAL/NO_EVIDENCE) 통제항목 수")
    coverage_percent: float = Field(description="평가 커버리지 비율 (%)")
    automation_percent: float = Field(description="자동화 평가 비율 (%)")
