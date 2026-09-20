"""Compliance Control 데이터 모델 모듈입니다.

KISA ISMS-P, ISO 27001, NIST 등 보안 프레임워크의 단일 통제항목을 정의합니다.
"""

from typing import List
from pydantic import BaseModel, Field


class Control(BaseModel):
    """보안 컴플라이언스 통제항목 모델"""

    control_id: str = Field(..., description="통제항목 식별자 (예: 'ISMS-P-2.5.1')")
    framework: str = Field(default="ISMS-P", description="보안 프레임워크 명칭 (ISMS-P, ISO27001 등)")
    domain: str = Field(..., description="통제 영역 (예: '인증 및 권한관리')")
    title: str = Field(..., description="통제항목 제목 (예: '사용자 계정 관리')")
    requirement: str = Field(..., description="법적/규정 요구사항 본문")
    evidence: List[str] = Field(
        default_factory=list,
        description="필요 감사 증적 목록 (예: 'IAM 사용자 목록', '퇴직자 계정 목록')"
    )
    risk: str = Field(default="", description="미준수 시 발생하는 핵심 보안 위험 (예: 'Unauthorized Access')")
    automatable: bool = Field(
        default=False,
        description="AWS/Azure API 또는 Prowler 등으로 기술적 자동 검증이 가능한지 여부"
    )
    keywords: List[str] = Field(default_factory=list, description="검색 가중치 키워드")
