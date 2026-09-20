"""컴플라이언스 프레임워크 간 크로스 매핑(Cross-Framework Mapping) 모델 모듈입니다.

ISMS-P, ISO 27001, NIST CSF 2.0, CIS Controls 간의 상호 매핑 관계를 정의합니다.
"""

from typing import List
from pydantic import BaseModel, Field


class FrameworkMapping(BaseModel):
    """프레임워크 간 통제 매핑 데이터 모델"""

    control_id: str = Field(..., description="기준 통제항목 식별자 (예: 'ISMS-P-2.5.2')")
    iso27001: List[str] = Field(
        default_factory=list,
        description="매핑되는 ISO/IEC 27001:2022 부속서 A 통제항목 (예: ['A.5.17 Authentication information'])"
    )
    nist_csf: List[str] = Field(
        default_factory=list,
        description="매핑되는 NIST CSF 2.0 카테고리/서브카테고리 (예: ['PR.AA-01'])"
    )
    cis_controls: List[str] = Field(
        default_factory=list,
        description="매핑되는 CIS Controls v8 세부 통제항목 (예: ['CIS 6.3'])"
    )
    nist_ai_rmf: List[str] = Field(
        default_factory=list,
        description="매핑되는 NIST AI RMF(인공지능 위험관리) 통제항목 (예: ['MANAGE 2.4'])"
    )
    rationale: str = Field(
        default="",
        description="통제항목 간 기술적/관리적 매핑 근거 및 해설"
    )
