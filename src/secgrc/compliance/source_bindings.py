"""Evidence Source Binding Models (Step 23.5B).

This module defines deterministic bindings between evidence requirements and acceptable
data sources/adapters, without creating live external connectors.
"""

from typing import Optional
from pydantic import Field, field_validator

from secgrc.compliance.models import (
    CanonicalDataType,
    ComplianceBaseModel,
    validate_identifier,
)


class EvidenceSourceBinding(ComplianceBaseModel):
    """증적 요구사항과 수집 원천 시스템/어댑터 간의 바인딩 명세."""

    source_type: str = Field(description="원천 데이터 소스 분류 (예: IAM, Firewall, SIEM, PolicyDocument)")
    canonical_data_type: CanonicalDataType = Field(description="매핑되는 정규 표준 데이터 유형")
    source_system: str = Field(description="구체적 시스템/벤더 솔루션 (예: AWS IAM, Palo Alto, Wazuh, Nessus)")
    adapter_type: str = Field(description="연계 어댑터 클래스명 (예: IAMPolicyDataAdapter, FirewallPolicyDataAdapter)")
    required: bool = Field(default=True, description="평가 시 해당 소스 필수 수집 여부")
    priority: int = Field(default=1, ge=1, description="소스 우선순위 (1이 최우선)")
    description: str = Field(default="", description="소스 바인딩 상세 설명")
    source_reference: Optional[str] = Field(default=None, description="외부 규격 또는 벤더 레퍼런스")

    @field_validator("source_type", "source_system", "adapter_type")
    @classmethod
    def check_binding_identifiers(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("source_reference")
    @classmethod
    def check_source_reference(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_identifier(v, "source_reference")
        return None
