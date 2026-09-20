"""Evidence Freshness Models & Constraints (Step 23.5B).

This module defines deterministic temporal freshness metadata for compliance evidence,
specifying allowable time windows without evaluating pass/fail status.
"""

from enum import Enum
from typing import Optional
from pydantic import Field, field_validator, model_validator

from secgrc.compliance.models import (
    ComplianceBaseModel,
    validate_identifier,
    validate_iso8601_timestamp,
)


class EvidenceFreshnessType(str, Enum):
    """증적 신선도 제약 유형."""
    ANY = "ANY"
    CURRENT = "CURRENT"
    WITHIN_HOURS = "WITHIN_HOURS"
    WITHIN_DAYS = "WITHIN_DAYS"
    WITHIN_MONTHS = "WITHIN_MONTHS"
    FIXED_PERIOD = "FIXED_PERIOD"


class EvidenceFreshness(ComplianceBaseModel):
    """증적 신선도 요구사항 메타데이터."""

    freshness_type: EvidenceFreshnessType = Field(
        default=EvidenceFreshnessType.ANY,
        description="신선도 제약 구분",
    )
    freshness_value: Optional[int] = Field(
        default=None,
        description="신선도 수치 (시간, 일수, 개월수 등 양의 정수)",
    )
    unit: Optional[str] = Field(
        default=None,
        description="신선도 단위 (hours, days, months)",
    )
    fixed_start_date: Optional[str] = Field(
        default=None,
        description="고정 기간 시작일시 (ISO 8601)",
    )
    fixed_end_date: Optional[str] = Field(
        default=None,
        description="고정 기간 종료일시 (ISO 8601)",
    )
    description: Optional[str] = Field(
        default=None,
        description="신선도 요건 상세 설명",
    )

    @field_validator("unit")
    @classmethod
    def check_unit(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_identifier(v, "unit")
        return None

    @field_validator("fixed_start_date", "fixed_end_date")
    @classmethod
    def check_fixed_dates(cls, v: Optional[str], info) -> Optional[str]:
        if v is not None:
            return validate_iso8601_timestamp(v, info.field_name)
        return None

    @field_validator("freshness_value")
    @classmethod
    def check_freshness_value(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v <= 0:
            raise ValueError(f"freshness_value must be a positive integer, got {v}")
        return v

    @model_validator(mode="after")
    def validate_freshness_configuration(self) -> "EvidenceFreshness":
        ft = self.freshness_type
        if ft in (EvidenceFreshnessType.WITHIN_HOURS, EvidenceFreshnessType.WITHIN_DAYS, EvidenceFreshnessType.WITHIN_MONTHS):
            if self.freshness_value is None:
                raise ValueError(f"freshness_value is required for freshness_type {ft.value}")
        elif ft == EvidenceFreshnessType.FIXED_PERIOD:
            if not self.fixed_start_date or not self.fixed_end_date:
                raise ValueError("fixed_start_date and fixed_end_date are required for FIXED_PERIOD")
        return self
