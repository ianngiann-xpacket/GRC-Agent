"""Temporal Coverage Models & Distinctions (Step 23.5B).

This module defines temporal coverage metadata for evidence, distinguishing between
point-in-time configuration snapshots and operational records spanning time periods.
"""

from enum import Enum
from typing import Optional
from pydantic import Field, field_validator

from secgrc.compliance.models import (
    ComplianceBaseModel,
    validate_identifier,
)


class TemporalCoverageType(str, Enum):
    """증적의 시간적 보장 범위 유형."""
    POINT_IN_TIME = "POINT_IN_TIME"
    PERIOD = "PERIOD"
    CONTINUOUS = "CONTINUOUS"
    RECURRENT = "RECURRENT"
    HISTORICAL = "HISTORICAL"


class TemporalCoverage(ComplianceBaseModel):
    """시간적 커버리지 메타데이터 모델."""

    temporal_type: TemporalCoverageType = Field(
        default=TemporalCoverageType.POINT_IN_TIME,
        description="시간적 커버리지 유형 (POINT_IN_TIME, PERIOD, CONTINUOUS 등)",
    )
    audit_period: Optional[str] = Field(
        default=None,
        description="감사 대상 주기 명칭 (예: 2024-H1, ANNUAL-2024)",
    )
    minimum_span_days: Optional[int] = Field(
        default=None,
        description="최소 요구 지속 기간 일수 (PERIOD/CONTINUOUS 시 요구)",
    )
    recurrence_interval: Optional[str] = Field(
        default=None,
        description="반복 주기 (예: MONTHLY, QUARTERLY, ANNUAL)",
    )
    description: Optional[str] = Field(
        default=None,
        description="시간적 보장 범위 요건 설명",
    )

    @field_validator("audit_period", "recurrence_interval")
    @classmethod
    def check_strings(cls, v: Optional[str], info) -> Optional[str]:
        if v is not None:
            return validate_identifier(v, info.field_name)
        return None

    @field_validator("minimum_span_days")
    @classmethod
    def check_span(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v <= 0:
            raise ValueError(f"minimum_span_days must be a positive integer, got {v}")
        return v
