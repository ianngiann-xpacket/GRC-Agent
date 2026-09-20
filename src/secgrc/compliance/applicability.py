"""Applicability & Scope Models (Step 23.5B).

This module defines deterministic applicability conditions and scope metadata.
Conditions are pure data declarations—no dynamic expression evaluation (eval/exec) is permitted.
"""

from enum import Enum
from typing import List, Optional
from pydantic import Field, field_validator

from secgrc.compliance.models import (
    ComplianceBaseModel,
    validate_identifier,
)


class EvidenceConditionType(str, Enum):
    """증적 및 요구사항 적용 조건 구분."""
    ALWAYS = "ALWAYS"
    IF_APPLICABLE = "IF_APPLICABLE"
    IF_ASSET_EXISTS = "IF_ASSET_EXISTS"
    IF_PERSONAL_DATA_EXISTS = "IF_PERSONAL_DATA_EXISTS"
    IF_EXTERNAL_PARTY_EXISTS = "IF_EXTERNAL_PARTY_EXISTS"
    IF_CLOUD_EXISTS = "IF_CLOUD_EXISTS"
    IF_PRIVILEGED_ACCESS_EXISTS = "IF_PRIVILEGED_ACCESS_EXISTS"
    IF_DEVELOPMENT_EXISTS = "IF_DEVELOPMENT_EXISTS"
    IF_PROCESSING_ACTIVITY_EXISTS = "IF_PROCESSING_ACTIVITY_EXISTS"
    IF_INCIDENT_EXISTS = "IF_INCIDENT_EXISTS"
    IF_HIGH_RISK_PROCESSING_EXISTS = "IF_HIGH_RISK_PROCESSING_EXISTS"


class EvidenceCondition(ComplianceBaseModel):
    """증적 적용 조건 메타데이터."""

    condition_type: EvidenceConditionType = Field(
        default=EvidenceConditionType.ALWAYS,
        description="조건 유형",
    )
    dimension: Optional[str] = Field(
        default=None,
        description="적용성 평가 차원 (예: asset, cloud, privacy)",
    )
    parameter: Optional[str] = Field(
        default=None,
        description="조건 파라미터/기준 (예: aws, resident_registration_number)",
    )
    description: str = Field(
        default="",
        description="조건 상세 설명",
    )

    @field_validator("dimension", "parameter")
    @classmethod
    def check_condition_strings(cls, v: Optional[str], info) -> Optional[str]:
        if v is not None:
            return validate_identifier(v, info.field_name)
        return None


class EvidenceScopeType(str, Enum):
    """증적 적용 스코프 유형."""
    GLOBAL = "GLOBAL"
    ORGANIZATION = "ORGANIZATION"
    BUSINESS_UNIT = "BUSINESS_UNIT"
    APPLICATION = "APPLICATION"
    SERVICE = "SERVICE"
    ASSET = "ASSET"
    ACCOUNT = "ACCOUNT"
    USER = "USER"
    PROCESSING_ACTIVITY = "PROCESSING_ACTIVITY"
    DATASET = "DATASET"
    FACILITY = "FACILITY"
    VENDOR = "VENDOR"


class EvidenceScope(ComplianceBaseModel):
    """증적 스코프 메타데이터."""

    scope_type: EvidenceScopeType = Field(
        default=EvidenceScopeType.GLOBAL,
        description="스코프 유형",
    )
    scope_id: Optional[str] = Field(
        default=None,
        description="스코프 대상 식별자 (예: SVC-FINANCE-01, AWS-ACCT-12345)",
    )
    description: Optional[str] = Field(
        default=None,
        description="스코프 상세 설명",
    )

    @field_validator("scope_id")
    @classmethod
    def check_scope_id(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_identifier(v, "scope_id")
        return None


class ApplicabilityProfile(ComplianceBaseModel):
    """요구사항 및 증적의 엔터프라이즈 적용성 프로필 메타데이터."""

    organization_scope: Optional[str] = Field(default=None, description="조직 범위")
    system_scope: Optional[str] = Field(default=None, description="정보시스템 범위")
    asset_scope: Optional[str] = Field(default=None, description="자산 범위")
    processing_scope: Optional[str] = Field(default=None, description="개인정보 처리 업무 범위")
    data_scope: Optional[str] = Field(default=None, description="데이터 유형/등급 범위")
    vendor_scope: Optional[str] = Field(default=None, description="위탁/수탁/협력사 범위")
    technology_scope: Optional[str] = Field(default=None, description="기술 스택/클라우드 범위")
    jurisdiction: Optional[str] = Field(default="KR", description="적용 법할 구역")
    business_process: Optional[str] = Field(default=None, description="비즈니스 프로세스")
    conditions: List[EvidenceCondition] = Field(
        default_factory=list,
        description="적용성 판단 메타데이터 조건 목록",
    )

    @field_validator(
        "organization_scope",
        "system_scope",
        "asset_scope",
        "processing_scope",
        "data_scope",
        "vendor_scope",
        "technology_scope",
        "jurisdiction",
        "business_process",
    )
    @classmethod
    def check_profile_strings(cls, v: Optional[str], info) -> Optional[str]:
        if v is not None:
            return validate_identifier(v, info.field_name)
        return None
