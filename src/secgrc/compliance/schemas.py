"""Adapter Schema Model & Definitions (Step 23.5A).

This module defines the AdapterSchema model and canonical field definitions
for supported security and compliance data sources.
"""

from typing import List, Optional
from pydantic import Field, field_validator

from secgrc.compliance.models import (
    CanonicalDataType,
    ComplianceBaseModel,
    validate_identifier,
)


class AdapterSchema(ComplianceBaseModel):
    """원천 데이터 어댑터 스키마 명세 모델."""

    source_type: str = Field(description="어댑터 소스 식별자 (예: Prowler, Nmap, IAM 등)")
    schema_version: str = Field(default="1.0", description="어댑터 스키마 버전")
    canonical_data_types: List[CanonicalDataType] = Field(description="변환 지원 정규 데이터 유형 목록")
    required_fields: List[str] = Field(description="원천 파싱 레코드 내 필수 필드 목록")
    optional_fields: List[str] = Field(default_factory=list, description="원천 레코드 내 선택 필드 목록")
    description: str = Field(description="어댑터 스키마 상세 설명")

    @field_validator("source_type", "schema_version")
    @classmethod
    def check_schema_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


# ---------------------------------------------------------------------------
# 8대 표준 어댑터 스키마 정의 (Section 24)
# ---------------------------------------------------------------------------

PROWLER_SCHEMA = AdapterSchema(
    source_type="Prowler",
    schema_version="1.0",
    canonical_data_types=[
        CanonicalDataType.CONFIGURATION_FINDING,
        CanonicalDataType.SECURITY_CONFIGURATION,
    ],
    required_fields=["check_id", "status", "resource_id", "service_name"],
    optional_fields=["severity", "region", "description", "remediation"],
    description="Prowler 클라우드 보안 점검 도구 CSV/JSON 결과 스키마",
)

NMAP_SCHEMA = AdapterSchema(
    source_type="Nmap",
    schema_version="1.0",
    canonical_data_types=[
        CanonicalDataType.PORT_OBSERVATION,
        CanonicalDataType.SERVICE_EXPOSURE,
    ],
    required_fields=["host", "port", "protocol", "state"],
    optional_fields=["service_name", "product", "version", "banner"],
    description="Nmap 포트 스캔 및 네트워크 서비스 노출 결과 스키마",
)

NESSUS_SCHEMA = AdapterSchema(
    source_type="Nessus",
    schema_version="1.0",
    canonical_data_types=[
        CanonicalDataType.VULNERABILITY_FINDING,
        CanonicalDataType.VULNERABILITY,
    ],
    required_fields=["plugin_id", "plugin_name", "host", "risk_factor"],
    optional_fields=["cve", "cvss_score", "synopsis", "solution"],
    description="Nessus 취약점 스캐너 리포트 결과 스키마",
)

IAM_SCHEMA = AdapterSchema(
    source_type="IAM",
    schema_version="1.0",
    canonical_data_types=[
        CanonicalDataType.IAM_POLICY,
        CanonicalDataType.PERMISSION,
        CanonicalDataType.ACCOUNT,
        CanonicalDataType.MFA_CONFIGURATION,
    ],
    required_fields=["policy_id", "policy_name", "statements"],
    optional_fields=["version", "attached_entities", "mfa_required"],
    description="클라우드 및 OS IAM 정책/권한 명세 스키마",
)

FIREWALL_SCHEMA = AdapterSchema(
    source_type="Firewall",
    schema_version="1.0",
    canonical_data_types=[
        CanonicalDataType.FIREWALL_RULE,
        CanonicalDataType.FIREWALL_POLICY,
    ],
    required_fields=["rule_id", "action", "direction", "destination_ports"],
    optional_fields=["source_ranges", "destination_ranges", "priority", "description"],
    description="네트워크 및 클라우드 방화벽 규칙 스키마",
)

SIEM_SCHEMA = AdapterSchema(
    source_type="SIEM",
    schema_version="1.0",
    canonical_data_types=[
        CanonicalDataType.ALERT,
        CanonicalDataType.SECURITY_EVENT,
    ],
    required_fields=["alert_id", "event_type", "timestamp", "severity"],
    optional_fields=["source_ip", "destination_ip", "user", "raw_message"],
    description="SIEM(Splunk, Elastic, Chronicle 등) 보안 경보 이벤트 스키마",
)

WINDOWS_EVENT_SCHEMA = AdapterSchema(
    source_type="WindowsEvent",
    schema_version="1.0",
    canonical_data_types=[
        CanonicalDataType.SECURITY_LOG,
        CanonicalDataType.AUTHENTICATION_CONFIGURATION,
    ],
    required_fields=["event_id", "provider_name", "timestamp", "computer"],
    optional_fields=["target_user_name", "logon_type", "status_code"],
    description="Windows 보안 이벤트 로그(EventID 4624, 4625 등) 스키마",
)

POLICY_DOCUMENT_SCHEMA = AdapterSchema(
    source_type="PolicyDocument",
    schema_version="1.0",
    canonical_data_types=[
        CanonicalDataType.POLICY,
        CanonicalDataType.PROCEDURE,
        CanonicalDataType.STANDARD,
        CanonicalDataType.SECURITY_PLAN,
    ],
    required_fields=["document_id", "title", "version", "approved_by"],
    optional_fields=["effective_date", "review_cycle", "summary", "author"],
    description="정보보호 및 개인정보보호 관리체계 규정/지침/계획서 문서 스키마",
)
