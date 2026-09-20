"""Enterprise Compliance & Canonical Security Data Models (Step 23.5A).

This module defines the canonical data models, enterprise domains,
provenance envelopes, and data types across Governance, Asset,
Identity, Network, Vulnerability, SecOps, Privacy, Supply Chain, and Physical domains.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class EnterpriseDomain(str, Enum):
    """엔터프라이즈 컴플라이언스 10대 도메인 분류."""
    GOVERNANCE = "GOVERNANCE"
    ASSET_CONFIGURATION = "ASSET_CONFIGURATION"
    IDENTITY_ACCESS = "IDENTITY_ACCESS"
    NETWORK_SECURITY = "NETWORK_SECURITY"
    VULNERABILITY_EXPOSURE = "VULNERABILITY_EXPOSURE"
    SECURITY_OPERATIONS = "SECURITY_OPERATIONS"
    DATA_SECURITY_PRIVACY = "DATA_SECURITY_PRIVACY"
    DEVELOPMENT_SUPPLY_CHAIN = "DEVELOPMENT_SUPPLY_CHAIN"
    PHYSICAL_HUMAN_OPERATIONAL = "PHYSICAL_HUMAN_OPERATIONAL"
    AUDIT_COMPLIANCE_EVIDENCE = "AUDIT_COMPLIANCE_EVIDENCE"


class CanonicalDataType(str, Enum):
    """정규화된 표준 보안/개인정보/거버넌스 데이터 유형."""

    # A. Governance
    ORGANIZATION = "ORGANIZATION"
    ROLE = "ROLE"
    RESPONSIBILITY = "RESPONSIBILITY"
    POLICY = "POLICY"
    STANDARD = "STANDARD"
    GUIDELINE = "GUIDELINE"
    PROCEDURE = "PROCEDURE"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    RISK_ACCEPTANCE = "RISK_ACCEPTANCE"
    EXCEPTION = "EXCEPTION"
    SECURITY_PLAN = "SECURITY_PLAN"
    AUDIT_PLAN = "AUDIT_PLAN"

    # B. Asset / Configuration
    ASSET = "ASSET"
    APPLICATION = "APPLICATION"
    SERVER = "SERVER"
    DATABASE = "DATABASE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    SECURITY_DEVICE = "SECURITY_DEVICE"
    SERVICE = "SERVICE"
    ENDPOINT = "ENDPOINT"
    CONTAINER = "CONTAINER"
    KUBERNETES_RESOURCE = "KUBERNETES_RESOURCE"
    CONFIGURATION = "CONFIGURATION"
    SECURITY_CONFIGURATION = "SECURITY_CONFIGURATION"

    # C. Identity / Access
    IDENTITY = "IDENTITY"
    ACCOUNT = "ACCOUNT"
    PRIVILEGED_ACCOUNT = "PRIVILEGED_ACCOUNT"
    GROUP = "GROUP"
    PERMISSION = "PERMISSION"
    IAM_POLICY = "IAM_POLICY"
    ACCESS_REVIEW = "ACCESS_REVIEW"
    AUTHENTICATION_CONFIGURATION = "AUTHENTICATION_CONFIGURATION"
    MFA_CONFIGURATION = "MFA_CONFIGURATION"
    PAM_RECORD = "PAM_RECORD"
    SSO_CONFIGURATION = "SSO_CONFIGURATION"

    # D. Network Security
    FIREWALL_POLICY = "FIREWALL_POLICY"
    FIREWALL_RULE = "FIREWALL_RULE"
    FIREWALL_EVENT = "FIREWALL_EVENT"
    WAF_POLICY = "WAF_POLICY"
    WAF_EVENT = "WAF_EVENT"
    VPN_CONFIGURATION = "VPN_CONFIGURATION"
    IDS_ALERT = "IDS_ALERT"
    IPS_ALERT = "IPS_ALERT"
    NDR_ALERT = "NDR_ALERT"
    NETWORK_FLOW = "NETWORK_FLOW"
    DNS_LOG = "DNS_LOG"
    PROXY_LOG = "PROXY_LOG"

    # E. Vulnerability / Exposure
    VULNERABILITY = "VULNERABILITY"
    VULNERABILITY_FINDING = "VULNERABILITY_FINDING"
    SCAN_RESULT = "SCAN_RESULT"
    PORT_OBSERVATION = "PORT_OBSERVATION"
    SERVICE_EXPOSURE = "SERVICE_EXPOSURE"
    CONFIGURATION_FINDING = "CONFIGURATION_FINDING"
    PATCH_STATUS = "PATCH_STATUS"
    PENETRATION_TEST = "PENETRATION_TEST"
    RED_TEAM_FINDING = "RED_TEAM_FINDING"
    AI_RED_TEAM_FINDING = "AI_RED_TEAM_FINDING"

    # F. Security Operations Data
    SECURITY_EVENT = "SECURITY_EVENT"
    SECURITY_LOG = "SECURITY_LOG"
    ALERT = "ALERT"
    DETECTION = "DETECTION"
    INCIDENT = "INCIDENT"
    INCIDENT_EVENT = "INCIDENT_EVENT"
    THREAT_INDICATOR = "THREAT_INDICATOR"
    THREAT_INTEL = "THREAT_INTEL"
    CASE = "CASE"
    TICKET = "TICKET"
    RESPONSE_ACTION = "RESPONSE_ACTION"
    FORENSIC_OBSERVATION = "FORENSIC_OBSERVATION"

    # G. Data Security / Privacy
    DATA_ASSET = "DATA_ASSET"
    DATA_STORE = "DATA_STORE"
    DATA_ELEMENT = "DATA_ELEMENT"
    DATA_CLASSIFICATION = "DATA_CLASSIFICATION"
    PERSONAL_DATA = "PERSONAL_DATA"
    SENSITIVE_PERSONAL_DATA = "SENSITIVE_PERSONAL_DATA"
    PROCESSING_ACTIVITY = "PROCESSING_ACTIVITY"
    PROCESSING_PURPOSE = "PROCESSING_PURPOSE"
    LEGAL_BASIS = "LEGAL_BASIS"
    CONSENT = "CONSENT"
    RETENTION_RULE = "RETENTION_RULE"
    DELETION_RECORD = "DELETION_RECORD"
    DATA_TRANSFER = "DATA_TRANSFER"
    THIRD_PARTY = "THIRD_PARTY"
    PROCESSOR = "PROCESSOR"
    CONTROLLER = "CONTROLLER"
    DPA = "DPA"
    DPIA = "DPIA"
    DSAR = "DSAR"
    PRIVACY_INCIDENT = "PRIVACY_INCIDENT"

    # H. Development / Supply Chain
    REPOSITORY = "REPOSITORY"
    SOURCE_CODE = "SOURCE_CODE"
    BUILD = "BUILD"
    PIPELINE = "PIPELINE"
    DEPENDENCY = "DEPENDENCY"
    SOFTWARE_COMPONENT = "SOFTWARE_COMPONENT"
    SAST_FINDING = "SAST_FINDING"
    DAST_FINDING = "DAST_FINDING"
    SCA_FINDING = "SCA_FINDING"
    SECRET_FINDING = "SECRET_FINDING"
    SBOM = "SBOM"
    CICD_CONFIGURATION = "CICD_CONFIGURATION"
    RELEASE = "RELEASE"
    CHANGE_REQUEST = "CHANGE_REQUEST"
    CODE_REVIEW = "CODE_REVIEW"

    # I. Physical / Human / Operational
    PHYSICAL_ACCESS_RECORD = "PHYSICAL_ACCESS_RECORD"
    VISITOR_RECORD = "VISITOR_RECORD"
    FACILITY = "FACILITY"
    TRAINING_RECORD = "TRAINING_RECORD"
    SECURITY_TRAINING = "SECURITY_TRAINING"
    AWARENESS_ACTIVITY = "AWARENESS_ACTIVITY"
    PERSONNEL_RECORD_REFERENCE = "PERSONNEL_RECORD_REFERENCE"
    JOINER_EVENT = "JOINER_EVENT"
    MOVER_EVENT = "MOVER_EVENT"
    LEAVER_EVENT = "LEAVER_EVENT"
    VENDOR = "VENDOR"
    THIRD_PARTY_ASSESSMENT = "THIRD_PARTY_ASSESSMENT"
    CONTRACT = "CONTRACT"
    SECURITY_CLAUSE = "SECURITY_CLAUSE"

    # J. Audit / Compliance Evidence
    SECURITY_DATA = "SECURITY_DATA"
    PRIVACY_DATA = "PRIVACY_DATA"
    GOVERNANCE_DATA = "GOVERNANCE_DATA"
    OPERATIONAL_DATA = "OPERATIONAL_DATA"
    EVIDENCE_REFERENCE = "EVIDENCE_REFERENCE"


class ClassificationLevel(str, Enum):
    """정보 보안 등급."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class AutomationLevel(str, Enum):
    """컴플라이언스 요구사항 자동화 수준."""
    AUTOMATIC = "AUTOMATIC"
    SEMI_AUTOMATIC = "SEMI_AUTOMATIC"
    MANUAL = "MANUAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class InputCoverageState(str, Enum):
    """입력 데이터 충족 상태."""
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    MANUAL = "MANUAL"
    UNKNOWN = "UNKNOWN"


class EvidenceState(str, Enum):
    """증적 확보 상태."""
    AVAILABLE = "AVAILABLE"
    PARTIALLY_AVAILABLE = "PARTIALLY_AVAILABLE"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    PENDING_REVIEW = "PENDING_REVIEW"
    CONFLICTING = "CONFLICTING"


class FrameworkStatus(str, Enum):
    """컴플라이언스 프레임워크 생명주기 상태."""
    ACTIVE = "ACTIVE"
    DRAFT = "DRAFT"
    SUPERSEDED = "SUPERSEDED"
    ARCHIVED = "ARCHIVED"


# ---------------------------------------------------------------------------
# Base Models
# ---------------------------------------------------------------------------

class ComplianceBaseModel(BaseModel):
    """컴플라이언스 데이터 모델 공통 베이스 (엄격한 속성 통제)."""
    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )


def validate_identifier(v: str, field_name: str) -> str:
    """식별자 유효성 및 보안 검증."""
    if not isinstance(v, str):
        raise ValueError(f"{field_name} must be a string, got {type(v).__name__}")
    if v != v.strip():
        raise ValueError(f"{field_name} cannot have leading or trailing whitespace")
    v_strip = v.strip()
    if not v_strip:
        raise ValueError(f"{field_name} cannot be empty or whitespace only")
    # 금지 패턴 (경로 조작, 스크립트 태그, 쉘 제어문자, 비인가 URL 프로토콜 등)
    lower = v_strip.lower()
    dangerous_patterns = (
        "../", "..\\", "<script", "javascript:", "\x00", "$(", "`", ";", "|", "&",
        "https://", "http://", "file://", "ftp://", "'", '"',
    )
    for pat in dangerous_patterns:
        if pat in lower:
            if pat in ("../", "..\\"):
                raise ValueError(f"{field_name} cannot contain path traversal token patterns: '{pat}'")
            raise ValueError(f"{field_name} contains forbidden dangerous injection characters: '{pat}'")
    if not v_strip.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in v_strip):
        raise ValueError(f"{field_name} must contain only printable ASCII characters")
    return v_strip



def validate_iso8601_timestamp(v: str, field_name: str) -> str:
    """ISO 8601 타임스탬프 유효성 검증."""
    if not isinstance(v, str):
        raise ValueError(f"{field_name} must be a string, got {type(v).__name__}")
    v_strip = v.strip()
    if not v_strip:
        raise ValueError(f"{field_name} cannot be empty")
    try:
        # datetime.fromisoformat 검증
        datetime.fromisoformat(v_strip.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValueError(f"{field_name} must be a valid ISO 8601 timestamp: {exc}")
    return v_strip


class ProvenanceRecord(ComplianceBaseModel):
    """정규화된 모든 레코드의 불변 출처 계보 정보."""

    source_system: str = Field(description="원천 시스템명 (예: Prowler, Nmap, Nessus, GCP-IAM, SIEM)")
    source_record_id: str = Field(description="원천 시스템 내 레코드 고유 식별자")
    source_document: Optional[str] = Field(default=None, description="원천 문서/파일 참조 (선택)")
    source_timestamp: str = Field(description="원천 데이터 발생/수집 시각 (ISO 8601)")
    ingestion_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="정규화/수집 처리 시각 (ISO 8601)",
    )
    source_hash: str = Field(description="원천 페이로드 SHA-256 해시")
    schema_version: str = Field(default="1.0", description="어댑터 스키마 버전")
    transform_version: str = Field(default="1.0", description="정규화 변환 로직 버전")

    @field_validator("source_system", "source_record_id", "source_hash", "schema_version", "transform_version")
    @classmethod
    def check_id_fields(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("source_timestamp", "ingestion_timestamp")
    @classmethod
    def check_timestamps(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)


class EntityReference(ComplianceBaseModel):
    """온톨로지 또는 연관 엔티티 참조."""

    entity_type: str = Field(description="참조 대상 엔티티 유형 (예: Asset, Control, Risk, User)")
    entity_id: str = Field(description="참조 대상 엔티티 식별자")
    relationship: Optional[str] = Field(default=None, description="엔티티와의 관계 (예: BELONGS_TO, PROTECTED_BY)")

    @field_validator("entity_type", "entity_id")
    @classmethod
    def check_entity_fields(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class CanonicalSecurityData(ComplianceBaseModel):
    """모든 정규화된 보안, 개인정보, 거버넌스 데이터의 표준 공통 봉투(Envelope)."""

    record_id: str = Field(description="정규화된 정규 레코드의 전역 고유 식별자 (예: CANON-PROWLER-001)")
    data_type: CanonicalDataType = Field(description="표준 정규 데이터 유형")
    source_system: str = Field(description="원천 시스템명")
    source_record_id: str = Field(description="원천 레코드 고유 ID")
    source_version: Optional[str] = Field(default=None, description="원천 시스템 도구 버전")
    observed_at: str = Field(description="데이터 관측/발생 시각 (ISO 8601)")
    ingested_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="정규화 및 유입 일시 (ISO 8601)",
    )
    tenant_id: str = Field(default="default", description="테넌트 격리 식별자")
    scope: str = Field(default="GLOBAL", description="조사/엔티티 스코프")
    entity_references: List[EntityReference] = Field(default_factory=list, description="연계 엔티티 참조 목록")
    payload: Dict[str, Any] = Field(description="정규화된 상세 속성 페이로드 (비실행 데이터)")
    provenance: ProvenanceRecord = Field(description="불변 원천 계보 레코드")
    classification: ClassificationLevel = Field(
        default=ClassificationLevel.INTERNAL,
        description="정보 자산 보안 등급",
    )
    integrity_hash: str = Field(description="페이로드 및 계보 무결성 SHA-256 해시")
    schema_version: str = Field(default="1.0", description="표준 정규 모델 스키마 버전")

    @field_validator("record_id", "source_system", "source_record_id", "tenant_id", "scope", "integrity_hash", "schema_version")
    @classmethod
    def check_canonical_ids(cls, v: str, info) -> str:
        res = validate_identifier(v, info.field_name)
        if info.field_name == "schema_version" and res != "1.0":
            raise ValueError(f"schema_version must be '1.0', got '{res}'")
        return res


    @field_validator("observed_at", "ingested_at")
    @classmethod
    def check_canonical_timestamps(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)

    @staticmethod
    def compute_integrity_hash(payload: Dict[str, Any], provenance: ProvenanceRecord) -> str:
        """페이로드와 계보 데이터로부터 재현 가능한 SHA-256 해시를 계산합니다."""
        raw_bytes = json.dumps(
            {
                "payload": payload,
                "source_system": provenance.source_system,
                "source_record_id": provenance.source_record_id,
                "source_timestamp": provenance.source_timestamp,
                "source_hash": provenance.source_hash,
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(raw_bytes).hexdigest()
