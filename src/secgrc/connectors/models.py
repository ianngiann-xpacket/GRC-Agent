"""Phase 33-A: Production Connector Architecture - Core Data Models.

Defines Pydantic v2 immutable contracts for:
- Connector definitions & capabilities
- Raw source records & collection batches
- Normalization results targeting CanonicalDataType
- Entity and scope resolution results
- Checkpoints, health status, and resource limits
- Audit records and readiness reports

Invariant:
- Strict Product != Capability decoupling
- Zero credential storage
- Semantic hashes exclude wall-clock timestamps
- Read-only pipeline: no PASS/FAIL or risk score fields in models
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from secgrc.compliance.models import CanonicalDataType, CanonicalSecurityData


class ConnectorType(str, Enum):
    """External security product category / domain."""
    CLOUD_SECURITY = "CLOUD_SECURITY"
    IAM = "IAM"
    SIEM = "SIEM"
    FIREWALL = "FIREWALL"
    CSPM = "CSPM"
    DSPM = "DSPM"
    VULNERABILITY = "VULNERABILITY"
    EDR = "EDR"
    POLICY = "POLICY"
    ITSM = "ITSM"
    ASSET_INVENTORY = "ASSET_INVENTORY"
    CUSTOM = "CUSTOM"


class ConnectorStatus(str, Enum):
    """Operational lifecycle status of a registered connector."""
    REGISTERED = "REGISTERED"
    READY = "READY"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    DISABLED = "DISABLED"


class CollectionMode(str, Enum):
    """Collection / ingestion operational mode."""
    FULL = "FULL"
    INCREMENTAL = "INCREMENTAL"
    DELTA = "DELTA"
    POINT_IN_TIME = "POINT_IN_TIME"
    HISTORICAL = "HISTORICAL"


class EntityStatus(str, Enum):
    """Result of mapping external entity identifiers to internal entities."""
    RESOLVED = "RESOLVED"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"
    CROSS_TENANT = "CROSS_TENANT"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class ScopeStatus(str, Enum):
    """Result of evaluating record against compliance / enterprise scope."""
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN_SCOPE = "UNKNOWN_SCOPE"


def compute_canonical_hash(data: Any) -> str:
    """Computes a deterministic SHA-256 hash over canonical JSON representation."""
    raw = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def compute_idempotency_key(
    connector_id: str,
    source_system: str,
    source_record_id: str,
    source_event_time: str,
) -> str:
    """Computes stable idempotency key derived strictly from source attributes."""
    raw = f"{connector_id}:{source_system}:{source_record_id}:{source_event_time}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CredentialReference(BaseModel):
    """Abstract external secret locator. Strictly prohibits storing secret values."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    credential_ref_id: str
    provider_type: str  # e.g. AWS_SECRETS_MANAGER, HASHICORP_VAULT, GCP_SECRET_MANAGER, ENVIRONMENT
    metadata: Dict[str, str] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_no_raw_secrets(cls, v: Dict[str, str]) -> Dict[str, str]:
        secret_keys = ("password", "token", "secret", "private_key", "api_key", "access_key")
        for key, val in v.items():
            if any(k in key.lower() for k in secret_keys):
                raise ValueError(f"Direct secret key '{key}' forbidden in CredentialReference metadata")
            if len(val) > 256 and ("BEGIN" in val or "PRIVATE KEY" in val):
                raise ValueError(f"Secret material forbidden in CredentialReference metadata")
        return v


class ConnectorDefinition(BaseModel):
    """Static capability and contract definition of an external security connector."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    connector_id: str
    connector_type: ConnectorType
    name: str
    version: str = "1.0.0"
    adapter_version: str = "1.0.0"
    capabilities: List[str] = Field(default_factory=list)
    supported_canonical_types: List[CanonicalDataType] = Field(default_factory=list)
    supported_operations: List[str] = Field(default_factory=lambda: ["fetch", "normalize", "validate"])
    supported_collection_modes: List[CollectionMode] = Field(default_factory=lambda: [CollectionMode.FULL])
    trust_level: str = "VERIFIED"
    enabled: bool = True
    provenance: Dict[str, Any] = Field(default_factory=lambda: {"authority": "NON_AUTHORITATIVE"})
    metadata_hash: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.metadata_hash:
            canonical_repr = {
                "connector_id": self.connector_id,
                "connector_type": self.connector_type.value,
                "name": self.name,
                "version": self.version,
                "adapter_version": self.adapter_version,
                "capabilities": sorted(self.capabilities),
                "supported_canonical_types": sorted(t.value for t in self.supported_canonical_types),
                "supported_operations": sorted(self.supported_operations),
                "supported_collection_modes": sorted(m.value for m in self.supported_collection_modes),
                "trust_level": self.trust_level,
                "enabled": self.enabled,
            }
            object.__setattr__(self, "metadata_hash", compute_canonical_hash(canonical_repr))


class RawSourceRecord(BaseModel):
    """Raw, vendor-specific observation payload isolated from the canonical layer."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: str
    connector_id: str
    source_system: str
    source_type: str
    source_version: str = "1.0"
    organization_ref: str
    collected_at: str  # ISO 8601 operational metadata (excluded from semantic hashes)
    source_event_time: str  # ISO 8601 source timestamp
    payload: Dict[str, Any]
    payload_hash: str = ""
    source_locator: str = ""
    collection_batch_id: str = ""
    raw_provenance: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.payload_hash:
            calculated = compute_canonical_hash(self.payload)
            object.__setattr__(self, "payload_hash", calculated)


class ConnectorCollectionBatch(BaseModel):
    """Batch ingestion tracking container."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    batch_id: str
    connector_id: str
    organization_id: str
    started_at: str
    completed_at: Optional[str] = None
    record_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    cursor: Optional[str] = None
    continuation_token: Optional[str] = None
    batch_hash: str = ""
    status: str = "COMPLETED"

    def model_post_init(self, __context: Any) -> None:
        if not self.batch_hash:
            # Note: Wall-clock timestamps are excluded from semantic batch hash!
            semantic_data = {
                "batch_id": self.batch_id,
                "connector_id": self.connector_id,
                "organization_id": self.organization_id,
                "record_count": self.record_count,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "cursor": self.cursor,
                "continuation_token": self.continuation_token,
                "status": self.status,
            }
            object.__setattr__(self, "batch_hash", compute_canonical_hash(semantic_data))


class FieldMapping(BaseModel):
    """Source field to canonical field mapping definition (code-owned)."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_field: str
    canonical_field: str
    transformation: Optional[str] = None  # e.g. "lowercase", "iso_timestamp", "boolean", "strip"
    required: bool = True
    nullable: bool = False
    semantic_notes: Optional[str] = None
    mapping_version: str = "1.0"


class EntityResolutionResult(BaseModel):
    """Result of mapping external entity identifier to internal enterprise entity."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: EntityStatus
    external_entity_id: str
    internal_entity_ref: Optional[str] = None
    resolution_strategy: str = "exact_mapping"
    confidence: float = 1.0
    notes: Optional[str] = None


class ScopeResolutionResult(BaseModel):
    """Result of evaluating record against enterprise/compliance scope."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ScopeStatus
    organization_id: str
    scope_id: Optional[str] = None
    asset_scope: Optional[str] = None
    notes: Optional[str] = None


class ConnectorValidationResult(BaseModel):
    """Outcome of 10-level multi-gate connector validation."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool
    validation_errors: List[str] = Field(default_factory=list)
    validation_warnings: List[str] = Field(default_factory=list)
    secret_detected: bool = False
    entity_resolution: Optional[EntityResolutionResult] = None
    scope_resolution: Optional[ScopeResolutionResult] = None
    tenant_valid: bool = True


class CanonicalNormalizationResult(BaseModel):
    """Result of normalizing raw records into CanonicalSecurityData."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    canonical_data_type: CanonicalDataType
    records: List[CanonicalSecurityData] = Field(default_factory=list)
    rejected_records: List[Dict[str, Any]] = Field(default_factory=list)
    mapping_version: str = "1.0"
    source_refs: List[str] = Field(default_factory=list)
    normalization_warnings: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    result_hash: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.result_hash:
            semantic_data = {
                "canonical_data_type": self.canonical_data_type.value,
                "record_count": len(self.records),
                "record_hashes": [r.integrity_hash for r in self.records],
                "rejected_count": len(self.rejected_records),
                "mapping_version": self.mapping_version,
                "source_refs": sorted(self.source_refs),
            }
            object.__setattr__(self, "result_hash", compute_canonical_hash(semantic_data))


class ConnectorCheckpoint(BaseModel):
    """Checkpoint for stateful incremental/delta collection recovery."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    connector_id: str
    organization_id: str
    cursor: str
    last_source_event: Optional[str] = None
    checkpoint_hash: str = ""
    mapping_version: str = "1.0"
    status: str = "ACTIVE"

    def model_post_init(self, __context: Any) -> None:
        if not self.checkpoint_hash:
            data = {
                "connector_id": self.connector_id,
                "organization_id": self.organization_id,
                "cursor": self.cursor,
                "last_source_event": self.last_source_event,
                "mapping_version": self.mapping_version,
                "status": self.status,
            }
            object.__setattr__(self, "checkpoint_hash", compute_canonical_hash(data))


class ConnectorHealth(BaseModel):
    """Operational health status (never a compliance score)."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    connector_id: str
    status: ConnectorStatus
    last_successful_collection: Optional[str] = None
    last_failure: Optional[str] = None
    records_processed: int = 0
    records_rejected: int = 0
    latency_ms: float = 0.0
    checkpoint_state: Optional[str] = None
    health_hash: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.health_hash:
            data = {
                "connector_id": self.connector_id,
                "status": self.status.value,
                "records_processed": self.records_processed,
                "records_rejected": self.records_rejected,
            }
            object.__setattr__(self, "health_hash", compute_canonical_hash(data))


class ConnectorResourceLimits(BaseModel):
    """Resource boundaries and rate limits for connector collection."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_records_per_batch: int = 1000
    max_payload_size_bytes: int = 10 * 1024 * 1024  # 10 MB
    max_pages: int = 50
    max_runtime_budget_seconds: float = 300.0
    max_error_records: int = 100
    max_retries: int = 3


class ConnectorAuditRecord(BaseModel):
    """Immutable audit trail for every connector collection/normalization pass."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_id: str
    connector_id: str
    operation: str
    organization_id: str
    started_at: str
    completed_at: str
    record_count: int
    success_count: int
    failure_count: int
    error_categories: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    audit_hash: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.audit_hash:
            data = {
                "audit_id": self.audit_id,
                "connector_id": self.connector_id,
                "operation": self.operation,
                "organization_id": self.organization_id,
                "record_count": self.record_count,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "error_categories": sorted(self.error_categories),
            }
            object.__setattr__(self, "audit_hash", compute_canonical_hash(data))


class ConnectorReadiness(BaseModel):
    """Production readiness assessment for a connector implementation."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    connector_id: str
    supported_capabilities: List[str]
    canonical_types: List[str]
    entity_resolution_status: str
    scope_support: bool
    provenance_support: bool
    checkpoint_support: bool
    idempotency_support: bool
    secret_safety: bool
    contract_test_status: str
