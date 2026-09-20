"""Phase 33-B: Prowler GCP Production Connector - Models and Invariants.

Defines immutable Pydantic models for Prowler GCP execution:
- ProwlerRuntimeConfig: Pinned Docker image, version, and digest
- GcpCredentialReference: Read-only credential reference (zero secrets persisted)
- ProwlerGcpTarget: Immutable GCP project & compliance scope targets
- ExecutionMode: PLAN, DRY_RUN, LIVE_READ_ONLY, REPLAY
- ProwlerRun: Operational run state excluding timestamps from semantic hash
- ProwlerRunManifest: Complete run manifest stored with raw & normalized artifacts
- ProwlerGcpMappingVersion: Explicit mapping versions
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from secgrc.connectors.models import compute_canonical_hash


class ExecutionMode(str, Enum):
    """Supported execution modes for Prowler GCP connector."""
    PLAN = "PLAN"
    DRY_RUN = "DRY_RUN"
    LIVE_READ_ONLY = "LIVE_READ_ONLY"
    REPLAY = "REPLAY"


class ProwlerGcpMappingVersion(str, Enum):
    """Immutable mapping version identifiers."""
    V1 = "prowler_gcp_mapping_v1"


class ProwlerRuntimeConfig(BaseModel):
    """Pinned Docker runtime configuration for Prowler execution."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    # GHCR의 prowler-cloud 패키지는 익명 pull이 차단됨 — Docker Hub의
    # prowlercloud/prowler는 버전 태그가 없어 digest로 고정한다 (태그보다 강한 고정).
    image: str = "prowlercloud/prowler@sha256:863beb094d8e526ffbbf8286d6f2a526db9455e173e1e99c2ea2802c637c7805"
    version: str = "5.43.0"
    digest: Optional[str] = "sha256:863beb094d8e526ffbbf8286d6f2a526db9455e173e1e99c2ea2802c637c7805"
    command: str = "prowler gcp"
    output_format: str = "json"  # json or json-ocsf
    connector_version: str = "1.0.0"

    @field_validator("image")
    @classmethod
    def validate_image_not_latest(cls, v: str) -> str:
        if ":latest" in v or v.endswith("prowler"):
            raise ValueError("Unpinned Prowler runtime ':latest' is strictly forbidden in production connector contract.")
        return v

    @field_validator("version")
    @classmethod
    def validate_version_not_latest(cls, v: str) -> str:
        if v.strip().lower() == "latest":
            raise ValueError("Prowler version 'latest' is forbidden. Version must be explicitly pinned.")
        return v

    @field_validator("output_format")
    @classmethod
    def validate_output_format(cls, v: str) -> str:
        if v.lower() not in ("json", "json-ocsf"):
            raise ValueError(f"Unsupported output format '{v}'. Only 'json' and 'json-ocsf' are supported.")
        return v.lower()


class GcpCredentialReference(BaseModel):
    """Read-only GCP credential reference without secret storage."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    credential_ref_id: str
    auth_mode: str  # ADC, SERVICE_ACCOUNT, WORKLOAD_IDENTITY
    project_ref: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("auth_mode")
    @classmethod
    def validate_auth_mode(cls, v: str) -> str:
        allowed = ("ADC", "SERVICE_ACCOUNT", "WORKLOAD_IDENTITY")
        if v.upper() not in allowed:
            raise ValueError(f"Invalid auth_mode '{v}'. Must be one of {allowed}")
        return v.upper()

    @field_validator("metadata")
    @classmethod
    def validate_no_secrets_in_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        forbidden_keys = (
            "password", "secret", "private_key", "private_key_id",
            "client_secret", "token", "access_token", "refresh_token",
            "key_data", "credential"
        )
        for k in v.keys():
            if any(f in k.lower() for f in forbidden_keys):
                raise ValueError(f"Direct secret key '{k}' forbidden in GcpCredentialReference metadata.")
        return v


class ProwlerGcpTarget(BaseModel):
    """Immutable scan target specification for GCP."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    organization_id: str
    tenant_id: str
    gcp_project_ids: List[str]
    billing_account_refs: List[str] = Field(default_factory=list)
    folder_refs: List[str] = Field(default_factory=list)
    organization_node_ref: Optional[str] = None
    region_scope: List[str] = Field(default_factory=list)
    compliance_scope_refs: List[str] = Field(default_factory=list)
    credential_ref: GcpCredentialReference
    target_hash: str = ""

    @field_validator("organization_id", "tenant_id")
    @classmethod
    def validate_non_empty_ids(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("organization_id and tenant_id cannot be empty")
        return v.strip()

    @field_validator("gcp_project_ids")
    @classmethod
    def validate_projects_non_empty(cls, v: List[str]) -> List[str]:
        if not v or any(not p.strip() for p in v):
            raise ValueError("gcp_project_ids must contain at least one non-empty project ID. Implicit scanning forbidden.")
        return [p.strip() for p in v]

    def model_post_init(self, __context: Any) -> None:
        if not self.target_hash:
            data = {
                "organization_id": self.organization_id,
                "tenant_id": self.tenant_id,
                "gcp_project_ids": sorted(self.gcp_project_ids),
                "billing_account_refs": sorted(self.billing_account_refs),
                "folder_refs": sorted(self.folder_refs),
                "organization_node_ref": self.organization_node_ref,
                "region_scope": sorted(self.region_scope),
                "compliance_scope_refs": sorted(self.compliance_scope_refs),
                "credential_ref_id": self.credential_ref.credential_ref_id,
            }
            object.__setattr__(self, "target_hash", compute_canonical_hash(data))


class ProwlerRun(BaseModel):
    """Tracks execution of a Prowler scan."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    connector_id: str = "conn-prowler-gcp"
    organization_id: str
    target_hash: str
    prowler_version: str
    runtime_image: str
    command_hash: str
    started_at: str
    completed_at: Optional[str] = None
    exit_code: int = 0
    output_format: str = "json"
    output_path: str = ""
    raw_output_hash: str = ""
    record_count: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED
    provenance: Dict[str, Any] = Field(default_factory=dict)
    run_hash: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.run_hash:
            # Operational timestamps started_at and completed_at are EXCLUDED from semantic run_hash
            semantic_data = {
                "run_id": self.run_id,
                "connector_id": self.connector_id,
                "organization_id": self.organization_id,
                "target_hash": self.target_hash,
                "prowler_version": self.prowler_version,
                "runtime_image": self.runtime_image,
                "command_hash": self.command_hash,
                "exit_code": self.exit_code,
                "output_format": self.output_format,
                "raw_output_hash": self.raw_output_hash,
                "record_count": self.record_count,
                "accepted_count": self.accepted_count,
                "rejected_count": self.rejected_count,
                "status": self.status,
            }
            object.__setattr__(self, "run_hash", compute_canonical_hash(semantic_data))


class ProwlerRunManifest(BaseModel):
    """Manifest describing completed run and generated artifact hashes."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    connector_id: str = "conn-prowler-gcp"
    organization_id: str
    project_refs: List[str]
    prowler_version: str
    runtime_image: str
    output_format: str
    raw_output_hash: str
    normalized_output_hash: str
    record_count: int
    accepted_count: int
    rejected_count: int
    mapping_version: str
    connector_version: str
    generated_at: str
    manifest_hash: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.manifest_hash:
            # generated_at excluded from semantic manifest hash
            semantic_data = {
                "run_id": self.run_id,
                "connector_id": self.connector_id,
                "organization_id": self.organization_id,
                "project_refs": sorted(self.project_refs),
                "prowler_version": self.prowler_version,
                "runtime_image": self.runtime_image,
                "output_format": self.output_format,
                "raw_output_hash": self.raw_output_hash,
                "normalized_output_hash": self.normalized_output_hash,
                "record_count": self.record_count,
                "accepted_count": self.accepted_count,
                "rejected_count": self.rejected_count,
                "mapping_version": self.mapping_version,
                "connector_version": self.connector_version,
            }
            object.__setattr__(self, "manifest_hash", compute_canonical_hash(semantic_data))
