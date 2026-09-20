"""Step 33-D: GCP Asset / Entity Resolution & Evidence Integration Models (Sections 4, 6, 8, 18).

Defines deterministic models for:
- Canonical GCP Resource Identity
- Entity Resolution Status & Confidence Class (Never LLM)
- Entity Resolution Result with cryptographic SHA-256 resolution_hash
- Queryable 10-Stage Evidence-to-Entity Lineage Record
"""

from __future__ import annotations

from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import ConfigDict, Field, field_validator

from secgrc.compliance.models import ComplianceBaseModel, validate_identifier


# ==============================================================================
# Enums
# ==============================================================================

class EntityResolutionStatus(str, Enum):
    """Deterministic status of an entity resolution operation (Section 8)."""
    EXACT_MATCH = "EXACT_MATCH"
    ALIAS_MATCH = "ALIAS_MATCH"
    NO_MATCH = "NO_MATCH"
    AMBIGUOUS_MATCH = "AMBIGUOUS_MATCH"
    WRONG_SCOPE = "WRONG_SCOPE"
    CROSS_TENANT = "CROSS_TENANT"
    INVALID_IDENTITY = "INVALID_IDENTITY"
    ORPHAN_SOURCE = "ORPHAN_SOURCE"
    UNSUPPORTED_RESOURCE = "UNSUPPORTED_RESOURCE"
    CONFLICTING_IDENTITY = "CONFLICTING_IDENTITY"


class ResolutionConfidenceClass(str, Enum):
    """Descriptive confidence class derived strictly from deterministic match rules.

    CRITICAL INVARIANT:
    This must NEVER mean LLM confidence or fuzzy score.
    """
    AUTHORITATIVE_EXACT = "AUTHORITATIVE_EXACT"
    REGISTERED_ALIAS = "REGISTERED_ALIAS"
    DETERMINISTIC_COMPOSITE = "DETERMINISTIC_COMPOSITE"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


class MatchMethod(str, Enum):
    """The deterministic matching rule that yielded the match."""
    FULL_RESOURCE_NAME = "FULL_RESOURCE_NAME"
    SELF_LINK = "SELF_LINK"
    COMPOSITE_KEY = "COMPOSITE_KEY"
    CANONICAL_RESOURCE_KEY = "CANONICAL_RESOURCE_KEY"
    REGISTERED_ALIAS = "REGISTERED_ALIAS"
    NONE = "NONE"


# ==============================================================================
# Canonical Key Helper
# ==============================================================================

def compute_canonical_resource_key(
    project_id: Optional[str],
    resource_type: Optional[str],
    normalized_resource_id: Optional[str],
) -> str:
    """Computes deterministic canonical resource key: gcp:<project_id>:<resource_type>:<normalized_id>.

    Example: gcp:prod-kr-001:storage_bucket:prod-data-archive
    """
    proj = (project_id or "unknown-project").strip().lower()
    rtype = (resource_type or "resource").strip().lower().replace(" ", "_")
    rid = (normalized_resource_id or "unknown-resource").strip()
    return f"gcp:{proj}:{rtype}:{rid}"


# ==============================================================================
# Canonical GCP Resource Identity
# ==============================================================================

class GCPResourceIdentity(ComplianceBaseModel):
    """Canonical representation of a GCP cloud resource identity (Section 4)."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    cloud_provider: str = Field(default="GCP", description="Cloud provider (always GCP)")
    organization_id: Optional[str] = Field(default=None, description="GCP Organization ID (numeric)")
    folder_id: Optional[str] = Field(default=None, description="GCP Folder ID if in folder")
    project_id: Optional[str] = Field(default=None, description="GCP Project string ID")
    project_number: Optional[str] = Field(default=None, description="GCP Project numeric number")
    service: Optional[str] = Field(default=None, description="GCP service name (e.g. compute, storage)")
    resource_type: Optional[str] = Field(default=None, description="Standardized resource type (e.g. bucket, instance)")
    resource_id: Optional[str] = Field(default=None, description="Specific resource identifier")
    resource_name: Optional[str] = Field(default=None, description="Human/short resource name")
    full_resource_name: Optional[str] = Field(default=None, description="//service.googleapis.com/... URI")
    region: Optional[str] = Field(default=None, description="GCP region (e.g. asia-northeast3)")
    zone: Optional[str] = Field(default=None, description="GCP zone (e.g. asia-northeast3-a)")
    location: Optional[str] = Field(default=None, description="Generic location (region, zone, or global)")
    asset_uri: Optional[str] = Field(default=None, description="Cloud Asset Inventory asset URI")
    self_link: Optional[str] = Field(default=None, description="GCP API self-link URL")
    canonical_resource_key: Optional[str] = Field(default=None, description="Deterministic gcp:proj:type:id key")
    source_account_id: Optional[str] = Field(default=None, description="Internal cloud account reference if pre-linked")


# ==============================================================================
# Hashing Helpers
# ==============================================================================

def compute_resolution_hash(data: Dict[str, Any]) -> str:
    """Computes SHA-256 hash over deterministic semantic resolution fields."""
    semantic = {
        "resolution_id": data.get("resolution_id"),
        "source_record_id": data.get("source_record_id"),
        "source_resource_identity": data.get("source_resource_identity"),
        "matched_entity_id": data.get("matched_entity_id"),
        "matched_entity_type": data.get("matched_entity_type"),
        "status": str(data.get("status")),
        "match_method": str(data.get("match_method")),
        "confidence_class": str(data.get("confidence_class")),
        "candidate_entity_ids": sorted(data.get("candidate_entity_ids") or []),
        "tenant_id": data.get("tenant_id"),
        "scope_id": data.get("scope_id"),
        "resolver_version": data.get("resolver_version"),
    }
    raw = json.dumps(semantic, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_lineage_hash(data: Dict[str, Any]) -> str:
    """Computes SHA-256 hash over deterministic 10-stage evidence lineage record."""
    semantic = {
        "lineage_id": data.get("lineage_id"),
        "requirement_id": data.get("requirement_id"),
        "evidence_requirement_id": data.get("evidence_requirement_id"),
        "plan_id": data.get("plan_id"),
        "connector_id": data.get("connector_id"),
        "run_id": data.get("run_id"),
        "source_record_id": data.get("source_record_id"),
        "canonical_record_id": data.get("canonical_record_id"),
        "resolution_id": data.get("resolution_id"),
        "matched_entity_id": data.get("matched_entity_id"),
        "canonical_resource_key": data.get("canonical_resource_key"),
        "scope_id": data.get("scope_id"),
        "tenant_id": data.get("tenant_id"),
        "resolution_status": str(data.get("resolution_status")),
    }
    raw = json.dumps(semantic, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ==============================================================================
# Resolution Result Model
# ==============================================================================

class EntityResolutionResult(ComplianceBaseModel):
    """Detailed result of resolving a GCP resource observation to an Enterprise Entity (Section 8)."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    resolution_id: str = Field(description="Unique deterministic resolution identifier")
    source_record_id: str = Field(description="Original source observation record ID")
    provider: str = Field(default="GCP", description="Cloud provider")
    source_resource_identity: str = Field(description="Raw source resource string")
    normalized_resource_identity: Optional[GCPResourceIdentity] = Field(default=None, description="Parsed GCP identity")
    matched_entity_id: Optional[str] = Field(default=None, description="Resolved Enterprise Entity ID")
    matched_entity_type: Optional[str] = Field(default=None, description="Resolved Enterprise Entity Type")
    status: EntityResolutionStatus = Field(description="Resolution outcome status")
    match_method: MatchMethod = Field(default=MatchMethod.NONE, description="Rule that matched")
    confidence_class: ResolutionConfidenceClass = Field(default=ResolutionConfidenceClass.UNRESOLVED)
    candidate_entity_ids: List[str] = Field(default_factory=list, description="All candidates if ambiguous")
    tenant_id: str = Field(description="Active organization/tenant context")
    scope_id: Optional[str] = Field(default=None, description="Compliance scope evaluated against")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="Provenance preservation")
    resolution_reason: str = Field(default="", description="Human-readable deterministic explanation")
    resolver_version: str = Field(default="1.0.0", description="Resolver component version")
    resolution_hash: str = Field(default="", description="Cryptographic SHA-256 result hash")

    @field_validator("resolution_id", "source_record_id")
    @classmethod
    def validate_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


# ==============================================================================
# Evidence-to-Entity Lineage Model
# ==============================================================================

class EvidenceEntityLineageRecord(ComplianceBaseModel):
    """Complete 10-stage queryable evidence lineage record (Section 18).

    Traces:
    Requirement -> Evidence Requirement -> Observation Plan -> Connector Run
    -> Raw Source Record -> Canonical Evidence -> Entity Resolution -> Enterprise Entity
    -> Compliance Scope -> Evidence Sufficiency
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    lineage_id: str = Field(description="Unique lineage identifier")
    requirement_id: Optional[str] = Field(default=None, description="Compliance requirement (e.g. ISMS-P-2.7.1)")
    evidence_requirement_id: Optional[str] = Field(default=None, description="Evidence requirement ID")
    plan_id: Optional[str] = Field(default=None, description="Evidence observation plan ID")
    connector_id: str = Field(default="prowler-gcp", description="Source connector ID")
    run_id: str = Field(description="Connector execution run ID")
    source_record_id: str = Field(description="Vendor observation record ID")
    canonical_record_id: str = Field(description="CanonicalSecurityData record ID")
    resolution_id: str = Field(description="Entity resolution ID")
    matched_entity_id: Optional[str] = Field(default=None, description="Matched enterprise entity ID")
    matched_entity_type: Optional[str] = Field(default=None, description="Matched enterprise entity type")
    canonical_resource_key: Optional[str] = Field(default=None, description="Deterministic canonical resource key")
    scope_id: str = Field(default="GLOBAL", description="Target compliance scope")
    tenant_id: str = Field(description="Tenant isolation context")
    resolution_status: EntityResolutionStatus = Field(description="Outcome of entity resolution")
    sufficiency_plan_hash: Optional[str] = Field(default=None, description="Hash of applied sufficiency plan")
    provenance_chain: List[Dict[str, Any]] = Field(default_factory=list, description="Preserved provenance envelopes")
    lineage_hash: str = Field(default="", description="SHA-256 lineage integrity hash")
    created_at: str = Field(description="ISO 8601 creation timestamp")

    @field_validator("lineage_id", "connector_id", "run_id", "canonical_record_id", "resolution_id")
    @classmethod
    def validate_lineage_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)
