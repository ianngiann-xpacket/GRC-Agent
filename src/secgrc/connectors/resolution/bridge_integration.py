"""Step 33-D: EvidenceSufficiencyBridge Integration & 5-Dimension Evidence Validity (Sections 31 & 32).

Implements the integrated pipeline:
Prowler Observation -> Canonical Evidence -> Entity Resolution -> Scope Validation
-> Evidence-to-Entity Lineage -> EvidenceSufficiencyBridge -> Assessment Engine.

CRITICAL INVARIANTS:
1. Unresolved entities (NO_MATCH / ORPHAN / AMBIGUOUS) do NOT silently satisfy scoped requirements.
2. Distinct 5-dimension validity:
   - OBSERVATION_EXISTS
   - ENTITY_RESOLVED
   - SCOPE_VALID
   - PROVENANCE_VALID
   - SUFFICIENCY_VALID
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from secgrc.compliance.models import (
    CanonicalDataType,
    CanonicalSecurityData,
    ClassificationLevel,
    EntityReference,
    ProvenanceRecord,
)
from secgrc.compliance.sufficiency.bridge import EvidenceSufficiencyBridge
from secgrc.compliance.sufficiency.models import (
    DimensionStatus,
    EvidenceObservationPlan,
    EvidenceSufficiencyResult,
)
from secgrc.connectors.resolution.lineage import EvidenceLineageTracker
from secgrc.connectors.resolution.models import (
    EntityResolutionResult,
    EntityResolutionStatus,
    EvidenceEntityLineageRecord,
)
from secgrc.connectors.resolution.resolver import DeterministicGCPResolver


from secgrc.compliance.models import ComplianceBaseModel
from pydantic import ConfigDict, Field

class EvidenceValidityDimension(ComplianceBaseModel):
    """The 5 distinct dimensions of evidence validity (Section 32)."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_exists: DimensionStatus = DimensionStatus.PASS
    entity_resolved: DimensionStatus = DimensionStatus.FAIL
    scope_valid: DimensionStatus = DimensionStatus.FAIL
    provenance_valid: DimensionStatus = DimensionStatus.PASS
    sufficiency_valid: Optional[DimensionStatus] = None
    notes: List[str] = Field(default_factory=list)


class IntegratedResolutionOutput(ComplianceBaseModel):
    """Integrated output containing resolved canonical records, lineage, and 5-dimension metrics."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    canonical_records: List[CanonicalSecurityData]
    resolution_results: List[EntityResolutionResult]
    lineage_records: List[EvidenceEntityLineageRecord]
    validity_dimensions: Dict[str, EvidenceValidityDimension]
    total_findings: int
    resolved_count: int
    orphan_count: int
    ambiguous_count: int
    wrong_scope_count: int
    cross_tenant_count: int


class IntegratedEvidenceResolver:
    """Orchestrates Prowler observation ingestion, entity resolution, and sufficiency bridge."""

    @classmethod
    def process_prowler_findings(
        cls,
        findings: List[Dict[str, Any]],
        resolver: DeterministicGCPResolver,
        tenant_id: str,
        scope_id: str = "GLOBAL",
        run_id: str = "RUN-LOCAL-001",
        connector_id: str = "prowler-gcp",
        requirement_id: Optional[str] = None,
        evidence_requirement_id: Optional[str] = None,
        lineage_tracker: Optional[EvidenceLineageTracker] = None,
        filter_unresolved_for_sufficiency: bool = False,
    ) -> IntegratedResolutionOutput:
        """Processes raw Prowler findings through the complete 10-stage resolution pipeline."""
        tracker = lineage_tracker or EvidenceLineageTracker()

        canonical_records: List[CanonicalSecurityData] = []
        resolution_results: List[EntityResolutionResult] = []
        lineage_records: List[EvidenceEntityLineageRecord] = []
        validity_dims: Dict[str, EvidenceValidityDimension] = {}

        resolved_count = 0
        orphan_count = 0
        ambiguous_count = 0
        wrong_scope_count = 0
        cross_tenant_count = 0

        for idx, f in enumerate(findings):
            source_rec_id = f.get("resource_id") or f.get("ResourceID") or f"res-{idx:05d}"
            raw_locator = f.get("resource_name") or f.get("resource_id") or source_rec_id
            finding_hash = f.get("finding_hash") or f"hash-finding-{idx:05d}"
            ts = f.get("timestamp") or f.get("observed_at") or f.get("Time") or "2026-09-01T00:00:00Z"
            check_id = f.get("check_id") or f.get("CheckID") or "prowler_check"
            service = f.get("service") or f.get("ServiceName") or "cloud"
            status_posture = str(f.get("status") or f.get("Status") or "UNKNOWN").upper()
            project_id = f.get("project_id") or f.get("ProjectID")

            ctx = {
                "project_id": project_id,
                "service": service,
                "resource_type": f.get("resource_type"),
                "region": f.get("region"),
                "zone": f.get("zone"),
                "tenant_id": f.get("tenant_id") or tenant_id,
            }
            prov = {
                "source_system": "PROWLER",
                "source_record_id": source_rec_id,
                "source_timestamp": ts,
                "source_hash": finding_hash,
                "tenant_id": tenant_id,
            }

            # 1. Resolve Entity
            res_result = resolver.resolve(
                source_record_id=source_rec_id,
                source_resource_locator=raw_locator,
                tenant_id=tenant_id,
                target_scope_id=scope_id,
                context=ctx,
                provenance=prov,
            )
            resolution_results.append(res_result)

            # Track counters
            if res_result.status in (EntityResolutionStatus.EXACT_MATCH, EntityResolutionStatus.ALIAS_MATCH):
                resolved_count += 1
            elif res_result.status == EntityResolutionStatus.ORPHAN_SOURCE:
                orphan_count += 1
            elif res_result.status == EntityResolutionStatus.AMBIGUOUS_MATCH:
                ambiguous_count += 1
            elif res_result.status == EntityResolutionStatus.WRONG_SCOPE:
                wrong_scope_count += 1
            elif res_result.status == EntityResolutionStatus.CROSS_TENANT:
                cross_tenant_count += 1

            # 2. Build CanonicalSecurityData
            canon_rec_id = f"CANON-PROWLER-{idx:05d}"
            ent_refs: List[EntityReference] = []
            if res_result.matched_entity_id:
                ent_refs.append(
                    EntityReference(
                        entity_type=res_result.matched_entity_type or "GCP_RESOURCE",
                        entity_id=res_result.matched_entity_id,
                    )
                )
            else:
                # Retain original source resource identity without fabricating entity
                ent_refs.append(
                    EntityReference(
                        entity_type="UNRESOLVED_GCP_RESOURCE",
                        entity_id=source_rec_id,
                    )
                )

            canon_rec = CanonicalSecurityData(
                record_id=canon_rec_id,
                data_type=CanonicalDataType.SECURITY_CONFIGURATION,
                source_system="PROWLER",
                source_record_id=source_rec_id,
                observed_at=ts,
                tenant_id=tenant_id,
                scope=scope_id,
                classification=ClassificationLevel.INTERNAL,
                entity_references=ent_refs,
                payload={
                    "check_id": check_id,
                    "service": service,
                    "posture_status": status_posture,
                    "severity": f.get("severity") or f.get("Severity") or "MEDIUM",
                    "resource_name": raw_locator,
                    "project_id": project_id or "",
                    "event_type": f.get("event_type") or "",
                    "resolution_id": res_result.resolution_id,
                    "resolution_status": res_result.status.value,
                    "matched_entity_id": res_result.matched_entity_id or "",
                    "canonical_resource_key": (
                        res_result.normalized_resource_identity.canonical_resource_key
                        if res_result.normalized_resource_identity
                        else ""
                    ),
                },
                provenance=ProvenanceRecord(
                    source_system="PROWLER",
                    source_record_id=source_rec_id,
                    source_timestamp=ts,
                    source_hash=finding_hash,
                ),
                integrity_hash=finding_hash,
            )
            canonical_records.append(canon_rec)

            # 3. Record Lineage
            lin_rec = tracker.record_lineage(
                resolution_result=res_result,
                canonical_record_id=canon_rec_id,
                run_id=run_id,
                connector_id=connector_id,
                requirement_id=requirement_id,
                evidence_requirement_id=evidence_requirement_id,
            )
            lineage_records.append(lin_rec)

            # 4. Compute 5-Dimension Validity (Section 32)
            is_resolved = res_result.status in (EntityResolutionStatus.EXACT_MATCH, EntityResolutionStatus.ALIAS_MATCH)
            is_scope_valid = res_result.status not in (EntityResolutionStatus.WRONG_SCOPE, EntityResolutionStatus.CROSS_TENANT)

            validity_dims[canon_rec_id] = EvidenceValidityDimension(
                observation_exists=DimensionStatus.PASS,
                entity_resolved=DimensionStatus.PASS if is_resolved else DimensionStatus.FAIL,
                scope_valid=DimensionStatus.PASS if is_scope_valid else DimensionStatus.FAIL,
                provenance_valid=DimensionStatus.PASS,
                sufficiency_valid=None,
                notes=[res_result.resolution_reason],
            )

        return IntegratedResolutionOutput(
            canonical_records=canonical_records,
            resolution_results=resolution_results,
            lineage_records=lineage_records,
            validity_dimensions=validity_dims,
            total_findings=len(findings),
            resolved_count=resolved_count,
            orphan_count=orphan_count,
            ambiguous_count=ambiguous_count,
            wrong_scope_count=wrong_scope_count,
            cross_tenant_count=cross_tenant_count,
        )

    @classmethod
    def decompose_resolved_streams(
        cls,
        output: IntegratedResolutionOutput,
        strict_scope_only: bool = True,
    ) -> Dict[str, List[CanonicalSecurityData]]:
        """Decomposes canonical records into the 4 evidence streams.

        If strict_scope_only is True, unresolved, orphan, wrong-scope, and cross-tenant
        observations are excluded from current_state and historical streams,
        preventing unmapped observations from satisfying scoped requirements.
        """
        valid_records = []
        for rec in output.canonical_records:
            status_str = rec.payload.get("resolution_status")
            if strict_scope_only:
                if status_str in ("EXACT_MATCH", "ALIAS_MATCH"):
                    valid_records.append(rec)
            else:
                valid_records.append(rec)

        return EvidenceSufficiencyBridge.decompose_stream(valid_records)
