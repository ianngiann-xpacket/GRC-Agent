"""Step 33-D: Evidence-to-Entity Lineage Tracker & Query API (Section 18).

Provides end-to-end queryable lineage across the 10-stage chain:
Requirement -> Evidence Requirement -> Observation Plan -> Connector Run
-> Raw Source Record -> Canonical Evidence -> Entity Resolution -> Enterprise Entity
-> Scope -> Evidence Sufficiency -> Assessment Engine.

Answers all 9 mandatory architectural questions per Section 18.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional

from secgrc.connectors.resolution.models import (
    EntityResolutionResult,
    EvidenceEntityLineageRecord,
    compute_lineage_hash,
)


class EvidenceLineageTracker:
    """Thread-safe queryable store for 10-stage evidence-to-entity lineage records."""

    def __init__(self) -> None:
        # lineage_id -> EvidenceEntityLineageRecord
        self._records_by_id: Dict[str, EvidenceEntityLineageRecord] = {}
        # canonical_record_id -> list of lineage_ids
        self._by_canonical: Dict[str, List[str]] = {}
        # matched_entity_id -> list of lineage_ids
        self._by_entity: Dict[str, List[str]] = {}
        # requirement_id -> list of lineage_ids
        self._by_requirement: Dict[str, List[str]] = {}
        # run_id -> list of lineage_ids
        self._by_run: Dict[str, List[str]] = {}

    def record_lineage(
        self,
        resolution_result: EntityResolutionResult,
        canonical_record_id: str,
        run_id: str,
        connector_id: str = "prowler-gcp",
        requirement_id: Optional[str] = None,
        evidence_requirement_id: Optional[str] = None,
        plan_id: Optional[str] = None,
        sufficiency_plan_hash: Optional[str] = None,
        provenance_chain: Optional[List[Dict[str, Any]]] = None,
    ) -> EvidenceEntityLineageRecord:
        """Constructs, validates, and indexes an EvidenceEntityLineageRecord."""
        res = resolution_result
        now_ts = datetime.now(timezone.utc).isoformat()
        h_base = f"{res.resolution_id}:{canonical_record_id}:{run_id}:{now_ts}"
        lid = f"LIN-{canonical_record_id[:16]}-{hashlib.sha256(h_base.encode('utf-8')).hexdigest()[:12]}"

        raw_data = {
            "lineage_id": lid,
            "requirement_id": requirement_id,
            "evidence_requirement_id": evidence_requirement_id,
            "plan_id": plan_id,
            "connector_id": connector_id,
            "run_id": run_id,
            "source_record_id": res.source_record_id,
            "canonical_record_id": canonical_record_id,
            "resolution_id": res.resolution_id,
            "matched_entity_id": res.matched_entity_id,
            "canonical_resource_key": (
                res.normalized_resource_identity.canonical_resource_key
                if res.normalized_resource_identity
                else None
            ),
            "scope_id": res.scope_id or "GLOBAL",
            "tenant_id": res.tenant_id,
            "resolution_status": res.status.value,
        }
        l_hash = compute_lineage_hash(raw_data)

        # Build preserved provenance chain
        chain = list(provenance_chain or [])
        if res.provenance:
            chain.append(res.provenance)

        record = EvidenceEntityLineageRecord(
            lineage_id=lid,
            requirement_id=requirement_id,
            evidence_requirement_id=evidence_requirement_id,
            plan_id=plan_id,
            connector_id=connector_id,
            run_id=run_id,
            source_record_id=res.source_record_id,
            canonical_record_id=canonical_record_id,
            resolution_id=res.resolution_id,
            matched_entity_id=res.matched_entity_id,
            matched_entity_type=res.matched_entity_type,
            canonical_resource_key=raw_data["canonical_resource_key"],
            scope_id=res.scope_id or "GLOBAL",
            tenant_id=res.tenant_id,
            resolution_status=res.status,
            sufficiency_plan_hash=sufficiency_plan_hash,
            provenance_chain=chain,
            lineage_hash=l_hash,
            created_at=now_ts,
        )

        self._records_by_id[lid] = record
        self._by_canonical.setdefault(canonical_record_id, []).append(lid)
        if res.matched_entity_id:
            self._by_entity.setdefault(res.matched_entity_id, []).append(lid)
        if requirement_id:
            self._by_requirement.setdefault(requirement_id, []).append(lid)
        self._by_run.setdefault(run_id, []).append(lid)

        return record

    # --------------------------------------------------------------------------
    # Query API (Answers the 9 Questions from Section 18)
    # --------------------------------------------------------------------------

    def get_lineage(self, lineage_id: str) -> Optional[EvidenceEntityLineageRecord]:
        return self._records_by_id.get(lineage_id)

    def find_by_canonical_record(self, canonical_record_id: str) -> List[EvidenceEntityLineageRecord]:
        lids = self._by_canonical.get(canonical_record_id, [])
        return [self._records_by_id[lid] for lid in lids if lid in self._records_by_id]

    def find_by_entity(self, entity_id: str) -> List[EvidenceEntityLineageRecord]:
        lids = self._by_entity.get(entity_id, [])
        return [self._records_by_id[lid] for lid in lids if lid in self._records_by_id]

    def find_by_requirement(self, requirement_id: str) -> List[EvidenceEntityLineageRecord]:
        lids = self._by_requirement.get(requirement_id, [])
        return [self._records_by_id[lid] for lid in lids if lid in self._records_by_id]

    def find_by_run(self, run_id: str) -> List[EvidenceEntityLineageRecord]:
        lids = self._by_run.get(run_id, [])
        return [self._records_by_id[lid] for lid in lids if lid in self._records_by_id]

    def trace_evidence(self, canonical_record_id: str) -> Optional[Dict[str, Any]]:
        """Answers all 9 mandatory lineage questions for a canonical evidence record (Section 18)."""
        recs = self.find_by_canonical_record(canonical_record_id)
        if not recs:
            return None
        rec = recs[0]

        return {
            "canonical_record_id": rec.canonical_record_id,
            # Q1: Which requirement requested this evidence?
            "requested_requirement_id": rec.requirement_id or "NONE_SPECIFIED",
            # Q2: Which evidence requirement generated the observation?
            "evidence_requirement_id": rec.evidence_requirement_id or "DIRECT_OBSERVATION",
            # Q3: Which connector produced it?
            "connector_id": rec.connector_id,
            # Q4: Which Prowler run produced it?
            "prowler_run_id": rec.run_id,
            # Q5: What was the original source identity?
            "source_record_id": rec.source_record_id,
            "canonical_resource_key": rec.canonical_resource_key,
            # Q6: Which enterprise entity was matched?
            "matched_entity_id": rec.matched_entity_id or "UNRESOLVED",
            "matched_entity_type": rec.matched_entity_type or "UNRESOLVED",
            # Q7: How was it matched? (Resolution Status)
            "resolution_status": rec.resolution_status.value,
            # Q8: Which scope owns it?
            "scope_id": rec.scope_id,
            "tenant_id": rec.tenant_id,
            # Q9: What evidence sufficiency plan applied?
            "sufficiency_plan_hash": rec.sufficiency_plan_hash or "NOT_APPLIED",
            # Q10: What was the provenance chain?
            "provenance_chain_length": len(rec.provenance_chain),
            "provenance_chain": rec.provenance_chain,
            "lineage_hash": rec.lineage_hash,
        }
