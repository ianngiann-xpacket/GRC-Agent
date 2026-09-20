"""Step 33-C: Connector & Prowler Evidence Sufficiency Bridge.

Bridges raw connector findings and normalized security data into decomposed
evidence streams (Current State, Historical Observations, Changes, Exceptions).

CRITICAL INVARIANTS:
1. Prowler FAIL != Compliance FAIL
2. Missing Evidence != Compliance FAIL
3. Connector captures observations; Policy Engine determines sufficiency; Assessment Engine determines compliance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from secgrc.compliance.models import (
    CanonicalDataType,
    CanonicalSecurityData,
    ClassificationLevel,
    EntityReference,
    ProvenanceRecord,
)


class EvidenceSufficiencyBridge:
    """Adapts connector output (Prowler, SIEM, IAM, etc.) into sufficiency observation streams."""

    @classmethod
    def adapt_prowler_findings(
        cls,
        findings: List[Dict[str, Any]],
        tenant_id: str = "DEFAULT_TENANT",
        scope_id: str = "GLOBAL",
    ) -> List[CanonicalSecurityData]:
        """Converts raw Prowler findings into CanonicalSecurityData for sufficiency evaluation.

        CRITICAL INVARIANT:
        Prowler's finding status (PASS/FAIL/MANUAL) represents the cloud configuration posture,
        NOT an evidence validity failure. A Prowler 'FAIL' is a valid, sufficient observation record!
        """
        records: List[CanonicalSecurityData] = []
        for idx, f in enumerate(findings):
            # Extract timestamp
            ts = f.get("timestamp") or f.get("observed_at") or f.get("Time") or datetime.now(timezone.utc).isoformat()
            check_id = f.get("check_id") or f.get("CheckID") or f.get("check") or "prowler_check"
            service = f.get("service") or f.get("ServiceName") or "cloud"
            status = str(f.get("status") or f.get("Status") or "UNKNOWN").upper()
            resource_id = f.get("resource_id") or f.get("ResourceID") or f"res-{idx}"

            rec = CanonicalSecurityData(
                record_id=f"CANON-PROWLER-{idx:05d}",
                data_type=CanonicalDataType.SECURITY_CONFIGURATION,
                source_system="PROWLER",
                source_record_id=resource_id,
                observed_at=ts,
                tenant_id=tenant_id,
                scope=scope_id,
                classification=ClassificationLevel.INTERNAL,
                entity_references=[
                    EntityReference(
                        entity_type="GCP_RESOURCE",
                        entity_id=resource_id,
                    )
                ],
                payload={
                    "check_id": check_id,
                    "service": service,
                    "posture_status": status,  # Posture only; NOT evidence failure
                    "severity": f.get("severity") or f.get("Severity") or "MEDIUM",
                    "resource_name": resource_id,
                    "project_id": f.get("project_id") or f.get("ProjectID") or "",
                    "event_type": f.get("event_type") or "",
                },
                provenance=ProvenanceRecord(
                    source_system="PROWLER",
                    source_record_id=resource_id,
                    source_timestamp=ts,
                    source_hash=f.get("finding_hash") or f"hash-{idx:05d}",
                ),
                integrity_hash=f.get("finding_hash") or f"hash-{idx:05d}",
            )
            records.append(rec)

        return records

    @classmethod
    def decompose_stream(
        cls,
        records: List[CanonicalSecurityData],
        material_change_types: Optional[List[str]] = None,
    ) -> Dict[str, List[CanonicalSecurityData]]:
        """Decomposes evidence records into 4 observation streams:

        - current_state: latest snapshot per entity
        - historical: all chronological observations
        - changes: material configuration alteration records
        - exceptions: non-compliant or high-severity anomaly observations
        """
        change_types = set(t.lower() for t in (material_change_types or ["CHANGE_DETECTED", "MUTATION", "POLICY_UPDATE"]))

        # Sort by timestamp ascending
        sorted_recs = sorted(records, key=lambda r: r.observed_at)

        # 1. Current state: map by entity canonical_identifier, keep latest
        entity_latest: Dict[str, CanonicalSecurityData] = {}
        for r in sorted_recs:
            ent_key = r.entity_references[0].entity_id if r.entity_references else r.record_id
            entity_latest[ent_key] = r

        current_state = list(entity_latest.values())
        historical = sorted_recs

        # 2. Changes
        changes = []
        for r in sorted_recs:
            dt_type = str(r.payload.get("event_type") or r.data_type.value).lower()
            if any(ct in dt_type for ct in change_types):
                changes.append(r)

        # 3. Exceptions (e.g. status FAIL or severity HIGH/CRITICAL)
        exceptions = []
        for r in sorted_recs:
            posture = str(r.payload.get("posture_status", "")).upper()
            sev = str(r.payload.get("severity", "")).upper()
            if posture in ("FAIL", "NON_COMPLIANT") or sev in ("HIGH", "CRITICAL"):
                exceptions.append(r)

        return {
            "current_state": current_state,
            "historical": historical,
            "changes": changes,
            "exceptions": exceptions,
        }
