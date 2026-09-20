"""Phase 33-A: Production Connector Architecture - Provenance Engine (Section 14 & 15).

Ensures complete, cryptographic, immutable provenance for every normalized record:
- connector_id
- source_system
- source_version
- source_record_id
- source_event_time
- collection_batch_id
- source_locator
- payload_hash
- normalization_version
- organization_id
- scope
- authority (strictly NON_AUTHORITATIVE)

Deterministic provenance hash changes if any source attribute or mapping changes.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, Optional

from secgrc.compliance.models import ProvenanceRecord
from secgrc.connectors.errors import ProvenanceInvalidError
from secgrc.connectors.models import RawSourceRecord, compute_canonical_hash


class ConnectorProvenanceBuilder:
    """Constructs and validates cryptographic provenance envelopes for connector records."""

    @staticmethod
    def build_provenance(
        raw_record: RawSourceRecord,
        mapping_version: str = "1.0",
        normalization_version: str = "1.0",
        organization_id: Optional[str] = None,
        scope: str = "GLOBAL",
    ) -> Dict[str, Any]:
        """Derives a complete, immutable provenance dictionary from a raw source record."""
        org_id = organization_id or raw_record.organization_ref
        if not org_id or not org_id.strip():
            raise ProvenanceInvalidError("organization_id must be present for provenance", raw_record.connector_id)

        prov_payload = {
            "connector_id": raw_record.connector_id,
            "source_system": raw_record.source_system,
            "source_version": raw_record.source_version,
            "source_record_id": raw_record.record_id,
            "source_event_time": raw_record.source_event_time,
            "collection_batch_id": raw_record.collection_batch_id,
            "source_locator": raw_record.source_locator,
            "payload_hash": raw_record.payload_hash,
            "mapping_version": mapping_version,
            "normalization_version": normalization_version,
            "organization_id": org_id,
            "scope": scope,
            "authority": "NON_AUTHORITATIVE",
        }
        prov_hash = compute_canonical_hash(prov_payload)
        prov_payload["provenance_hash"] = prov_hash
        return prov_payload

    @staticmethod
    def to_canonical_provenance_record(prov_dict: Dict[str, Any]) -> ProvenanceRecord:
        """Converts connector provenance dictionary to compliance model ProvenanceRecord."""
        # Validate mandatory keys
        for key in ("source_system", "source_record_id", "source_event_time", "payload_hash"):
            if key not in prov_dict or not prov_dict[key]:
                raise ProvenanceInvalidError(f"Missing required provenance field: {key}")

        return ProvenanceRecord(
            source_system=prov_dict["source_system"],
            source_record_id=prov_dict["source_record_id"],
            source_document=prov_dict.get("source_locator") or None,
            source_timestamp=prov_dict["source_event_time"],
            source_hash=prov_dict["payload_hash"],
            schema_version="1.0",
            transform_version=prov_dict.get("normalization_version", "1.0"),
        )

    @staticmethod
    def verify_provenance_integrity(prov_dict: Dict[str, Any]) -> bool:
        """Verifies provenance dictionary hasn't been stripped or tampered with."""
        if prov_dict.get("authority") != "NON_AUTHORITATIVE":
            return False

        stored_hash = prov_dict.get("provenance_hash")
        if not stored_hash:
            return False

        copy_dict = dict(prov_dict)
        copy_dict.pop("provenance_hash", None)
        expected_hash = compute_canonical_hash(copy_dict)
        return stored_hash == expected_hash
