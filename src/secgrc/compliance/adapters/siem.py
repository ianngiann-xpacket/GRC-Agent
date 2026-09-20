"""SIEM Security Event & Alert Data Adapter (Step 23.5A).

Normalizes SIEM security monitoring alerts and detection events
into canonical ALERT and SECURITY_EVENT records.
"""

import json
from typing import Any, Dict, List

from secgrc.compliance.adapters.base import BaseSecurityDataAdapter
from secgrc.compliance.models import (
    CanonicalDataType,
    CanonicalSecurityData,
    ClassificationLevel,
    EntityReference,
    ProvenanceRecord,
)


class SIEMEventDataAdapter(BaseSecurityDataAdapter):
    """SIEM 보안 관제 이벤트 및 경보 전용 어댑터."""

    source_type: str = "SIEM"
    schema_version: str = "1.0"

    def detect(self, payload: Any) -> bool:
        if not payload:
            return False
        if isinstance(payload, dict):
            return "alert_id" in payload or "event_type" in payload or "siem" in str(payload).lower()
        if isinstance(payload, list) and len(payload) > 0 and isinstance(payload[0], dict):
            return "alert_id" in payload[0] or "event_type" in payload[0]
        if isinstance(payload, str):
            lower = payload.lower()
            return "siem" in lower or ("alert_id" in lower and "severity" in lower)
        return False

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        self.check_payload_safety(payload)
        records: List[Dict[str, Any]] = []

        if isinstance(payload, dict):
            if "alerts" in payload and isinstance(payload["alerts"], list):
                for a in payload["alerts"]:
                    if isinstance(a, dict):
                        records.append(a)
            else:
                records.append(payload)
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    records.append(item)
        elif isinstance(payload, str):
            clean = payload.strip()
            if clean.startswith("{") or clean.startswith("["):
                return self.parse(json.loads(clean))

        return records

    def normalize(
        self,
        records: List[Dict[str, Any]],
        tenant_id: str = "default",
        scope: str = "GLOBAL",
    ) -> List[CanonicalSecurityData]:
        canonical_list: List[CanonicalSecurityData] = []

        for idx, rec in enumerate(records, 1):
            alert_id = str(rec.get("alert_id") or rec.get("id") or f"SIEM-ALT-{idx}").strip()
            event_type = str(rec.get("event_type") or "SecurityAlert").strip()
            severity = str(rec.get("severity") or "MEDIUM").upper()

            source_rec_id = alert_id
            rec_id = f"CANON-SIEM-{alert_id}-{idx:04d}"
            source_hash = self.compute_hash(rec)
            observed_at = self.safe_timestamp(rec.get("timestamp"))

            provenance = ProvenanceRecord(
                source_system=self.source_type,
                source_record_id=source_rec_id,
                source_timestamp=observed_at,
                source_hash=source_hash,
                schema_version=self.schema_version,
                transform_version="1.0",
            )

            entity_refs = []
            if "host" in rec:
                entity_refs.append(EntityReference(entity_type="Asset", entity_id=f"ASSET-{rec['host']}"))

            payload_data = {
                "alert_id": alert_id,
                "event_type": event_type,
                "severity": severity,
                "source_ip": str(rec.get("source_ip") or ""),
                "destination_ip": str(rec.get("destination_ip") or ""),
                "user": str(rec.get("user") or ""),
                "raw_message": str(rec.get("raw_message") or rec.get("message") or ""),
            }

            integ_hash = CanonicalSecurityData.compute_integrity_hash(payload_data, provenance)

            canonical_data = CanonicalSecurityData(
                record_id=rec_id,
                data_type=CanonicalDataType.ALERT,
                source_system=self.source_type,
                source_record_id=source_rec_id,
                observed_at=observed_at,
                tenant_id=tenant_id,
                scope=scope,
                entity_references=entity_refs,
                payload=payload_data,
                provenance=provenance,
                classification=ClassificationLevel.INTERNAL,
                integrity_hash=integ_hash,
                schema_version=self.schema_version,
            )
            canonical_list.append(canonical_data)

        return canonical_list
