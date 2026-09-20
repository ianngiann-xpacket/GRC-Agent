"""Nessus Vulnerability Scan Data Adapter (Step 23.5A).

Normalizes Nessus vulnerability scan findings into canonical
VULNERABILITY_FINDING records.
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


class NessusDataAdapter(BaseSecurityDataAdapter):
    """Nessus 취약점 진단 결과 전용 어댑터."""

    source_type: str = "Nessus"
    schema_version: str = "1.0"

    def detect(self, payload: Any) -> bool:
        if not payload:
            return False
        if isinstance(payload, dict):
            if "plugin_id" in payload or "plugin_name" in payload:
                return True
            if "items" in payload and isinstance(payload["items"], list):
                if len(payload["items"]) > 0 and isinstance(payload["items"][0], dict):
                    return "plugin_id" in payload["items"][0] or "plugin_name" in payload["items"][0]
            if "nessus" in str(payload).lower():
                return True
        if isinstance(payload, list) and len(payload) > 0 and isinstance(payload[0], dict):
            return "plugin_id" in payload[0] or "risk_factor" in payload[0]
        if isinstance(payload, str):
            lower = payload.lower()
            return "nessus" in lower or ("plugin_id" in lower and "cve" in lower)
        return False

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        self.check_payload_safety(payload)
        records: List[Dict[str, Any]] = []

        if isinstance(payload, dict):
            if "items" in payload and isinstance(payload["items"], list):
                for it in payload["items"]:
                    if isinstance(it, dict):
                        records.append(it)
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
            plugin_id = str(rec.get("plugin_id") or f"PLUGIN-{idx}").strip()
            plugin_name = str(rec.get("plugin_name") or "Unknown Vulnerability").strip()
            host = str(rec.get("host") or "unknown-host").strip()
            risk_factor = str(rec.get("risk_factor") or "Medium").upper()
            cve = str(rec.get("cve") or "")

            source_rec_id = f"{plugin_id}:{host}"
            rec_id = f"CANON-NESSUS-{plugin_id}-{idx:04d}"
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

            entity_refs = [
                EntityReference(entity_type="Asset", entity_id=f"ASSET-{host}"),
            ]
            if cve:
                entity_refs.append(EntityReference(entity_type="Vulnerability", entity_id=cve))

            payload_data = {
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "host": host,
                "risk_factor": risk_factor,
                "cve": cve,
                "cvss_score": float(rec.get("cvss_score") or 5.0),
                "synopsis": str(rec.get("synopsis") or ""),
                "solution": str(rec.get("solution") or ""),
            }

            integ_hash = CanonicalSecurityData.compute_integrity_hash(payload_data, provenance)

            canonical_data = CanonicalSecurityData(
                record_id=rec_id,
                data_type=CanonicalDataType.VULNERABILITY_FINDING,
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
