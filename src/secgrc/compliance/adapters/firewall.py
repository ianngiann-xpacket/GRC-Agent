"""Firewall Policy & Rule Data Adapter (Step 23.5A).

Normalizes Network and Cloud Firewall Rules into canonical
FIREWALL_RULE and FIREWALL_POLICY records.
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


class FirewallPolicyDataAdapter(BaseSecurityDataAdapter):
    """방화벽 정책 및 룰셋 전용 어댑터."""

    source_type: str = "Firewall"
    schema_version: str = "1.0"

    def detect(self, payload: Any) -> bool:
        if not payload:
            return False
        if isinstance(payload, dict):
            if "rule_id" in payload or "destination_ports" in payload:
                return True
            if "rules" in payload and isinstance(payload["rules"], list):
                if len(payload["rules"]) > 0 and isinstance(payload["rules"][0], dict):
                    return "rule_id" in payload["rules"][0] or "action" in payload["rules"][0]
            if "firewall" in str(payload).lower():
                return True
        if isinstance(payload, list) and len(payload) > 0 and isinstance(payload[0], dict):
            return "rule_id" in payload[0] or "action" in payload[0]
        if isinstance(payload, str):
            lower = payload.lower()
            return "firewall" in lower or ("rule_id" in lower and "direction" in lower)
        return False

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        self.check_payload_safety(payload)
        records: List[Dict[str, Any]] = []

        if isinstance(payload, dict):
            if "rules" in payload and isinstance(payload["rules"], list):
                for r in payload["rules"]:
                    if isinstance(r, dict):
                        records.append(r)
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
            rule_id = str(rec.get("rule_id") or rec.get("id") or f"FW-RULE-{idx}").strip()
            action = str(rec.get("action") or "ALLOW").upper()
            direction = str(rec.get("direction") or "INGRESS").upper()
            dest_ports = rec.get("destination_ports") or ["all"]
            if isinstance(dest_ports, str):
                dest_ports = [dest_ports]

            source_rec_id = rule_id
            rec_id = f"CANON-FW-{rule_id}-{idx:04d}"
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
                EntityReference(entity_type="SecurityDevice", entity_id="DEV-FIREWALL-MAIN"),
            ]

            payload_data = {
                "rule_id": rule_id,
                "action": action,
                "direction": direction,
                "destination_ports": dest_ports,
                "source_ranges": rec.get("source_ranges") or ["0.0.0.0/0"],
                "destination_ranges": rec.get("destination_ranges") or [],
                "priority": int(rec.get("priority") or 1000),
                "description": str(rec.get("description") or ""),
            }

            integ_hash = CanonicalSecurityData.compute_integrity_hash(payload_data, provenance)

            canonical_data = CanonicalSecurityData(
                record_id=rec_id,
                data_type=CanonicalDataType.FIREWALL_RULE,
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
