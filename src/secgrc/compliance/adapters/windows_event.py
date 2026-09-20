"""Windows Event Log Data Adapter (Step 23.5A).

Normalizes Windows Security Event Logs (e.g. EventID 4624 Logon, 4625 Failed Logon)
into canonical SECURITY_LOG and AUTHENTICATION_CONFIGURATION records.
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


class WindowsEventDataAdapter(BaseSecurityDataAdapter):
    """Windows 보안 이벤트 로그 전용 어댑터."""

    source_type: str = "WindowsEvent"
    schema_version: str = "1.0"

    def detect(self, payload: Any) -> bool:
        if not payload:
            return False
        if isinstance(payload, dict):
            if "event_id" in payload or "EventID" in payload:
                return True
            if "events" in payload and isinstance(payload["events"], list):
                if len(payload["events"]) > 0 and isinstance(payload["events"][0], dict):
                    return "event_id" in payload["events"][0] or "EventID" in payload["events"][0]
            if "winlog" in str(payload).lower() or "windowsevent" in str(payload).lower():
                return True
        if isinstance(payload, list) and len(payload) > 0 and isinstance(payload[0], dict):
            return "event_id" in payload[0] or "EventID" in payload[0]
        if isinstance(payload, str):
            lower = payload.lower()
            return "eventid" in lower or "event_id" in lower or "windowsevent" in lower
        return False

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        self.check_payload_safety(payload)
        records: List[Dict[str, Any]] = []

        if isinstance(payload, dict):
            if "events" in payload and isinstance(payload["events"], list):
                for ev in payload["events"]:
                    if isinstance(ev, dict):
                        records.append(ev)
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
            event_id = int(rec.get("event_id") or rec.get("EventID") or 4624)
            provider = str(rec.get("provider_name") or rec.get("Provider") or "Microsoft-Windows-Security-Auditing").strip()
            computer = str(rec.get("computer") or rec.get("Computer") or "DC01").strip()
            user = str(rec.get("target_user_name") or rec.get("TargetUserName") or rec.get("user") or "SYSTEM").strip()

            source_rec_id = f"{computer}:{event_id}:{idx}"
            rec_id = f"CANON-WINEVT-{event_id}-{idx:04d}"
            source_hash = self.compute_hash(rec)
            observed_at = self.safe_timestamp(rec.get("timestamp") or rec.get("TimeCreated"))

            provenance = ProvenanceRecord(
                source_system=self.source_type,
                source_record_id=source_rec_id,
                source_timestamp=observed_at,
                source_hash=source_hash,
                schema_version=self.schema_version,
                transform_version="1.0",
            )

            entity_refs = [
                EntityReference(entity_type="Asset", entity_id=f"ASSET-SERVER-{computer}"),
                EntityReference(entity_type="Identity", entity_id=f"ID-USER-{user}"),
            ]

            payload_data = {
                "event_id": event_id,
                "provider_name": provider,
                "computer": computer,
                "target_user_name": user,
                "logon_type": int(rec.get("logon_type") or rec.get("LogonType") or 2),
                "status_code": str(rec.get("status_code") or "0x0"),
            }

            integ_hash = CanonicalSecurityData.compute_integrity_hash(payload_data, provenance)

            canonical_data = CanonicalSecurityData(
                record_id=rec_id,
                data_type=CanonicalDataType.SECURITY_LOG,
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
