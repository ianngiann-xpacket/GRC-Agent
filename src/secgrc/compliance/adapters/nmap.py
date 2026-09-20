"""Nmap Port & Exposure Data Adapter (Step 23.5A).

Normalizes Nmap port scan and service banner results into canonical
PORT_OBSERVATION and SERVICE_EXPOSURE records.
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


class NmapDataAdapter(BaseSecurityDataAdapter):
    """Nmap 포트 스캔 및 노출 서비스 전용 어댑터."""

    source_type: str = "Nmap"
    schema_version: str = "1.0"

    def detect(self, payload: Any) -> bool:
        if not payload:
            return False
        if isinstance(payload, dict):
            if "nmaprun" in payload or "scan_info" in payload or ("port" in payload and "state" in payload):
                return True
            if "ports" in payload and isinstance(payload["ports"], list):
                return True
            if "nmap" in str(payload).lower():
                return True
        if isinstance(payload, list) and len(payload) > 0 and isinstance(payload[0], dict):
            return "port" in payload[0] and "state" in payload[0]
        if isinstance(payload, str):
            lower = payload.lower()
            return "nmap" in lower or ("open" in lower and "port" in lower)
        return False

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        self.check_payload_safety(payload)
        records: List[Dict[str, Any]] = []

        if isinstance(payload, dict):
            # 단일 포트 또는 scan dict
            if "port" in payload:
                records.append(payload)
            elif "ports" in payload and isinstance(payload["ports"], list):
                host = payload.get("host", "unknown")
                for p in payload["ports"]:
                    if isinstance(p, dict):
                        p_rec = dict(p)
                        p_rec.setdefault("host", host)
                        records.append(p_rec)
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
            host = str(rec.get("host") or "localhost").strip()
            port = int(rec.get("port") or 80)
            proto = str(rec.get("protocol") or "tcp").lower()
            state = str(rec.get("state") or "open").lower()
            service_name = str(rec.get("service_name") or rec.get("service") or "unknown").strip()

            source_rec_id = f"{host}:{port}/{proto}"
            rec_id = f"CANON-NMAP-{host}-{port}-{idx:04d}"
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
                EntityReference(entity_type="Asset", entity_id=f"ASSET-HOST-{host}"),
            ]

            payload_data = {
                "host": host,
                "port": port,
                "protocol": proto,
                "state": state,
                "service_name": service_name,
                "product": str(rec.get("product") or ""),
                "version": str(rec.get("version") or ""),
            }

            integ_hash = CanonicalSecurityData.compute_integrity_hash(payload_data, provenance)

            canonical_data = CanonicalSecurityData(
                record_id=rec_id,
                data_type=CanonicalDataType.PORT_OBSERVATION,
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
