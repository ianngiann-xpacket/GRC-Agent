"""Prowler Security Data Adapter (Step 23.5A).

Normalizes Prowler CSPM cloud configuration scan findings into canonical
CONFIGURATION_FINDING and SECURITY_CONFIGURATION records.
"""

import csv
import io
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


class ProwlerDataAdapter(BaseSecurityDataAdapter):
    """Prowler 클라우드 보안 점검 도구 전용 어댑터."""

    source_type: str = "Prowler"
    schema_version: str = "1.0"

    def detect(self, payload: Any) -> bool:
        """Prowler CSV/JSON 형식 감지."""
        if not payload:
            return False
        if isinstance(payload, dict):
            return "check_id" in payload or "CheckID" in payload or "prowler" in str(payload).lower()
        if isinstance(payload, list) and len(payload) > 0 and isinstance(payload[0], dict):
            return "check_id" in payload[0] or "CheckID" in payload[0]
        if isinstance(payload, str):
            lower = payload.lower()
            return ("check_id" in lower and "status" in lower) or "prowler" in lower
        return False

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        """원천 페이로드 파싱 (CSV 문자열, 딕셔너리, 리스트 지원)."""
        self.check_payload_safety(payload)
        records: List[Dict[str, Any]] = []

        if isinstance(payload, dict):
            records.append(payload)
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    records.append(item)
        elif isinstance(payload, str):
            clean_str = payload.strip()
            if clean_str.startswith("{") or clean_str.startswith("["):
                parsed = json.loads(clean_str)
                return self.parse(parsed)
            # CSV 파싱
            reader = csv.DictReader(io.StringIO(clean_str))
            for row in reader:
                records.append(dict(row))

        return records

    def normalize(
        self,
        records: List[Dict[str, Any]],
        tenant_id: str = "default",
        scope: str = "GLOBAL",
    ) -> List[CanonicalSecurityData]:
        """Prowler 레코드를 정규 CanonicalSecurityData로 변환."""
        canonical_list: List[CanonicalSecurityData] = []

        for idx, rec in enumerate(records, 1):
            check_id = str(rec.get("check_id") or rec.get("CheckID") or f"PROWLER-CHK-{idx}").strip()
            resource_id = str(rec.get("resource_id") or rec.get("ResourceID") or f"RES-{idx}").strip()
            status_val = str(rec.get("status") or rec.get("Status") or "UNKNOWN").upper()
            service_name = str(rec.get("service_name") or rec.get("ServiceName") or "cloud").strip()
            severity_val = str(rec.get("severity") or rec.get("Severity") or "LOW").upper()

            rec_id = f"CANON-PROWLER-{check_id}-{idx:04d}"
            source_rec_id = f"{check_id}:{resource_id}"
            source_hash = self.compute_hash(rec)
            observed_at = self.safe_timestamp(rec.get("timestamp") or rec.get("Timestamp"))

            provenance = ProvenanceRecord(
                source_system=self.source_type,
                source_record_id=source_rec_id,
                source_document=rec.get("source_file"),
                source_timestamp=observed_at,
                source_hash=source_hash,
                schema_version=self.schema_version,
                transform_version="1.0",
            )

            entity_refs = [
                EntityReference(entity_type="Asset", entity_id=f"ASSET-{resource_id}"),
            ]

            payload_data = {
                "check_id": check_id,
                "status": status_val,
                "resource_id": resource_id,
                "service_name": service_name,
                "severity": severity_val,
                "description": str(rec.get("description") or rec.get("Description") or ""),
                "remediation": str(rec.get("remediation") or rec.get("Remediation") or ""),
            }

            integ_hash = CanonicalSecurityData.compute_integrity_hash(payload_data, provenance)

            canonical_data = CanonicalSecurityData(
                record_id=rec_id,
                data_type=CanonicalDataType.CONFIGURATION_FINDING,
                source_system=self.source_type,
                source_record_id=source_rec_id,
                source_version=rec.get("prowler_version") or "3.0",
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
