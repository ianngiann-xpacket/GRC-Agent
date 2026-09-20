"""Security Policy & Governance Document Data Adapter (Step 23.5A).

Normalizes Security policies, standards, guidelines, procedures, and annual plans
into canonical POLICY, PROCEDURE, STANDARD, and SECURITY_PLAN records.
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


class PolicyDocumentDataAdapter(BaseSecurityDataAdapter):
    """정보보호 규정/지침 및 거버넌스 문서 전용 어댑터."""

    source_type: str = "PolicyDocument"
    schema_version: str = "1.0"

    def detect(self, payload: Any) -> bool:
        if not payload:
            return False
        if isinstance(payload, dict):
            return "document_id" in payload or "approved_by" in payload or "policy_title" in payload
        if isinstance(payload, list) and len(payload) > 0 and isinstance(payload[0], dict):
            return "document_id" in payload[0] or "approved_by" in payload[0]
        if isinstance(payload, str):
            lower = payload.lower()
            return "policy" in lower and ("approved" in lower or "document_id" in lower)
        return False

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        self.check_payload_safety(payload)
        records: List[Dict[str, Any]] = []

        if isinstance(payload, dict):
            if "documents" in payload and isinstance(payload["documents"], list):
                for doc in payload["documents"]:
                    if isinstance(doc, dict):
                        records.append(doc)
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
            doc_id = str(rec.get("document_id") or rec.get("id") or f"DOC-{idx}").strip()
            title = str(rec.get("title") or rec.get("policy_title") or "Information Security Policy").strip()
            version_str = str(rec.get("version") or "1.0").strip()
            approved_by = str(rec.get("approved_by") or "CISO").strip()
            doc_type = str(rec.get("doc_type") or "POLICY").upper()

            rec_id = f"CANON-DOC-{doc_id}-{idx:04d}"
            source_rec_id = doc_id
            source_hash = self.compute_hash(rec)
            observed_at = self.safe_timestamp(rec.get("effective_date") or rec.get("timestamp"))

            provenance = ProvenanceRecord(
                source_system=self.source_type,
                source_record_id=source_rec_id,
                source_document=doc_id,
                source_timestamp=observed_at,
                source_hash=source_hash,
                schema_version=self.schema_version,
                transform_version="1.0",
            )

            entity_refs = [
                EntityReference(entity_type="Policy", entity_id=f"POL-DOC-{doc_id}"),
            ]

            payload_data = {
                "document_id": doc_id,
                "title": title,
                "version": version_str,
                "approved_by": approved_by,
                "review_cycle": str(rec.get("review_cycle") or "ANNUAL"),
                "summary": str(rec.get("summary") or ""),
            }

            integ_hash = CanonicalSecurityData.compute_integrity_hash(payload_data, provenance)

            if "PLAN" in doc_type:
                dtype = CanonicalDataType.SECURITY_PLAN
            elif "PROCEDURE" in doc_type:
                dtype = CanonicalDataType.PROCEDURE
            elif "STANDARD" in doc_type:
                dtype = CanonicalDataType.STANDARD
            else:
                dtype = CanonicalDataType.POLICY

            canonical_data = CanonicalSecurityData(
                record_id=rec_id,
                data_type=dtype,
                source_system=self.source_type,
                source_record_id=source_rec_id,
                source_version=version_str,
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
