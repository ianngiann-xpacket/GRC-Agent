"""IAM Policy & Access Control Data Adapter (Step 23.5A).

Normalizes Cloud/OS IAM Policies, Role assignments, and MFA configurations
into canonical IAM_POLICY, MFA_CONFIGURATION, and PERMISSION records.
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


class IAMPolicyDataAdapter(BaseSecurityDataAdapter):
    """IAM 정책 및 인증 설정 전용 어댑터."""

    source_type: str = "IAM"
    schema_version: str = "1.0"

    def detect(self, payload: Any) -> bool:
        if not payload:
            return False
        if isinstance(payload, dict):
            return "policy_id" in payload or "Statement" in payload or "statements" in payload or "mfa_enabled" in payload
        if isinstance(payload, list) and len(payload) > 0 and isinstance(payload[0], dict):
            return "policy_id" in payload[0] or "Statement" in payload[0]
        if isinstance(payload, str):
            lower = payload.lower()
            return "iam" in lower or "policy_id" in lower or "statement" in lower
        return False

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        self.check_payload_safety(payload)
        records: List[Dict[str, Any]] = []

        if isinstance(payload, dict):
            if "policies" in payload and isinstance(payload["policies"], list):
                for pol in payload["policies"]:
                    if isinstance(pol, dict):
                        records.append(pol)
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
            policy_id = str(rec.get("policy_id") or rec.get("PolicyId") or f"IAM-POL-{idx}").strip()
            policy_name = str(rec.get("policy_name") or rec.get("PolicyName") or f"Policy-{idx}").strip()
            statements = rec.get("statements") or rec.get("Statement") or []
            mfa_req = bool(rec.get("mfa_required") or rec.get("mfa_enabled") or False)

            rec_id = f"CANON-IAM-{policy_id}-{idx:04d}"
            source_rec_id = policy_id
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
                EntityReference(entity_type="Policy", entity_id=f"POL-IAM-{policy_id}"),
            ]

            payload_data = {
                "policy_id": policy_id,
                "policy_name": policy_name,
                "statements": statements,
                "mfa_required": mfa_req,
                "attached_entities": rec.get("attached_entities") or [],
            }

            integ_hash = CanonicalSecurityData.compute_integrity_hash(payload_data, provenance)

            # MFA 설정인 경우 MFA_CONFIGURATION, 일반 정책은 IAM_POLICY
            dtype = CanonicalDataType.MFA_CONFIGURATION if mfa_req else CanonicalDataType.IAM_POLICY

            canonical_data = CanonicalSecurityData(
                record_id=rec_id,
                data_type=dtype,
                source_system=self.source_type,
                source_record_id=source_rec_id,
                observed_at=observed_at,
                tenant_id=tenant_id,
                scope=scope,
                entity_references=entity_refs,
                payload=payload_data,
                provenance=provenance,
                classification=ClassificationLevel.CONFIDENTIAL,
                integrity_hash=integ_hash,
                schema_version=self.schema_version,
            )
            canonical_list.append(canonical_data)

        return canonical_list
