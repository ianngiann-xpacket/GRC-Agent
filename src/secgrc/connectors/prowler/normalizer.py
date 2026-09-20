"""Phase 33-B: Prowler GCP Finding Normalizer.

Transforms raw Prowler findings into CanonicalSecurityData targeting existing CanonicalDataTypes:
- Enforces non-authoritative boundary (no PASS/FAIL or risk score generation)
- Applies ProductionEntityResolver for project & resource resolution
- Validates scope boundaries
- Stamped with cryptographic provenance envelope
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from secgrc.compliance.models import (
    CanonicalDataType,
    CanonicalSecurityData,
    ClassificationLevel,
    EntityReference,
    ProvenanceRecord,
)
from secgrc.connectors.errors import (
    ConnectorError,
    ConnectorErrorCode,
    CrossTenantError,
    SecretDetectedError,
    UnsupportedCanonicalTypeError,
)
from secgrc.connectors.models import (
    CanonicalNormalizationResult,
    EntityStatus,
    RawSourceRecord,
    ScopeStatus,
    compute_canonical_hash,
)
from secgrc.connectors.prowler.models import ProwlerGcpMappingVersion, ProwlerGcpTarget
from secgrc.connectors.prowler.resolver import ProductionEntityResolver
from secgrc.connectors.provenance import ConnectorProvenanceBuilder
from secgrc.connectors.validator import SecretScanner


class ProwlerGcpNormalizer:
    """Normalizes raw Prowler GCP findings into CanonicalSecurityData."""

    def __init__(
        self,
        resolver: Optional[ProductionEntityResolver] = None,
        mapping_version: str = ProwlerGcpMappingVersion.V1.value,
    ) -> None:
        self.resolver = resolver or ProductionEntityResolver()
        self.mapping_version = mapping_version
        self.secret_scanner = SecretScanner()

    def determine_canonical_type(self, check_id: str, service: str = "", resource_type: str = "") -> CanonicalDataType:
        """Determines the appropriate registered CanonicalDataType for a Prowler check."""
        chk = (check_id or "").lower()

        # 1. Vulnerability findings
        if any(w in chk for w in ("vulnerability", "cve", "package_vuln")):
            return CanonicalDataType.VULNERABILITY_FINDING

        # 2. Firewall rules by explicit prefix (e.g. firewall_rule_logging_disabled, compute_firewall_*, vpc_firewall_*)
        if chk.startswith(("firewall_", "vpc_firewall_", "compute_firewall_")):
            return CanonicalDataType.FIREWALL_RULE

        # 3. Logging & monitoring checks (must precede fallback firewall/iam checks)
        if any(w in chk for w in ("logging", "audit_logs", "log_metric_filter", "monitoring", "sink")):
            return CanonicalDataType.SECURITY_CONFIGURATION

        # 4. IAM policies & roles (bindings, role definitions, separations)
        if any(w in chk for w in ("iam_binding", "iam_role", "iam_policy", "primitive_roles", "service_account_token_creator")):
            return CanonicalDataType.IAM_POLICY

        # 5. IAM accounts & users
        if any(w in chk for w in ("iam_service_account", "iam_user", "service_account", "user_managed_keys")):
            return CanonicalDataType.ACCOUNT

        # 6. Fallback Firewall & Network rules
        if any(w in chk for w in ("firewall", "vpc_firewall", "ingress", "egress")):
            return CanonicalDataType.FIREWALL_RULE

        # 7. Security configuration (public access, encryption, KMS)
        if any(w in chk for w in ("public_access", "publicly_accessible", "allusers", "allauthenticatedusers", "encryption", "kms", "customer_managed_key")):
            return CanonicalDataType.SECURITY_CONFIGURATION

        return CanonicalDataType.CONFIGURATION_FINDING

    def normalize_record(
        self,
        raw_record: RawSourceRecord,
        target: ProwlerGcpTarget,
    ) -> CanonicalSecurityData:
        """Normalizes a single raw Prowler record into CanonicalSecurityData."""
        payload = raw_record.payload

        # 1. Secret Scanner Gate
        has_secret, secret_types = SecretScanner.scan_for_secrets(payload)
        if has_secret:
            raise SecretDetectedError(
                f"Secret pattern {secret_types} detected in Prowler finding {raw_record.record_id}.",
                connector_id=raw_record.connector_id,
                details={"secret_types": secret_types},
            )

        # 2. Extract Prowler Attributes — v3/v4 네이티브 JSON과 v5 OCSF 형식 모두 지원.
        # OCSF: metadata.event_code=check_id, status_code=PASS/FAIL/MANUAL,
        #       cloud.account.uid=project, resources[0]=resource, remediation.desc
        ocsf_res = payload.get("resources") or []
        ocsf_res0 = ocsf_res[0] if ocsf_res and isinstance(ocsf_res[0], dict) else {}
        ocsf_fi = payload.get("finding_info") or {}
        check_id = str(
            payload.get("CheckID") or payload.get("check_id")
            or (payload.get("metadata") or {}).get("event_code")
            or (ocsf_fi.get("analytic") or {}).get("uid")
            or "unknown_check"
        )
        status = str(
            payload.get("Status") or payload.get("status_code")
            or payload.get("status") or "UNKNOWN"
        )
        severity = str(payload.get("Severity") or payload.get("severity") or "INFORMATIONAL")
        project_id = str(
            payload.get("Project") or payload.get("project_id") or payload.get("account_id")
            or (payload.get("cloud", {}).get("account") or {}).get("uid") or ""
        )
        region = str(
            payload.get("Region") or payload.get("region")
            or ocsf_res0.get("region") or "global"
        )
        resource_id = str(
            payload.get("ResourceID") or payload.get("resource_id") or payload.get("ResourceId")
            or (ocsf_res0.get("data", {}).get("metadata") or {}).get("id")
            or ocsf_res0.get("uid") or ocsf_res0.get("name") or ""
        )
        resource_name = str(
            payload.get("ResourceName") or payload.get("resource_name")
            or ocsf_res0.get("name") or resource_id
        )
        resource_type = str(
            payload.get("ResourceType") or payload.get("resource_type")
            or ocsf_res0.get("type") or ""
        )
        service = str(
            payload.get("ServiceName") or payload.get("service")
            or (ocsf_fi.get("analytic") or {}).get("category")
            or (check_id.split("_")[0] if "_" in check_id else "")
        )
        description = str(
            payload.get("Description") or payload.get("description")
            or payload.get("status_detail") or payload.get("message")
            or ocsf_fi.get("desc") or ""
        )
        rem = payload.get("Remediation") or payload.get("remediation_recommendation") or ""
        if not rem and isinstance(payload.get("remediation"), dict):
            rem = payload["remediation"].get("desc", "")
        remediation = str(rem)
        compliance = (
            payload.get("Compliance") or payload.get("compliance_frameworks")
            or (payload.get("unmapped") or {}).get("compliance") or {}
        )

        # 3. Entity Resolution: Project
        proj_res = self.resolver.resolve_project(project_id, expected_tenant_id=target.tenant_id)
        if proj_res.status == EntityStatus.CROSS_TENANT:
            raise CrossTenantError(
                f"Prowler finding belongs to foreign tenant project '{project_id}'. Cross-tenant ingestion blocked.",
                connector_id=raw_record.connector_id,
            )

        # 4. Entity Resolution: Resource
        res_res = self.resolver.resolve_resource(
            resource_id=resource_id,
            resource_type=resource_type,
            project_id=project_id,
            expected_tenant_id=target.tenant_id,
        )

        # 5. Scope Resolution
        scope_res = self.resolver.resolve_scope(
            project_id=project_id,
            target_projects=target.gcp_project_ids,
            organization_id=target.organization_id,
        )

        # 6. Determine Canonical Data Type
        canonical_type = self.determine_canonical_type(check_id, service, resource_type)

        # 7. Provenance Envelope
        prov_dict = ConnectorProvenanceBuilder.build_provenance(
            raw_record=raw_record,
            mapping_version=self.mapping_version,
            normalization_version="1.0",
            organization_id=target.organization_id,
            scope=scope_res.status.value,
        )
        prov_record = ConnectorProvenanceBuilder.to_canonical_provenance_record(prov_dict)

        # 8. Assemble Entity References
        entity_refs: List[EntityReference] = []
        if proj_res.internal_entity_ref:
            entity_refs.append(EntityReference(
                entity_type="Asset",
                entity_id=proj_res.internal_entity_ref,
                relationship="OBSERVED_ON",
            ))
        if res_res.internal_entity_ref:
            entity_refs.append(EntityReference(
                entity_type="Asset",
                entity_id=res_res.internal_entity_ref,
                relationship="OBSERVED_ON",
            ))

        # 9. Clean Canonical Payload
        clean_payload = {
            "check_id": check_id,
            "source_status": status,  # Kept as source status, NEVER authoritative PASS/FAIL
            "source_severity": severity,
            "project_id": project_id,
            "resource_id": resource_id,
            "resource_name": resource_name,
            "resource_type": resource_type,
            "region": region,
            "service": service,
            "description": description,
            "remediation_guidance": remediation,
            "source_framework_reference": compliance,
            "scope_status": scope_res.status.value,
            "entity_resolution_status": res_res.status.value,
            "mapping_version": self.mapping_version,
        }
        sanitized_payload = self.secret_scanner.sanitize_secrets(clean_payload)

        # 10. Build CanonicalSecurityData (STRICTLY NON-AUTHORITATIVE, NO COMPLIANCE VERDICT)
        clean_record_id = raw_record.record_id.replace(":", "-").replace("/", "-")
        record_id = f"CANON-{clean_record_id}"

        integrity_hash = CanonicalSecurityData.compute_integrity_hash(
            payload=sanitized_payload,
            provenance=prov_record,
        )

        return CanonicalSecurityData(
            record_id=record_id,
            data_type=canonical_type,
            source_system="Prowler",
            source_record_id=raw_record.record_id.replace(":", "-").replace("/", "-"),
            source_version=raw_record.source_version,
            observed_at=raw_record.source_event_time,
            ingested_at=raw_record.collected_at,
            tenant_id=target.tenant_id,
            scope=scope_res.status.value,
            entity_references=entity_refs,
            payload=sanitized_payload,
            provenance=prov_record,
            classification=ClassificationLevel.INTERNAL,
            integrity_hash=integrity_hash,
            schema_version="1.0",
        )

    def normalize_batch(
        self,
        raw_records: List[RawSourceRecord],
        target: ProwlerGcpTarget,
    ) -> CanonicalNormalizationResult:
        """Normalizes a batch of raw records into a CanonicalNormalizationResult."""
        records: List[CanonicalSecurityData] = []
        rejected: List[Dict[str, Any]] = []
        source_refs: List[str] = []
        warnings: List[str] = []

        for raw in raw_records:
            source_refs.append(raw.record_id)
            try:
                canon = self.normalize_record(raw, target)
                records.append(canon)
            except Exception as e:
                reason = "SECRET_DETECTED" if isinstance(e, SecretDetectedError) else str(e)
                rejected.append({
                    "record_id": raw.record_id,
                    "reason": reason,
                })
                warnings.append(f"Rejected record {raw.record_id}: {reason}")

        canonical_data_type = (
            records[0].data_type if records else CanonicalDataType.CONFIGURATION_FINDING
        )

        return CanonicalNormalizationResult(
            canonical_data_type=canonical_data_type,
            records=records,
            rejected_records=rejected,
            mapping_version=self.mapping_version,
            source_refs=source_refs,
            normalization_warnings=warnings,
        )
