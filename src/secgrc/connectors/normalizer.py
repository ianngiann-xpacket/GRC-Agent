"""Phase 33-A: Production Connector Architecture - 9-Stage Normalization Pipeline (Section 11-13, 30).

Implements the deterministic 9-stage normalization pipeline:
Stage 1: RawSourceRecord Ingestion
Stage 2: Schema Validation
Stage 3: Field Mapping Application
Stage 4: Entity Resolution
Stage 5: Scope Resolution
Stage 6: Canonical Normalization
Stage 7: Provenance Construction
Stage 8: Secret Scan
Stage 9: Canonical Validation & Integrity Sealing

Produces CanonicalNormalizationResult targeting CanonicalDataType.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional

from secgrc.compliance.models import (
    CanonicalDataType,
    CanonicalSecurityData,
    EntityReference,
)
from secgrc.connectors.errors import (
    ConnectorErrorCode,
    SecretDetectedError,
    UnsupportedCanonicalTypeError,
)
from secgrc.connectors.models import (
    CanonicalNormalizationResult,
    EntityResolutionResult,
    EntityStatus,
    FieldMapping,
    RawSourceRecord,
    ScopeResolutionResult,
    ScopeStatus,
    compute_canonical_hash,
)
from secgrc.connectors.provenance import ConnectorProvenanceBuilder
from secgrc.connectors.scope import EntityResolver, ScopeResolver
from secgrc.connectors.validator import ConnectorValidator, SecretScanner


class ConnectorNormalizer:
    """Deterministic 9-stage normalizer converting raw records to CanonicalSecurityData."""

    def __init__(
        self,
        mappings: Optional[List[FieldMapping]] = None,
        validator: Optional[ConnectorValidator] = None,
        mapping_version: str = "1.0",
    ) -> None:
        self.mappings = mappings or []
        self.validator = validator or ConnectorValidator()
        self.mapping_version = mapping_version
        self.secret_scanner = SecretScanner()

    def normalize_batch(
        self,
        raw_records: List[RawSourceRecord],
        target_canonical_type: CanonicalDataType,
        organization_id: str,
        scope: str = "GLOBAL",
    ) -> CanonicalNormalizationResult:
        """Runs the 9-stage normalization pipeline across a batch of raw records."""
        accepted_records: List[CanonicalSecurityData] = []
        rejected_records: List[Dict[str, Any]] = []
        warnings: List[str] = []
        source_refs: List[str] = []

        # Validate target canonical type is valid
        if not isinstance(target_canonical_type, CanonicalDataType):
            try:
                target_canonical_type = CanonicalDataType(target_canonical_type)
            except Exception:
                raise UnsupportedCanonicalTypeError(
                    f"Invalid canonical type '{target_canonical_type}'",
                    details={"provided_type": str(target_canonical_type)},
                )

        for raw in raw_records:
            source_refs.append(raw.record_id)
            try:
                # Stage 1 & 2: Ingestion & Validation
                val_res = self.validator.validate_raw_record(
                    record=raw,
                    expected_organization_id=organization_id,
                )
                if val_res.secret_detected:
                    rejected_records.append({
                        "raw_record_id": raw.record_id,
                        "reason": "SECRET_DETECTED",
                        "errors": ["Forbidden secret material in raw payload"],
                    })
                    continue

                if not val_res.is_valid:
                    rejected_records.append({
                        "raw_record_id": raw.record_id,
                        "reason": "VALIDATION_FAILED",
                        "errors": val_res.validation_errors,
                    })
                    continue

                # Stage 3: Field Mapping
                canonical_payload = self._apply_field_mappings(raw.payload)

                # Stage 4: Entity Resolution
                entity_refs = []
                if val_res.entity_resolution and val_res.entity_resolution.status == EntityStatus.RESOLVED:
                    if val_res.entity_resolution.internal_entity_ref:
                        entity_refs.append(
                            EntityReference(
                                entity_type="Asset",
                                entity_id=val_res.entity_resolution.internal_entity_ref,
                                relationship="OBSERVED_ON",
                            )
                        )
                elif val_res.entity_resolution and val_res.entity_resolution.status in (EntityStatus.AMBIGUOUS, EntityStatus.UNRESOLVED):
                    warnings.append(
                        f"Record '{raw.record_id}' entity '{val_res.entity_resolution.external_entity_id}' "
                        f"is {val_res.entity_resolution.status.value}; requires review."
                    )

                # Stage 5: Scope Resolution
                effective_scope = scope
                if val_res.scope_resolution and val_res.scope_resolution.scope_id:
                    effective_scope = val_res.scope_resolution.scope_id

                # Stage 6: Canonical Normalization Envelope
                record_id = f"CANON-{raw.connector_id}-{raw.record_id.replace('RAW-', '')}"

                # Stage 7: Provenance Construction
                prov_dict = ConnectorProvenanceBuilder.build_provenance(
                    raw_record=raw,
                    mapping_version=self.mapping_version,
                    normalization_version="1.0",
                    organization_id=organization_id,
                    scope=effective_scope,
                )
                provenance_record = ConnectorProvenanceBuilder.to_canonical_provenance_record(prov_dict)

                # Stage 8: Secret Scan on canonical payload
                sanitized_payload = self.secret_scanner.sanitize_secrets(canonical_payload)

                # Stage 9: Canonical Validation & Integrity Sealing
                integrity_hash = CanonicalSecurityData.compute_integrity_hash(
                    payload=sanitized_payload,
                    provenance=provenance_record,
                )

                canonical_record = CanonicalSecurityData(
                    record_id=record_id,
                    data_type=target_canonical_type,
                    source_system=raw.source_system,
                    source_record_id=raw.record_id,
                    source_version=raw.source_version,
                    observed_at=raw.source_event_time,
                    ingested_at=raw.collected_at,  # Excluded from semantic hash
                    tenant_id=organization_id,
                    scope=effective_scope,
                    entity_references=entity_refs,
                    payload=sanitized_payload,
                    provenance=provenance_record,
                    integrity_hash=integrity_hash,
                )
                accepted_records.append(canonical_record)

            except Exception as ex:
                rejected_records.append({
                    "raw_record_id": raw.record_id,
                    "reason": "NORMALIZATION_EXCEPTION",
                    "error": str(ex),
                })

        return CanonicalNormalizationResult(
            canonical_data_type=target_canonical_type,
            records=accepted_records,
            rejected_records=rejected_records,
            mapping_version=self.mapping_version,
            source_refs=source_refs,
            normalization_warnings=warnings,
            provenance={
                "organization_id": organization_id,
                "scope": scope,
                "authority": "NON_AUTHORITATIVE",
                "mapping_version": self.mapping_version,
            },
        )

    def _apply_field_mappings(self, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Applies configured FieldMapping rules to transform raw payload into canonical payload."""
        if not self.mappings:
            # Pass-through clean dictionary if no specific mappings defined
            return dict(raw_payload)

        mapped: Dict[str, Any] = {}
        for m in self.mappings:
            if m.source_field in raw_payload:
                val = raw_payload[m.source_field]
                if m.transformation == "lowercase" and isinstance(val, str):
                    val = val.lower()
                elif m.transformation == "uppercase" and isinstance(val, str):
                    val = val.upper()
                elif m.transformation == "boolean":
                    val = bool(val)
                elif m.transformation == "strip" and isinstance(val, str):
                    val = val.strip()
                mapped[m.canonical_field] = val
            elif m.required:
                if not m.nullable:
                    mapped[m.canonical_field] = ""
                else:
                    mapped[m.canonical_field] = None

        return mapped
