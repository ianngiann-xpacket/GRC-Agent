"""Phase 33-B: Prowler GCP Connector Adapter Implementation.

Implements BaseConnector for Prowler GCP:
- Product != Capability separation
- Strictly read-only operations
- Integrates ProwlerRawIngestor and ProwlerGcpNormalizer
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from secgrc.compliance.models import CanonicalDataType
from secgrc.connectors.base import BaseConnector
from secgrc.connectors.health import ConnectorHealthMonitor
from secgrc.connectors.models import (
    CanonicalNormalizationResult,
    ConnectorDefinition,
    ConnectorHealth,
    ConnectorStatus,
    ConnectorType,
    ConnectorValidationResult,
    CredentialReference,
    RawSourceRecord,
)
from secgrc.connectors.prowler.ingestor import ProwlerRawIngestor
from secgrc.connectors.prowler.models import GcpCredentialReference, ProwlerGcpTarget
from secgrc.connectors.prowler.normalizer import ProwlerGcpNormalizer
from secgrc.connectors.prowler.resolver import ProductionEntityResolver
from secgrc.connectors.validator import ConnectorValidator


class ProwlerGcpAdapter(BaseConnector):
    """Production connector adapter for Prowler GCP scans."""

    def __init__(
        self,
        connector_id: str = "conn-prowler-gcp",
        definition: Optional[ConnectorDefinition] = None,
        normalizer: Optional[ProwlerGcpNormalizer] = None,
        validator: Optional[ConnectorValidator] = None,
    ) -> None:
        defn = definition or ConnectorDefinition(
            connector_id=connector_id,
            connector_type=ConnectorType.CLOUD_SECURITY,
            name="Prowler GCP Production Connector",
            version="1.0.0",
            adapter_version="1.0.0",
            capabilities=["READ_FINDINGS", "READ_CONFIG", "READ_ACCOUNT_METADATA", "READ_TELEMETRY"],
            supported_canonical_types=[
                CanonicalDataType.CONFIGURATION_FINDING,
                CanonicalDataType.SECURITY_CONFIGURATION,
                CanonicalDataType.FIREWALL_RULE,
                CanonicalDataType.ACCOUNT,
                CanonicalDataType.IAM_POLICY,
                CanonicalDataType.SECURITY_LOG,
                CanonicalDataType.VULNERABILITY_FINDING,
            ],
            supported_operations=["READ", "FETCH", "NORMALIZE", "VALIDATE"],
            enabled=True,
        )
        super().__init__(defn)
        self.normalizer = normalizer or ProwlerGcpNormalizer()
        self.validator = validator or ConnectorValidator()
        self.health_monitor = ConnectorHealthMonitor()
        self._target: Optional[ProwlerGcpTarget] = None

    def set_target(self, target: ProwlerGcpTarget) -> None:
        """Sets the active GCP scan target."""
        self._target = target

    def describe(self) -> ConnectorDefinition:
        return self._definition

    def health(self) -> ConnectorHealth:
        return self.health_monitor.get_health(self.connector_id, ConnectorStatus.READY)

    def capabilities(self) -> List[str]:
        return list(self._definition.capabilities)

    def fetch(self, batch_params: Optional[Dict[str, Any]] = None) -> List[RawSourceRecord]:
        """Fetches raw records from output file or parameters."""
        params = batch_params or {}
        file_path = params.get("file_path") or params.get("output_path")
        if not file_path:
            return []

        org_ref = params.get("organization_id") or "ORG-REAL-001"
        findings, _ = ProwlerRawIngestor.load_raw_findings(file_path)
        return ProwlerRawIngestor.ingest_to_raw_records(
            findings=findings,
            connector_id=self.connector_id,
            organization_ref=org_ref,
            source_locator=str(file_path),
            collection_batch_id=params.get("batch_id", ""),
        )

    def normalize(self, raw_record: RawSourceRecord) -> CanonicalNormalizationResult:
        """Normalizes a single raw record into CanonicalNormalizationResult."""
        target = self._target or ProwlerGcpTarget(
            organization_id=raw_record.organization_ref,
            tenant_id=raw_record.organization_ref,
            gcp_project_ids=[raw_record.organization_ref],
            credential_ref=GcpCredentialReference(
                credential_ref_id="cred-default",
                auth_mode="ADC",
            ),
        )
        return self.normalizer.normalize_batch([raw_record], target)

    def validate(self, raw_or_canonical: Any) -> ConnectorValidationResult:
        """Executes validation over raw or canonical record."""
        if isinstance(raw_or_canonical, RawSourceRecord):
            target_org = self._target.organization_id if self._target else raw_or_canonical.organization_ref
            return self.validator.validate_raw_record(raw_or_canonical, expected_organization_id=target_org)
        return ConnectorValidationResult(is_valid=True)
