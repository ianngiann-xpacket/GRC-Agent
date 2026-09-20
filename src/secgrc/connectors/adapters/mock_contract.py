"""Phase 33-A: Production Connector Architecture - Mock Contract Adapter.

Generic reference connector adapter used for contract testing and architectural validation:
- Implements BaseConnector
- Fetches configurable raw records
- Normalizes using ConnectorNormalizer
- Validates using ConnectorValidator
- Strict READ-ONLY boundary
"""

from typing import Any, Dict, List, Optional

from secgrc.compliance.models import CanonicalDataType
from secgrc.connectors.base import BaseConnector
from secgrc.connectors.health import ConnectorHealthMonitor
from secgrc.connectors.models import (
    CanonicalNormalizationResult,
    CollectionMode,
    ConnectorDefinition,
    ConnectorHealth,
    ConnectorStatus,
    ConnectorType,
    ConnectorValidationResult,
    RawSourceRecord,
)
from secgrc.connectors.normalizer import ConnectorNormalizer
from secgrc.connectors.source import ConnectorSourceHandler
from secgrc.connectors.validator import ConnectorValidator


class ContractMockAdapter(BaseConnector):
    """Reference implementation of BaseConnector for unit tests and contract validation."""

    def __init__(
        self,
        connector_id: str = "CONN-MOCK-001",
        connector_type: ConnectorType = ConnectorType.CLOUD_SECURITY,
        supported_types: Optional[List[CanonicalDataType]] = None,
        capabilities_list: Optional[List[str]] = None,
    ) -> None:
        defn = ConnectorDefinition(
            connector_id=connector_id,
            connector_type=connector_type,
            name="Contract Mock Adapter",
            version="1.0.0",
            adapter_version="1.0.0",
            capabilities=capabilities_list or ["CLOUD_SECURITY_POSTURE", "CONFIGURATION_INSPECTION"],
            supported_canonical_types=supported_types or [CanonicalDataType.CONFIGURATION, CanonicalDataType.SECURITY_CONFIGURATION],
            supported_operations=["fetch", "normalize", "validate"],
            supported_collection_modes=[CollectionMode.FULL, CollectionMode.INCREMENTAL],
        )
        super().__init__(defn)
        self._validator = ConnectorValidator()
        self._normalizer = ConnectorNormalizer(validator=self._validator)
        self._health_monitor = ConnectorHealthMonitor()
        self._mock_records: List[RawSourceRecord] = []

    def set_mock_records(self, records: List[RawSourceRecord]) -> None:
        """Injects raw records to be returned by fetch()."""
        self._mock_records = list(records)

    def describe(self) -> ConnectorDefinition:
        return self._definition

    def health(self) -> ConnectorHealth:
        return self._health_monitor.get_health(self.connector_id, ConnectorStatus.READY)

    def capabilities(self) -> List[str]:
        return list(self._definition.capabilities)

    def fetch(self, batch_params: Optional[Dict[str, Any]] = None) -> List[RawSourceRecord]:
        """Returns configured mock records."""
        return list(self._mock_records)

    def normalize(self, raw_record: RawSourceRecord) -> CanonicalNormalizationResult:
        """Normalizes a single record using default target type."""
        target_type = self._definition.supported_canonical_types[0]
        return self._normalizer.normalize_batch(
            raw_records=[raw_record],
            target_canonical_type=target_type,
            organization_id=raw_record.organization_ref,
        )

    def normalize_batch(
        self,
        raw_records: List[RawSourceRecord],
        target_type: Optional[CanonicalDataType] = None,
        organization_id: str = "ORG-SYN-001",
    ) -> CanonicalNormalizationResult:
        """Normalizes multiple records."""
        effective_type = target_type or self._definition.supported_canonical_types[0]
        return self._normalizer.normalize_batch(
            raw_records=raw_records,
            target_canonical_type=effective_type,
            organization_id=organization_id,
        )

    def validate(self, raw_or_canonical: Any) -> ConnectorValidationResult:
        """Validates raw source record."""
        if isinstance(raw_or_canonical, RawSourceRecord):
            return self._validator.validate_raw_record(
                record=raw_or_canonical,
                expected_organization_id=raw_or_canonical.organization_ref,
            )
        return ConnectorValidationResult(is_valid=True)
