"""Phase 33-A: Production Connector Architecture - Base Connector Abstract Class (Section 8).

Defines the mandatory interface for all external security connectors:
- describe() -> ConnectorDefinition
- health() -> ConnectorHealth
- capabilities() -> List[str]
- fetch() -> List[RawSourceRecord]
- normalize() -> CanonicalNormalizationResult
- validate() -> ConnectorValidationResult
- close() -> None

Invariant:
- Read-only contract
- fetch() returns ONLY RawSourceRecord
- normalize() returns CanonicalNormalizationResult
- validate() returns ConnectorValidationResult
- Strictly blocks direct returns of Compliance Assessment, Risk, Investigation, or Decision
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from secgrc.connectors.models import (
    CanonicalNormalizationResult,
    ConnectorDefinition,
    ConnectorHealth,
    ConnectorValidationResult,
    RawSourceRecord,
)


class BaseConnector(ABC):
    """Abstract base class for all production and test connectors."""

    def __init__(self, definition: ConnectorDefinition) -> None:
        self._definition = definition
        # Validate read-only nature: no write operations allowed
        disallowed_ops = {"write", "remediate", "mutate", "delete", "assess_compliance", "calculate_risk"}
        for op in definition.supported_operations:
            if op.lower() in disallowed_ops:
                raise PermissionError(
                    f"Disallowed operation '{op}' for connector '{definition.connector_id}'. "
                    f"Phase 33-A connectors must be strictly READ-ONLY."
                )

    @property
    def connector_id(self) -> str:
        return self._definition.connector_id

    @property
    def definition(self) -> ConnectorDefinition:
        return self._definition

    @abstractmethod
    def describe(self) -> ConnectorDefinition:
        """Returns the static capability and configuration definition."""
        ...

    @abstractmethod
    def health(self) -> ConnectorHealth:
        """Returns operational health status (records processed, latency, errors)."""
        ...

    @abstractmethod
    def capabilities(self) -> List[str]:
        """Returns list of enabled capability types."""
        ...

    @abstractmethod
    def fetch(self, batch_params: Optional[Dict[str, Any]] = None) -> List[RawSourceRecord]:
        """Fetches raw source records from external system. Must return RawSourceRecord only."""
        ...

    @abstractmethod
    def normalize(self, raw_record: RawSourceRecord) -> CanonicalNormalizationResult:
        """Normalizes a raw record into CanonicalSecurityData."""
        ...

    @abstractmethod
    def validate(self, raw_or_canonical: Any) -> ConnectorValidationResult:
        """Executes multi-gate validation across schema, entity, scope, and secret detection."""
        ...

    def close(self) -> None:
        """Closes any external connections / sessions."""
        pass
