"""Phase 33-A: Production Connector Architecture Package.

Provides generic, read-only external security connector integration contracts:
- Raw Source Ingestion
- 9-Stage Normalization Pipeline
- 10-Gate Validation & Secret Scanner
- Deterministic Entity & Scope Resolution
- Immutable Cryptographic Provenance
- Synthetic Contract Testing Harness
"""

from secgrc.connectors.base import BaseConnector
from secgrc.connectors.contracts import ConnectorContractTestHarness
from secgrc.connectors.errors import (
    ConnectorError,
    ConnectorErrorCode,
    CrossTenantError,
    ProvenanceInvalidError,
    ResourceLimitError,
    SecretDetectedError,
    UnsupportedCanonicalTypeError,
)
from secgrc.connectors.health import ConnectorAuditLogger, ConnectorHealthMonitor
from secgrc.connectors.hr_connector import HRConnector, EmployeeRecord, hr_connector
from secgrc.connectors.iam_connector import IAMConnector, UserAccount, iam_connector
from secgrc.connectors.models import (
    CanonicalNormalizationResult,
    CollectionMode,
    ConnectorAuditRecord,
    ConnectorCheckpoint,
    ConnectorCollectionBatch,
    ConnectorDefinition,
    ConnectorHealth,
    ConnectorReadiness,
    ConnectorResourceLimits,
    ConnectorStatus,
    ConnectorType,
    ConnectorValidationResult,
    CredentialReference,
    EntityResolutionResult,
    EntityStatus,
    FieldMapping,
    RawSourceRecord,
    ScopeResolutionResult,
    ScopeStatus,
    compute_canonical_hash,
    compute_idempotency_key,
)
from secgrc.connectors.normalizer import ConnectorNormalizer
from secgrc.connectors.provenance import ConnectorProvenanceBuilder
from secgrc.connectors.registry import ConnectorRegistry
from secgrc.connectors.scope import EntityResolver, ScopeResolver, TenantIsolationValidator
from secgrc.connectors.service import (
    ConnectorService,
    get_connector_service,
    reset_connector_service,
)
from secgrc.connectors.source import ConnectorSourceHandler
from secgrc.connectors.validator import ConnectorValidator, SecretScanner

__all__ = [
    "BaseConnector",
    "CanonicalNormalizationResult",
    "CollectionMode",
    "ConnectorAuditLogger",
    "ConnectorAuditRecord",
    "ConnectorCheckpoint",
    "ConnectorCollectionBatch",
    "ConnectorContractTestHarness",
    "ConnectorDefinition",
    "ConnectorError",
    "ConnectorErrorCode",
    "ConnectorHealth",
    "ConnectorHealthMonitor",
    "ConnectorNormalizer",
    "ConnectorProvenanceBuilder",
    "ConnectorReadiness",
    "ConnectorRegistry",
    "EmployeeRecord",
    "HRConnector",
    "IAMConnector",
    "UserAccount",
    "hr_connector",
    "iam_connector",
    "ConnectorResourceLimits",
    "ConnectorService",
    "ConnectorSourceHandler",
    "ConnectorStatus",
    "ConnectorType",
    "ConnectorValidationResult",
    "ConnectorValidator",
    "CredentialReference",
    "CrossTenantError",
    "EntityResolutionResult",
    "EntityResolver",
    "EntityStatus",
    "FieldMapping",
    "ProvenanceInvalidError",
    "RawSourceRecord",
    "ResourceLimitError",
    "ScopeResolutionResult",
    "ScopeResolver",
    "ScopeStatus",
    "SecretDetectedError",
    "SecretScanner",
    "TenantIsolationValidator",
    "UnsupportedCanonicalTypeError",
    "compute_canonical_hash",
    "compute_idempotency_key",
    "get_connector_service",
    "reset_connector_service",
]
