"""Phase 33-A: Production Connector Architecture - Explicit Error Model (Section 27).

Defines machine-readable connector error codes and structured exceptions:
1. CONNECTOR_UNAVAILABLE
2. AUTHENTICATION_ERROR
3. AUTHORIZATION_ERROR
4. RATE_LIMITED
5. SOURCE_SCHEMA_CHANGED
6. MAPPING_ERROR
7. ENTITY_UNRESOLVED
8. ENTITY_AMBIGUOUS
9. OUT_OF_SCOPE
10. CROSS_TENANT
11. PROVENANCE_INVALID
12. SECRET_DETECTED
13. RESOURCE_LIMIT
14. UNSUPPORTED_CANONICAL_TYPE
"""

from enum import Enum
from typing import Any, Dict, Optional


class ConnectorErrorCode(str, Enum):
    """Machine-readable connector error codes."""
    CONNECTOR_UNAVAILABLE = "CONNECTOR_UNAVAILABLE"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    SOURCE_SCHEMA_CHANGED = "SOURCE_SCHEMA_CHANGED"
    MAPPING_ERROR = "MAPPING_ERROR"
    ENTITY_UNRESOLVED = "ENTITY_UNRESOLVED"
    ENTITY_AMBIGUOUS = "ENTITY_AMBIGUOUS"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    CROSS_TENANT = "CROSS_TENANT"
    PROVENANCE_INVALID = "PROVENANCE_INVALID"
    SECRET_DETECTED = "SECRET_DETECTED"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    UNSUPPORTED_CANONICAL_TYPE = "UNSUPPORTED_CANONICAL_TYPE"


class ConnectorError(Exception):
    """Base exception for all connector operations with machine-readable error details."""

    def __init__(
        self,
        code: ConnectorErrorCode,
        message: str,
        connector_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(f"[{code.value}] {message}")
        self.code = code
        self.message = message
        self.connector_id = connector_id
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.code.value,
            "message": self.message,
            "connector_id": self.connector_id,
            "details": self.details,
        }


class CrossTenantError(ConnectorError):
    def __init__(self, message: str, connector_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(ConnectorErrorCode.CROSS_TENANT, message, connector_id, details)


class SecretDetectedError(ConnectorError):
    def __init__(self, message: str, connector_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(ConnectorErrorCode.SECRET_DETECTED, message, connector_id, details)


class UnsupportedCanonicalTypeError(ConnectorError):
    def __init__(self, message: str, connector_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(ConnectorErrorCode.UNSUPPORTED_CANONICAL_TYPE, message, connector_id, details)


class ProvenanceInvalidError(ConnectorError):
    def __init__(self, message: str, connector_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(ConnectorErrorCode.PROVENANCE_INVALID, message, connector_id, details)


class ResourceLimitError(ConnectorError):
    def __init__(self, message: str, connector_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(ConnectorErrorCode.RESOURCE_LIMIT, message, connector_id, details)
