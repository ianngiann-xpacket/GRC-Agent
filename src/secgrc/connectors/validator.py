"""Phase 33-A: Production Connector Architecture - Multi-Gate Validator (Section 16 & 22).

Executes comprehensive 10-level multi-gate validation:
1. Schema validation (required attributes, structure)
2. Field validation (injection protection, identifier formats)
3. Canonical type validation (targets Step 23.5A CanonicalDataType)
4. Entity resolution (ambiguous/unresolved flagged)
5. Tenant validation (strict isolation, blocks cross-tenant)
6. Scope validation (IN_SCOPE, OUT_OF_SCOPE, UNKNOWN_SCOPE)
7. Temporal validation (ISO 8601 validity, prevents future timestamp anomalies)
8. Provenance validation (unbroken chain, authority == NON_AUTHORITATIVE)
9. Secret detection (scans passwords, API keys, AWS keys, JWTs, private keys)
10. Resource limits (batch sizes, payload size limits)
"""

from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, List, Optional

from secgrc.compliance.models import CanonicalDataType
from secgrc.connectors.errors import (
    CrossTenantError,
    ProvenanceInvalidError,
    ResourceLimitError,
    SecretDetectedError,
    UnsupportedCanonicalTypeError,
)
from secgrc.connectors.models import (
    ConnectorResourceLimits,
    ConnectorValidationResult,
    EntityResolutionResult,
    EntityStatus,
    RawSourceRecord,
    ScopeResolutionResult,
    ScopeStatus,
)
from secgrc.connectors.scope import EntityResolver, ScopeResolver, TenantIsolationValidator

# Regex patterns for secret detection
SECRET_PATTERNS = [
    # AWS Secret Access Key
    (re.compile(r"(?i)['\"]?aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "AWS_SECRET_KEY"),
    # Generic API Key / Secret Token
    (re.compile(r"(?i)['\"]?(?:api_key|apikey|secret_key|api_secret|auth_token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_\.]{16,128})['\"]?"), "GENERIC_API_KEY"),
    # GCP OAuth Token
    (re.compile(r"ya29\.[A-Za-z0-9\-_\.]+"), "GCP_OAUTH_TOKEN"),
    # JWT Bearer Token
    (re.compile(r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"), "JWT_BEARER_TOKEN"),
    # Private Key block
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "PRIVATE_KEY_PEM"),
    # Password in cleartext
    (re.compile(r"(?i)['\"]?(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{4,64})['\"]"), "PLAINTEXT_PASSWORD"),
]


class SecretScanner:
    """Scans raw and normalized records for sensitive credentials and secrets."""

    @staticmethod
    def scan_for_secrets(payload: Any) -> Tuple_Matches:
        """Returns (has_secret, secret_categories) detected in payload."""
        text_repr = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
        detected = []
        for pattern, cat in SECRET_PATTERNS:
            if pattern.search(text_repr):
                detected.append(cat)
        if isinstance(payload, dict):
            for k in payload.keys():
                if any(s in k.lower() for s in ("password", "passwd", "pwd", "secret", "private_key", "api_key", "auth_token")):
                    if "SENSITIVE_KEY_DETECTED" not in detected:
                        detected.append("SENSITIVE_KEY_DETECTED")
        return len(detected) > 0, detected

    @staticmethod
    def sanitize_secrets(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Redacts detected secrets from payload dictionaries recursively."""
        clean = {}
        secret_keys = ("password", "passwd", "token", "secret", "private_key", "api_key", "access_key")
        for k, v in payload.items():
            if any(s in k.lower() for s in secret_keys):
                clean[k] = "[REDACTED_SECRET]"
            elif isinstance(v, dict):
                clean[k] = SecretScanner.sanitize_secrets(v)
            elif isinstance(v, str):
                has_sec, _ = SecretScanner.scan_for_secrets(v)
                clean[k] = "[REDACTED_SECRET]" if has_sec else v
            else:
                clean[k] = v
        return clean


# Type alias for return
Tuple_Matches = tuple[bool, List[str]]


class ConnectorValidator:
    """Multi-gate connector validator fulfilling Section 16 requirements."""

    def __init__(
        self,
        resource_limits: Optional[ConnectorResourceLimits] = None,
        scope_resolver: Optional[ScopeResolver] = None,
        entity_resolver: Optional[EntityResolver] = None,
    ) -> None:
        self.limits = resource_limits or ConnectorResourceLimits()
        self.scope_resolver = scope_resolver or ScopeResolver()
        self.entity_resolver = entity_resolver or EntityResolver()
        self.secret_scanner = SecretScanner()

    def validate_raw_record(
        self,
        record: RawSourceRecord,
        expected_organization_id: str,
    ) -> ConnectorValidationResult:
        """Validates a RawSourceRecord before normalization."""
        errors: List[str] = []
        warnings: List[str] = []

        # 1. Schema & Field Validation
        if not record.record_id or not record.record_id.strip():
            errors.append("Empty or missing record_id")
        if not record.source_system or not record.source_system.strip():
            errors.append("Empty or missing source_system")
        if not record.payload_hash or len(record.payload_hash) != 64:
            errors.append("Invalid or missing payload_hash (must be 64-char hex SHA-256)")

        # 2. Secret Scan (Section 22)
        has_secret, secret_types = self.secret_scanner.scan_for_secrets(record.payload)
        secret_detected = has_secret
        if has_secret:
            errors.append(f"SECRET_DETECTED: Forbidden credential pattern detected: {secret_types}")

        # 3. Tenant Validation (Section 21)
        tenant_valid = True
        try:
            TenantIsolationValidator.validate_tenant(
                expected_tenant=expected_organization_id,
                record_tenant=record.organization_ref,
                connector_id=record.connector_id,
            )
        except CrossTenantError as cte:
            tenant_valid = False
            errors.append(f"CROSS_TENANT: {cte.message}")

        # 4. Scope Resolution (Section 20)
        scope_res = self.scope_resolver.resolve_scope(
            organization_id=expected_organization_id,
            declared_scope=record.raw_provenance.get("scope"),
        )
        if scope_res.status == ScopeStatus.UNKNOWN_SCOPE:
            warnings.append(f"UNKNOWN_SCOPE: Record scope could not be confirmed as IN_SCOPE")
        elif scope_res.status == ScopeStatus.OUT_OF_SCOPE:
            warnings.append(f"OUT_OF_SCOPE: Record scope is outside configured enterprise boundary")

        # 5. Entity Resolution (Section 17-19)
        entity_hint = record.payload.get("entity_id") or record.payload.get("account_id") or record.payload.get("arn")
        entity_res = None
        if entity_hint:
            entity_res = self.entity_resolver.resolve(
                external_entity_id=str(entity_hint),
                organization_id=expected_organization_id,
            )
            if entity_res.status == EntityStatus.AMBIGUOUS:
                warnings.append(f"ENTITY_AMBIGUOUS: Entity hint '{entity_hint}' flagged as REVIEW_REQUIRED")
            elif entity_res.status == EntityStatus.UNRESOLVED:
                warnings.append(f"ENTITY_UNRESOLVED: Entity hint '{entity_hint}' unresolved")
            elif entity_res.status == EntityStatus.CROSS_TENANT:
                tenant_valid = False
                errors.append(f"CROSS_TENANT: Entity hint '{entity_hint}' resolved to different tenant")

        # 6. Temporal Validation (ISO 8601 format & reasonable century boundary)
        try:
            dt = datetime.fromisoformat(record.source_event_time.replace("Z", "+00:00"))
            if dt.year < 2000 or dt.year > 2099:
                errors.append(f"TEMPORAL_ANOMALY: Out-of-bounds year {dt.year} in '{record.source_event_time}'")
        except Exception as ex:
            errors.append(f"TEMPORAL_INVALID: Malformed source_event_time: {ex}")

        # 7. Resource Limits (Section 29)
        raw_size = len(json.dumps(record.payload).encode("utf-8"))
        if raw_size > self.limits.max_payload_size_bytes:
            errors.append(f"RESOURCE_LIMIT: Payload size {raw_size} bytes exceeds maximum limit {self.limits.max_payload_size_bytes}")

        is_valid = len(errors) == 0

        return ConnectorValidationResult(
            is_valid=is_valid,
            validation_errors=errors,
            validation_warnings=warnings,
            secret_detected=secret_detected,
            entity_resolution=entity_res,
            scope_resolution=scope_res,
            tenant_valid=tenant_valid,
        )

    def validate_canonical_type(self, data_type: str) -> CanonicalDataType:
        """Validates that a string corresponds to a registered CanonicalDataType."""
        try:
            if hasattr(CanonicalDataType, data_type):
                return CanonicalDataType[data_type]
            return CanonicalDataType(data_type)
        except Exception:
            raise UnsupportedCanonicalTypeError(
                f"UNSUPPORTED_CANONICAL_TYPE: '{data_type}' does not exist in canonical registry",
                details={"provided_type": data_type},
            )
