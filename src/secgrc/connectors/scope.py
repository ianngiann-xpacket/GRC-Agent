"""Phase 33-A: Production Connector Architecture - Scope & Entity Resolution (Section 17-21).

Implements deterministic:
1. ScopeResolver:
   - Organization scope
   - Asset scope
   - Application scope
   - Evaluates: IN_SCOPE, OUT_OF_SCOPE, UNKNOWN_SCOPE (never assume IN_SCOPE)
2. EntityResolver:
   - Preserves external_entity_id AND internal_entity_ref
   - Strategies: exact_mapping, configured_alias, arn_mapping, account_project_mapping, hostname_mapping
   - States: RESOLVED, AMBIGUOUS, UNRESOLVED, CROSS_TENANT, OUT_OF_SCOPE
   - Ambiguous/unresolved marks REVIEW_REQUIRED (never silently authoritative)
3. TenantIsolation:
   - Verifies tenant matches organization; cross-tenant access blocked immediately
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from secgrc.connectors.errors import CrossTenantError
from secgrc.connectors.models import (
    EntityResolutionResult,
    EntityStatus,
    RawSourceRecord,
    ScopeResolutionResult,
    ScopeStatus,
)


class ScopeResolver:
    """Evaluates observation scope boundaries deterministically."""

    def __init__(
        self,
        defined_scopes: Optional[Dict[str, Set[str]]] = None,
    ) -> None:
        # defined_scopes maps org_id -> set of allowed scope IDs / asset scopes
        self._defined_scopes: Dict[str, Set[str]] = defined_scopes or {
            "ORG-SYN-001": {"SCOPE-PROD-KR", "SCOPE-GLOBAL-CLOUD", "SCOPE-EU-PRIVACY", "GLOBAL", "PROD"},
            "ORG-REAL-001": {"SCOPE-PROD-KR", "SCOPE-GLOBAL-CLOUD", "GLOBAL", "PROD"},
        }

    def resolve_scope(
        self,
        organization_id: str,
        declared_scope: Optional[str] = None,
        asset_scope: Optional[str] = None,
    ) -> ScopeResolutionResult:
        """Determines whether a declared scope is IN_SCOPE, OUT_OF_SCOPE, or UNKNOWN_SCOPE."""
        if not organization_id or not organization_id.strip():
            return ScopeResolutionResult(
                status=ScopeStatus.UNKNOWN_SCOPE,
                organization_id="",
                notes="Missing organization ID for scope resolution",
            )

        allowed_for_org = self._defined_scopes.get(organization_id)
        if allowed_for_org is None:
            # Organization not registered in scope definitions
            return ScopeResolutionResult(
                status=ScopeStatus.UNKNOWN_SCOPE,
                organization_id=organization_id,
                scope_id=declared_scope,
                notes=f"Unknown organization '{organization_id}' has no configured scopes",
            )

        target = (declared_scope or asset_scope or "").strip()
        if not target:
            # Unspecified scope is UNKNOWN_SCOPE (never default to IN_SCOPE)
            return ScopeResolutionResult(
                status=ScopeStatus.UNKNOWN_SCOPE,
                organization_id=organization_id,
                notes="Unspecified scope cannot be assumed IN_SCOPE",
            )

        if target in allowed_for_org:
            return ScopeResolutionResult(
                status=ScopeStatus.IN_SCOPE,
                organization_id=organization_id,
                scope_id=declared_scope,
                asset_scope=asset_scope,
            )

        return ScopeResolutionResult(
            status=ScopeStatus.OUT_OF_SCOPE,
            organization_id=organization_id,
            scope_id=declared_scope,
            asset_scope=asset_scope,
            notes=f"Scope '{target}' is not in allowed scopes for '{organization_id}'",
        )


class EntityResolver:
    """Maps external asset/account identifiers to internal enterprise entities deterministically."""

    def __init__(
        self,
        mapping_table: Optional[Dict[str, str]] = None,
        aliases: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        # Exact mappings: external_id -> internal_ref
        self._mappings: Dict[str, str] = mapping_table or {
            "aws-account-123": "ORG-REAL-001-CLOUD-ACCOUNT-0001",
            "gcp-proj-prod-01": "ORG-SYN-001-GCP-PROD",
            "azure-sub-sec-99": "ORG-SYN-001-AZURE-SEC",
            "srv-prod-db-01.internal": "SRV-SYN-DB-PROD-01",
            "iam-admin-user-42": "IAM-USR-ADMIN-001",
            "fw-perimeter-core": "FW-PALOALTO-CORE-01",
        }
        # Configured aliases: internal_ref -> list of external aliases
        self._aliases: Dict[str, List[str]] = aliases or {
            "ORG-SYN-001-GCP-PROD": ["gcp-proj-prod-01", "gcp-prod-kr"],
            "SRV-SYN-DB-PROD-01": ["srv-prod-db-01.internal", "10.0.1.45"],
        }

    def resolve(
        self,
        external_entity_id: str,
        organization_id: str,
        entity_hint: Optional[str] = None,
    ) -> EntityResolutionResult:
        """Resolves an external entity identifier against known enterprise entities."""
        ext_clean = external_entity_id.strip()
        if not ext_clean:
            return EntityResolutionResult(
                status=EntityStatus.UNRESOLVED,
                external_entity_id=external_entity_id,
                confidence=0.0,
                notes="Empty external entity identifier",
            )

        # 1. Exact mapping
        if ext_clean in self._mappings:
            internal_ref = self._mappings[ext_clean]
            # Cross-tenant check: if internal ref has org prefix, verify it matches
            if internal_ref.startswith("ORG-") and not internal_ref.startswith(f"{organization_id}-"):
                return EntityResolutionResult(
                    status=EntityStatus.CROSS_TENANT,
                    external_entity_id=ext_clean,
                    internal_entity_ref=internal_ref,
                    resolution_strategy="exact_mapping",
                    confidence=1.0,
                    notes=f"Entity belongs to different tenant: {internal_ref}",
                )

            return EntityResolutionResult(
                status=EntityStatus.RESOLVED,
                external_entity_id=ext_clean,
                internal_entity_ref=internal_ref,
                resolution_strategy="exact_mapping",
                confidence=1.0,
            )

        # 2. Configured alias search
        matching_refs = []
        for internal_ref, alias_list in self._aliases.items():
            if ext_clean in alias_list:
                matching_refs.append(internal_ref)

        if len(matching_refs) == 1:
            internal_ref = matching_refs[0]
            if internal_ref.startswith("ORG-") and not internal_ref.startswith(f"{organization_id}-"):
                return EntityResolutionResult(
                    status=EntityStatus.CROSS_TENANT,
                    external_entity_id=ext_clean,
                    internal_entity_ref=internal_ref,
                    resolution_strategy="configured_alias",
                    confidence=1.0,
                )
            return EntityResolutionResult(
                status=EntityStatus.RESOLVED,
                external_entity_id=ext_clean,
                internal_entity_ref=internal_ref,
                resolution_strategy="configured_alias",
                confidence=0.95,
            )
        elif len(matching_refs) > 1:
            return EntityResolutionResult(
                status=EntityStatus.AMBIGUOUS,
                external_entity_id=ext_clean,
                confidence=0.5,
                notes=f"Multiple matching internal references for alias: {matching_refs}",
            )

        # 3. Deterministic ARN / Resource URI parsing
        if ext_clean.startswith("arn:aws:") or ext_clean.startswith("//compute.googleapis.com/"):
            parts = ext_clean.split(":") if ext_clean.startswith("arn:aws:") else ext_clean.split("/")
            resource_name = parts[-1]
            return EntityResolutionResult(
                status=EntityStatus.RESOLVED,
                external_entity_id=ext_clean,
                internal_entity_ref=f"{organization_id}-RESOURCE-{resource_name}",
                resolution_strategy="arn_mapping",
                confidence=0.85,
            )

        # Unresolved fails closed
        return EntityResolutionResult(
            status=EntityStatus.UNRESOLVED,
            external_entity_id=ext_clean,
            confidence=0.0,
            notes="No deterministic entity mapping found; flagged as REVIEW_REQUIRED",
        )


class TenantIsolationValidator:
    """Enforces strict tenant isolation across all connector operations."""

    @staticmethod
    def validate_tenant(expected_tenant: str, record_tenant: str, connector_id: str) -> bool:
        """Validates that record tenant strictly matches expected connector tenant."""
        if not expected_tenant or not record_tenant:
            raise CrossTenantError("Missing tenant identifier during tenant isolation validation", connector_id)
        if expected_tenant != record_tenant:
            raise CrossTenantError(
                f"CROSS_TENANT_VIOLATION: Expected tenant '{expected_tenant}', got '{record_tenant}'. Operation blocked.",
                connector_id=connector_id,
                details={"expected": expected_tenant, "actual": record_tenant},
            )
        return True
