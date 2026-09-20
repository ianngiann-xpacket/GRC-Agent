"""Phase 33-B: Production Entity & Scope Resolver for Prowler GCP.

Decouples production entity resolution from the Synthetic EntityGraph.
Enforces:
- Explicit GCP project resolution with cross-tenant blocking
- GCP resource identifier resolution to internal canonical entity references
- Fail-closed ambiguity and unresolved handling (REVIEW_REQUIRED / UNRESOLVED)
- Scope boundary verification (UNKNOWN_SCOPE != IN_SCOPE)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from secgrc.connectors.errors import CrossTenantError
from secgrc.connectors.models import (
    EntityResolutionResult,
    EntityStatus,
    ScopeResolutionResult,
    ScopeStatus,
)


class ProductionEntityResolver:
    """Resolves GCP projects and cloud resources to internal enterprise entities."""

    def __init__(
        self,
        project_mappings: Optional[Dict[str, str]] = None,
        resource_mappings: Optional[Dict[str, str]] = None,
        tenant_projects: Optional[Dict[str, Set[str]]] = None,
        ambiguous_entries: Optional[Set[str]] = None,
    ) -> None:
        # project_id -> canonical_account_ref
        self._project_mappings = project_mappings or {
            "gcp-prod-kr-001": "ORG-REAL-001-CLOUD-ACCOUNT-0001",
            "gcp-syn-project-001": "ORG-SYN-001-CLOUD-ACCOUNT-0001",
            "gcp-proj-prod-01": "ORG-SYN-001-GCP-PROD",
            "gcp-foreign-tenant-999": "ORG-FOREIGN-001-ACCOUNT-0001",
        }
        # resource_id / ARN -> internal_entity_ref
        self._resource_mappings = resource_mappings or {
            "bucket-prod-kr-data": "ORG-REAL-001-RES-GCS-0001",
            "bucket-syn-001": "ORG-SYN-001-CLOUD-RESOURCE-0001",
            "vm-prod-app-01": "ORG-REAL-001-RES-GCE-0001",
            "fw-allow-ssh-all": "ORG-REAL-001-RES-FW-0001",
            "sa-admin-service": "ORG-REAL-001-RES-IAM-0001",
            "kms-key-database": "ORG-REAL-001-RES-KMS-0001",
        }
        # tenant_id -> set of allowed project_ids
        self._tenant_projects = tenant_projects or {
            "ORG-REAL-001": {"gcp-prod-kr-001"},
            "ORG-SYN-001": {"gcp-syn-project-001", "gcp-proj-prod-01"},
        }
        self._ambiguous_entries = ambiguous_entries or {"ambiguous-resource-ref"}

    def resolve_project(
        self,
        source_project_id: str,
        expected_tenant_id: str,
    ) -> EntityResolutionResult:
        """Resolves GCP project identifier to internal cloud account entity."""
        clean_proj = (source_project_id or "").strip()
        if not clean_proj:
            return EntityResolutionResult(
                status=EntityStatus.UNRESOLVED,
                external_entity_id="",
                confidence=0.0,
                notes="Empty GCP project ID",
            )

        if clean_proj in self._ambiguous_entries:
            return EntityResolutionResult(
                status=EntityStatus.AMBIGUOUS,
                external_entity_id=clean_proj,
                confidence=0.5,
                notes="Ambiguous project mapping; flagged as REVIEW_REQUIRED",
            )

        # Cross-tenant check
        allowed_projects = self._tenant_projects.get(expected_tenant_id, set())
        if clean_proj in self._project_mappings:
            target_ref = self._project_mappings[clean_proj]
            if allowed_projects and clean_proj not in allowed_projects:
                return EntityResolutionResult(
                    status=EntityStatus.CROSS_TENANT,
                    external_entity_id=clean_proj,
                    internal_entity_ref=target_ref,
                    confidence=1.0,
                    notes=f"Project '{clean_proj}' belongs to different tenant",
                )
            return EntityResolutionResult(
                status=EntityStatus.RESOLVED,
                external_entity_id=clean_proj,
                internal_entity_ref=target_ref,
                resolution_strategy="exact_mapping",
                confidence=1.0,
            )

        # Unresolved fails closed
        return EntityResolutionResult(
            status=EntityStatus.UNRESOLVED,
            external_entity_id=clean_proj,
            confidence=0.0,
            notes=f"Project '{clean_proj}' not registered in production registry",
        )

    def resolve_resource(
        self,
        resource_id: str,
        resource_type: str = "",
        project_id: str = "",
        expected_tenant_id: str = "",
    ) -> EntityResolutionResult:
        """Resolves external cloud resource ID to internal production entity."""
        clean_res = (resource_id or "").strip()
        if not clean_res:
            return EntityResolutionResult(
                status=EntityStatus.UNRESOLVED,
                external_entity_id="",
                confidence=0.0,
                notes="Empty resource ID",
            )

        if clean_res in self._ambiguous_entries:
            return EntityResolutionResult(
                status=EntityStatus.AMBIGUOUS,
                external_entity_id=clean_res,
                confidence=0.5,
                notes="Ambiguous resource identifier; flagged as REVIEW_REQUIRED",
            )

        # Direct mapped lookup
        if clean_res in self._resource_mappings:
            internal_ref = self._resource_mappings[clean_res]
            return EntityResolutionResult(
                status=EntityStatus.RESOLVED,
                external_entity_id=clean_res,
                internal_entity_ref=internal_ref,
                resolution_strategy="exact_resource_mapping",
                confidence=1.0,
            )

        # Standard GCP URI extraction
        # e.g. //storage.googleapis.com/buckets/bucket-name or //compute.googleapis.com/projects/.../firewalls/fw-name
        extracted_name = clean_res.rstrip("/").split("/")[-1]
        if extracted_name in self._resource_mappings:
            return EntityResolutionResult(
                status=EntityStatus.RESOLVED,
                external_entity_id=clean_res,
                internal_entity_ref=self._resource_mappings[extracted_name],
                resolution_strategy="uri_parsed_mapping",
                confidence=0.95,
            )

        match = re.search(r"//[a-z\.]+/projects/[^/]+/[^/]+/([^/]+)", clean_res)
        if match:
            extracted_name = match.group(1)
            if extracted_name in self._resource_mappings:
                return EntityResolutionResult(
                    status=EntityStatus.RESOLVED,
                    external_entity_id=clean_res,
                    internal_entity_ref=self._resource_mappings[extracted_name],
                    resolution_strategy="uri_parsed_mapping",
                    confidence=0.9,
                )

        # Fallback: unresolved fails closed
        return EntityResolutionResult(
            status=EntityStatus.UNRESOLVED,
            external_entity_id=clean_res,
            confidence=0.0,
            notes=f"Resource '{clean_res}' ({resource_type}) not found in production registry",
        )

    def resolve_scope(
        self,
        project_id: str,
        target_projects: List[str],
        organization_id: str,
        declared_scope: Optional[str] = None,
    ) -> ScopeResolutionResult:
        """Evaluates whether a finding is IN_SCOPE, OUT_OF_SCOPE, or UNKNOWN_SCOPE."""
        if not project_id:
            return ScopeResolutionResult(
                status=ScopeStatus.UNKNOWN_SCOPE,
                organization_id=organization_id,
                notes="Unspecified project scope cannot be assumed IN_SCOPE",
            )

        if target_projects and project_id in target_projects:
            return ScopeResolutionResult(
                status=ScopeStatus.IN_SCOPE,
                organization_id=organization_id,
                scope_id=declared_scope or "GCP_TARGET_SCOPE",
            )

        return ScopeResolutionResult(
            status=ScopeStatus.OUT_OF_SCOPE,
            organization_id=organization_id,
            scope_id=declared_scope,
            notes=f"Project '{project_id}' is outside targeted project list {target_projects}",
        )
