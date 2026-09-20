"""Step 33-D: Deterministic GCP Entity Resolver (Sections 8, 9, 10, 11, 12, 13, 14, 15, 24).

Implements the 10-step deterministic resolution algorithm:
1. Normalize source identity
2. Validate tenant (prevent cross-tenant contamination)
3. Execute exact lookups (full_resource_name, self_link, canonical_resource_key, composite key)
4. Execute registered alias lookups
5. Detect ambiguity (fail-closed, record all candidates)
6. Detect orphan sources (valid GCP resource absent from EnterpriseState; zero mutation)
7. Validate compliance scope (WRONG_SCOPE if out-of-scope)
8. Preserve provenance and original source identity
9. Emit immutable EntityResolutionResult stamped with SHA-256 resolution_hash.

CRITICAL INVARIANTS:
- Zero LLM dependency
- Zero fuzzy guessing
- Zero silent mutations to EnterpriseState
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Set

from secgrc.connectors.resolution.models import (
    EntityResolutionResult,
    EntityResolutionStatus,
    GCPResourceIdentity,
    MatchMethod,
    ResolutionConfidenceClass,
    compute_resolution_hash,
)
from secgrc.connectors.resolution.normalizer import GCPIdentityNormalizer
from secgrc.connectors.resolution.registry import GCPResourceIdentityRegistry, RegistryEntry


class DeterministicGCPResolver:
    """Deterministic, fail-closed entity resolver for GCP cloud observations."""

    def __init__(self, registry: Optional[GCPResourceIdentityRegistry] = None) -> None:
        self.registry = registry or GCPResourceIdentityRegistry()

    def resolve(
        self,
        source_record_id: str,
        source_resource_locator: str,
        tenant_id: str,
        target_scope_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> EntityResolutionResult:
        """Deterministically resolves a GCP source observation to an Enterprise Entity.

        Args:
            source_record_id: Identifier of the source observation record.
            source_resource_locator: Raw resource string (URI, URL, gs://, name, ID).
            tenant_id: Expected active tenant/organization context.
            target_scope_id: Optional compliance scope evaluated against (e.g. SCOPE-PROD-KR).
            context: Additional vendor metadata (e.g. project_id, service, finding_id).
            provenance: Preserved provenance dictionary.
        """
        ctx = context or {}
        prov = provenance or {}

        # ----------------------------------------------------------------------
        # Step 1: Normalize source identity
        # ----------------------------------------------------------------------
        try:
            norm_ident = GCPIdentityNormalizer.normalize(source_resource_locator, ctx)
        except ValueError as exc:
            return self._build_result(
                source_record_id=source_record_id,
                source_resource_identity=source_resource_locator,
                normalized_identity=None,
                matched_entry=None,
                status=EntityResolutionStatus.INVALID_IDENTITY,
                match_method=MatchMethod.NONE,
                confidence=ResolutionConfidenceClass.UNRESOLVED,
                tenant_id=tenant_id,
                scope_id=target_scope_id,
                provenance=prov,
                reason=f"Failed to normalize GCP identity: {exc}",
            )

        # ----------------------------------------------------------------------
        # Step 2: Validate tenant (Cross-tenant check)
        # ----------------------------------------------------------------------
        # A. Declared source tenant vs expected tenant
        src_tenant = ctx.get("tenant_id") or prov.get("tenant_id")
        if src_tenant and src_tenant != tenant_id:
            return self._build_result(
                source_record_id=source_record_id,
                source_resource_identity=source_resource_locator,
                normalized_identity=norm_ident,
                matched_entry=None,
                status=EntityResolutionStatus.CROSS_TENANT,
                match_method=MatchMethod.NONE,
                confidence=ResolutionConfidenceClass.UNRESOLVED,
                tenant_id=tenant_id,
                scope_id=target_scope_id,
                provenance=prov,
                reason=f"Source record tenant '{src_tenant}' does not match active tenant '{tenant_id}'",
            )

        # B. Project ownership cross-tenant check
        if norm_ident.project_id:
            owner_tenant = self.registry.get_tenant_for_project(norm_ident.project_id)
            if owner_tenant and owner_tenant != tenant_id:
                return self._build_result(
                    source_record_id=source_record_id,
                    source_resource_identity=source_resource_locator,
                    normalized_identity=norm_ident,
                    matched_entry=None,
                    status=EntityResolutionStatus.CROSS_TENANT,
                    match_method=MatchMethod.NONE,
                    confidence=ResolutionConfidenceClass.UNRESOLVED,
                    tenant_id=tenant_id,
                    scope_id=target_scope_id,
                    provenance=prov,
                    reason=f"GCP project '{norm_ident.project_id}' belongs to tenant '{owner_tenant}', not active tenant '{tenant_id}'",
                )

        # ----------------------------------------------------------------------
        # Step 3: Exact lookups in preferred order (Section 9)
        # ----------------------------------------------------------------------
        candidates: List[Tuple[RegistryEntry, MatchMethod]] = []

        # Case 1: Full resource name exact match
        if norm_ident.full_resource_name:
            fn_matches = self.registry.lookup_by_full_name(tenant_id, norm_ident.full_resource_name)
            for m in fn_matches:
                candidates.append((m, MatchMethod.FULL_RESOURCE_NAME))

        # Case 2: Self-link exact match
        if not candidates and norm_ident.self_link:
            sl_matches = self.registry.lookup_by_self_link(tenant_id, norm_ident.self_link)
            for m in sl_matches:
                candidates.append((m, MatchMethod.SELF_LINK))

        # Case 3: Canonical resource key exact match
        if not candidates and norm_ident.canonical_resource_key:
            ck_matches = self.registry.lookup_by_canonical_key(tenant_id, norm_ident.canonical_resource_key)
            for m in ck_matches:
                candidates.append((m, MatchMethod.CANONICAL_RESOURCE_KEY))

        # Case 4: Composite key (type + project + id)
        if not candidates and norm_ident.resource_type and norm_ident.project_id and norm_ident.resource_id:
            comp_matches = self.registry.lookup_by_resource_composite(
                tenant_id,
                norm_ident.resource_type,
                norm_ident.project_id,
                norm_ident.resource_id,
            )
            for m in comp_matches:
                candidates.append((m, MatchMethod.COMPOSITE_KEY))

        # ----------------------------------------------------------------------
        # Step 4: Registered alias lookup (Section 10)
        # ----------------------------------------------------------------------
        if not candidates:
            # Check resource name as alias
            alias_to_check = norm_ident.resource_name or norm_ident.resource_id
            if alias_to_check:
                alias_entry = self.registry.lookup_by_alias(tenant_id, alias_to_check)
                if alias_entry:
                    candidates.append((alias_entry, MatchMethod.REGISTERED_ALIAS))

        # ----------------------------------------------------------------------
        # Step 5: Ambiguity detection (Section 11)
        # ----------------------------------------------------------------------
        # Deduplicate candidates by entity_id
        unique_candidate_map: Dict[str, Tuple[RegistryEntry, MatchMethod]] = {}
        for entry, method in candidates:
            if entry.entity_id not in unique_candidate_map:
                unique_candidate_map[entry.entity_id] = (entry, method)

        if len(unique_candidate_map) > 1:
            # Multiple candidates found -> Ambiguous match! Fail-closed.
            cand_ids = sorted(list(unique_candidate_map.keys()))
            return self._build_result(
                source_record_id=source_record_id,
                source_resource_identity=source_resource_locator,
                normalized_identity=norm_ident,
                matched_entry=None,
                status=EntityResolutionStatus.AMBIGUOUS_MATCH,
                match_method=MatchMethod.NONE,
                confidence=ResolutionConfidenceClass.AMBIGUOUS,
                candidate_ids=cand_ids,
                tenant_id=tenant_id,
                scope_id=target_scope_id,
                provenance=prov,
                reason=f"Ambiguous match: {len(cand_ids)} candidate entities found: {cand_ids}",
            )

        # ----------------------------------------------------------------------
        # Step 6: Orphan detection (Sections 12 & 13)
        # ----------------------------------------------------------------------
        if len(unique_candidate_map) == 0:
            # Valid GCP resource identity, but absent in EnterpriseState
            if norm_ident.project_id and norm_ident.resource_id:
                return self._build_result(
                    source_record_id=source_record_id,
                    source_resource_identity=source_resource_locator,
                    normalized_identity=norm_ident,
                    matched_entry=None,
                    status=EntityResolutionStatus.ORPHAN_SOURCE,
                    match_method=MatchMethod.NONE,
                    confidence=ResolutionConfidenceClass.UNRESOLVED,
                    tenant_id=tenant_id,
                    scope_id=target_scope_id,
                    provenance=prov,
                    reason=f"Valid GCP resource '{norm_ident.canonical_resource_key}' not present in baseline EnterpriseState (ORPHAN)",
                )
            return self._build_result(
                source_record_id=source_record_id,
                source_resource_identity=source_resource_locator,
                normalized_identity=norm_ident,
                matched_entry=None,
                status=EntityResolutionStatus.NO_MATCH,
                match_method=MatchMethod.NONE,
                confidence=ResolutionConfidenceClass.UNRESOLVED,
                tenant_id=tenant_id,
                scope_id=target_scope_id,
                provenance=prov,
                reason="No matching enterprise entity found",
            )

        # ----------------------------------------------------------------------
        # Step 7: Scope validation (Section 14)
        # ----------------------------------------------------------------------
        matched_entry, match_method = next(iter(unique_candidate_map.values()))

        if target_scope_id and target_scope_id != "GLOBAL":
            allowed_scopes = matched_entry.scope_ids or {"GLOBAL"}
            if target_scope_id not in allowed_scopes and "GLOBAL" not in allowed_scopes:
                return self._build_result(
                    source_record_id=source_record_id,
                    source_resource_identity=source_resource_locator,
                    normalized_identity=norm_ident,
                    matched_entry=matched_entry,
                    status=EntityResolutionStatus.WRONG_SCOPE,
                    match_method=match_method,
                    confidence=ResolutionConfidenceClass.AUTHORITATIVE_EXACT if match_method != MatchMethod.REGISTERED_ALIAS else ResolutionConfidenceClass.REGISTERED_ALIAS,
                    tenant_id=tenant_id,
                    scope_id=target_scope_id,
                    provenance=prov,
                    reason=f"Entity {matched_entry.entity_id} is in scopes {sorted(allowed_scopes)}, outside requested scope '{target_scope_id}'",
                )

        # ----------------------------------------------------------------------
        # Step 8: Success Match (EXACT or ALIAS)
        # ----------------------------------------------------------------------
        final_status = (
            EntityResolutionStatus.ALIAS_MATCH
            if match_method == MatchMethod.REGISTERED_ALIAS
            else EntityResolutionStatus.EXACT_MATCH
        )
        conf = (
            ResolutionConfidenceClass.REGISTERED_ALIAS
            if match_method == MatchMethod.REGISTERED_ALIAS
            else ResolutionConfidenceClass.AUTHORITATIVE_EXACT
        )

        return self._build_result(
            source_record_id=source_record_id,
            source_resource_identity=source_resource_locator,
            normalized_identity=norm_ident,
            matched_entry=matched_entry,
            status=final_status,
            match_method=match_method,
            confidence=conf,
            tenant_id=tenant_id,
            scope_id=target_scope_id,
            provenance=prov,
            reason=f"Deterministically resolved via {match_method.value} to {matched_entry.entity_id}",
        )

    # --------------------------------------------------------------------------
    # Helper Builder
    # --------------------------------------------------------------------------

    def _build_result(
        self,
        source_record_id: str,
        source_resource_identity: str,
        normalized_identity: Optional[GCPResourceIdentity],
        matched_entry: Optional[RegistryEntry],
        status: EntityResolutionStatus,
        match_method: MatchMethod,
        confidence: ResolutionConfidenceClass,
        tenant_id: str,
        scope_id: Optional[str],
        provenance: Dict[str, Any],
        reason: str,
        candidate_ids: Optional[List[str]] = None,
    ) -> EntityResolutionResult:
        h_input = f"{source_record_id}:{source_resource_identity}:{tenant_id}:{status.value}"
        res_suffix = hashlib.sha256(h_input.encode("utf-8")).hexdigest()[:12]
        res_id = f"RES-{source_record_id[:16]}-{res_suffix}"

        matched_id = matched_entry.entity_id if matched_entry else None
        matched_type = matched_entry.entity_type if matched_entry else None

        raw_dict = {
            "resolution_id": res_id,
            "source_record_id": source_record_id,
            "source_resource_identity": source_resource_identity,
            "matched_entity_id": matched_id,
            "matched_entity_type": matched_type,
            "status": status.value,
            "match_method": match_method.value,
            "confidence_class": confidence.value,
            "candidate_entity_ids": candidate_ids or [],
            "tenant_id": tenant_id,
            "scope_id": scope_id or "GLOBAL",
            "resolver_version": "1.0.0",
        }
        res_hash = compute_resolution_hash(raw_dict)

        return EntityResolutionResult(
            resolution_id=res_id,
            source_record_id=source_record_id,
            provider="GCP",
            source_resource_identity=source_resource_identity,
            normalized_resource_identity=normalized_identity,
            matched_entity_id=matched_id,
            matched_entity_type=matched_type,
            status=status,
            match_method=match_method,
            confidence_class=confidence,
            candidate_entity_ids=candidate_ids or [],
            tenant_id=tenant_id,
            scope_id=scope_id or "GLOBAL",
            provenance=provenance,
            resolution_reason=reason,
            resolver_version="1.0.0",
            resolution_hash=res_hash,
        )
