"""Step 33-D: Tenant-Aware GCP Resource Identity Registry & Indexer (Sections 7, 10, 15).

Creates a deterministic, in-memory namespaced index over EnterpriseState and EntityGraph.
Guarantees:
- Strict tenant isolation: all index keys are namespaced by tenant_id
- Namespaced lookup: GCP_PROJECT, GCP_FULL_NAME, GCP_SELF_LINK, GCP_RESOURCE, GCP_ALIAS
- Deterministic alias registration with collision prevention
- Zero cross-tenant fallback or name-only leakage
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from secgrc.connectors.resolution.models import GCPResourceIdentity


class RegistryEntry:
    """Entry stored in the identity index."""
    __slots__ = ("entity_id", "entity_type", "tenant_id", "canonical_resource_key", "metadata", "scope_ids")

    def __init__(
        self,
        entity_id: str,
        entity_type: str,
        tenant_id: str,
        canonical_resource_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        scope_ids: Optional[Set[str]] = None,
    ):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.tenant_id = tenant_id
        self.canonical_resource_key = canonical_resource_key
        self.metadata = metadata or {}
        self.scope_ids = scope_ids or set()

    def __repr__(self) -> str:
        return f"<RegistryEntry {self.entity_type}:{self.entity_id} tenant={self.tenant_id}>"


class GCPResourceIdentityRegistry:
    """Namespaced index over enterprise cloud resources and entities."""

    def __init__(self) -> None:
        # Key format: <NAMESPACE>:<TENANT_ID>:<KEY_DATA>
        self._index: Dict[str, List[RegistryEntry]] = {}
        # Explicit registered aliases: GCP_ALIAS:<TENANT_ID>:<ALIAS> -> RegistryEntry
        self._alias_index: Dict[str, RegistryEntry] = {}
        # Known tenant IDs
        self._known_tenants: Set[str] = set()
        # Tenant -> set of authorized project IDs
        self._tenant_projects: Dict[str, Set[str]] = {}

    # --------------------------------------------------------------------------
    # Index Construction
    # --------------------------------------------------------------------------

    def register_entry(
        self,
        entry: RegistryEntry,
        identity: Optional[GCPResourceIdentity] = None,
        aliases: Optional[List[str]] = None,
    ) -> None:
        """Registers an enterprise entity into the namespaced index."""
        t_id = entry.tenant_id
        self._known_tenants.add(t_id)

        if identity:
            # 1. Project index
            if identity.project_id:
                self._add_tenant_project(t_id, identity.project_id)
                proj_key = f"GCP_PROJECT:{t_id}:{identity.project_id.lower()}"
                self._append_to_index(proj_key, entry)

            # 2. Full resource name index
            if identity.full_resource_name:
                fn_key = f"GCP_FULL_NAME:{t_id}:{identity.full_resource_name.strip()}"
                self._append_to_index(fn_key, entry)

            # 3. Self-link index
            if identity.self_link:
                sl_key = f"GCP_SELF_LINK:{t_id}:{identity.self_link.strip()}"
                self._append_to_index(sl_key, entry)

            # 4. Canonical resource key index
            if identity.canonical_resource_key:
                ck_key = f"GCP_CANONICAL:{t_id}:{identity.canonical_resource_key.strip().lower()}"
                self._append_to_index(ck_key, entry)

            # 5. Composite resource key (type + project + id)
            if identity.project_id and identity.resource_type and identity.resource_id:
                comp_key = f"GCP_RESOURCE:{t_id}:{identity.resource_type.lower()}:{identity.project_id.lower()}:{identity.resource_id.strip()}"
                self._append_to_index(comp_key, entry)

        # 6. Explicit aliases
        if aliases:
            for alias in aliases:
                self.register_alias(
                    tenant_id=t_id,
                    alias=alias,
                    entity_id=entry.entity_id,
                    entity_type=entry.entity_type,
                    canonical_resource_key=entry.canonical_resource_key,
                    scope_ids=entry.scope_ids,
                )

    def register_alias(
        self,
        tenant_id: str,
        alias: str,
        entity_id: str,
        entity_type: str,
        canonical_resource_key: Optional[str] = None,
        scope_ids: Optional[Set[str]] = None,
    ) -> None:
        """Explicitly registers a unique alias for an entity within a tenant context."""
        clean_alias = alias.strip().lower()
        if not clean_alias:
            raise ValueError("Alias cannot be empty")

        alias_key = f"GCP_ALIAS:{tenant_id}:{clean_alias}"
        existing = self._alias_index.get(alias_key)
        if existing:
            if existing.entity_id != entity_id:
                raise ValueError(
                    f"Alias collision: '{alias}' already mapped to {existing.entity_id}, "
                    f"cannot reassign to {entity_id} in tenant '{tenant_id}'"
                )
            return  # Idempotent re-registration

        entry = RegistryEntry(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=tenant_id,
            canonical_resource_key=canonical_resource_key,
            scope_ids=scope_ids,
        )
        self._alias_index[alias_key] = entry
        self._append_to_index(alias_key, entry)

    def _append_to_index(self, key: str, entry: RegistryEntry) -> None:
        entries = self._index.setdefault(key, [])
        if not any(e.entity_id == entry.entity_id and e.tenant_id == entry.tenant_id for e in entries):
            entries.append(entry)

    def _add_tenant_project(self, tenant_id: str, project_id: str) -> None:
        projs = self._tenant_projects.setdefault(tenant_id, set())
        projs.add(project_id.lower())

    # --------------------------------------------------------------------------
    # Deterministic Query Operations
    # --------------------------------------------------------------------------

    def is_known_tenant(self, tenant_id: str) -> bool:
        return tenant_id in self._known_tenants

    def is_tenant_project(self, tenant_id: str, project_id: str) -> bool:
        allowed = self._tenant_projects.get(tenant_id, set())
        return (project_id or "").strip().lower() in allowed

    def get_tenant_for_project(self, project_id: str) -> Optional[str]:
        p = (project_id or "").strip().lower()
        for t, projs in self._tenant_projects.items():
            if p in projs:
                return t
        return None

    def lookup_by_full_name(self, tenant_id: str, full_resource_name: str) -> List[RegistryEntry]:
        key = f"GCP_FULL_NAME:{tenant_id}:{full_resource_name.strip()}"
        return self._index.get(key, [])

    def lookup_by_self_link(self, tenant_id: str, self_link: str) -> List[RegistryEntry]:
        key = f"GCP_SELF_LINK:{tenant_id}:{self_link.strip()}"
        return self._index.get(key, [])

    def lookup_by_canonical_key(self, tenant_id: str, canonical_key: str) -> List[RegistryEntry]:
        key = f"GCP_CANONICAL:{tenant_id}:{canonical_key.strip().lower()}"
        return self._index.get(key, [])

    def lookup_by_resource_composite(
        self,
        tenant_id: str,
        resource_type: str,
        project_id: str,
        resource_id: str,
    ) -> List[RegistryEntry]:
        key = f"GCP_RESOURCE:{tenant_id}:{resource_type.lower()}:{project_id.lower()}:{resource_id.strip()}"
        return self._index.get(key, [])

    def lookup_by_alias(self, tenant_id: str, alias: str) -> Optional[RegistryEntry]:
        key = f"GCP_ALIAS:{tenant_id}:{alias.strip().lower()}"
        return self._alias_index.get(key)

    def lookup_project(self, tenant_id: str, project_id: str) -> List[RegistryEntry]:
        key = f"GCP_PROJECT:{tenant_id}:{project_id.strip().lower()}"
        return self._index.get(key, [])

    # --------------------------------------------------------------------------
    # Integration with EnterpriseState / EntityGraph
    # --------------------------------------------------------------------------

    @classmethod
    def from_enterprise_state(
        cls,
        enterprise_state: Any,
        aliases_map: Optional[Dict[str, List[str]]] = None,
        scope_mapping: Optional[Dict[str, Set[str]]] = None,
    ) -> "GCPResourceIdentityRegistry":
        """Builds an index from an EnterpriseState instance."""
        registry = cls()
        tenant_id = getattr(enterprise_state, "organization_id", "DEFAULT_TENANT")
        aliases = aliases_map or {}
        scopes = scope_mapping or {}

        # 1. Cloud accounts
        for ca in getattr(enterprise_state, "cloud_accounts", []):
            if str(getattr(ca, "provider", "")).upper() == "GCP":
                c_id = getattr(ca, "cloud_account_id", "")
                proj_id = ca.metadata.get("project_id") if hasattr(ca, "metadata") else None
                if not proj_id:
                    proj_id = f"gcp-proj-{c_id.lower()}"
                entry = RegistryEntry(
                    entity_id=c_id,
                    entity_type="CLOUD_ACCOUNT",
                    tenant_id=tenant_id,
                    scope_ids=scopes.get(c_id, {"GLOBAL", "PROD"}),
                )
                ident = GCPResourceIdentity(
                    cloud_provider="GCP",
                    project_id=proj_id,
                    resource_type="cloud_account",
                    resource_id=c_id,
                )
                registry.register_entry(entry, ident, aliases.get(c_id))

        # 2. Cloud resources
        for cr in getattr(enterprise_state, "cloud_resources", []):
            r_id = getattr(cr, "resource_id", "")
            r_type = str(getattr(cr, "resource_type", "cloud_resource")).lower()
            acc_ref = getattr(cr, "cloud_account_ref", "")
            # Project inference
            proj_id = f"gcp-proj-{tenant_id.lower()}"
            fn = f"//compute.googleapis.com/projects/{proj_id}/{r_type}s/{r_id}"
            sl = f"https://www.googleapis.com/compute/v1/projects/{proj_id}/{r_type}s/{r_id}"
            ck = f"gcp:{proj_id}:{r_type}:{r_id}"

            entry = RegistryEntry(
                entity_id=r_id,
                entity_type="CLOUD_RESOURCE",
                tenant_id=tenant_id,
                canonical_resource_key=ck,
                scope_ids=scopes.get(r_id, {"GLOBAL", "PROD"}),
            )
            ident = GCPResourceIdentity(
                cloud_provider="GCP",
                project_id=proj_id,
                resource_type=r_type,
                resource_id=r_id,
                full_resource_name=fn,
                self_link=sl,
                canonical_resource_key=ck,
            )
            registry.register_entry(entry, ident, aliases.get(r_id))

        # 3. Assets
        for ast in getattr(enterprise_state, "assets", []):
            a_id = getattr(ast, "asset_id", "")
            a_type = str(getattr(ast, "asset_type", "asset")).lower()
            entry = RegistryEntry(
                entity_id=a_id,
                entity_type="ASSET",
                tenant_id=tenant_id,
                scope_ids=scopes.get(a_id, {"GLOBAL", "PROD"}),
            )
            registry.register_entry(entry, None, aliases.get(a_id))

        return registry
