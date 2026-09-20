"""Step 33-D: Entity Resolution CLI & Diagnostic Reporting (Sections 25 & 26).

Provides:
- Diagnostic inspection of GCP resource resolution
- Batch resolution over Prowler run artifacts
- Deterministic Resolution Summary reports
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from secgrc.connectors.resolution.models import (
    EntityResolutionResult,
    EntityResolutionStatus,
)
from secgrc.connectors.resolution.normalizer import GCPIdentityNormalizer
from secgrc.connectors.resolution.registry import GCPResourceIdentityRegistry, RegistryEntry
from secgrc.connectors.resolution.resolver import DeterministicGCPResolver


def build_default_demo_registry(tenant_id: str = "ORG-REAL-001") -> GCPResourceIdentityRegistry:
    """Creates a demonstration registry with standard enterprise entities and aliases."""
    reg = GCPResourceIdentityRegistry()

    # 1. Cloud Project
    proj_entry = RegistryEntry(
        entity_id="ORG-REAL-001-CA-001",
        entity_type="CLOUD_ACCOUNT",
        tenant_id=tenant_id,
        scope_ids={"GLOBAL", "SCOPE-PROD-KR", "PROD"},
    )
    from secgrc.connectors.resolution.models import GCPResourceIdentity
    reg.register_entry(
        proj_entry,
        GCPResourceIdentity(
            cloud_provider="GCP",
            project_id="my-schedule-505308",
            resource_type="cloud_account",
            resource_id="ORG-REAL-001-CA-001",
        ),
    )

    # 2. Production Storage Bucket
    bucket_entry = RegistryEntry(
        entity_id="ORG-REAL-001-CR-GCS-001",
        entity_type="CLOUD_RESOURCE",
        tenant_id=tenant_id,
        canonical_resource_key="gcp:my-schedule-505308:storage_bucket:grc-prowler-reports-my-schedule-505308",
        scope_ids={"GLOBAL", "SCOPE-PROD-KR", "PROD"},
    )
    reg.register_entry(
        bucket_entry,
        GCPResourceIdentity(
            cloud_provider="GCP",
            project_id="my-schedule-505308",
            service="storage",
            resource_type="storage_bucket",
            resource_id="grc-prowler-reports-my-schedule-505308",
            full_resource_name="//storage.googleapis.com/projects/my-schedule-505308/buckets/grc-prowler-reports-my-schedule-505308",
            self_link="https://storage.googleapis.com/storage/v1/b/grc-prowler-reports-my-schedule-505308",
            canonical_resource_key="gcp:my-schedule-505308:storage_bucket:grc-prowler-reports-my-schedule-505308",
        ),
        aliases=["grc-reports-bucket", "audit-evidence-bucket"],
    )

    # 3. Compute VM Instance
    vm_entry = RegistryEntry(
        entity_id="ORG-REAL-001-CR-GCE-001",
        entity_type="CLOUD_RESOURCE",
        tenant_id=tenant_id,
        canonical_resource_key="gcp:my-schedule-505308:compute_instance:web-server-01",
        scope_ids={"GLOBAL", "SCOPE-PROD-KR", "PROD"},
    )
    reg.register_entry(
        vm_entry,
        GCPResourceIdentity(
            cloud_provider="GCP",
            project_id="my-schedule-505308",
            service="compute",
            resource_type="compute_instance",
            resource_id="web-server-01",
            full_resource_name="//compute.googleapis.com/projects/my-schedule-505308/zones/asia-northeast3-a/instances/web-server-01",
            self_link="https://www.googleapis.com/compute/v1/projects/my-schedule-505308/zones/asia-northeast3-a/instances/web-server-01",
            canonical_resource_key="gcp:my-schedule-505308:compute_instance:web-server-01",
        ),
        aliases=["prod-web-01"],
    )

    # 4. Out-of-Scope Dev VM
    dev_entry = RegistryEntry(
        entity_id="ORG-REAL-001-CR-DEV-001",
        entity_type="CLOUD_RESOURCE",
        tenant_id=tenant_id,
        canonical_resource_key="gcp:my-schedule-505308:compute_instance:dev-test-01",
        scope_ids={"DEV-ONLY"},  # Excluded from SCOPE-PROD-KR
    )
    reg.register_entry(
        dev_entry,
        GCPResourceIdentity(
            cloud_provider="GCP",
            project_id="my-schedule-505308",
            service="compute",
            resource_type="compute_instance",
            resource_id="dev-test-01",
            full_resource_name="//compute.googleapis.com/projects/my-schedule-505308/zones/asia-northeast3-a/instances/dev-test-01",
            canonical_resource_key="gcp:my-schedule-505308:compute_instance:dev-test-01",
        ),
    )

    # 5. Foreign Tenant Project (for cross-tenant detection)
    foreign_entry = RegistryEntry(
        entity_id="ORG-FOREIGN-CA-001",
        entity_type="CLOUD_ACCOUNT",
        tenant_id="TENANT-EXTERNAL-999",
        scope_ids={"GLOBAL"},
    )
    reg.register_entry(
        foreign_entry,
        GCPResourceIdentity(
            cloud_provider="GCP",
            project_id="foreign-project-999",
            resource_type="cloud_account",
            resource_id="ORG-FOREIGN-CA-001",
        ),
    )

    return reg


def render_resolution_result(result: EntityResolutionResult) -> None:
    """Displays formatted resolution diagnostic details (Section 25)."""
    norm = result.normalized_resource_identity
    print("\n" + "=" * 60)
    print("   GCP Entity Resolution Diagnostic Output")
    print("=" * 60)
    print(f"  Source Identity:       {result.source_resource_identity}")
    print(f"  Normalized Canonical:  {norm.canonical_resource_key if norm else 'N/A'}")
    print(f"  Resolution Status:     {result.status.value}")
    print(f"  Match Method:          {result.match_method.value}")
    print(f"  Matched Entity:        {result.matched_entity_id or 'NONE'}")
    print(f"  Matched Type:          {result.matched_entity_type or 'NONE'}")
    print(f"  Confidence Class:      {result.confidence_class.value}")
    print(f"  Scope:                 {result.scope_id}")
    print(f"  Tenant:                {result.tenant_id}")
    print(f"  Resolution Hash:       {result.resolution_hash}")
    print(f"  Explanation:           {result.resolution_reason}")

    if result.status == EntityResolutionStatus.AMBIGUOUS_MATCH:
        print(f"  Candidate Entities:    {result.candidate_entity_ids}")
    elif result.status == EntityResolutionStatus.ORPHAN_SOURCE:
        print("  Notice:                No Enterprise Entity registered in baseline EnterpriseState")
    print("=" * 60 + "\n")


def render_summary_report(results: List[EntityResolutionResult]) -> None:
    """Renders resolution summary table (Section 26)."""
    counts = {s: 0 for s in EntityResolutionStatus}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print("\nEntity Resolution Summary")
    print("-" * 35)
    for s in EntityResolutionStatus:
        print(f"{s.value:<22} {counts[s]:>8}")
    print("-" * 35)
    print(f"{'TOTAL OBSERVATIONS':<22} {len(results):>8}\n")


def run_cli(args: Optional[List[str]] = None) -> int:
    """CLI runner for secgrc entity-resolve."""
    parser = argparse.ArgumentParser(
        prog="secgrc entity-resolve",
        description="GCP Asset / Entity Resolution Diagnostic CLI (Step 33-D)",
    )
    parser.add_argument("--resource", help="Single raw GCP resource locator to resolve")
    parser.add_argument("--source", default="prowler", help="Source type (default: prowler)")
    parser.add_argument("--run-id", help="Prowler run ID to resolve from data/prowler/raw/")
    parser.add_argument("--project", default="my-schedule-505308", help="GCP project ID")
    parser.add_argument("--tenant", default="ORG-REAL-001", help="Target organization/tenant ID")
    parser.add_argument("--scope", default="SCOPE-PROD-KR", help="Target compliance scope ID")
    parser.add_argument("--scenarios", action="store_true", help="Demonstrate standard resolution scenarios")

    parsed = parser.parse_args(args)
    reg = build_default_demo_registry(parsed.tenant)
    resolver = DeterministicGCPResolver(registry=reg)

    if parsed.scenarios:
        demo_scenarios = [
            ("Exact Match: Storage Bucket", "gs://grc-prowler-reports-my-schedule-505308", parsed.scope, parsed.tenant),
            ("Alias Match: Registered Alias", "prod-web-01", parsed.scope, parsed.tenant),
            ("Wrong Scope: Dev Instance", "dev-test-01", "SCOPE-PROD-KR", parsed.tenant),
            ("Orphan: Unregistered Bucket", "gs://new-discovered-shadow-bucket", parsed.scope, parsed.tenant),
            ("Cross-Tenant: Foreign Project", "//compute.googleapis.com/projects/foreign-project-999/instances/ex-vm", parsed.scope, parsed.tenant),
        ]
        results = []
        for label, locator, scope, tenant in demo_scenarios:
            print(f"--> Testing scenario: {label}")
            res = resolver.resolve(
                source_record_id=f"rec-{locator[:10]}",
                source_resource_locator=locator,
                tenant_id=tenant,
                target_scope_id=scope,
                context={"project_id": parsed.project},
            )
            render_resolution_result(res)
            results.append(res)
        render_summary_report(results)
        return 0

    if parsed.resource:
        res = resolver.resolve(
            source_record_id="CLI-REC-001",
            source_resource_locator=parsed.resource,
            tenant_id=parsed.tenant,
            target_scope_id=parsed.scope,
            context={"project_id": parsed.project},
        )
        render_resolution_result(res)
        return 0

    if parsed.run_id:
        # Resolve all findings from run directory
        run_file = os.path.join("data", "prowler", "raw", parsed.run_id, "canonical.jsonl")
        if not os.path.exists(run_file):
            print(f"Error: Run artifact not found at '{run_file}'")
            return 1
        results = []
        with open(run_file, "r", encoding="utf-8") as fp:
            for idx, line in enumerate(fp):
                if not line.strip():
                    continue
                rec = json.loads(line)
                res = resolver.resolve(
                    source_record_id=rec.get("record_id", f"rec-{idx}"),
                    source_resource_locator=rec.get("source_record_id") or rec.get("payload", {}).get("resource_name", ""),
                    tenant_id=parsed.tenant,
                    target_scope_id=parsed.scope,
                    context=rec.get("payload", {}),
                )
                results.append(res)
        render_summary_report(results)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(run_cli())
