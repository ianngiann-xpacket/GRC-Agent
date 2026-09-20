"""Step 33-C: Evidence Period & Sufficiency CLI Dispatcher.

Commands:
  secgrc evidence-plan plan --requirement <REQ> [--framework <FW>] [--eval-time <TS>]
  secgrc evidence-plan policies [--framework <FW>]
  secgrc evidence-plan scenarios
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys
from typing import List, Optional

from secgrc.compliance.models import (
    CanonicalDataType,
    CanonicalSecurityData,
    ClassificationLevel,
    EntityReference,
    ProvenanceRecord,
)
from secgrc.compliance.sufficiency.evaluator import EvidenceSufficiencyEvaluator
from secgrc.compliance.sufficiency.policy_registry import get_policy_registry
from secgrc.compliance.sufficiency.resolver import EvidencePeriodResolver


def build_evidence_plan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secgrc evidence-plan",
        description="Evidence Period & Sufficiency Policy Engine CLI",
    )
    sub = parser.add_subparsers(dest="action", help="Evidence Plan Action")

    # plan
    p_plan = sub.add_parser("plan", help="Resolve observation plan for requirement")
    p_plan.add_argument("--requirement", required=True, help="Requirement identifier (e.g. ISMS-P-2.7.1)")
    p_plan.add_argument("--framework", default=None, help="Framework identifier (e.g. ISMS-P)")
    p_plan.add_argument("--eval-time", default=None, help="Injected evaluation timestamp (ISO8601)")
    p_plan.add_argument("--maturity", default="MANAGED", help="Organization maturity (MANAGED, OPTIMIZING, INITIAL)")

    # policies
    p_pol = sub.add_parser("policies", help="List registered sufficiency policies")
    p_pol.add_argument("--framework", default=None, help="Optional framework filter")

    # scenarios
    sub.add_parser("scenarios", help="Run CSPM Scenarios A, B, C, D demonstration")

    return parser


def run_evidence_plan_cli(args: Optional[List[str]] = None) -> int:
    parser = build_evidence_plan_parser()
    parsed = parser.parse_args(args)

    if not parsed.action:
        parser.print_help()
        return 1

    resolver = EvidencePeriodResolver()
    evaluator = EvidenceSufficiencyEvaluator()
    registry = get_policy_registry()

    if parsed.action == "policies":
        policies = registry.list_policies(parsed.framework)
        output = [
            {
                "policy_id": p.policy_id,
                "framework_id": p.framework_id,
                "requirement_id": p.requirement_id or "*",
                "frequency": p.expected_frequency.value,
                "min_cycles": p.minimum_observation_cycles,
                "period_type": p.required_observation_period.value,
                "continuity": p.continuity_requirement.value,
                "hash": p.policy_hash[:16],
            }
            for p in policies
        ]
        print(json.dumps(output, indent=2))
        return 0

    elif parsed.action == "plan":
        plan = resolver.resolve_plan(
            requirement_id=parsed.requirement,
            framework_id=parsed.framework,
            organization_profile={"maturity": parsed.maturity},
            evaluation_time=parsed.eval_time,
        )
        print(json.dumps(plan.model_dump(), indent=2, default=str))
        return 0

    elif parsed.action == "scenarios":
        ref_time = "2026-09-01T00:00:00Z"
        plan = resolver.resolve_plan(
            requirement_id="ISMS-P-2.5.2",
            evaluation_time=ref_time,
        )

        def make_rec(rec_id: str, ts: str, status: str = "PASS") -> CanonicalSecurityData:
            return CanonicalSecurityData(
                record_id=rec_id,
                data_type=CanonicalDataType.SECURITY_CONFIGURATION,
                source_system="CSPM",
                source_record_id=f"src-{rec_id}",
                observed_at=ts,
                tenant_id="DEFAULT_TENANT",
                scope="GLOBAL",
                classification=ClassificationLevel.INTERNAL,
                entity_references=[
                    EntityReference(
                        entity_id="bucket-prod-01",
                        entity_type="GCP_BUCKET",
                    )
                ],
                payload={"posture_status": status, "encrypted": True},
                provenance=ProvenanceRecord(
                    source_system="CSPM",
                    source_record_id=f"src-{rec_id}",
                    source_timestamp=ts,
                    source_hash=f"h-{rec_id}",
                ),
                integrity_hash=f"h-{rec_id}",
            )

        print("\n=======================================================")
        print("   Step 33-C: CSPM Evidence Sufficiency Demonstration  ")
        print("=======================================================")

        # Scenario A: Current state valid + 3 months complete
        recs_a = [
            make_rec("REC-01", "2026-06-15T10:00:00Z"),
            make_rec("REC-02", "2026-07-15T10:00:00Z"),
            make_rec("REC-03", "2026-08-30T10:00:00Z"),  # fresh
        ]
        res_a = evaluator.evaluate(plan, recs_a, evaluation_time=ref_time)
        print(f"\n[Scenario A: Complete 3 Months + Fresh Current State]")
        print(f"  Result: {res_a.status.value} (Coverage: {res_a.coverage.value}, Freshness: {res_a.freshness.value}, Cycles: {res_a.observed_cycles}/{res_a.required_cycles})")

        # Scenario B: Current state valid + only 1 month
        recs_b = [
            make_rec("REC-04", "2026-08-30T10:00:00Z"),
        ]
        res_b = evaluator.evaluate(plan, recs_b, evaluation_time=ref_time)
        print(f"\n[Scenario B: Fresh Current State + Only 1 Month]")
        print(f"  Result: {res_b.status.value} (Coverage: {res_b.coverage.value}, Gaps: {len(res_b.gaps)})")

        # Scenario C: Stale current state (2 months ago)
        recs_c = [
            make_rec("REC-05", "2026-06-15T10:00:00Z"),
            make_rec("REC-06", "2026-07-01T10:00:00Z"),
        ]
        res_c = evaluator.evaluate(plan, recs_c, evaluation_time=ref_time)
        print(f"\n[Scenario C: Stale Current State]")
        print(f"  Result: {res_c.status.value} (Freshness: {res_c.freshness.value})")

        # Scenario D: Prowler FAIL != Compliance FAIL
        recs_d = [
            make_rec("REC-07", "2026-06-15T10:00:00Z", status="FAIL"),
            make_rec("REC-08", "2026-07-15T10:00:00Z", status="FAIL"),
            make_rec("REC-09", "2026-08-30T10:00:00Z", status="FAIL"),
        ]
        res_d = evaluator.evaluate(plan, recs_d, evaluation_time=ref_time)
        print(f"\n[Scenario D: Prowler Status = FAIL across observations]")
        print(f"  Result: {res_d.status.value} (Sufficiency is SUFFICIENT: observation captured; NOT Compliance FAIL)")
        print("=======================================================\n")
        return 0

    return 0
