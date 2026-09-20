"""Step 33-C: Evidence Period & Observation Plan Resolver.

Deterministic resolver that computes an EvidenceObservationPlan from:
- Requirement & Evidence Requirement metadata
- Compliance Framework & Scope
- Organization Profile & Maturity
- Evidence Sufficiency Policies
- Injected Evaluation Clock (Zero Wall-Clock Dependency)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, Optional

from secgrc.compliance.sufficiency.models import (
    ChangeHistoryRequirement,
    ContinuityRequirement,
    CurrentStateRequirement,
    EvidenceObservationPlan,
    EvidenceSufficiencyPolicy,
    ExceptionHistoryRequirement,
    HistoricalObservationRequirement,
    ObservationFrequency,
    RequiredObservationPeriod,
    SamplingStrategy,
    compute_plan_hash,
)
from secgrc.compliance.sufficiency.policy_registry import (
    EvidencePolicyRegistry,
    get_policy_registry,
)


def parse_iso_duration_to_timedelta(duration_str: Optional[str]) -> timedelta:
    """Parses simple ISO 8601 duration strings or shorthand into timedelta."""
    if not duration_str:
        return timedelta(days=90)

    s = duration_str.strip().upper()

    # Match hour shorthand (e.g. "24h", "48h")
    if s.endswith("H") and not s.startswith("P"):
        try:
            return timedelta(hours=int(s[:-1]))
        except ValueError:
            pass

    # Match day shorthand (e.g. "30d", "90d")
    if s.endswith("D") and not s.startswith("P"):
        try:
            return timedelta(days=int(s[:-1]))
        except ValueError:
            pass

    # ISO 8601 formats: P3M, P1Y, P90D, P6M, P35D, PT24H
    m_hours = re.match(r"^PT(\d+)H$", s)
    if m_hours:
        return timedelta(hours=int(m_hours.group(1)))

    m_days = re.match(r"^P(\d+)D$", s)
    if m_days:
        return timedelta(days=int(m_days.group(1)))

    m_months = re.match(r"^P(\d+)M$", s)
    if m_months:
        return timedelta(days=int(m_months.group(1)) * 30)

    m_years = re.match(r"^P(\d+)Y$", s)
    if m_years:
        return timedelta(days=int(m_years.group(1)) * 365)

    return timedelta(days=90)


def extract_framework_id(requirement_id: str) -> str:
    """Infers framework identifier from standard requirement ID formats."""
    rid = (requirement_id or "").upper()
    if rid.startswith("ISMS-P"):
        return "ISMS-P"
    if "ISO" in rid:
        return "ISO-27001"
    if "GDPR" in rid:
        return "GDPR"
    if "NIST-CSF" in rid or "CSF" in rid:
        return "NIST-CSF"
    if "CIS" in rid:
        return "CIS-CONTROLS"
    if "NIST-AI" in rid or "RMF" in rid:
        return "NIST-AI-RMF"
    return "*"


class EvidencePeriodResolver:
    """Resolves deterministic EvidenceObservationPlans without runtime network or LLM calls."""

    def __init__(self, registry: Optional[EvidencePolicyRegistry] = None) -> None:
        self.registry = registry or get_policy_registry()

    def resolve_plan(
        self,
        requirement_id: str,
        framework_id: Optional[str] = None,
        evidence_requirement_id: Optional[str] = None,
        policy: Optional[EvidenceSufficiencyPolicy] = None,
        organization_profile: Optional[Dict[str, Any]] = None,
        compliance_scope: Optional[Dict[str, Any]] = None,
        evaluation_time: Optional[str] = None,
    ) -> EvidenceObservationPlan:
        """Deterministically derives an EvidenceObservationPlan.

        Args:
            requirement_id: The target compliance requirement identifier.
            framework_id: Optional framework identifier.
            evidence_requirement_id: Optional evidence requirement identifier.
            policy: Explicit policy override; if None, resolved from registry.
            organization_profile: Organization capabilities and maturity.
            compliance_scope: Scope boundaries (scope_id, tenant_id).
            evaluation_time: Explicit reference timestamp (ISO8601). Injected for determinism.
        """
        fid = framework_id or extract_framework_id(requirement_id)

        # 1. Resolve policy
        active_policy = policy or self.registry.get_policy(framework_id=fid, requirement_id=requirement_id)
        if active_policy is None:
            active_policy = self.registry.get_policy(framework_id="*", requirement_id=None)
            if active_policy is None:
                raise RuntimeError("No sufficiency policy found and global default is missing.")

        # 2. Scope extraction
        scope_id = (compliance_scope or {}).get("scope_id", "GLOBAL")
        tenant_id = (compliance_scope or {}).get("tenant_id", "DEFAULT_TENANT")

        # 3. Observation window calculation
        # Evaluation time is strictly deterministic; default to fixed anchor if None
        ref_time_str = evaluation_time or "2026-09-01T00:00:00Z"
        ref_dt = datetime.fromisoformat(ref_time_str.replace("Z", "+00:00"))

        window_duration = active_policy.historical.window_duration
        if not window_duration:
            # Derive window from frequency and minimum cycles
            freq = active_policy.expected_frequency
            cycles = max(1, active_policy.minimum_observation_cycles)
            if freq == ObservationFrequency.DAILY:
                window_duration = f"P{cycles * 2}D"
            elif freq == ObservationFrequency.WEEKLY:
                window_duration = f"P{cycles * 14}D"
            elif freq == ObservationFrequency.MONTHLY:
                window_duration = f"P{cycles}M"
            elif freq == ObservationFrequency.QUARTERLY:
                window_duration = f"P{cycles * 3}M"
            elif freq == ObservationFrequency.ANNUAL:
                window_duration = f"P{cycles}Y"
            else:
                window_duration = "P3M"

        delta = parse_iso_duration_to_timedelta(window_duration)
        obs_end_dt = ref_dt
        obs_start_dt = obs_end_dt - delta

        obs_start = obs_start_dt.isoformat()
        obs_end = obs_end_dt.isoformat()

        # 4. Organization maturity interaction (modulates gap tolerance or sampling strategy)
        maturity = ((organization_profile or {}).get("maturity") or "").upper()
        gap_tolerance = active_policy.gap_tolerance
        sampling = active_policy.sampling_strategy

        if maturity in ("OPTIMIZING", "QUANTITATIVE"):
            # High maturity: tighter gap tolerance, continuous or risk-based sample
            if active_policy.continuity_requirement == ContinuityRequirement.CONTINUOUS:
                gap_tolerance = "12h"
        elif maturity == "INITIAL":
            # Low maturity: relaxed tolerance, periodic sample fallback
            if gap_tolerance == "24h":
                gap_tolerance = "48h"

        # 5. Build decomposed requirements
        cur_state = active_policy.current_state
        hist_req = active_policy.historical.model_copy(
            update={
                "minimum_cycles": active_policy.minimum_observation_cycles,
                "window_duration": window_duration,
            }
        )
        change_req = active_policy.changes
        exc_req = active_policy.exceptions

        # Plan ID derived deterministically
        safe_req = requirement_id.replace(":", "-").replace(".", "-")
        plan_id = f"PLAN-{safe_req}"

        plan_dict = {
            "plan_id": plan_id,
            "requirement_id": requirement_id,
            "evidence_requirement_id": evidence_requirement_id,
            "current_state": cur_state.model_dump(),
            "historical": hist_req.model_dump(),
            "changes": change_req.model_dump(),
            "exceptions": exc_req.model_dump(),
            "observation_start": obs_start,
            "observation_end": obs_end,
            "observation_period_type": active_policy.required_observation_period.value,
            "expected_frequency": active_policy.expected_frequency.value,
            "minimum_observation_cycles": active_policy.minimum_observation_cycles,
            "continuity_requirement": active_policy.continuity_requirement.value,
            "sampling_strategy": sampling.value,
            "gap_tolerance": gap_tolerance,
            "material_change_lookback": active_policy.material_change_lookback,
            "freshness_policy": active_policy.freshness_requirement.model_dump() if active_policy.freshness_requirement else None,
            "derived_from_policy_id": active_policy.policy_id,
            "derived_from_policy_version": active_policy.policy_version,
            "scope_id": scope_id,
            "provenance": {
                "resolved_at": ref_time_str,
                "organization_maturity": maturity or "UNSPECIFIED",
                "tenant_id": tenant_id,
                "policy_hash": active_policy.policy_hash,
            },
        }

        p_hash = compute_plan_hash(plan_dict)

        return EvidenceObservationPlan(
            plan_id=plan_id,
            requirement_id=requirement_id,
            evidence_requirement_id=evidence_requirement_id,
            current_state=cur_state,
            historical=hist_req,
            changes=change_req,
            exceptions=exc_req,
            observation_start=obs_start,
            observation_end=obs_end,
            observation_period_type=active_policy.required_observation_period,
            expected_frequency=active_policy.expected_frequency,
            minimum_observation_cycles=active_policy.minimum_observation_cycles,
            continuity_requirement=active_policy.continuity_requirement,
            sampling_strategy=sampling,
            gap_tolerance=gap_tolerance,
            material_change_lookback=active_policy.material_change_lookback,
            freshness_policy=active_policy.freshness_requirement,
            derived_from_policy_id=active_policy.policy_id,
            derived_from_policy_version=active_policy.policy_version,
            scope_id=scope_id,
            provenance=plan_dict["provenance"],
            plan_hash=p_hash,
        )
