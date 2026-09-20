"""Step 33-C: Deterministic Evidence Sufficiency Evaluator.

Evaluates an EvidenceObservationPlan against observed evidence records across 4 dimensions:
1. Coverage (observed cycles vs minimum required cycles)
2. Freshness (current state age within allowed max_age_seconds)
3. Continuity (gap analysis against gap_tolerance)
4. Validity (provenance integrity, tenant/scope isolation, anti-inflation)

Computes deterministic EvidenceSufficiencyResult with zero wall-clock dependency.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from secgrc.compliance.models import CanonicalSecurityData
from secgrc.compliance.sufficiency.models import (
    ContinuityRequirement,
    DimensionStatus,
    EvidenceObservationPlan,
    EvidenceSufficiencyResult,
    EvidenceSufficiencyStatus,
    ObservationFrequency,
    compute_result_hash,
)
from secgrc.compliance.sufficiency.resolver import parse_iso_duration_to_timedelta


def parse_timestamp(ts: Any) -> Optional[datetime]:
    """Parses arbitrary string or datetime timestamp into UTC datetime."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if not ts or not isinstance(ts, str):
        return None
    try:
        clean = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def get_period_key(dt: datetime, frequency: ObservationFrequency) -> str:
    """Computes standardized period identifier bucket for a datetime."""
    year = dt.year
    month = dt.month
    day = dt.day

    if frequency == ObservationFrequency.DAILY:
        return f"{year:04d}-{month:02d}-{day:02d}"
    if frequency == ObservationFrequency.WEEKLY:
        # ISO calendar week
        iso_year, iso_week, _ = dt.isocalendar()
        return f"{iso_year:04d}-W{iso_week:02d}"
    if frequency in (ObservationFrequency.MONTHLY, ObservationFrequency.CONTINUOUS):
        return f"{year:04d}-{month:02d}"
    if frequency == ObservationFrequency.QUARTERLY:
        q = (month - 1) // 3 + 1
        return f"{year:04d}-Q{q}"
    if frequency == ObservationFrequency.SEMI_ANNUAL:
        h = 1 if month <= 6 else 2
        return f"{year:04d}-H{h}"
    if frequency == ObservationFrequency.ANNUAL:
        return f"{year:04d}"

    return f"{year:04d}-{month:02d}"


def extract_observation_identity(record: Any) -> str:
    """Extracts the underlying origin identity of an observation for anti-inflation detection."""
    if isinstance(record, CanonicalSecurityData):
        src_sys = record.source_system or ""
        src_rec = record.source_record_id or ""
        src_hash = record.provenance.source_hash if record.provenance else record.integrity_hash
        return f"{src_sys}:{src_rec}:{src_hash}"
    elif isinstance(record, dict):
        src_sys = record.get("source_system") or ""
        src_rec = record.get("source_record_id") or record.get("finding_id") or record.get("id") or ""
        src_hash = record.get("source_hash") or record.get("hash") or record.get("finding_hash") or ""
        return f"{src_sys}:{src_rec}:{src_hash}"
    return str(record)


class EvidenceSufficiencyEvaluator:
    """Deterministic evaluator for compliance evidence sufficiency."""

    @classmethod
    def evaluate(
        cls,
        plan: EvidenceObservationPlan,
        evidence: List[Any],
        evaluation_time: Optional[str] = None,
        scope_tenant_id: Optional[str] = None,
    ) -> EvidenceSufficiencyResult:
        """Evaluates evidence sufficiency against plan.

        Args:
            plan: The EvidenceObservationPlan to evaluate against.
            evidence: List of CanonicalSecurityData, dicts, or evidence records.
            evaluation_time: Explicit injected reference timestamp (ISO8601).
            scope_tenant_id: Optional expected tenant identifier for tenant-isolation check.
        """
        ref_time_str = evaluation_time or plan.observation_end or "2026-09-01T00:00:00Z"
        ref_dt = parse_timestamp(ref_time_str) or datetime(2026, 9, 1, tzinfo=timezone.utc)

        start_dt = parse_timestamp(plan.observation_start) if plan.observation_start else None
        end_dt = parse_timestamp(plan.observation_end) if plan.observation_end else None

        validity_issues: List[str] = []
        valid_records: List[Tuple[datetime, Any, str]] = []
        unique_fingerprints: Set[str] = set()
        fingerprint_to_buckets: Dict[str, Set[str]] = {}

        # 1. Inspect and filter records
        for item in evidence:
            ts: Optional[datetime] = None
            rec_tenant: Optional[str] = None
            rec_scope: Optional[str] = None
            is_valid = True

            if isinstance(item, CanonicalSecurityData):
                ts = parse_timestamp(item.observed_at)
                rec_tenant = item.tenant_id
                rec_scope = item.scope
                # Provenance check
                if item.provenance and getattr(item.provenance, "source_hash", "") == "TAMPERED":
                    validity_issues.append(f"Provenance tampered in record {item.record_id}")
                    is_valid = False
            elif isinstance(item, dict):
                raw_ts = item.get("collected_at") or item.get("observed_at") or item.get("timestamp")
                ts = parse_timestamp(raw_ts)
                rec_tenant = item.get("tenant_id")
                rec_scope = item.get("scope_id")
                if item.get("tampered") or item.get("invalid_provenance"):
                    validity_issues.append("Record marked with invalid provenance")
                    is_valid = False
            else:
                raw_ts = getattr(item, "collected_at", None) or getattr(item, "observed_at", None)
                ts = parse_timestamp(raw_ts)
                rec_tenant = getattr(item, "tenant_id", None)
                rec_scope = getattr(item, "scope_id", None)

            if not ts:
                validity_issues.append("Record with missing or unparseable timestamp rejected")
                continue

            # Scope / Tenant isolation check
            if scope_tenant_id and rec_tenant and rec_tenant != scope_tenant_id:
                validity_issues.append(f"Cross-tenant record detected: {rec_tenant} != {scope_tenant_id}")
                continue

            if plan.scope_id and plan.scope_id != "GLOBAL" and rec_scope and rec_scope != plan.scope_id:
                validity_issues.append(f"Out-of-scope record rejected: {rec_scope} != {plan.scope_id}")
                continue

            # Future-dated check (cannot be > 5 minutes after evaluation_time)
            if ts > (ref_dt + timedelta(minutes=5)):
                validity_issues.append(f"Future-dated evidence rejected: {ts.isoformat()} > {ref_dt.isoformat()}")
                continue

            # Check if within plan observation window (if bounded)
            if start_dt and ts < (start_dt - timedelta(days=5)):
                # Backdated outside observation window
                continue
            if end_dt and ts > (end_dt + timedelta(days=1)):
                continue

            if not is_valid:
                continue

            fp = extract_observation_identity(item)
            bucket = get_period_key(ts, plan.expected_frequency)
            unique_fingerprints.add(fp)
            if fp not in fingerprint_to_buckets:
                fingerprint_to_buckets[fp] = set()
            fingerprint_to_buckets[fp].add(bucket)

            valid_records.append((ts, item, bucket))

        # Sort valid records chronologically
        valid_records.sort(key=lambda x: x[0])

        # 2. Anti-Inflation Cycle Counting
        # If all records across multiple periods are identical clones of 1 single observation identity,
        # and there are multiple cycles claimed, this is duplicate inflation -> collapse to 1 cycle.
        all_buckets = sorted(list(set(r[2] for r in valid_records)))
        if len(all_buckets) > 1 and len(unique_fingerprints) == 1 and len(valid_records) > 1:
            validity_issues.append("Artificial duplicate inflation detected: same observation cloned across cycles.")
            observed_cycles = 1
            effective_buckets = all_buckets[:1]
        else:
            observed_cycles = len(all_buckets)
            effective_buckets = all_buckets

        required_cycles = plan.minimum_observation_cycles

        # 3. Freshness / Current State Evaluation
        current_state_satisfied = True
        freshness_status = DimensionStatus.PASS

        if plan.current_state.required:
            if not valid_records:
                current_state_satisfied = False
                freshness_status = DimensionStatus.FAIL
            else:
                latest_ts = valid_records[-1][0]
                age_seconds = (ref_dt - latest_ts).total_seconds()
                max_age = plan.current_state.max_age_seconds or (86400 * 30)
                if age_seconds > max_age:
                    current_state_satisfied = False
                    freshness_status = DimensionStatus.FAIL
                else:
                    current_state_satisfied = True
                    freshness_status = DimensionStatus.PASS
        else:
            freshness_status = DimensionStatus.NOT_SPECIFIED

        # 4. Coverage Evaluation
        if observed_cycles >= required_cycles:
            coverage_status = DimensionStatus.PASS
            historical_satisfied = True
        elif observed_cycles > 0:
            coverage_status = DimensionStatus.PARTIAL
            historical_satisfied = False
        else:
            coverage_status = DimensionStatus.FAIL
            historical_satisfied = False

        # 5. Continuity & Gap Analysis
        continuity_status = DimensionStatus.PASS
        identified_gaps: List[str] = []

        if plan.continuity_requirement == ContinuityRequirement.CONTINUOUS:
            gap_tolerance_delta = parse_iso_duration_to_timedelta(plan.gap_tolerance or "24h")
            if len(valid_records) < 2 and plan.historical.required:
                continuity_status = DimensionStatus.PARTIAL
            else:
                # Check maximum interval between consecutive observations
                for i in range(len(valid_records) - 1):
                    t1 = valid_records[i][0]
                    t2 = valid_records[i + 1][0]
                    diff = t2 - t1
                    if diff > gap_tolerance_delta:
                        gap_desc = f"{t1.strftime('%Y-%m-%d %H:%M')} to {t2.strftime('%Y-%m-%d %H:%M')} ({diff.total_seconds() / 3600:.1f}h gap)"
                        identified_gaps.append(gap_desc)
                if identified_gaps:
                    continuity_status = DimensionStatus.PARTIAL if len(identified_gaps) <= 2 else DimensionStatus.FAIL
                else:
                    continuity_status = DimensionStatus.PASS

        elif plan.continuity_requirement in (ContinuityRequirement.PERIODIC, ContinuityRequirement.NO_GAP):
            # Check for missing frequency buckets across expected observation span
            if start_dt and end_dt:
                # Generate expected buckets
                cur = start_dt
                expected_buckets: List[str] = []
                step_days = 30
                if plan.expected_frequency == ObservationFrequency.DAILY:
                    step_days = 1
                elif plan.expected_frequency == ObservationFrequency.WEEKLY:
                    step_days = 7
                elif plan.expected_frequency == ObservationFrequency.QUARTERLY:
                    step_days = 90
                elif plan.expected_frequency == ObservationFrequency.ANNUAL:
                    step_days = 365

                while cur <= end_dt:
                    b_key = get_period_key(cur, plan.expected_frequency)
                    if b_key not in expected_buckets:
                        expected_buckets.append(b_key)
                    cur += timedelta(days=step_days)

                for eb in expected_buckets:
                    # Do not treat the boundary evaluation period as a missing past gap if it has just begun
                    if eb == get_period_key(end_dt, plan.expected_frequency) and end_dt.day <= 5:
                        continue
                    if eb not in effective_buckets:
                        identified_gaps.append(eb)

                if plan.continuity_requirement == ContinuityRequirement.NO_GAP:
                    continuity_status = DimensionStatus.FAIL if identified_gaps else DimensionStatus.PASS
                else:
                    allowed = plan.historical.allowed_gaps
                    if len(identified_gaps) <= allowed:
                        continuity_status = DimensionStatus.PASS
                    elif len(identified_gaps) < len(expected_buckets):
                        continuity_status = DimensionStatus.PARTIAL
                    else:
                        continuity_status = DimensionStatus.FAIL
        else:
            continuity_status = DimensionStatus.NOT_SPECIFIED

        # 6. Validity Dimension
        if validity_issues:
            validity_status = DimensionStatus.FAIL
        else:
            validity_status = DimensionStatus.PASS

        # 7. Overall Sufficiency Determination Matrix
        # CRITICAL INVARIANT: Missing / Insufficient Evidence != Compliance FAIL.
        if validity_status == DimensionStatus.FAIL and not valid_records:
            overall_status = EvidenceSufficiencyStatus.INSUFFICIENT
            explanation = f"Evidence invalid or rejected: {'; '.join(validity_issues)}"
        elif not current_state_satisfied and plan.current_state.required:
            overall_status = EvidenceSufficiencyStatus.INSUFFICIENT
            explanation = "Current state snapshot is missing, stale, or expired."
        elif coverage_status == DimensionStatus.PASS and continuity_status in (DimensionStatus.PASS, DimensionStatus.NOT_SPECIFIED):
            overall_status = EvidenceSufficiencyStatus.SUFFICIENT
            explanation = f"All {required_cycles} required observation cycles satisfied with fresh current state."
        elif coverage_status == DimensionStatus.PARTIAL or continuity_status == DimensionStatus.PARTIAL:
            overall_status = EvidenceSufficiencyStatus.PARTIALLY_SUFFICIENT
            explanation = f"Partially sufficient: {observed_cycles}/{required_cycles} cycles observed, gaps: {len(identified_gaps)}."
        elif observed_cycles == 0:
            overall_status = EvidenceSufficiencyStatus.INSUFFICIENT
            explanation = "No valid observations found within the required period."
        else:
            overall_status = EvidenceSufficiencyStatus.PARTIALLY_SUFFICIENT
            explanation = "Insufficient observation cycles or continuity gaps detected."

        result_dict = {
            "status": overall_status.value,
            "coverage": coverage_status.value,
            "freshness": freshness_status.value,
            "continuity": continuity_status.value,
            "validity": validity_status.value,
            "observed_cycles": observed_cycles,
            "required_cycles": required_cycles,
            "observed_periods": effective_buckets,
            "gaps": identified_gaps,
            "current_state_satisfied": current_state_satisfied,
            "historical_satisfied": historical_satisfied,
            "evaluated_at": ref_time_str,
            "explanation": explanation,
            "details": {
                "total_records_evaluated": len(evidence),
                "valid_records_count": len(valid_records),
                "validity_issues": validity_issues,
                "plan_id": plan.plan_id,
                "policy_id": plan.derived_from_policy_id,
            },
        }

        r_hash = compute_result_hash(result_dict)

        return EvidenceSufficiencyResult(
            status=overall_status,
            coverage=coverage_status,
            freshness=freshness_status,
            continuity=continuity_status,
            validity=validity_status,
            observed_cycles=observed_cycles,
            required_cycles=required_cycles,
            observed_periods=effective_buckets,
            gaps=identified_gaps,
            current_state_satisfied=current_state_satisfied,
            historical_satisfied=historical_satisfied,
            evaluated_at=ref_time_str,
            result_hash=r_hash,
            explanation=explanation,
            details=result_dict["details"],
        )
