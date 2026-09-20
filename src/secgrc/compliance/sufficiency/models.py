"""Step 33-C: Evidence Period & Sufficiency Policy Engine - Domain Models & Invariants.

Defines immutable Pydantic models, enums, cryptographic hashes, and invariants for:
- Required observation periods and frequencies
- Minimum observation cycles and continuity requirements
- Sampling strategies and 4-dimensional sufficiency metrics
- Decomposed evidence plans (current state, operating history, changes, exceptions)
- Evidence sufficiency policies, observation plans, and evaluation results
"""

from __future__ import annotations

from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import ConfigDict, Field, field_validator

from secgrc.compliance.freshness import EvidenceFreshness
from secgrc.compliance.models import (
    ComplianceBaseModel,
    validate_identifier,
    validate_iso8601_timestamp,
)


class RequiredObservationPeriod(str, Enum):
    """The required observation period classification for compliance evidence."""
    POINT_IN_TIME = "POINT_IN_TIME"
    CURRENT_STATE = "CURRENT_STATE"
    ROLLING_WINDOW = "ROLLING_WINDOW"
    FIXED_PERIOD = "FIXED_PERIOD"
    AUDIT_CYCLE = "AUDIT_CYCLE"
    ANNUAL_CYCLE = "ANNUAL_CYCLE"
    HISTORICAL = "HISTORICAL"
    EVENT_DRIVEN = "EVENT_DRIVEN"


class ObservationFrequency(str, Enum):
    """The expected frequency at which evidence must be generated or captured."""
    ON_DEMAND = "ON_DEMAND"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"
    QUARTERLY = "QUARTERLY"
    SEMI_ANNUAL = "SEMI_ANNUAL"
    ANNUAL = "ANNUAL"
    CONTINUOUS = "CONTINUOUS"
    EVENT_DRIVEN = "EVENT_DRIVEN"
    IRREGULAR = "IRREGULAR"


class ContinuityRequirement(str, Enum):
    """The continuity guarantees required across the observation window."""
    NONE = "NONE"
    POINT_ONLY = "POINT_ONLY"
    PERIODIC = "PERIODIC"
    CONTINUOUS = "CONTINUOUS"
    NO_GAP = "NO_GAP"
    TOLERABLE_GAP = "TOLERABLE_GAP"


class SamplingStrategy(str, Enum):
    """The sampling strategy for submitting/inspecting audit evidence."""
    ALL = "ALL"
    LATEST = "LATEST"
    FIRST_AND_LAST = "FIRST_AND_LAST"
    PERIODIC_SAMPLE = "PERIODIC_SAMPLE"
    RISK_BASED_SAMPLE = "RISK_BASED_SAMPLE"
    EVENT_TRIGGERED = "EVENT_TRIGGERED"
    EXCEPTION_ONLY = "EXCEPTION_ONLY"
    FULL_PERIOD = "FULL_PERIOD"


class DimensionStatus(str, Enum):
    """Evaluation status for an individual sufficiency dimension."""
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"
    NOT_SPECIFIED = "NOT_SPECIFIED"


class EvidenceSufficiencyStatus(str, Enum):
    """Comprehensive evidence sufficiency outcome.

    CRITICAL INVARIANT:
    INSUFFICIENT != Compliance FAIL.
    Sufficiency reflects evidence adequacy, not compliance verdict.
    """
    SUFFICIENT = "SUFFICIENT"
    PARTIALLY_SUFFICIENT = "PARTIALLY_SUFFICIENT"
    INSUFFICIENT = "INSUFFICIENT"
    UNDETERMINED = "UNDETERMINED"


# ==============================================================================
# Plan Sub-Requirements Decomposition
# ==============================================================================

class CurrentStateRequirement(ComplianceBaseModel):
    """Requirements for point-in-time fresh snapshot."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    required: bool = True
    max_age_seconds: Optional[int] = Field(default=86400 * 30, ge=1)  # Default 30 days if specified
    description: str = "Valid current configuration state snapshot required"


class HistoricalObservationRequirement(ComplianceBaseModel):
    """Requirements for operational history over time."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    required: bool = False
    frequency: ObservationFrequency = ObservationFrequency.MONTHLY
    minimum_cycles: int = Field(default=1, ge=1)
    window_duration: Optional[str] = None  # e.g., "P3M", "P1Y", "P90D"
    allowed_gaps: int = Field(default=0, ge=0)
    description: str = "Operating history across observation cycles"


class ChangeHistoryRequirement(ComplianceBaseModel):
    """Requirements for recording material configuration changes."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    required: bool = False
    lookback_window: Optional[str] = None  # e.g., "P90D"
    monitored_event_types: List[str] = Field(default_factory=list)
    description: str = "Material changes tracking during lookback window"


class ExceptionHistoryRequirement(ComplianceBaseModel):
    """Requirements for tracking policy exceptions and security deviations."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    required: bool = False
    lookback_window: Optional[str] = None
    severity_threshold: Optional[str] = "HIGH"
    description: str = "Exception and deviation history"


# ==============================================================================
# Policy & Observation Plan Models
# ==============================================================================

class EvidenceSufficiencyPolicy(ComplianceBaseModel):
    """Deterministic policy defining evidence sufficiency rules for requirements."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str
    policy_version: str = "1.0.0"
    framework_id: str
    requirement_id: Optional[str] = None  # None = framework-level fallback
    required_observation_period: RequiredObservationPeriod = RequiredObservationPeriod.ROLLING_WINDOW
    minimum_observation_cycles: int = Field(default=1, ge=1)
    expected_frequency: ObservationFrequency = ObservationFrequency.MONTHLY
    continuity_requirement: ContinuityRequirement = ContinuityRequirement.PERIODIC
    sampling_strategy: SamplingStrategy = SamplingStrategy.PERIODIC_SAMPLE
    gap_tolerance: Optional[str] = "P35D"  # Tolerates minor scheduling offsets (e.g. 35 days for monthly)
    current_state: CurrentStateRequirement = Field(default_factory=CurrentStateRequirement)
    historical: HistoricalObservationRequirement = Field(default_factory=HistoricalObservationRequirement)
    changes: ChangeHistoryRequirement = Field(default_factory=ChangeHistoryRequirement)
    exceptions: ExceptionHistoryRequirement = Field(default_factory=ExceptionHistoryRequirement)
    freshness_requirement: Optional[EvidenceFreshness] = None
    material_change_lookback: Optional[str] = "P90D"
    effective_from: Optional[str] = None
    effective_to: Optional[str] = None
    risk_adjustment: Dict[str, Any] = Field(default_factory=dict)
    policy_hash: str = ""

    @field_validator("policy_id", "framework_id")
    @classmethod
    def validate_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class EvidenceObservationPlan(ComplianceBaseModel):
    """Deterministic observation plan derived for a specific compliance requirement."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    requirement_id: str
    evidence_requirement_id: Optional[str] = None
    current_state: CurrentStateRequirement
    historical: HistoricalObservationRequirement
    changes: ChangeHistoryRequirement
    exceptions: ExceptionHistoryRequirement
    observation_start: Optional[str] = None  # ISO8601
    observation_end: Optional[str] = None    # ISO8601
    observation_period_type: RequiredObservationPeriod
    expected_frequency: ObservationFrequency
    minimum_observation_cycles: int
    continuity_requirement: ContinuityRequirement
    sampling_strategy: SamplingStrategy
    gap_tolerance: Optional[str] = None
    material_change_lookback: Optional[str] = None
    freshness_policy: Optional[EvidenceFreshness] = None
    derived_from_policy_id: str
    derived_from_policy_version: str
    scope_id: str = "GLOBAL"
    provenance: Dict[str, Any] = Field(default_factory=dict)
    plan_hash: str = ""

    @field_validator("plan_id", "requirement_id")
    @classmethod
    def validate_plan_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


# ==============================================================================
# Evaluation Result Model
# ==============================================================================

class EvidenceSufficiencyResult(ComplianceBaseModel):
    """Deterministic 4-dimensional sufficiency evaluation result."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: EvidenceSufficiencyStatus
    coverage: DimensionStatus
    freshness: DimensionStatus
    continuity: DimensionStatus
    validity: DimensionStatus
    observed_cycles: int = Field(ge=0)
    required_cycles: int = Field(ge=0)
    observed_periods: List[str] = Field(default_factory=list)
    gaps: List[str] = Field(default_factory=list)
    current_state_satisfied: bool = True
    historical_satisfied: bool = True
    changes_satisfied: bool = True
    exceptions_satisfied: bool = True
    evaluated_at: str
    result_hash: str = ""
    explanation: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("evaluated_at")
    @classmethod
    def validate_eval_ts(cls, v: str) -> str:
        return validate_iso8601_timestamp(v, "evaluated_at")


# ==============================================================================
# Deterministic Hash Functions
# ==============================================================================

def compute_policy_hash(policy_dict: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 hash for EvidenceSufficiencyPolicy."""
    filtered = {
        "policy_id": policy_dict.get("policy_id", ""),
        "policy_version": policy_dict.get("policy_version", "1.0.0"),
        "framework_id": policy_dict.get("framework_id", ""),
        "requirement_id": policy_dict.get("requirement_id") or "",
        "period": str(policy_dict.get("required_observation_period", "")),
        "frequency": str(policy_dict.get("expected_frequency", "")),
        "min_cycles": int(policy_dict.get("minimum_observation_cycles", 1)),
        "continuity": str(policy_dict.get("continuity_requirement", "")),
        "sampling": str(policy_dict.get("sampling_strategy", "")),
        "gap_tolerance": policy_dict.get("gap_tolerance") or "",
        "current_state_req": bool(policy_dict.get("current_state", {}).get("required", True)),
        "historical_req": bool(policy_dict.get("historical", {}).get("required", False)),
        "changes_req": bool(policy_dict.get("changes", {}).get("required", False)),
        "exceptions_req": bool(policy_dict.get("exceptions", {}).get("required", False)),
        "material_change_lookback": policy_dict.get("material_change_lookback") or "",
    }
    dumped = json.dumps(filtered, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def compute_plan_hash(plan_dict: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 hash for EvidenceObservationPlan."""
    filtered = {
        "plan_id": plan_dict.get("plan_id", ""),
        "requirement_id": plan_dict.get("requirement_id", ""),
        "evidence_requirement_id": plan_dict.get("evidence_requirement_id") or "",
        "observation_start": plan_dict.get("observation_start") or "",
        "observation_end": plan_dict.get("observation_end") or "",
        "period_type": str(plan_dict.get("observation_period_type", "")),
        "frequency": str(plan_dict.get("expected_frequency", "")),
        "min_cycles": int(plan_dict.get("minimum_observation_cycles", 1)),
        "continuity": str(plan_dict.get("continuity_requirement", "")),
        "sampling": str(plan_dict.get("sampling_strategy", "")),
        "gap_tolerance": plan_dict.get("gap_tolerance") or "",
        "derived_from_policy_id": plan_dict.get("derived_from_policy_id", ""),
        "derived_from_policy_version": plan_dict.get("derived_from_policy_version", ""),
        "scope_id": plan_dict.get("scope_id", "GLOBAL"),
        "current_state_req": bool(plan_dict.get("current_state", {}).get("required", True)),
        "historical_req": bool(plan_dict.get("historical", {}).get("required", False)),
    }
    dumped = json.dumps(filtered, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def compute_result_hash(result_dict: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 hash for EvidenceSufficiencyResult."""
    filtered = {
        "status": str(result_dict.get("status", "")),
        "coverage": str(result_dict.get("coverage", "")),
        "freshness": str(result_dict.get("freshness", "")),
        "continuity": str(result_dict.get("continuity", "")),
        "validity": str(result_dict.get("validity", "")),
        "observed_cycles": int(result_dict.get("observed_cycles", 0)),
        "required_cycles": int(result_dict.get("required_cycles", 0)),
        "observed_periods": sorted(result_dict.get("observed_periods") or []),
        "gaps": sorted(result_dict.get("gaps") or []),
        "current_state_satisfied": bool(result_dict.get("current_state_satisfied", True)),
        "historical_satisfied": bool(result_dict.get("historical_satisfied", True)),
    }
    dumped = json.dumps(filtered, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()
