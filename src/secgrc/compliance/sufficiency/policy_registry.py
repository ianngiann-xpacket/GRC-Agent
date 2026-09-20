"""Step 33-C: Evidence Sufficiency Policy Registry.

Manages deterministic, versioned EvidenceSufficiencyPolicy instances across
multiple compliance frameworks (ISMS-P, ISO 27001, GDPR, NIST CSF, CIS, NIST AI RMF).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from secgrc.compliance.freshness import EvidenceFreshness, EvidenceFreshnessType
from secgrc.compliance.sufficiency.models import (
    ChangeHistoryRequirement,
    ContinuityRequirement,
    CurrentStateRequirement,
    EvidenceSufficiencyPolicy,
    ExceptionHistoryRequirement,
    HistoricalObservationRequirement,
    ObservationFrequency,
    RequiredObservationPeriod,
    SamplingStrategy,
    compute_policy_hash,
)


class EvidencePolicyRegistry:
    """Registry holding framework-specific and requirement-specific sufficiency policies."""

    def __init__(self) -> None:
        # Key: (framework_id, requirement_id or "")
        self._policies: Dict[Tuple[str, str], EvidenceSufficiencyPolicy] = {}
        self._load_seed_policies()

    def register_policy(self, policy: EvidenceSufficiencyPolicy) -> None:
        """Registers an EvidenceSufficiencyPolicy, computing policy_hash if missing."""
        pol_dict = policy.model_dump()
        computed_hash = compute_policy_hash(pol_dict)
        if policy.policy_hash != computed_hash:
            # Recreate with deterministic hash
            policy = policy.model_copy(update={"policy_hash": computed_hash})

        key = (policy.framework_id.upper(), (policy.requirement_id or "").upper())
        self._policies[key] = policy

    def get_policy(
        self,
        framework_id: str,
        requirement_id: Optional[str] = None,
    ) -> Optional[EvidenceSufficiencyPolicy]:
        """Resolves the best matching policy: exact requirement first, then framework fallback."""
        fid = (framework_id or "").upper()
        rid = (requirement_id or "").upper()

        # 1. Exact requirement policy
        if rid:
            exact = self._policies.get((fid, rid))
            if exact:
                return exact

        # 2. Framework fallback policy
        fallback = self._policies.get((fid, ""))
        if fallback:
            return fallback

        # 3. Global fallback
        return self._policies.get(("*", ""))

    def list_policies(self, framework_id: Optional[str] = None) -> List[EvidenceSufficiencyPolicy]:
        """Lists registered policies, optionally filtered by framework ID."""
        if framework_id:
            fid = framework_id.upper()
            return [p for (f, _), p in self._policies.items() if f == fid]
        return list(self._policies.values())

    def _load_seed_policies(self) -> None:
        """Loads deterministic seed policies for major compliance frameworks."""
        seeds = [
            # ==================================================================
            # Global Default Fallback
            # ==================================================================
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-GLOBAL-DEFAULT",
                policy_version="1.0.0",
                framework_id="*",
                requirement_id=None,
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=1,
                expected_frequency=ObservationFrequency.MONTHLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P35D",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 30),
                historical=HistoricalObservationRequirement(required=False, minimum_cycles=1),
            ),

            # ==================================================================
            # ISMS-P Seed Policies
            # ==================================================================
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-ISMS-P-DEFAULT",
                policy_version="1.0.0",
                framework_id="ISMS-P",
                requirement_id=None,
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=1,
                expected_frequency=ObservationFrequency.MONTHLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P35D",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 30),
                historical=HistoricalObservationRequirement(required=False, minimum_cycles=1),
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-ISMS-P-2.5.2",
                policy_version="1.0.0",
                framework_id="ISMS-P",
                requirement_id="ISMS-P-2.5.2",
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=3,
                expected_frequency=ObservationFrequency.MONTHLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P35D",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 30),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.MONTHLY,
                    minimum_cycles=3,
                    window_duration="P3M",
                    allowed_gaps=0,
                ),
                changes=ChangeHistoryRequirement(required=True, lookback_window="P90D"),
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-ISMS-P-2.7.1",
                policy_version="1.0.0",
                framework_id="ISMS-P",
                requirement_id="ISMS-P-2.7.1",
                required_observation_period=RequiredObservationPeriod.CURRENT_STATE,
                minimum_observation_cycles=3,
                expected_frequency=ObservationFrequency.CONTINUOUS,
                continuity_requirement=ContinuityRequirement.CONTINUOUS,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="24h",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 7),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.MONTHLY,
                    minimum_cycles=3,
                    window_duration="P3M",
                    allowed_gaps=0,
                ),
                changes=ChangeHistoryRequirement(required=True, lookback_window="P90D"),
                exceptions=ExceptionHistoryRequirement(required=True, lookback_window="P90D", severity_threshold="HIGH"),
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-ISMS-P-1.1.1",
                policy_version="1.0.0",
                framework_id="ISMS-P",
                requirement_id="ISMS-P-1.1.1",
                required_observation_period=RequiredObservationPeriod.ANNUAL_CYCLE,
                minimum_observation_cycles=1,
                expected_frequency=ObservationFrequency.ANNUAL,
                continuity_requirement=ContinuityRequirement.POINT_ONLY,
                sampling_strategy=SamplingStrategy.LATEST,
                gap_tolerance="P400D",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 365),
                historical=HistoricalObservationRequirement(required=False, minimum_cycles=1),
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-ISMS-P-2.6.1",
                policy_version="1.0.0",
                framework_id="ISMS-P",
                requirement_id="ISMS-P-2.6.1",
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=3,
                expected_frequency=ObservationFrequency.CONTINUOUS,
                continuity_requirement=ContinuityRequirement.CONTINUOUS,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="24h",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 7),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.MONTHLY,
                    minimum_cycles=3,
                    window_duration="P3M",
                    allowed_gaps=0,
                ),
                changes=ChangeHistoryRequirement(required=True, lookback_window="P90D"),
            ),

            # ==================================================================
            # ISO/IEC 27001:2022 Seed Policies
            # ==================================================================
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-ISO27001-DEFAULT",
                policy_version="1.0.0",
                framework_id="ISO-27001",
                requirement_id=None,
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=1,
                expected_frequency=ObservationFrequency.QUARTERLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P100D",
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-ISO27001-A.5.15",
                policy_version="1.0.0",
                framework_id="ISO-27001",
                requirement_id="ISO27001-A.5.15",
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=2,
                expected_frequency=ObservationFrequency.QUARTERLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P100D",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 90),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.QUARTERLY,
                    minimum_cycles=2,
                    window_duration="P6M",
                ),
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-ISO27001-A.8.8",
                policy_version="1.0.0",
                framework_id="ISO-27001",
                requirement_id="ISO27001-A.8.8",
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=3,
                expected_frequency=ObservationFrequency.MONTHLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P35D",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 30),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.MONTHLY,
                    minimum_cycles=3,
                    window_duration="P3M",
                ),
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-ISO27001-A.8.24",
                policy_version="1.0.0",
                framework_id="ISO-27001",
                requirement_id="ISO27001-A.8.24",
                required_observation_period=RequiredObservationPeriod.CURRENT_STATE,
                minimum_observation_cycles=3,
                expected_frequency=ObservationFrequency.CONTINUOUS,
                continuity_requirement=ContinuityRequirement.CONTINUOUS,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="24h",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 7),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.MONTHLY,
                    minimum_cycles=3,
                    window_duration="P3M",
                ),
            ),

            # ==================================================================
            # GDPR Seed Policies
            # ==================================================================
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-GDPR-DEFAULT",
                policy_version="1.0.0",
                framework_id="GDPR",
                requirement_id=None,
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=1,
                expected_frequency=ObservationFrequency.QUARTERLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P100D",
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-GDPR-ART-32",
                policy_version="1.0.0",
                framework_id="GDPR",
                requirement_id="GDPR-ART-32",
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=2,
                expected_frequency=ObservationFrequency.QUARTERLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P100D",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 30),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.QUARTERLY,
                    minimum_cycles=2,
                    window_duration="P6M",
                ),
            ),

            # ==================================================================
            # NIST CSF 2.0 Seed Policies
            # ==================================================================
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-NIST-CSF-DEFAULT",
                policy_version="1.0.0",
                framework_id="NIST-CSF",
                requirement_id=None,
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=1,
                expected_frequency=ObservationFrequency.MONTHLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P35D",
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-NIST-CSF-DE.CM-1",
                policy_version="1.0.0",
                framework_id="NIST-CSF",
                requirement_id="NIST-CSF-DE.CM-1",
                required_observation_period=RequiredObservationPeriod.CURRENT_STATE,
                minimum_observation_cycles=3,
                expected_frequency=ObservationFrequency.CONTINUOUS,
                continuity_requirement=ContinuityRequirement.CONTINUOUS,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="24h",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 7),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.MONTHLY,
                    minimum_cycles=3,
                    window_duration="P3M",
                ),
            ),

            # ==================================================================
            # CIS Controls v8 Seed Policies
            # ==================================================================
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-CIS-DEFAULT",
                policy_version="1.0.0",
                framework_id="CIS-CONTROLS",
                requirement_id=None,
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=1,
                expected_frequency=ObservationFrequency.MONTHLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P35D",
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-CIS-5.1",
                policy_version="1.0.0",
                framework_id="CIS-CONTROLS",
                requirement_id="CIS-5.1",
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=3,
                expected_frequency=ObservationFrequency.MONTHLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P35D",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 30),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.MONTHLY,
                    minimum_cycles=3,
                    window_duration="P3M",
                ),
            ),

            # ==================================================================
            # NIST AI RMF 1.0 Seed Policies
            # ==================================================================
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-NIST-AI-DEFAULT",
                policy_version="1.0.0",
                framework_id="NIST-AI-RMF",
                requirement_id=None,
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=1,
                expected_frequency=ObservationFrequency.SEMI_ANNUAL,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P200D",
            ),
            EvidenceSufficiencyPolicy(
                policy_id="POL-SUF-NIST-AI-MANAGE-2.1",
                policy_version="1.0.0",
                framework_id="NIST-AI-RMF",
                requirement_id="NIST-AI-MANAGE-2.1",
                required_observation_period=RequiredObservationPeriod.ROLLING_WINDOW,
                minimum_observation_cycles=3,
                expected_frequency=ObservationFrequency.MONTHLY,
                continuity_requirement=ContinuityRequirement.PERIODIC,
                sampling_strategy=SamplingStrategy.PERIODIC_SAMPLE,
                gap_tolerance="P35D",
                current_state=CurrentStateRequirement(required=True, max_age_seconds=86400 * 30),
                historical=HistoricalObservationRequirement(
                    required=True,
                    frequency=ObservationFrequency.MONTHLY,
                    minimum_cycles=3,
                    window_duration="P3M",
                ),
            ),
        ]

        for p in seeds:
            self.register_policy(p)


_GLOBAL_POLICY_REGISTRY: Optional[EvidencePolicyRegistry] = None


def get_policy_registry() -> EvidencePolicyRegistry:
    """Returns the singleton EvidencePolicyRegistry instance."""
    global _GLOBAL_POLICY_REGISTRY
    if _GLOBAL_POLICY_REGISTRY is None:
        _GLOBAL_POLICY_REGISTRY = EvidencePolicyRegistry()
    return _GLOBAL_POLICY_REGISTRY


def reset_policy_registry() -> None:
    """Resets the singleton EvidencePolicyRegistry instance for test isolation."""
    global _GLOBAL_POLICY_REGISTRY
    _GLOBAL_POLICY_REGISTRY = None
