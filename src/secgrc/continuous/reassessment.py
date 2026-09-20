"""Targeted Incremental Assessment Engine (Step 25).

Orchestrates re-assessment of ONLY affected requirements identified by
ImpactAnalysis, delegating evaluation strictly to the authoritative
Step 23.5C ComplianceAssessmentEngine. Does not duplicate assessment logic.
"""

from copy import deepcopy
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from secgrc.compliance.assessment import (
    ComplianceAssessment,
    ComplianceAssessmentEngine,
)
from secgrc.compliance.assessment_history import (
    AssessmentHistoryStore,
    default_assessment_history,
)
from secgrc.compliance.assessment_rules import AssessmentStatus
from secgrc.compliance.models import CanonicalSecurityData
from secgrc.continuous.models import ImpactAnalysis


def compute_reassessment_id(
    change_id: str,
    requirement_id: str,
    assessment_rule_version: str = "1.0",
    current_state_hash: str = "",
) -> str:
    """결정론적 재평가 식별자를 생성합니다 (Section 30)."""
    raw = f"{change_id}:{requirement_id}:{assessment_rule_version}:{current_state_hash}"
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"ASM-RE-{requirement_id}-{h}"


class IncrementalAssessmentEngine:
    """영향 받는 요구사항만을 선별적으로 재평가하는 증분 평가 오케스트레이터."""

    def __init__(
        self,
        assessment_engine: Optional[ComplianceAssessmentEngine] = None,
        history_store: Optional[AssessmentHistoryStore] = None,
    ) -> None:
        self.history_store = history_store or default_assessment_history
        self.assessment_engine = assessment_engine or ComplianceAssessmentEngine(history_store=self.history_store)

    def reassess(
        self,
        impact: ImpactAnalysis,
        available_data: List[CanonicalSecurityData],
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
    ) -> List[Tuple[Optional[ComplianceAssessment], ComplianceAssessment]]:
        """ImpactAnalysis의 affected_requirements 목록에 대해 23.5C 엔진에 위임하여 재평가를 수행합니다.
        
        기존 평가 이력을 절대 덮어쓰지 않고, (previous_assessment, current_assessment) 튜플 목록을 반환합니다.
        """
        results: List[Tuple[Optional[ComplianceAssessment], ComplianceAssessment]] = []

        # Compute hash of current available data
        data_hashes = sorted([getattr(d, "record_id", getattr(d, "data_id", "")) for d in available_data])
        state_hash = hashlib.sha256("".join(data_hashes).encode("utf-8")).hexdigest()[:8]

        for req_id in impact.affected_requirements:
            # 1. Fetch previous authoritative assessment from history if exists
            prev_assessment = self.history_store.get_latest_assessment(
                framework_id=framework_id,
                requirement_id=req_id,
            )

            # 2. Delegate to authoritative 23.5C Assessment Engine
            try:
                new_assessment = self.assessment_engine.assess(
                    framework_id=framework_id,
                    framework_version=framework_version,
                    requirement_id=req_id,
                    available_data=available_data,
                    target_scope=impact.impact_scope,
                )
            except Exception as e:
                # Failure recovery (Section 55): Fail-Closed/Undetermined
                new_assessment = ComplianceAssessment(
                    assessment_id=compute_reassessment_id(impact.change_id, req_id, "1.0", state_hash),
                    framework_id=framework_id,
                    framework_version=framework_version,
                    requirement_id=req_id,
                    status=AssessmentStatus.UNDETERMINED,
                    explanation_code="REASSESSMENT_FAILED",
                    provenance={
                        "error": str(e),
                        "cause_change_id": impact.change_id,
                    },
                )

            # Deterministic reassessment ID & causal link
            re_id = compute_reassessment_id(
                impact.change_id,
                req_id,
                new_assessment.rule_version or "1.0",
                state_hash,
            )

            prov = dict(new_assessment.provenance)
            prov["cause_change_id"] = impact.change_id
            if prev_assessment:
                prov["previous_assessment_id"] = prev_assessment.assessment_id

            final_new_assessment = new_assessment.model_copy(
                update={
                    "assessment_id": re_id,
                    "provenance": prov,
                }
            )

            # Record into history store (never overwrite previous)
            if hasattr(self.assessment_engine, "history_store") and self.assessment_engine.history_store is self.history_store:
                self.history_store._history.pop(new_assessment.assessment_id, None)
                if new_assessment in self.history_store._timeline:
                    self.history_store._timeline.remove(new_assessment)

            self.history_store.record(final_new_assessment)
            results.append((prev_assessment, final_new_assessment))

        return results
