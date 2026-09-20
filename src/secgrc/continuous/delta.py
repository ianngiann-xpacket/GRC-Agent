"""Compliance Delta Engine (Step 25).

Calculates deterministic deltas between previous and current compliance assessments,
tracking all state transitions (PASS <-> FAIL <-> PARTIAL <-> NO_EVIDENCE) and reasons.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional

from secgrc.compliance.assessment import ComplianceAssessment
from secgrc.continuous.models import ComplianceDelta


class ComplianceDeltaEngine:
    """컴플라이언스 평가 전후 델타 산출 엔진."""

    @classmethod
    def compute_delta(
        cls,
        previous_assessment: Optional[ComplianceAssessment],
        current_assessment: ComplianceAssessment,
        change_ids: Optional[List[str]] = None,
        now_iso: Optional[str] = None,
    ) -> ComplianceDelta:
        """이전 평가와 신규 재평가 간의 델타를 계산합니다."""
        if not isinstance(current_assessment, ComplianceAssessment):
            raise TypeError("Expected ComplianceAssessment instance for current_assessment")

        req_id = current_assessment.requirement_id
        timestamp = now_iso or datetime.now(timezone.utc).isoformat()
        c_ids = change_ids or []

        prev_id = previous_assessment.assessment_id if previous_assessment else None
        prev_st = previous_assessment.status.value if previous_assessment else None
        curr_st = current_assessment.status.value

        status_changed = (prev_st != curr_st)

        changed_fields: List[str] = []
        reason_codes: List[str] = []

        if status_changed:
            changed_fields.append("status")
            reason_codes.append(f"TRANSITION:{prev_st or 'INITIAL'}->{curr_st}")
        else:
            reason_codes.append(f"STATUS_UNCHANGED:{curr_st}")

        # Check detail field changes
        if previous_assessment:
            if previous_assessment.available_items != current_assessment.available_items:
                changed_fields.append("available_items")
            if previous_assessment.missing_items != current_assessment.missing_items:
                changed_fields.append("missing_items")
            if previous_assessment.failed_conditions != current_assessment.failed_conditions:
                changed_fields.append("failed_conditions")
            if previous_assessment.rule_id != current_assessment.rule_id:
                changed_fields.append("rule_id")

        # Specific transition reason tags
        if prev_st == "PASS" and curr_st == "FAIL":
            reason_codes.append("COMPLIANCE_DEGRADATION")
        elif prev_st in ("FAIL", "PARTIAL", "NO_EVIDENCE") and curr_st == "PASS":
            reason_codes.append("COMPLIANCE_IMPROVEMENT")
        elif curr_st == "NO_EVIDENCE" and prev_st != "NO_EVIDENCE":
            reason_codes.append("EVIDENCE_GAP_DETECTED")
        elif curr_st == "CONFLICTING":
            reason_codes.append("CONFLICT_DETECTED")

        # Deterministic delta_id
        raw_seed = f"{req_id}:{prev_id or 'none'}:{current_assessment.assessment_id}"
        d_hash = hashlib.sha256(raw_seed.encode("utf-8")).hexdigest()[:10]
        d_id = f"DLT-{req_id}-{d_hash}"

        return ComplianceDelta(
            delta_id=d_id,
            requirement_id=req_id,
            previous_assessment_id=prev_id,
            current_assessment_id=current_assessment.assessment_id,
            previous_status=prev_st,
            current_status=curr_st,
            status_changed=status_changed,
            changed_fields=sorted(changed_fields),
            change_ids=c_ids,
            reason_codes=reason_codes,
            detected_at=timestamp,
            provenance={
                "engine": "ComplianceDeltaEngine",
                "explanation_code": current_assessment.explanation_code,
            },
        )
