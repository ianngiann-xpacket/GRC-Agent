"""Deterministic Change Replay Engine (Step 25, Section 51).

Replays a sequence of ChangeEvents from a baseline state, reproducing identical
canonical states, affected requirements, assessments, and compliance deltas.
"""

from copy import deepcopy
from typing import Any, Dict, List, Optional

from secgrc.compliance.assessment import ComplianceAssessment, ComplianceAssessmentEngine
from secgrc.compliance.assessment_history import AssessmentHistoryStore
from secgrc.compliance.models import (
    CanonicalDataType,
    CanonicalSecurityData,
    ProvenanceRecord,
)
from secgrc.continuous.delta import ComplianceDeltaEngine
from secgrc.continuous.impact import ComplianceImpactAnalyzer
from secgrc.continuous.models import ChangeEvent, ComplianceDelta, ImpactAnalysis
from secgrc.continuous.reassessment import IncrementalAssessmentEngine
from secgrc.continuous.timeline import ComplianceTimelineManager


def replay_changes(
    start_canonical_data: List[CanonicalSecurityData],
    change_events: List[ChangeEvent],
    framework_id: str = "ISMS-P",
    framework_version: str = "2024-07",
) -> Dict[str, Any]:
    """기준 정규 데이터 상태로부터 변경 이벤트를 순차 재생하여 동일한 결과를 결정론적으로 도출합니다.
    
    외부 네트워크, 비결정론적 난수, LLM을 전면 배제하며 로컬 결정론적 파이프라인만 실행합니다.
    """
    history_store = AssessmentHistoryStore()
    assessment_engine = ComplianceAssessmentEngine(history_store=history_store)
    impact_analyzer = ComplianceImpactAnalyzer()
    reassessment_engine = IncrementalAssessmentEngine(assessment_engine=assessment_engine, history_store=history_store)
    timeline_mgr = ComplianceTimelineManager()

    current_data: Dict[str, CanonicalSecurityData] = {
        getattr(d, "record_id", getattr(d, "data_id", f"rec-{i}")): deepcopy(d)
        for i, d in enumerate(start_canonical_data)
    }
    impact_analyses: List[ImpactAnalysis] = []
    all_deltas: List[ComplianceDelta] = []
    all_reassessments: List[ComplianceAssessment] = []

    for change in change_events:
        # 1. Update working canonical data based on change
        rec_key = change.source_record_id or change.entity_id
        if change.change_type.value == "DELETE":
            current_data.pop(rec_key, None)
        else:
            # Modify or add
            if rec_key in current_data:
                rec = current_data[rec_key]
                updated_payload = dict(rec.payload)
                for fc in change.changed_fields:
                    updated_payload[fc.field_name] = fc.new_value
                current_data[rec_key] = rec.model_copy(update={"payload": updated_payload})
            else:
                # Add new record
                dt = CanonicalDataType.CONFIGURATION
                if hasattr(CanonicalDataType, change.entity_type):
                    dt = CanonicalDataType[change.entity_type]
                elif change.entity_type in [e.value for e in CanonicalDataType]:
                    dt = CanonicalDataType(change.entity_type)

                new_rec = CanonicalSecurityData(
                    record_id=rec_key,
                    data_type=dt,
                    source_system=change.source_system,
                    source_record_id=change.source_record_id,
                    payload={fc.field_name: fc.new_value for fc in change.changed_fields},
                    observed_at=change.observed_at,
                    scope=change.scope,
                    tenant_id=change.tenant_id,
                    schema_version="1.0",
                    provenance=ProvenanceRecord(
                        source_system=change.source_system,
                        source_record_id=change.source_record_id,
                        source_timestamp=change.observed_at,
                        source_hash=change.new_hash or "hash",
                    ),
                    integrity_hash=change.integrity_hash or change.new_hash or "hash",
                )
                current_data[rec_key] = new_rec

        # 2. Impact Analysis
        impact = impact_analyzer.analyze(change)
        impact_analyses.append(impact)

        # 3. Targeted Reassessment
        active_data_list = list(current_data.values())
        reassessment_pairs = reassessment_engine.reassess(
            impact=impact,
            available_data=active_data_list,
            framework_id=framework_id,
            framework_version=framework_version,
        )

        # 4. Deltas & Timeline
        for prev_asm, new_asm in reassessment_pairs:
            all_reassessments.append(new_asm)
            delta = ComplianceDeltaEngine.compute_delta(
                previous_assessment=prev_asm,
                current_assessment=new_asm,
                change_ids=[change.change_id],
                now_iso=change.observed_at,
            )
            all_deltas.append(delta)

            # Record in timeline
            req_id = new_asm.requirement_id
            timeline_mgr.record_change(req_id, change)
            timeline_mgr.record_assessment(req_id, new_asm)
            timeline_mgr.record_delta(req_id, delta)

    return {
        "final_canonical_data": list(current_data.values()),
        "impact_analyses": impact_analyses,
        "reassessments": all_reassessments,
        "deltas": all_deltas,
        "timelines": {
            req: timeline_mgr.get_timeline(req, framework_id=framework_id)
            for req in timeline_mgr.list_requirements()
        },
    }
