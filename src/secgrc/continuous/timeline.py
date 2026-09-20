"""Compliance Timeline Manager (Step 25).

Maintains a deterministic historical timeline of compliance state transitions,
change events, reassessments, and deltas per requirement (Section 35, 68).
"""

from copy import deepcopy
from typing import Dict, List, Optional

from secgrc.compliance.assessment import ComplianceAssessment
from secgrc.continuous.models import (
    ChangeEvent,
    ComplianceDelta,
    ComplianceTimeline,
    ComplianceTimelineEntry,
)


class ComplianceTimelineManager:
    """요구사항별 컴플라이언스 변동 타임라인 관리자."""

    def __init__(self) -> None:
        # requirement_id -> list of entries
        self._timelines: Dict[str, List[ComplianceTimelineEntry]] = {}

    def record_change(self, requirement_id: str, change: ChangeEvent) -> None:
        """타임라인에 원인 변경 이벤트를 기록합니다."""
        entry = ComplianceTimelineEntry(
            timestamp=change.occurred_at,
            event_type="CHANGE",
            status=None,
            change_id=change.change_id,
            summary=f"Change detected: {change.entity_type} ({change.change_type.value})",
        )
        self._append_entry(requirement_id, entry)

    def record_assessment(self, requirement_id: str, assessment: ComplianceAssessment) -> None:
        """타임라인에 평가 결과를 기록합니다."""
        entry = ComplianceTimelineEntry(
            timestamp=assessment.evaluated_at,
            event_type="REASSESSMENT",
            status=assessment.status.value,
            assessment_id=assessment.assessment_id,
            summary=f"Reassessment completed: status={assessment.status.value} (code={assessment.explanation_code})",
        )
        self._append_entry(requirement_id, entry)

    def record_delta(self, requirement_id: str, delta: ComplianceDelta) -> None:
        """타임라인에 상태 델타를 기록합니다."""
        entry = ComplianceTimelineEntry(
            timestamp=delta.detected_at,
            event_type="DELTA",
            status=delta.current_status,
            delta_id=delta.delta_id,
            summary=f"Compliance delta: {'CHANGED' if delta.status_changed else 'STABLE'} ({delta.previous_status or 'INIT'} -> {delta.current_status})",
        )
        self._append_entry(requirement_id, entry)

    def _append_entry(self, requirement_id: str, entry: ComplianceTimelineEntry) -> None:
        if requirement_id not in self._timelines:
            self._timelines[requirement_id] = []
        self._timelines[requirement_id].append(entry)
        # Ensure chronological ordering by timestamp
        self._timelines[requirement_id].sort(key=lambda e: e.timestamp)

    def get_timeline(self, requirement_id: str, framework_id: str = "ISMS-P") -> ComplianceTimeline:
        """요구사항의 전체 타임라인을 조회합니다."""
        entries = self._timelines.get(requirement_id, [])
        return ComplianceTimeline(
            requirement_id=requirement_id,
            framework_id=framework_id,
            entries=[deepcopy(e) for e in entries],
        )

    def list_requirements(self) -> List[str]:
        """타임라인이 기록된 요구사항 ID 목록을 반환합니다."""
        return sorted(list(self._timelines.keys()))

    def clear(self) -> None:
        """테스트 격리용 초기화."""
        self._timelines.clear()


default_timeline_manager = ComplianceTimelineManager()
