"""Public Read-Only Query APIs for Continuous Compliance (Step 25, Section 49).

Provides audit-ready, read-only interfaces to inspect ChangeEvents,
ImpactAnalyses, ComplianceDeltas, and Timelines.
"""

from typing import Any, Dict, List, Optional

from secgrc.compliance.assessment_history import default_assessment_history
from secgrc.continuous.impact import ComplianceImpactAnalyzer
from secgrc.continuous.ledger import default_change_ledger
from secgrc.continuous.models import (
    ChangeEvent,
    ComplianceDelta,
    ComplianceTimeline,
    ImpactAnalysis,
)
from secgrc.continuous.timeline import default_timeline_manager

# In-memory storage for generated deltas during runtime sessions
_global_delta_store: List[ComplianceDelta] = []


def record_delta_for_query(delta: ComplianceDelta) -> None:
    """도출된 델타를 쿼리용 글로벌 저장소에 기록합니다."""
    _global_delta_store.append(delta)


def clear_delta_store() -> None:
    """테스트 격리용 델타 저장소 초기화."""
    _global_delta_store.clear()


def get_changes(tenant_id: Optional[str] = None, limit: int = 100) -> List[ChangeEvent]:
    """변경 이벤트 목록을 조회합니다."""
    return default_change_ledger.list(tenant_id=tenant_id, limit=limit)


def get_change(change_id: str, tenant_id: Optional[str] = None) -> Optional[ChangeEvent]:
    """특정 변경 이벤트를 조회합니다."""
    return default_change_ledger.get(change_id=change_id, tenant_id=tenant_id)


def get_entity_changes(entity_id: str, tenant_id: Optional[str] = None) -> List[ChangeEvent]:
    """특정 엔티티의 변경 이력을 조회합니다."""
    return default_change_ledger.find_by_entity(entity_id=entity_id, tenant_id=tenant_id)


def get_impacts(change_id: str) -> Optional[ImpactAnalysis]:
    """특정 변경 이벤트의 영향 분석 결과를 계산하여 반환합니다."""
    ev = default_change_ledger.get(change_id)
    if not ev:
        return None
    analyzer = ComplianceImpactAnalyzer()
    return analyzer.analyze(ev)


def get_affected_requirements(change_id: str) -> List[str]:
    """특정 변경으로 인해 영향 받는 요구사항 ID 목록을 반환합니다."""
    impact = get_impacts(change_id)
    return impact.affected_requirements if impact else []


def get_compliance_deltas(requirement_id: Optional[str] = None, limit: int = 50) -> List[ComplianceDelta]:
    """컴플라이언스 상태 델타 목록을 반환합니다."""
    if requirement_id:
        res = [d for d in _global_delta_store if d.requirement_id == requirement_id]
    else:
        res = list(_global_delta_store)
    return res[:limit]


def get_requirement_timeline(requirement_id: str, framework_id: str = "ISMS-P") -> ComplianceTimeline:
    """특정 요구사항의 컴플라이언스 타임라인을 반환합니다."""
    return default_timeline_manager.get_timeline(requirement_id, framework_id=framework_id)


def get_recent_compliance_changes(limit: int = 10) -> List[Dict[str, Any]]:
    """최근 컴플라이언스 변동 요약 목록을 반환합니다 (대시보드 연동용)."""
    deltas = get_compliance_deltas(limit=limit)
    return [
        {
            "delta_id": d.delta_id,
            "requirement_id": d.requirement_id,
            "previous_status": d.previous_status,
            "current_status": d.current_status,
            "status_changed": d.status_changed,
            "detected_at": d.detected_at,
            "reason_codes": d.reason_codes,
        }
        for d in deltas
    ]


def get_reassessment_history(requirement_id: str, framework_id: str = "ISMS-P") -> List[Any]:
    """특정 요구사항의 재평가 이력을 반환합니다."""
    return default_assessment_history.get_history(framework_id=framework_id, requirement_id=requirement_id)
