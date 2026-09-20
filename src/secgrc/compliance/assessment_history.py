"""Assessment History Store (Step 23.5C).

This module manages the append-only, immutable history of compliance assessments,
ensuring that historical evaluations are never overwritten and auditability is preserved.
"""

from typing import Any, Dict, List, Optional
from pydantic import Field

from secgrc.compliance.models import ComplianceBaseModel, validate_identifier


class AssessmentHistoryStore:
    """불변 평가 이력 저장소 (Append-only)."""

    def __init__(self) -> None:
        # assessment_id -> ComplianceAssessment
        self._history: Dict[str, Any] = {}
        self._timeline: List[Any] = []

    def record(self, assessment: Any) -> None:
        """새로운 평가 결과를 불변 이력으로 추가합니다 (덮어쓰기 금지)."""
        if assessment.assessment_id in self._history:
            raise ValueError(f"Assessment ID {assessment.assessment_id} already exists in history")
        self._history[assessment.assessment_id] = assessment
        self._timeline.append(assessment)

    def get(self, assessment_id: str) -> Optional[Any]:
        """평가 ID로 과거 평가 결과를 조회합니다."""
        clean_id = validate_identifier(assessment_id, "assessment_id")
        return self._history.get(clean_id)

    def list_by_requirement(
        self,
        requirement_id: str,
        framework_id: Optional[str] = None,
    ) -> List[Any]:
        """특정 요구사항의 과거 평가 이력을 시간순으로 반환합니다."""
        res = [a for a in self._timeline if a.requirement_id == requirement_id]
        if framework_id:
            res = [a for a in res if a.framework_id == framework_id]
        return res

    def get_history(
        self,
        framework_id: Optional[str] = None,
        requirement_id: Optional[str] = None,
    ) -> List[Any]:
        """list_by_requirement의 유연한 별칭 메서드."""
        res = list(self._timeline)
        if requirement_id:
            res = [a for a in res if a.requirement_id == requirement_id]
        if framework_id:
            res = [a for a in res if a.framework_id == framework_id]
        return res

    def get_latest_assessment(
        self,
        framework_id_or_req: Optional[str] = None,
        requirement_id: Optional[str] = None,
        framework_id: Optional[str] = None,
    ) -> Optional[Any]:
        """특정 요구사항의 가장 최신 평가 결과를 반환합니다."""
        # Handle flexible argument orders: (req), (req, fw), or (fw, req)
        req = requirement_id
        fw = framework_id
        if framework_id_or_req is not None:
            if requirement_id is None:
                req = framework_id_or_req
            else:
                # Two positional args passed: first is either fw or req
                if framework_id_or_req in ("ISMS-P", "ISO27001", "GDPR", "DEFAULT"):
                    fw = framework_id_or_req
                    req = requirement_id
                else:
                    req = framework_id_or_req
                    fw = requirement_id

        history = self.get_history(framework_id=fw, requirement_id=req)
        return history[-1] if history else None

    def append(self, assessment: Any) -> None:
        """record의 별칭으로 평가 결과를 추가합니다."""
        self.record(assessment)

    def list_by_status(self, status: Any) -> List[Any]:
        """특정 평가 상태의 과거 평가 이력을 반환합니다."""
        val = status.value if hasattr(status, "value") else str(status)
        return [a for a in self._timeline if (a.status.value if hasattr(a.status, "value") else str(a.status)) == val]

    def list_all(self) -> List[Any]:
        """전체 평가 이력을 시간순으로 반환합니다."""
        return list(self._timeline)

    def clear(self) -> None:
        """테스트 격리를 위해 이력을 초기화합니다."""
        self._history.clear()
        self._timeline.clear()


# 기본 싱글톤 평가 이력 저장소
default_assessment_history = AssessmentHistoryStore()
