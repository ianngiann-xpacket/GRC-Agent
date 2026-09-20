"""Compliance & Investigation Report History Store (Step 23.6).

This module provides an append-only, immutable history store for generated reports.
Historical reports are never overwritten; regenerated reports receive distinct IDs.
"""

from copy import deepcopy
from typing import Dict, List, Optional
from secgrc.compliance.reporting_models import ComplianceReport, ReportType


class ReportHistoryStore:
    """불변 보고서 이력 저장소 (Append-only)."""

    def __init__(self) -> None:
        self._reports: Dict[str, ComplianceReport] = {}
        self._order: List[str] = []

    def record(self, report: ComplianceReport) -> str:
        """보고서를 이력 저장소에 불변 기록합니다. 기존 ID가 이미 존재할 경우 ValueError를 발생시킵니다."""
        if not isinstance(report, ComplianceReport):
            raise TypeError("Only ComplianceReport instances can be recorded in ReportHistoryStore.")

        if report.report_id in self._reports:
            raise ValueError(f"Report ID '{report.report_id}' already exists. Historical reports are immutable and cannot be overwritten.")

        self._reports[report.report_id] = deepcopy(report)
        self._order.append(report.report_id)
        return report.report_id

    def get(self, report_id: str) -> Optional[ComplianceReport]:
        """고유 식별자로 보고서를 조회합니다. (불변 깊은 복사본 반환)"""
        report = self._reports.get(report_id)
        return deepcopy(report) if report else None

    def list_all(self) -> List[ComplianceReport]:
        """기록된 모든 보고서 목록을 생성 순서대로 반환합니다."""
        return [deepcopy(self._reports[rid]) for rid in self._order]

    def list_by_type(self, report_type: ReportType) -> List[ComplianceReport]:
        """지정된 보고서 유형에 해당하는 보고서 목록을 반환합니다."""
        type_val = report_type.value if isinstance(report_type, ReportType) else str(report_type)
        return [deepcopy(self._reports[rid]) for rid in self._order if self._reports[rid].report_type == type_val]

    def list_by_framework(self, framework_id: str) -> List[ComplianceReport]:
        """지정된 프레임워크 식별자에 해당하는 보고서 목록을 반환합니다."""
        return [deepcopy(self._reports[rid]) for rid in self._order if self._reports[rid].framework_id == framework_id]

    def count(self) -> int:
        """저장된 총 보고서 건수를 반환합니다."""
        return len(self._reports)

    def clear(self) -> None:
        """테스트 격리를 위해 이력 저장소를 초기화합니다."""
        self._reports.clear()
        self._order.clear()


# Default singleton history store
default_report_history = ReportHistoryStore()
