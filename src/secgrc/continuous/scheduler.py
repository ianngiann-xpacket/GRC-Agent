"""지속적 컴플라이언스 건전성 점수(Compliance Health) 산출 및 시계열 트렌드 감지 스케줄러 모듈입니다."""

from datetime import datetime, timezone
from typing import List, Optional
from secgrc.continuous.models import (
    ComplianceHealthSnapshot,
    ControlSnapshot,
    TrendDirection,
)


class ContinuousScheduler:
    """이벤트 기반 즉시 실행 및 주기적(Hourly/Daily/Weekly) 컴플라이언스 점수 집계 스케줄러입니다."""

    def __init__(self):
        self._health_history: List[ComplianceHealthSnapshot] = []
        self._seed_default_history()

    def _seed_default_history(self):
        """기본 시계열 건전성 데이터 시드 (최근 5일간)"""
        self._health_history.extend([
            ComplianceHealthSnapshot(timestamp="2026-09-05T00:00:00Z", health_score=78.0, average_risk=22.0, total_controls=10, failing_controls=1),
            ComplianceHealthSnapshot(timestamp="2026-09-06T00:00:00Z", health_score=74.0, average_risk=26.0, total_controls=10, failing_controls=2),
            ComplianceHealthSnapshot(timestamp="2026-09-07T00:00:00Z", health_score=75.0, average_risk=25.0, total_controls=10, failing_controls=2),
            ComplianceHealthSnapshot(timestamp="2026-09-08T00:00:00Z", health_score=68.0, average_risk=32.0, total_controls=10, failing_controls=3),
            ComplianceHealthSnapshot(timestamp="2026-09-09T00:00:00Z", health_score=62.0, average_risk=38.0, total_controls=10, failing_controls=4),
        ])

    @staticmethod
    def calculate_compliance_health(snapshots: List[ControlSnapshot]) -> ComplianceHealthSnapshot:
        """현재 통제항목들의 스냅샷을 기반으로 Compliance Health = 100 - normalized weighted risk 를 산출합니다."""
        if not snapshots:
            return ComplianceHealthSnapshot(
                timestamp=datetime.now(timezone.utc).isoformat(),
                health_score=100.0,
                average_risk=0.0,
                total_controls=0,
                failing_controls=0,
            )

        total = len(snapshots)
        failing = sum(1 for s in snapshots if s.status == "FAIL")
        avg_risk = sum(s.risk_score for s in snapshots) / total

        # Compliance Health 점수 (100점 만점 기준)
        # 위험 점수가 높을수록 건전성 점수는 감소
        health = max(0.0, min(100.0, 100.0 - avg_risk))

        return ComplianceHealthSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            health_score=round(health, 1),
            average_risk=round(avg_risk, 1),
            total_controls=total,
            failing_controls=failing,
        )

    def record_snapshot(self, snapshots: List[ControlSnapshot]) -> ComplianceHealthSnapshot:
        """새로운 시점의 건전성 스냅샷을 계산하고 이력에 보관합니다."""
        record = self.calculate_compliance_health(snapshots)
        self._health_history.append(record)
        return record

    def get_history(self) -> List[ComplianceHealthSnapshot]:
        """시계열 건전성 스냅샷 이력을 반환합니다."""
        return list(self._health_history)

    @classmethod
    def analyze_trend(cls, scores: List[float]) -> TrendDirection:
        """최근 N개 점수(또는 위험도)를 분석하여 트렌드 방향(IMPROVING, STABLE, DEGRADING, VOLATILE)을 판정합니다.
        
        예:
        - 93, 82, 76, 71, 65 (위험도 하락) -> IMPROVING
        - 35, 41, 58, 72, 89 (위험도 상승) -> DEGRADING
        - 변화폭이 5점 이내 -> STABLE
        - 등락이 교차 -> VOLATILE
        """
        if len(scores) < 3:
            return TrendDirection.STABLE

        diffs = [scores[i + 1] - scores[i] for i in range(len(scores) - 1)]

        # 전체 변화폭
        total_change = scores[-1] - scores[0]

        if all(d <= 0 for d in diffs) and total_change <= -5.0:
            return TrendDirection.IMPROVING
        elif all(d >= 0 for d in diffs) and total_change >= 5.0:
            return TrendDirection.DEGRADING
        elif all(abs(d) < 5.0 for d in diffs):
            return TrendDirection.STABLE
        else:
            return TrendDirection.VOLATILE
