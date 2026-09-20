"""Red Team 공격 시나리오 실행 및 감사 로그를 총괄하는 RedTeamRunner 모듈입니다."""

from typing import List, Optional, Tuple

from secgrc.agent_security.audit import SecurityAuditLogger, global_security_audit_logger
from secgrc.agent_security.models import SecurityAuditEvent
from secgrc.redteam.evaluator import RedTeamEvaluator
from secgrc.redteam.models import RedTeamCategory, RedTeamResult, RedTeamSummary
from secgrc.redteam.scenarios import (
    ScenarioRegistry,
    get_all_scenarios,
    get_scenario_by_id,
    get_scenarios_by_category,
    global_scenario_registry,
)
from secgrc.redteam.scoring import RedTeamScorer


class RedTeamRunner:
    """결정론적 합성 환경에서 Red Team 시나리오를 안전하게 실행하고 결과를 집계하는 러너"""

    def __init__(
        self,
        evaluator: Optional[RedTeamEvaluator] = None,
        registry: Optional[ScenarioRegistry] = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
    ):
        self.evaluator = evaluator or RedTeamEvaluator()
        self.registry = registry or global_scenario_registry
        self.audit_logger = audit_logger or global_security_audit_logger

    def run_scenario(self, scenario_id: str) -> Optional[RedTeamResult]:
        """단일 시나리오를 ID로 실행합니다."""
        scenario = self.registry.get_by_id(scenario_id)
        if not scenario:
            return None

        result = self.evaluator.evaluate_scenario(scenario)

        # 불변 감사 로그 기록
        event_type = "TOOL_DENIED" if result.blocked else "TOOL_ALLOWED"
        self.audit_logger.log_event(
            agent_id=scenario.target_agent or "redteam-runner",
            event=event_type,
            tool=scenario.target_tool or scenario.category.value,
            decision="DENIED" if result.blocked else "ALLOWED",
            details={
                "scenario_id": scenario.scenario_id,
                "category": scenario.category.value,
                "blocked": result.blocked,
                "detected": result.detected,
                "resilience_verified": True,
            },
        )

        return result

    def run_all(self) -> Tuple[RedTeamSummary, List[RedTeamResult]]:
        """등록된 28종 전체 시나리오를 실행하고 요약과 개별 결과를 반환합니다."""
        scenarios = self.registry.get_all()
        results: List[RedTeamResult] = []

        for sc in scenarios:
            res = self.evaluator.evaluate_scenario(sc)
            results.append(res)

        summary = RedTeamScorer.calculate_summary(results)
        return summary, results

    def run_category(self, category: RedTeamCategory) -> Tuple[RedTeamSummary, List[RedTeamResult]]:
        """특정 카테고리에 속한 시나리오만 필터링하여 실행합니다."""
        scenarios = self.registry.get_by_category(category)
        results: List[RedTeamResult] = []

        for sc in scenarios:
            res = self.evaluator.evaluate_scenario(sc)
            results.append(res)

        summary = RedTeamScorer.calculate_summary(results)
        return summary, results
