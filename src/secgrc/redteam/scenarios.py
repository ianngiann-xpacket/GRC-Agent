"""Red Team 공격 시나리오 인덱싱, 검색 및 필터링 유틸리티 모듈입니다."""

from typing import List, Optional
from secgrc.redteam.corpus import DEFAULT_REDTEAM_SCENARIOS
from secgrc.redteam.models import RedTeamCategory, RedTeamScenario


class ScenarioRegistry:
    """시나리오 목록 인메모리 관리 및 필터링 레지스트리"""

    def __init__(self, scenarios: Optional[List[RedTeamScenario]] = None):
        self._scenarios: List[RedTeamScenario] = list(scenarios or DEFAULT_REDTEAM_SCENARIOS)
        self._index_by_id = {s.scenario_id: s for s in self._scenarios}

    def get_all(self) -> List[RedTeamScenario]:
        """등록된 모든 시나리오 목록 반환"""
        return list(self._scenarios)

    def get_by_id(self, scenario_id: str) -> Optional[RedTeamScenario]:
        """ID로 단일 시나리오 검색"""
        return self._index_by_id.get(scenario_id)

    def get_by_category(self, category: RedTeamCategory) -> List[RedTeamScenario]:
        """카테고리별 시나리오 필터링"""
        cat_str = category.value if hasattr(category, "value") else str(category)
        return [s for s in self._scenarios if s.category.value == cat_str]

    def get_by_severity(self, severity: str) -> List[RedTeamScenario]:
        """심각도별 시나리오 필터링"""
        s_up = severity.upper()
        return [s for s in self._scenarios if s.severity.upper() == s_up]

    def register(self, scenario: RedTeamScenario) -> None:
        """신규 시나리오 동적 등록"""
        self._scenarios.append(scenario)
        self._index_by_id[scenario.scenario_id] = scenario


global_scenario_registry = ScenarioRegistry()


def get_all_scenarios() -> List[RedTeamScenario]:
    return global_scenario_registry.get_all()


def get_scenario_by_id(scenario_id: str) -> Optional[RedTeamScenario]:
    return global_scenario_registry.get_by_id(scenario_id)


def get_scenarios_by_category(category: RedTeamCategory) -> List[RedTeamScenario]:
    return global_scenario_registry.get_by_category(category)
