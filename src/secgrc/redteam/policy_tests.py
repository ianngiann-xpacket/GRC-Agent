"""Purple Team 연동 및 취약 시나리오 재검증(Retest) 워크플로우 모듈입니다."""

from typing import Any, Dict, List, Optional
from secgrc.redteam.evaluator import RedTeamEvaluator
from secgrc.redteam.models import RedTeamResult, RedTeamScenario


class PurpleTeamWorkflow:
    """Attack -> Detection -> Control Identification -> Risk -> Remediation -> Retest 프로세스를 관리하는 워크플로우 엔진"""

    def __init__(self, evaluator: Optional[RedTeamEvaluator] = None):
        self.evaluator = evaluator or RedTeamEvaluator()

    def analyze_finding(self, scenario: RedTeamScenario, result: RedTeamResult) -> Dict[str, Any]:
        """Red Team 결과 중 방어 실패 건에 대한 취약 통제 식별 및 조치 권고를 도출합니다."""
        is_failed = (not result.blocked) or result.policy_violated or result.secret_leaked or result.approval_bypassed

        if not is_failed:
            return {
                "status": "SECURE",
                "violated_control": None,
                "risk": "NONE",
                "evidence": result.evidence,
                "recommended_remediation": "Current defense controls effective. Continue routine monitoring.",
                "retest_required": False,
            }

        # 실패 시 Purple Team 소견 구성
        risk_level = scenario.severity
        violated_control = scenario.expected_control

        return {
            "status": "VULNERABLE",
            "violated_control": violated_control,
            "risk": f"High exposure of {scenario.category.value} in {violated_control} layer.",
            "evidence": result.evidence or result.explanation,
            "recommended_remediation": result.remediation or f"Enhance {violated_control} filtering rules.",
            "retest_required": True,
        }

    def execute_retest(self, scenario: RedTeamScenario) -> RedTeamResult:
        """보안 패치 적용 후 시나리오 재평가를 즉시 실행합니다."""
        return self.evaluator.evaluate_scenario(scenario)
