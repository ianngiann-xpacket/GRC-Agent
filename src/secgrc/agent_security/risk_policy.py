"""에이전트 위험 등급(Agent Risk Classification) 및 과도한 에이전시(Excessive Agency) 방어 모듈입니다."""

from typing import Tuple
from secgrc.agent_security.models import AgentRiskLevel


class ExcessiveAgencyGuard:
    """AI 에이전트가 인간 승인 없이 자율적으로 위험한 프로덕션 변경을 수행하는 과도한 에이전시를 차단합니다.
    
    강제 파이프라인:
    Finding → Risk Scoring → Recommendation → Human Approval → Action
    
    차단되는 위험 패턴:
    - Finding 발견 즉시 AI가 변경 명령을 자동 실행
    - CRITICAL / HIGH 위험도 통제에 대한 결재 우회 시도
    - L5(완전 자율 운영) 승인 시도
    """

    @classmethod
    def validate_action_pipeline(
        cls,
        risk_level: str,
        has_human_approval: bool,
        is_dry_run: bool,
        agent_risk_level: AgentRiskLevel,
    ) -> Tuple[bool, str]:
        """조치 실행 전 파이프라인 유효성을 검사합니다."""
        # L5 완전 자율 실행은 현 단계에서 전면 차단
        if agent_risk_level == AgentRiskLevel.L5:
            return False, "보안 거버넌스 위반: L5 완전 자율 프로덕션 액션은 허용되지 않습니다."

        # 실제 변경(dry_run=False)인 경우
        if not is_dry_run:
            if not has_human_approval:
                return False, "과도한 에이전시 차단: 실제 프로덕션 변경은 사람(CISO/보안관리자)의 승인 없이 실행될 수 없습니다."

        # CRITICAL 또는 HIGH 위험 조치인 경우
        if risk_level.upper() in ("CRITICAL", "HIGH"):
            if not is_dry_run and not has_human_approval:
                return False, f"승인 필수: {risk_level} 등급의 고위험 조치는 승인 절차를 우회할 수 없습니다."

        return True, "Pipeline validated"
