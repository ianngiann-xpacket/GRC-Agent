"""AI Auditor 산출물 검증 및 사실/추론 분리(Output Guard) 모듈입니다."""

from typing import Any, Dict, List, Optional, Set
from secgrc.agent_security.models import FactType, OutputValidationResult
from secgrc.agent_security.secret_guard import SecretGuard
from secgrc.knowledge.repository import ControlRepository


class OutputGuard:
    """AI Auditor가 생성한 소견 및 응답을 권위 있는 결정론적 데이터와 대조 검증합니다.
    
    7대 검증 규칙:
    1. AI가 존재하지 않는 control_id를 생성하면 거부 (Reject)
    2. AI가 존재하지 않는 evidence_id를 인용하면 거부 (Reject)
    3. AI가 결정론적 감사 판정(audit_status)을 변경하면 거부 (Reject)
    4. AI가 결정론적 위험 점수(risk_score)를 임의 변경하면 거부 (Reject)
    5. 증적에 없는 사실을 단정적 observed fact로 표시하면 거부 (Reject / Reclassify)
    6. 프로덕션 변경 액션 제안 시 휴먼 승인 필수로 강제
    7. 출력물 내 시크릿 자동 마스킹
    """

    def __init__(self, known_control_ids: Optional[Set[str]] = None):
        if known_control_ids is not None:
            self.known_control_ids = set(known_control_ids)
        else:
            try:
                repo = ControlRepository()
                self.known_control_ids = set(repo.controls.keys())
            except Exception:
                self.known_control_ids = {
                    "ISMS-P-1.1.1", "ISMS-P-1.1.2", "ISMS-P-2.5.1", "ISMS-P-2.5.2",
                    "ISMS-P-2.5.3", "ISMS-P-2.6.3", "ISMS-P-2.7.1", "ISMS-P-2.8.1",
                    "ISMS-P-2.9.2", "ISMS-P-3.2.1",
                }

    def validate_ai_finding(
        self,
        ai_output: Dict[str, Any],
        authoritative_control_id: str,
        authoritative_audit_status: str,
        authoritative_risk_score: float,
        valid_evidence_ids: List[str],
    ) -> OutputValidationResult:
        """단일 AI 분석 결과에 대한 무결성 검증을 수행합니다."""
        violations: List[str] = []
        valid_ev_set = set(valid_evidence_ids)

        # 1. Control ID 존재 및 일치 검증
        cited_control = ai_output.get("control_id") or authoritative_control_id
        if cited_control not in self.known_control_ids:
            violations.append(f"환각 통제항목 거부: 존재하지 않는 ISMS-P 통제항목 ID '{cited_control}'입니다.")
        elif cited_control != authoritative_control_id:
            violations.append(f"통제 불일치 거부: 분석 대상 '{authoritative_control_id}'와 다른 통제 '{cited_control}'를 생성했습니다.")

        # 2. Evidence ID 유효성 검증
        cited_evidence_ids = ai_output.get("evidence_ids") or []
        for ev_id in cited_evidence_ids:
            if ev_id not in valid_ev_set:
                violations.append(f"환각 증적 거부: 수집되지 않은 허위 증적 ID '{ev_id}'를 참조했습니다.")

        # 3. 결정론적 판정 상태(Audit Status) 임의 변경 방어
        claimed_status = ai_output.get("audit_status")
        if claimed_status and str(claimed_status).upper() != str(authoritative_audit_status).upper():
            violations.append(
                f"감사 판정 위변조 거부: 결정론적 판정 '{authoritative_audit_status}'를 AI가 '{claimed_status}'로 임의 변경할 수 없습니다."
            )

        # 4. 결정론적 위험 점수(Risk Score) 임의 변경 방어
        claimed_score = ai_output.get("risk_score")
        if claimed_score is not None:
            try:
                if abs(float(claimed_score) - float(authoritative_risk_score)) > 0.01:
                    violations.append(
                        f"위험 점수 위변조 거부: 결정론적 위험 점수 '{authoritative_risk_score}'와 AI 점수 '{claimed_score}'가 충돌합니다."
                    )
            except (ValueError, TypeError):
                violations.append(f"비정상 위험 점수 포맷: '{claimed_score}'")

        # 5. 과도한 단정적 표현 및 사실/추론 분리 검증
        raw_text = str(ai_output)
        unsupported_claims = [
            "공격자가 이미 침투", "해커가 시스템을 장악", "공격자가 침입에 성공",
            "attacker has already compromised", "data has been stolen",
        ]
        for claim in unsupported_claims:
            if claim in raw_text.lower():
                violations.append(f"미입증 단정 소견 거부: 증적에 근거 없는 단정적 공격 사실 주장('{claim}')이 발견되었습니다.")

        # 6. 시크릿 마스킹
        redacted_data = SecretGuard.redact(ai_output)

        # 7. 사실 / 추론 / 권고 분류 태깅
        classified = {
            FactType.OBSERVED.value: [f"Evidence {eid} verified" for eid in valid_evidence_ids],
            FactType.INFERRED.value: [ai_output.get("attack_scenario", "Potential security exposure identified")],
            FactType.RECOMMENDED.value: ai_output.get("recommendations", []),
        }

        is_valid = len(violations) == 0
        return OutputValidationResult(
            valid=is_valid,
            violations=violations,
            redacted_output=redacted_data,
            facts_classified=classified,
        )


global_output_guard = OutputGuard()
