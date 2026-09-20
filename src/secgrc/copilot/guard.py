"""AI 환각 방지 및 결정론적 일관성 검증 가드레일(CopilotGuard) 모듈입니다."""

import re
from typing import Any, Dict, List, Optional, Tuple

from secgrc.copilot.context import CopilotContext
from secgrc.ontology.repository import OntologyRepository


class CopilotGuard:
    """답변 출력 전 수치, 엔티티, 상태 및 출처의 정합성을 교차 검증하는 가드레일"""

    def __init__(self, repo: OntologyRepository) -> None:
        self.repo = repo

    def verify_and_guard(
        self,
        answer_text: str,
        context: CopilotContext,
    ) -> Tuple[bool, str, List[str]]:
        """생성된 답변의 사실성과 불변 데이터 정합성을 검증합니다.

        Returns:
            Tuple[bool, str, List[str]]: (검증통과여부, 수정/보정된 답변, 위반내역 목록)
        """
        violations: List[str] = []

        # 1. 통제 ID 유효성 검증 (단, 시스템이 유효하지 않은 식별자로 명시한 설명문 제외)
        ctrl_ids = re.findall(r"\bISMS-P-\d+\.\d+\.\d+\b", answer_text)
        for cid in set(ctrl_ids):
            if not self.repo.get_entity(cid):
                if f"[{cid}]는" in answer_text or f"'{cid}'는" in answer_text or f"[{cid}]" in answer_text:
                    continue
                violations.append(f"Hallucinated Control ID: '{cid}' does not exist in ontology repository")

        # 2. 위험 점수 수치 정합성 검증
        if context.risk:
            true_score = float(context.risk.get("risk_score", 0.0))
            # 텍스트 내 수치 점수 패턴 탐색 (예: 93.0점, 93점, score: 93)
            score_matches = re.findall(r"(\d+(?:\.\d+)?)\s*(?:점|score)", answer_text, re.IGNORECASE)
            for sm in score_matches:
                mentioned_score = float(sm)
                # 정답 점수와 현저히 다른 임의의 날조 수치 검출
                if abs(mentioned_score - true_score) > 0.05 and mentioned_score > 0.0:
                    violations.append(
                        f"Hallucinated Risk Score: mentioned {mentioned_score}, but true deterministic score is {true_score}"
                    )

        # 3. 비적합 및 NO_EVIDENCE / MANUAL 통제에 대한 상태 날조 방지
        if context.control:
            ctrl_status = str(context.control.get("effectiveness", "")).upper()
            if ctrl_status != "EFFECTIVE":
                if any(w in answer_text for w in ["통제 통과", "완전 적합", "상태: PASS", "상태: 적합", "COMPLIANT", "취약점 없음"]):
                    violations.append(
                        f"Compliance Tampering: Control is '{ctrl_status}', but answer claimed PASS/COMPLIANT"
                    )
            if ctrl_status in ("NOT_ASSESSED", "NO_EVIDENCE"):
                if any(w in answer_text for w in ["통과", "적합", "PASS", "COMPLIANT", "취약점 없음"]):
                    violations.append(
                        f"Compliance Tampering: Control is NOT_ASSESSED/NO_EVIDENCE, but answer claimed PASS"
                    )

        # 4. 카나리 시크릿 및 민감 토큰 누설 방지
        if any(w in answer_text for w in ["CANARY_SECRET", "AIzaSy", "ghp_", "xoxb-"]):
            violations.append("Security Violation: Secret or canary token detected in output")

        is_valid = (len(violations) == 0)
        final_answer = answer_text

        # 위반 발생 시 즉각 경고 첨부 또는 결정론적 안내
        if not is_valid:
            final_answer = self._sanitize_or_fallback(answer_text, context, violations)

        return is_valid, final_answer, violations

    def verify_provenance(self, provenance_list: List[Any]) -> Tuple[bool, List[str]]:
        """출처(Provenance)의 신뢰성 및 실제 온톨로지/인가 기관 정합성 검증"""
        trusted_authorities = {
            "REDTEAM_RUNNER", "ISMS-P", "NIST-CSF", "ISO-27001",
            "CIS-Controls", "NIST-AI-RMF", "INPUT_GUARD", "ONTOLOGY_REPO",
            "AGENT_SECURITY", "RiskEngine", "AuditEngine", "EVIDENCE_ADAPTER"
        }
        violations: List[str] = []
        for prov in provenance_list:
            sid = getattr(prov, "source_id", "") if not isinstance(prov, dict) else prov.get("source_id", "")
            stype = getattr(prov, "source_type", "") if not isinstance(prov, dict) else prov.get("source_type", "")
            if not sid:
                continue
            if sid in trusted_authorities:
                continue
            if not self.repo.get_entity(sid):
                violations.append(f"Spoofed Provenance: Entity '{sid}' of type '{stype}' does not exist in repository")
        return len(violations) == 0, violations

    def _sanitize_or_fallback(
        self,
        original_text: str,
        context: CopilotContext,
        violations: List[str],
    ) -> str:
        """위반 사항 발견 시 안전한 결정론적 답변으로 폴백 대체"""
        warning_header = f"⚠️ [안내] 모델의 일부 설명에서 검증 불일치 항목({len(violations)}건)이 감지되어 결정론적 데이터 기준으로 보정되었습니다.\n\n"
        
        # 기본 팩트 기반 요약문 조립
        summary_lines = []
        if context.risk:
            r = context.risk
            summary_lines.append(f"• 대상 위험: {r.get('risk_id')} (점수: {r.get('risk_score')}, 우선순위: {r.get('priority')})")
        if context.control:
            c = context.control
            summary_lines.append(f"• 관련 통제: {c.get('entity_id')} - {c.get('name')} [유효성: {c.get('effectiveness')}]")
        if context.evidence:
            ev_names = [e.get('name') for e in context.evidence[:3]]
            summary_lines.append(f"• 근거 증적: {', '.join(ev_names)}")

        from secgrc.copilot.context import sanitize_text
        fallback_body = "\n".join(summary_lines) if summary_lines else "시스템에 등록된 정합성 있는 보안 데이터만을 기반으로 재구성합니다."
        return sanitize_text(warning_header + fallback_body)
