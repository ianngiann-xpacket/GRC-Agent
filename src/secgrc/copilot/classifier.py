"""자연어 의도 분류(Intent Classification) 및 엔티티 추출 모듈입니다."""

import re
from typing import Any, Dict, List, Optional

from secgrc.agent_security.input_guard import InputGuard
from secgrc.copilot.intents import INTENT_METADATA, IntentCategory, IntentResult
from secgrc.ontology.repository import OntologyRepository


class CopilotIntentClassifier:
    """결정론적 규칙 우선 의도 분류기 및 안전 검증기"""

    def __init__(self, repo: Optional[OntologyRepository] = None) -> None:
        self.repo = repo
        self.input_guard = InputGuard()

    def classify(self, question: str) -> IntentResult:
        """사용자 질문을 분석하여 의도(Intent)와 엔티티를 추출합니다."""
        # 1. 입력 보안 가드레일 (Prompt Injection & Secret Extraction & Path Traversal 검사)
        detect_res = self.input_guard.detect_injection(question)
        if detect_res.detected:
            return IntentResult(
                intent=IntentCategory.UNKNOWN,
                confidence=0.0,
                entities={
                    "security_violation": f"Prompt injection detected ({detect_res.category.value if detect_res.category else 'UNKNOWN'})",
                    "category": detect_res.category.value if detect_res.category else "UNKNOWN",
                },
                required_data=[],
                allowed_operations=[],
            )

        # 경로 조작(Path Traversal) 공격 방어
        if re.search(r"(?:\.\.[/\\]|/etc/(?:passwd|shadow)|\b\.env\b|/proc/version)", question, re.IGNORECASE):
            return IntentResult(
                intent=IntentCategory.UNKNOWN,
                confidence=0.0,
                entities={
                    "security_violation": "Path traversal attempt detected",
                    "category": "PATH_TRAVERSAL",
                },
                required_data=[],
                allowed_operations=[],
            )

        # 2. 엔티티 추출 및 검증
        entities = self._extract_entities(question)

        # 3. 규칙 기반 의도 분류
        intent, confidence = self._determine_intent(question, entities)

        meta = INTENT_METADATA.get(intent, {"required_data": [], "allowed_operations": []})

        return IntentResult(
            intent=intent,
            confidence=confidence,
            entities=entities,
            required_data=meta["required_data"],
            allowed_operations=meta["allowed_operations"],
        )

    def _extract_entities(self, text: str) -> Dict[str, Any]:
        """정규식 및 키워드 기반 엔티티 추출 및 온톨로지 대조 검증"""
        entities: Dict[str, Any] = {}

        # 교차 테넌트 / 권한 경계 검사
        if re.search(r"(?i)(다른\s*조직|타\s*조직|다른\s*테넌트|all\s*tenants?|another\s+org(?:anization)?|cross-tenant|requested_scope)", text):
            entities["cross_tenant_query"] = True

        # 1. Control ID 추출 (접두어 RISK- 또는 EV- 배제하여 혼동 방지)
        ctrl_match = re.search(r"(?<!RISK-)(?<!EV-)(?<![A-Za-z0-9_-])ISMS-P-\d+\.\d+\.\d+(?!\d)", text, re.IGNORECASE)
        if ctrl_match:
            ctrl_id = ctrl_match.group(0).upper()
            entities["control_id"] = ctrl_id
            if self.repo:
                from secgrc.ontology.entities import Control
                ent = self.repo.get_entity(ctrl_id)
                exists = bool(ent is not None and isinstance(ent, Control))
                entities["control_exists"] = exists
                if not exists:
                    entities["invalid_control_id"] = ctrl_id
            else:
                entities["control_exists"] = True

        # 2. Risk ID 추출 (예: RISK-ISMS-P-2.7.1, RISK-001)
        risk_match = re.search(r"RISK-[A-Za-z0-9_.-]+(?![A-Za-z0-9_.-])", text, re.IGNORECASE)
        if risk_match:
            risk_id = risk_match.group(0).upper()
            entities["risk_id"] = risk_id
            if self.repo:
                from secgrc.ontology.entities import RiskEntity
                rent = self.repo.get_entity(risk_id)
                exists = bool(rent is not None and isinstance(rent, RiskEntity))
                entities["risk_exists"] = exists
                if not exists:
                    entities["invalid_risk_id"] = risk_id
            else:
                entities["risk_exists"] = True

        # 3. Evidence ID 추출 (예: prowler-gcp-storage-001, EV-001)
        ev_match = re.search(r"(?:EV-)?prowler-[a-zA-Z0-9_-]+", text, re.IGNORECASE)
        if ev_match:
            ev_id = ev_match.group(0)
            if not ev_id.startswith("EV-"):
                ev_id = f"EV-{ev_id}"
            entities["evidence_id"] = ev_id
            if self.repo:
                from secgrc.ontology.entities import EvidenceEntity
                eent = self.repo.get_entity(ev_id)
                exists = bool(eent is not None and isinstance(eent, EvidenceEntity))
                entities["evidence_exists"] = exists
                if not exists:
                    entities["invalid_evidence_id"] = ev_id
            else:
                entities["evidence_exists"] = True

        # 4. 프레임워크명 추출 (통제 식별자 내 ISMS-P를 제외한 대상 프레임워크 정밀 추출)
        cleaned_for_fw = re.sub(r"ISMS-P-\d+\.\d+\.\d+", "", text)
        fw_match = re.search(r"(NIST(?:-CSF|-AI-RMF)?|ISO(?:-27001)?|CIS(?:-Controls)?|ISMS-P)", cleaned_for_fw, re.IGNORECASE)
        if fw_match:
            raw_fw = fw_match.group(0).upper()
            if "NIST" in raw_fw:
                entities["framework_id"] = "NIST-CSF"
            elif "ISO" in raw_fw:
                entities["framework_id"] = "ISO-27001"
            elif "CIS" in raw_fw:
                entities["framework_id"] = "CIS-Controls"
            else:
                entities["framework_id"] = "ISMS-P"
        elif re.search(r"(?i)(NIST[A-Za-z0-9_.-]*|ISO[A-Za-z0-9_.-]*|CIS[A-Za-z0-9_.-]*|[A-Z]{3,}-[A-Z0-9]+)", cleaned_for_fw):
            entities["unknown_framework"] = True

        # 5. 수치 점수 및 가상 시나리오 추출
        score_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:점|score)", text, re.IGNORECASE)
        if score_match:
            try:
                entities["score_reference"] = float(score_match.group(1))
            except ValueError:
                pass
        if any(w in text for w in ["가정", "가상", "계산하면", "assume", "hypothetical"]):
            entities["hypothetical_scenario"] = True

        return entities

    def _determine_intent(self, text: str, entities: Dict[str, Any]) -> tuple[IntentCategory, float]:
        """텍스트 패턴 및 추출된 엔티티에 따른 결정론적 의도 판정"""
        q = text.lower().strip()

        # 1. Agent Security / Red Team
        if any(k in q for k in ["ai agent", "에이전트 보안", "레드팀", "red team", "redteam", "복원력"]):
            if "red" in q or "시나리오" in q:
                return IntentCategory.REDTEAM_STATUS, 1.0
            return IntentCategory.AGENT_SECURITY, 1.0

        # 2. Continuous GRC / Risk Trend
        if any(k in q for k in ["최근", "위험 변화", "위험 증가", "변동", "trend", "추이", "새로 발견"]):
            return IntentCategory.RISK_TREND, 1.0

        # 3. Framework Mapping / Coverage
        if any(k in q for k in ["nist", "iso", "cis", "글로벌", "비교", "해당해", "해당"]):
            return IntentCategory.FRAMEWORK_MAPPING, 1.0
        if any(k in q for k in ["커버리지", "평가 커버리지", "coverage", "진척률"]):
            return IntentCategory.FRAMEWORK_COVERAGE, 1.0

        # 4. Control Gap / Effectiveness
        if any(k in q for k in ["평가되지 않은", "미평가", "no_evidence", "gap", "결여", "증적 없는", "증적이 없"]):
            return IntentCategory.CONTROL_GAP, 1.0
        if any(k in q for k in ["통제 유효성", "유효한 통제", "비효과적", "effective", "ineffective"]):
            return IntentCategory.CONTROL_EFFECTIVENESS, 1.0

        # 5. Remediation
        if any(k in q for k in ["조치", "해결", "remediation", "가장 먼저", "어떤 조치", "시정조치"]):
            return IntentCategory.REMEDIATION_LOOKUP, 1.0

        # 6. Evidence Lineage / Lookup
        if any(k in q for k in ["어디에 영향", "혈통", "lineage", "연결된 자산"]) and "evidence_id" in entities:
            return IntentCategory.EVIDENCE_LINEAGE, 1.0
        if any(k in q for k in ["증적", "evidence", "근거", "증거", "뒷받침"]):
            return IntentCategory.EVIDENCE_LOOKUP, 1.0

        # 7. Risk Cause / Detail / Overview
        if any(k in q for k in ["왜", "원인", "이유", "cause", "why"]):
            return IntentCategory.RISK_CAUSE, 1.0
        if "risk_id" in entities or ("control_id" in entities and any(k in q for k in ["위험 점수", "위험도", "점수는", "점수를"])):
            return IntentCategory.RISK_DETAIL, 1.0
        if any(k in q for k in ["가장 위험", "최고 위험", "위험한 보안 문제", "top risk", "위험 순위", "위험 목록", "위험 점수", "위험도는", "높은 위험"]):
            return IntentCategory.RISK_OVERVIEW, 1.0

        # 8. Control Detail / Status
        if "control_id" in entities:
            if any(k in q for k in ["상태", "판정", "결과", "status"]):
                return IntentCategory.CONTROL_STATUS, 0.95
            return IntentCategory.CONTROL_DETAIL, 0.90

        # 9. Finding Lookup
        if any(k in q for k in ["결함", "finding", "취약점", "prowler"]):
            return IntentCategory.FINDING_LOOKUP, 0.85

        return IntentCategory.UNKNOWN, 0.5
