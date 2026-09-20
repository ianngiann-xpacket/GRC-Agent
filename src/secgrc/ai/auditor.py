"""AI Auditor 핵심 엔진 모듈 (v1.1.0).

결정론적 컴플라이언스 및 위험 평가 결과를 바탕으로,
Evidence-Grounded 원칙, 프롬프트 인젝션 방어 및 판정 불변성을 준수하여
LLM 기반 심층 감사 소견을 도출합니다.
"""

import json
import re
from typing import Any, Dict, List, Optional

from secgrc.ai.models import AIAnalysis, EvidenceBasis, RemediationItem
from secgrc.ai.prompts import PROMPT_VERSION, SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from secgrc.audit.models import AuditResult, AuditStatus
from secgrc.evidence.prowler_adapter import NormalizedEvidence
from secgrc.llm import get_gemini_api_key
from secgrc.risk.models import RiskAssessment, RiskLevel, RiskPriority


class AIAuditor:
    """ISMS-P 수석 감사관 관점의 AI 보안 감사 추론 엔진"""

    def __init__(
        self,
        model_name: str = "gemini-2.5-flash",
        api_key: Optional[str] = None,
    ):
        self.model_name = model_name
        self.api_key = api_key or get_gemini_api_key()

    def sanitize_evidence_text(self, text: str) -> str:
        """증적 데이터 내의 태그 및 잠재적 프롬프트 인젝션 패턴을 안전하게 무해화합니다."""
        if not text:
            return ""
        # XML 태그 탈출 방지
        sanitized = text.replace("</untrusted_evidence>", "[ESCAPED_TAG]")
        sanitized = sanitized.replace("<untrusted_evidence>", "[ESCAPED_TAG]")
        sanitized = sanitized.replace("```", "'''")
        return sanitized

    def sanitize_fallback_reason(self, err: Any) -> str:
        """오류 메시지에서 API Key, 토큰 등 민감정보를 완벽히 마스킹하여 사유를 반환합니다."""
        if err is None:
            return "unknown_error"
        msg = str(err)
        # 16자 이상의 연속된 영숫자/특수문자 키 토큰을 안전하게 마스킹
        sanitized = re.sub(r"[A-Za-z0-9_\-]{16,}", "[REDACTED]", msg)
        err_cls = err.__class__.__name__ if hasattr(err, "__class__") else "Error"
        # 1줄로 축약 및 최대 100자 내 단어 단위 자르기
        clean_msg = " ".join(sanitized.split())
        if len(clean_msg) > 100:
            truncated = clean_msg[:100]
            if "[" in truncated and "]" not in truncated[truncated.rfind("["):]:
                truncated = truncated[:truncated.rfind("[")]
            clean_msg = truncated.rstrip() + "..."
        return f"{err_cls}: {clean_msg}"

    def format_evidence_payload(
        self,
        audit_result: AuditResult,
        evidence_list: Optional[List[NormalizedEvidence]] = None,
    ) -> str:
        """분석에 주입할 증적 요약 텍스트를 구성하고 살균합니다."""
        if not evidence_list:
            if audit_result.evidence_ids:
                return f"Evidence IDs: {', '.join(audit_result.evidence_ids)} (상세 증적 객체 생략됨)"
            return "수집된 증적 없음 (NO_EVIDENCE)"

        ev_map = {e.finding_uid: e for e in evidence_list}
        lines = []
        for ev_id in audit_result.evidence_ids:
            ev = ev_map.get(ev_id)
            if not ev:
                lines.append(f"- ID: {ev_id} (상세 정보 없음)")
                continue

            # Remediation 정보 포함
            raw_dict = ev.get("raw") if isinstance(ev.get("raw"), dict) else {}
            remed_text = ev.get("remediation") or raw_dict.get("REMEDIATION_RECOMMENDATION_TEXT", "")

            ev_title = ev.get("title") or ev.get("check_title") or ev.get("check_id") or "Check"
            ev_res_type = ev.get("resource_type") or "resource"
            ev_res_name = ev.get("resource_name") or ev.get("resource_uid") or ""
            ev_status = ev.get("status", "UNKNOWN")
            if hasattr(ev_status, "value"):
                ev_status = ev_status.value
            ev_status_ext = raw_dict.get("STATUS_EXTENDED") or ev.get("status_extended") or ev_status
            ev_desc = ev.get("description") or ""

            raw_desc = (
                f"{ev_title} | {ev_res_type}: {ev_res_name} | "
                f"{ev_status_ext} | {ev_desc}"
            )
            if remed_text:
                raw_desc += f" | Remediation: {remed_text}"

            clean_desc = self.sanitize_evidence_text(raw_desc)
            lines.append(f"- [{ev_status}] {ev.get('check_id', '')}: {clean_desc}")

        return "\n".join(lines) if lines else "수집된 증적 없음"

    def compute_grounded_confidence(
        self,
        status: AuditStatus,
        severity: Any,
        mapping_confidence: float = 1.0,
    ) -> float:
        """증적 품질 및 상태에 비례하는 AI Analysis Confidence 산정"""
        if status == AuditStatus.NO_EVIDENCE:
            return 0.25
        elif status == AuditStatus.MANUAL:
            return 0.50
        elif status == AuditStatus.PARTIAL:
            return round(min(0.80, max(0.65, 0.70 * mapping_confidence + 0.05)), 2)
        elif status == AuditStatus.FAIL:
            return round(min(0.95, max(0.85, 0.90 * mapping_confidence + 0.05)), 2)
        else:  # PASS
            return round(min(0.90, max(0.80, 0.85 * mapping_confidence)), 2)

    def analyze(
        self,
        audit_result: AuditResult,
        risk_assessment: RiskAssessment,
        evidence_list: Optional[List[NormalizedEvidence]] = None,
    ) -> AIAnalysis:
        """
        단일 통제항목에 대한 AI 심층 감사 소견을 생성합니다.

        중요: AI가 반환한 판정이나 위험 점수와 무관하게,
        결정론적 엔진의 결과(audit_status, risk_score, risk_level, priority)를 강제 부여합니다.
        """
        if not self.api_key:
            return self._fallback_analysis(
                audit_result,
                risk_assessment,
                evidence_list,
                fallback_reason="api_key_not_configured",
            )

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)

            ev_text = self.format_evidence_payload(audit_result, evidence_list)
            user_prompt = USER_PROMPT_TEMPLATE.format(
                control_id=audit_result.control_id,
                control_title=audit_result.control_title,
                framework=audit_result.framework,
                audit_status=audit_result.status.value,
                severity=audit_result.severity.value,
                risk_score=risk_assessment.risk_score,
                risk_level=risk_assessment.risk_level.value,
                priority=risk_assessment.priority.value,
                rationale=audit_result.rationale,
                gaps=", ".join(audit_result.gaps) if audit_result.gaps else "없음",
                recommendations=", ".join(audit_result.recommendations) if audit_result.recommendations else "없음",
                evidence_text=ev_text,
            )

            full_prompt = f"{SYSTEM_PROMPT}\n\n{user_prompt}"

            candidate_models = [self.model_name, "gemini-2.5-flash", "gemini-1.5-flash"]
            unique_models = []
            for m in candidate_models:
                if m not in unique_models:
                    unique_models.append(m)

            response = None
            last_err = None
            used_model = self.model_name

            config = types.GenerateContentConfig(
                temperature=0.2,
                response_mime_type="application/json",
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            )

            for m in unique_models:
                try:
                    response = client.models.generate_content(
                        model=m,
                        contents=full_prompt,
                        config=config,
                    )
                    if response and response.text:
                        used_model = m
                        break
                except Exception as err:
                    last_err = err
                    continue

            if not response or not response.text:
                raise last_err or RuntimeError("Gemini API 호출 결과가 비어 있습니다.")

            raw_text = response.text.strip()
            if raw_text.startswith("```"):
                raw_text = re.sub(r"^```(?:json)?\n", "", raw_text)
                raw_text = re.sub(r"\n```$", "", raw_text)

            parsed = json.loads(raw_text)
            return self._build_analysis_record(
                parsed,
                audit_result,
                risk_assessment,
                model_name=used_model,
                evidence_list=evidence_list,
            )

        except Exception as e:
            clean_reason = self.sanitize_fallback_reason(e)
            return self._fallback_analysis(
                audit_result,
                risk_assessment,
                evidence_list,
                fallback_reason=clean_reason,
            )

    def _build_analysis_record(
        self,
        data: Dict[str, Any],
        audit_result: AuditResult,
        risk_assessment: RiskAssessment,
        model_name: str,
        evidence_list: Optional[List[NormalizedEvidence]] = None,
    ) -> AIAnalysis:
        """LLM 반환 데이터를 정제하고 불변 필드 및 Evidence Grounding을 보증하여 객체를 생성합니다."""
        status = audit_result.status
        cid = audit_result.control_id
        ctitle = audit_result.control_title

        # 1. Remediation items 파싱 및 구조화
        raw_remediation = data.get("remediation") or audit_result.recommendations or []
        remediation_items = []
        tagged_remediation = []

        if data.get("remediation_items"):
            for item in data["remediation_items"]:
                if isinstance(item, dict) and "action" in item:
                    source = item.get("source", "evidence")
                    ref_url = item.get("reference_url")
                    remediation_items.append(
                        RemediationItem(action=str(item["action"]), source=source, reference_url=ref_url)
                    )
                    tag = "[Evidence]" if source == "evidence" else "[AI Suggested]"
                    act = str(item["action"])
                    tagged_remediation.append(act if act.startswith("[") else f"{tag} {act}")

        if not remediation_items:
            for r in raw_remediation:
                r_str = str(r)
                source = "ai_generated" if "AI" in r_str or "권고" in r_str else "evidence"
                tag = "[Evidence]" if source == "evidence" else "[AI Suggested]"
                remediation_items.append(RemediationItem(action=r_str, source=source))
                tagged_remediation.append(r_str if r_str.startswith("[") else f"{tag} {r_str}")

        # 2. Evidence Basis 파싱
        evidence_basis = []
        if data.get("evidence_basis"):
            for eb in data["evidence_basis"]:
                if isinstance(eb, dict) and "claim" in eb:
                    evidence_basis.append(
                        EvidenceBasis(
                            evidence_id=str(eb.get("evidence_id") or cid),
                            claim=str(eb["claim"]),
                            basis=str(eb.get("basis", "inferred")),
                        )
                    )

        if not evidence_basis:
            # Fallback to direct mapping from evidence_ids
            if audit_result.evidence_ids:
                for eid in audit_result.evidence_ids[:3]:
                    evidence_basis.append(
                        EvidenceBasis(evidence_id=eid, claim=f"{ctitle} 관련 증적 식별", basis="direct")
                    )
            else:
                evidence_basis.append(
                    EvidenceBasis(evidence_id=cid, claim="증적 미수집 (Evidence Gap)", basis="direct")
                )

        # 3. Status별 Grounded 포맷 강제
        exec_summary = str(data.get("executive_summary") or f"{cid} 보안 평가 보고")
        tech_summary = str(data.get("technical_summary") or audit_result.rationale)
        biz_impact = str(data.get("business_impact") or "비즈니스 영향도 평가 완료")
        attack_scenario = str(data.get("attack_scenario") or "")
        auditor_questions = list(data.get("auditor_questions") or [])

        if status == AuditStatus.NO_EVIDENCE:
            attack_scenario = "Not assessable from the available evidence."
            biz_impact = "Compliance visibility is insufficient because required evidence was not collected."
            required_q = "Which documents, policies, records, or technical evidence can demonstrate implementation of this control?"
            if required_q not in auditor_questions:
                auditor_questions.insert(0, required_q)
        elif status == AuditStatus.MANUAL:
            if "Manual auditor verification is required" not in exec_summary:
                exec_summary = (
                    f"Automated evidence is insufficient to determine compliance. "
                    f"Manual auditor verification is required for ISMS-P {cid}({ctitle})."
                )
            if "Manual auditor verification is required" not in tech_summary:
                tech_summary = "Automated evidence is insufficient to determine compliance. Manual auditor verification is required."
            for mq in [
                "정책/절차 문서가 존재하는가?",
                "실제 운영 기록이 존재하는가?",
                "최근 테스트/훈련 결과가 존재하는가?",
                "예외 승인 기록이 존재하는가?",
            ]:
                if mq not in auditor_questions:
                    auditor_questions.append(mq)
        else:
            # FAIL / PARTIAL / PASS: 구조화된 Attack Scenario 보증
            if "Observed Evidence:" not in attack_scenario:
                attack_scenario = (
                    f"Observed Evidence:\n{audit_result.rationale}\n\n"
                    f"Potential Attack Path:\n{attack_scenario or '설정 미흡을 악용한 비인가 접근 가능성'}\n\n"
                    f"Limitations:\nThe evidence does not demonstrate that an actual compromise occurred."
                )

        # 4. Confidence 계산 및 반영
        computed_conf = self.compute_grounded_confidence(
            status=status,
            severity=audit_result.severity,
            mapping_confidence=audit_result.mapping_confidence,
        )

        return AIAnalysis(
            risk_id=risk_assessment.risk_id,
            control_id=cid,
            control_title=ctitle,
            audit_status=status.value,
            risk_level=risk_assessment.risk_level.value,
            priority=risk_assessment.priority.value,
            risk_score=risk_assessment.risk_score,
            executive_summary=exec_summary,
            technical_summary=tech_summary,
            root_cause=str(data.get("root_cause") or "설정 및 프로세스 관리 미흡"),
            business_impact=biz_impact,
            attack_scenario=attack_scenario,
            remediation=tagged_remediation,
            remediation_items=remediation_items,
            auditor_questions=auditor_questions,
            evidence_basis=evidence_basis,
            confidence=computed_conf,
            evidence_ids=audit_result.evidence_ids,
            assumptions=list(data.get("assumptions") or ["클라우드 설정 증적의 스캔 시점 완전성을 전제함"]),
            limitations=list(
                data.get("limitations")
                or ["The evidence does not demonstrate that an actual compromise occurred."]
            ),
            source_references=list(data.get("source_references") or ["ISMS-P 인증기준 안내서", "CIS GCP Benchmark"]),
            model_name=model_name,
            prompt_version=PROMPT_VERSION,
            llm_used=True,
            fallback_reason=None,
        )

    def _fallback_analysis(
        self,
        audit_result: AuditResult,
        risk_assessment: RiskAssessment,
        evidence_list: Optional[List[NormalizedEvidence]] = None,
        fallback_reason: Optional[str] = None,
    ) -> AIAnalysis:
        """API Key 부재 또는 호출 장애 시 동작하는 Evidence-Grounded 규칙 기반 폴백 생성기"""
        status = audit_result.status
        cid = audit_result.control_id
        ctitle = audit_result.control_title
        ev_count = len(audit_result.evidence_ids)

        remediation_items: List[RemediationItem] = []
        tagged_remediation: List[str] = []
        evidence_basis: List[EvidenceBasis] = []

        # 증적 맵 구성
        ev_map = {e.finding_uid: e for e in evidence_list} if evidence_list else {}
        matched_evs = [ev_map[eid] for eid in audit_result.evidence_ids if eid in ev_map]

        if status == AuditStatus.NO_EVIDENCE:
            exec_summary = (
                f"ISMS-P {cid}({ctitle}) 항목에 대응하는 클라우드 자동 점검 증적이 수집되지 않았습니다 (Evidence Gap). "
                "이는 규정 준수(PASS)를 의미하지 않습니다."
            )
            tech_summary = f"증적 부재(NO_EVIDENCE): Control {cid} ({ctitle}) is assessed as NO_EVIDENCE because no normalized evidence was mapped to the control."
            root_cause = "해당 통제항목에 대한 클라우드 수집 룰 미설정 또는 미지원 서비스 사용."
            biz_impact = "Compliance visibility is insufficient because required evidence was not collected."
            attack_scenario = "Not assessable from the available evidence."
            auditor_questions = [
                "Which documents, policies, records, or technical evidence can demonstrate implementation of this control?",
                f"{cid} 관련 통제 이행 상태를 입증할 대체 기술적/관리적 증빙이 존재하는가?",
                "점검 도구의 스캔 범위에서 해당 서비스가 누락된 기술적 사유가 존재하는가?",
            ]
            remediation_items = [
                RemediationItem(
                    action=f"{cid} 항목 점검을 위한 추가 Prowler 룰 활성화 또는 수동 점검 체크리스트 보완",
                    source="ai_generated",
                ),
                RemediationItem(
                    action="감사 대상 클라우드 리소스 자산 인벤토리 재조사",
                    source="ai_generated",
                ),
            ]
            tagged_remediation = [f"[AI Suggested] {item.action}" for item in remediation_items]
            evidence_basis = [
                EvidenceBasis(
                    evidence_id=cid,
                    claim="클라우드 점검 증적이 수집되지 않음 (Evidence Gap)",
                    basis="direct",
                )
            ]
            assumptions = ["현재 스캔 대상 계정 및 서비스 범위에 한정됨"]
            limitations = ["증적 미수집으로 인한 기술적 상태 판단 보류"]

        elif status == AuditStatus.MANUAL:
            exec_summary = (
                f"Automated evidence is insufficient to determine compliance. "
                f"Manual auditor verification is required for ISMS-P {cid}({ctitle})."
            )
            tech_summary = (
                "Automated evidence is insufficient to determine compliance. "
                f"Manual auditor verification is required. {audit_result.rationale}"
            )
            root_cause = "조직 체계, 관리 규정, 보안 서약, 교육 등 정성적 운영 통제에 해당함."
            biz_impact = "수동 증빙(문서, 회의록) 미제출 시 인증 심사 부적합 처리 위험."
            attack_scenario = (
                "Observed Evidence:\n"
                "본 통제항목은 자동화 점검 도구로 판정할 수 없는 관리적/물리적 점검 항목입니다.\n\n"
                "Potential Attack Path:\n"
                "관리적 절차 및 승인 프로세스 부재 시 내부 보안 사고 또는 부정 행위가 탐지되지 않을 수 있습니다.\n\n"
                "Limitations:\n"
                "The evidence does not demonstrate that an actual compromise occurred."
            )
            auditor_questions = [
                "정책/절차 문서가 존재하는가?",
                "실제 운영 기록이 존재하는가?",
                "최근 테스트/훈련 결과가 존재하는가?",
                "예외 승인 기록이 존재하는가?",
            ]
            remediation_items = [
                RemediationItem(
                    action=f"{cid} 관련 규정, 절차서, 이행 증적(서명부, 결재문서)을 최신화하여 구비",
                    source="ai_generated",
                ),
                RemediationItem(
                    action="수동 검토 체크리스트 작성 및 현장 심사 사전 준비",
                    source="ai_generated",
                ),
            ]
            tagged_remediation = [f"[AI Suggested] {item.action}" for item in remediation_items]
            evidence_basis = [
                EvidenceBasis(
                    evidence_id=cid,
                    claim="수동 검토 대상 통제항목으로 지정됨",
                    basis="direct",
                )
            ]
            assumptions = ["관리적/운영적 보안 통제 기준이 문서로 수립되어 있음을 전제"]
            limitations = ["API 기반 클라우드 증적 도구로는 이행 여부 검증 불가"]

        elif status in (AuditStatus.FAIL, AuditStatus.PARTIAL):
            is_partial = status == AuditStatus.PARTIAL
            status_desc = "부분 적합(PARTIAL)" if is_partial else "부적합(FAIL)"

            exec_summary = (
                f"ISMS-P {cid}({ctitle}) 항목에서 {status_desc} 상태의 결함이 식별되어 "
                f"시정 조치(대응 우선순위: {risk_assessment.priority.value})가 요구됩니다."
            )
            tech_summary = f"클라우드 감사 결과 {ev_count}건의 증적이 매핑되었습니다: {audit_result.rationale}"
            root_cause = (
                "클라우드 리소스 생성 및 배포 시 보안 표준 템플릿(IaC) 미적용 및 "
                "지속적 컴플라이언스 모니터링 체계 미흡."
            )
            biz_impact = (
                "ISMS-P 인증 취득/갱신 결함 지적에 따른 인증 지연 및 "
                "취약 설정을 경유한 데이터 유출 위험."
            )

            # 증적 기반 관측 사실 추출
            observed_lines = []
            for ev in matched_evs:
                ev_title = ev.get("title") or ev.get("check_title") or ev.get("check_id") or "Check"
                ev_res_type = ev.get("resource_type") or "resource"
                ev_res_name = ev.get("resource_name") or ev.get("resource_uid") or ""
                raw_dict = ev.get("raw") if isinstance(ev.get("raw"), dict) else {}
                ev_status_ext = raw_dict.get("STATUS_EXTENDED") or ev.get("status_extended") or ev.get("status")
                observed_lines.append(f"{ev_title} ({ev_res_type}: {ev_res_name}) -> {ev_status_ext}")
            if not observed_lines:
                observed_lines.append(audit_result.rationale)

            obs_str = "\n".join(observed_lines)
            attack_scenario = (
                f"Observed Evidence:\n{obs_str}\n\n"
                f"Potential Attack Path:\n"
                f"외부 공격자 또는 내부 비인가자가 {ctitle} 관련 보안 결함을 식별할 경우, "
                f"비인가 접근 또는 권한 상승을 시도할 잠재적 공격 경로가 존재합니다.\n\n"
                f"Limitations:\n"
                f"The evidence does not demonstrate that an actual compromise occurred."
            )

            auditor_questions = [
                f"{cid} 관련 사내 보안 지침이 제정되어 있고 실무에 공유되었는가?",
                f"취약점이 식별된 리소스({ev_count}건)의 형상 변경 승인 이력이 존재하는가?",
                "보안 설정 예외 적용에 대한 정당한 승인 문서가 존재하는가?",
            ]

            # Remediation 추출 (증적 우선)
            for ev in matched_evs:
                raw_dict = ev.get("raw") or {}
                remed_text = raw_dict.get("REMEDIATION_RECOMMENDATION_TEXT") if isinstance(raw_dict, dict) else ""
                remed_url = raw_dict.get("REMEDIATION_RECOMMENDATION_URL") if isinstance(raw_dict, dict) else ""
                if remed_text and remed_text not in [i.action for i in remediation_items]:
                    remediation_items.append(
                        RemediationItem(action=remed_text, source="evidence", reference_url=remed_url or None)
                    )
                    tagged_remediation.append(f"[Evidence] {remed_text}")

            for rec in audit_result.recommendations:
                if rec not in [i.action for i in remediation_items]:
                    remediation_items.append(RemediationItem(action=rec, source="evidence"))
                    tagged_remediation.append(f"[Evidence] {rec}")

            if not remediation_items:
                ai_rec = f"{cid} 통제항목에 위배되는 클라우드 리소스 형상 즉시 시정"
                remediation_items.append(RemediationItem(action=ai_rec, source="ai_generated"))
                tagged_remediation.append(f"[AI Suggested] {ai_rec}")

            # Evidence Basis 작성
            for eid in audit_result.evidence_ids:
                evidence_basis.append(
                    EvidenceBasis(
                        evidence_id=eid,
                        claim=f"{ctitle} 관련 결함 증적 탐지",
                        basis="direct",
                    )
                )
            evidence_basis.append(
                EvidenceBasis(
                    evidence_id=cid,
                    claim="미흡 설정에 따른 잠재적 권한 상승 가능성",
                    basis="inferred",
                )
            )

            assumptions = ["클라우드 스캔 시점에 수집된 형상 정보가 정확함"]
            limitations = [
                "The evidence does not demonstrate that an actual compromise occurred.",
                "클라우드 콘솔 수동 설정 내역에 국한되며 정책 운영 기록은 수동 검증 필요",
            ]

        else:  # PASS
            exec_summary = (
                f"ISMS-P {cid}({ctitle}) 항목은 클라우드 점검 증적상 기준을 만족하여 "
                "적합(PASS)으로 판정되었습니다. 지속적인 모니터링이 권장됩니다."
            )
            tech_summary = f"검사 대상 리소스가 요구사항을 충족함: {audit_result.rationale}"
            root_cause = "표준 보안 기준에 부합하는 설정이 안정적으로 유지되고 있음."
            biz_impact = "인증 기준 준수 및 기본 보안 침해 위협 예방 효과 달성."
            attack_scenario = (
                f"Observed Evidence:\n{audit_result.rationale}\n\n"
                f"Potential Attack Path:\n"
                f"현재 적합 통제가 적용되어 있어 직접적인 침투 경로는 제한적입니다.\n\n"
                f"Limitations:\n"
                f"The evidence does not demonstrate that an actual compromise occurred."
            )
            auditor_questions = [
                "현재의 적합 설정을 보증하는 자동화된 드리프트 감지 알림이 설정되어 있는가?",
            ]
            remediation_items = [
                RemediationItem(
                    action="현재 적합 보안 형상이 임의로 변경되지 않도록 형상 드리프트(Drift) 모니터링 유지",
                    source="ai_generated",
                )
            ]
            tagged_remediation = [f"[AI Suggested] {remediation_items[0].action}"]
            for eid in audit_result.evidence_ids:
                evidence_basis.append(
                    EvidenceBasis(evidence_id=eid, claim="보안 기준 부합 증적 확인", basis="direct")
                )
            assumptions = ["평가된 증적이 현재 운영 중인 모든 해당 리소스를 대변함"]
            limitations = ["스캔 시점의 스냅샷이므로 향후 설정 변경에 대한 지속 추적 필요"]

        computed_conf = self.compute_grounded_confidence(
            status=status,
            severity=audit_result.severity,
            mapping_confidence=audit_result.mapping_confidence,
        )

        return AIAnalysis(
            risk_id=risk_assessment.risk_id,
            control_id=cid,
            control_title=ctitle,
            audit_status=status.value,
            risk_level=risk_assessment.risk_level.value,
            priority=risk_assessment.priority.value,
            risk_score=risk_assessment.risk_score,
            executive_summary=exec_summary,
            technical_summary=tech_summary,
            root_cause=root_cause,
            business_impact=biz_impact,
            attack_scenario=attack_scenario,
            remediation=tagged_remediation,
            remediation_items=remediation_items,
            auditor_questions=auditor_questions,
            evidence_basis=evidence_basis,
            confidence=computed_conf,
            evidence_ids=audit_result.evidence_ids,
            assumptions=assumptions,
            limitations=limitations,
            source_references=["ISMS-P 인증기준 안내서", "CIS GCP Benchmark"],
            model_name="rule-based-auditor-fallback",
            prompt_version=PROMPT_VERSION,
            llm_used=False,
            fallback_reason=fallback_reason,
        )

    def analyze_all(
        self,
        audit_results: List[AuditResult],
        risk_assessments: List[RiskAssessment],
        evidence_list: Optional[List[NormalizedEvidence]] = None,
    ) -> List[AIAnalysis]:
        """복수 통제항목에 대한 AI 분석 일괄 수행"""
        risk_map = {r.control_id: r for r in risk_assessments}
        analyses = []
        for audit in audit_results:
            risk = risk_map.get(audit.control_id)
            if not risk:
                continue
            analysis = self.analyze(audit, risk, evidence_list)
            analyses.append(analysis)
        return analyses
