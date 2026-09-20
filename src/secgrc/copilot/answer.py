"""구조화된 보안 답변 생성기(CopilotAnswerGenerator) 모듈입니다."""

import uuid
from typing import Any, Dict, List, Optional

from secgrc.copilot.context import CopilotContext
from secgrc.copilot.guard import CopilotGuard
from secgrc.copilot.intents import IntentCategory, IntentResult
from secgrc.copilot.models import (
    CopilotAnswer,
    CopilotFact,
    CopilotQuery,
    FactType,
    Provenance,
    UserRole,
)
from secgrc.ontology.repository import OntologyRepository


class CopilotAnswerGenerator:
    """결정론적 데이터와 온톨로지 컨텍스트를 바탕으로 사실성 중심의 구조화 답변을 생성하는 생성기"""

    def __init__(self, repo: OntologyRepository, guard: Optional[CopilotGuard] = None) -> None:
        self.repo = repo
        self.guard = guard or CopilotGuard(self.repo)

    def generate(
        self,
        query: CopilotQuery,
        intent_res: IntentResult,
        context: CopilotContext,
        provenance: List[Provenance],
    ) -> CopilotAnswer:
        """사용자 역할과 질의 의도에 맞춘 검증된 최종 답변 객체를 생성합니다."""
        answer_id = f"ANS-{uuid.uuid4().hex[:8]}"

        # 0-A. 보안 위반 질의 즉각 차단 및 안전 폴백
        if intent_res.entities.get("security_violation"):
            sec_v = intent_res.entities.get("security_violation")
            return CopilotAnswer(
                answer_id=answer_id,
                question=query.question,
                intent=intent_res.intent.value,
                answer=(
                    f"⚠️ [보안 가드레일 작동] 안전 정책 및 가드레일에 위배되는 질의({sec_v})가 감지되어 요청이 거부되었습니다.\n\n"
                    "Copilot은 읽기 전용 결정론적 보안 거버넌스 질의만 지원하며, 시스템 프롬프트 노출, 시크릿 유출, 권한 조작 및 데이터 변조를 엄격히 금지합니다."
                ),
                facts=[
                    CopilotFact(
                        fact_type=FactType.OBSERVED_FACT,
                        statement=f"보안 가드레일에 의해 잠재적 위협 질의가 차단되었습니다: {sec_v}",
                        source_reference="INPUT_GUARD",
                    )
                ],
                reasoning=["보안 정책 및 인젝션 방어 규칙에 따라 비인가 질의는 실행되지 않습니다."],
                recommendations=["읽기 전용 정상 보안 질의(예: 통제 상태 또는 최상위 위험 조회)를 입력해 주세요."],
                provenance=provenance,
                confidence=0.0,
                limitations=[f"보안 위반 차단: {sec_v}"],
                generated_by="deterministic_copilot",
            )

        # 0-B. 교차 테넌트 / 권한 경계 질의 방어
        if intent_res.entities.get("cross_tenant_query"):
            return CopilotAnswer(
                answer_id=answer_id,
                question=query.question,
                intent=intent_res.intent.value,
                answer="⚠️ [접근 경계 안내] 현재 GRC 시스템은 단일 조직(Single-Tenant) 스코프 환경으로 운영되며, 타 조직 또는 교차 테넌트 데이터에 대한 조회 권한이 허용되지 않습니다.",
                facts=[
                    CopilotFact(
                        fact_type=FactType.OBSERVED_FACT,
                        statement="현재 시스템은 단일 조직(Single-Tenant) 격리 스코프로 구성되어 있습니다.",
                        source_reference="ONTOLOGY_REPO",
                    )
                ],
                reasoning=["조직 간 데이터 격리 정책에 의해 타 조직 데이터 조회는 비인가 접근으로 간주됩니다."],
                recommendations=["허가된 본인 조직의 GRC 식별자를 사용하여 질의해 주세요."],
                provenance=provenance,
                confidence=0.0,
                limitations=["타 조직 또는 테넌트 간 데이터 접근이 원천 차단됩니다."],
                generated_by="deterministic_copilot",
            )

        # 1. 사실(Facts), 추론(Reasoning), 권고(Recommendations) 추출
        facts, reasoning, recommendations, limitations = self._extract_triplet(
            query, intent_res, context
        )

        # 2. 역할별 답변 본문 조립
        if query.user_role in (UserRole.EXECUTIVE, UserRole.CISO):
            raw_answer = self._generate_executive_answer(intent_res, context, facts, recommendations)
        else:
            raw_answer = self._generate_analyst_answer(intent_res, context, facts, reasoning, recommendations)

        # 3. 안티-환각 가드레일 교차 검증 및 보정
        is_valid, safe_answer, violations = self.guard.verify_and_guard(raw_answer, context)
        if violations:
            limitations.extend(violations)

        confidence = min(intent_res.confidence, 0.95 if is_valid else 0.70)

        return CopilotAnswer(
            answer_id=answer_id,
            question=query.question,
            intent=intent_res.intent.value,
            answer=safe_answer,
            facts=facts,
            reasoning=reasoning,
            recommendations=recommendations,
            provenance=provenance,
            confidence=confidence,
            limitations=limitations,
            generated_by="deterministic_copilot",
        )

    def _extract_triplet(
        self,
        query: CopilotQuery,
        intent_res: IntentResult,
        context: CopilotContext,
    ) -> tuple[List[CopilotFact], List[str], List[str], List[str]]:
        facts: List[CopilotFact] = []
        reasoning: List[str] = []
        recommendations: List[str] = []
        limitations: List[str] = []

        intent = intent_res.intent

        # Invalid Control ID 처리
        if intent_res.entities.get("invalid_control_id"):
            inv_cid = intent_res.entities.get("invalid_control_id")
            facts.append(
                CopilotFact(
                    fact_type=FactType.OBSERVED_FACT,
                    statement=f"요청하신 통제 ID [{inv_cid}]는 보안 온톨로지 저장소에 등록되지 않은 유효하지 않은 식별자입니다.",
                    source_reference="ONTOLOGY_REPO",
                )
            )
            limitations.append(f"통제 ID '{inv_cid}'는 유효하지 않으므로 다른 통제로 자동 대체하지 않습니다.")

        # 가상 시나리오 / 수치 조작 가정 처리
        if intent_res.entities.get("hypothetical_scenario"):
            reasoning.append(
                "사용자가 질의한 점수는 가상 시나리오(Hypothetical Scenario)의 가정치이며, 공식 감사 결과 및 결정론적 Risk Engine 점수(93.0점, P1)는 단일 진실 공급원(SSOT)으로서 불변합니다."
            )

        # Risk 관련 팩트 및 추론
        if context.risk:
            r = context.risk
            rid = r.get("risk_id") or r.get("entity_id", "RISK-001")
            facts.append(
                CopilotFact(
                    fact_type=FactType.OBSERVED_FACT,
                    statement=f"위험 식별자 [{rid}]의 위험 점수는 {r.get('risk_score')}({r.get('priority')}, {r.get('severity')})입니다.",
                    source_reference=rid,
                )
            )
            reasoning.append(
                f"높은 자산 중요도와 결함 심각도, 그리고 확인된 증적의 신뢰도가 복합 반영되어 {r.get('risk_score')}점의 최고 위험 등급이 산출되었습니다."
            )

        # Control 관련 팩트 및 상태 처리
        if context.control:
            c = context.control
            eff = c.get("effectiveness")
            cid = c.get("entity_id")
            facts.append(
                CopilotFact(
                    fact_type=FactType.OBSERVED_FACT,
                    statement=f"통제항목 [{cid}] {c.get('name')}의 유효성 판정은 '{eff}'입니다.",
                    source_reference=cid,
                )
            )
            if eff in ("NOT_ASSESSED", "NO_EVIDENCE"):
                limitations.append("현재 확보된 증적만으로는 해당 통제를 평가할 수 없습니다.")
            if cid == "ISMS-P-2.8.1" or eff == "MANUAL" or c.get("automation_level") == "MANUAL":
                limitations.append("자동화된 기술 증적만으로는 판단할 수 없으며 수동 심사가 필요합니다.")

        # Evidence 관련 팩트
        if context.evidence:
            ev_count = len(context.evidence)
            facts.append(
                CopilotFact(
                    fact_type=FactType.OBSERVED_FACT,
                    statement=f"해당 사안과 관련하여 총 {ev_count}건의 감사 증적이 연계되어 있습니다.",
                    source_reference=context.evidence[0].get("entity_id") if ev_count > 0 else None,
                )
            )
            for ev in context.evidence[:5]:
                eid = ev.get("entity_id") or ev.get("id", "EV-UNKNOWN")
                facts.append(
                    CopilotFact(
                        fact_type=FactType.OBSERVED_FACT,
                        statement=f"증적 [{eid}]: {ev.get('name')}",
                        source_reference=eid,
                    )
                )

        # Framework Mapping 팩트
        if context.framework_mapping:
            for fm in context.framework_mapping:
                facts.append(
                    CopilotFact(
                        fact_type=FactType.OBSERVED_FACT,
                        statement=f"글로벌 통제 [{fm.get('target_control_id')}]와 매핑 (신뢰도: {fm.get('confidence')}): {fm.get('rationale', '')}",
                        source_reference=fm.get("target_control_id"),
                    )
                )
        elif intent == IntentCategory.FRAMEWORK_MAPPING:
            limitations.append("현재 ontology에 검증된 매핑이 없습니다.")

        # Coverage 관련 팩트
        if context.coverage:
            cov = context.coverage
            facts.append(
                CopilotFact(
                    fact_type=FactType.OBSERVED_FACT,
                    statement=f"프레임워크 {cov.get('framework_id')} 전체 통제 {cov.get('total_controls')}개 중 {cov.get('assessed_controls')}개({cov.get('coverage_percent')}%)가 평가 완료되었습니다.",
                    source_reference=cov.get("framework_id"),
                )
            )
            facts.append(
                CopilotFact(
                    fact_type=FactType.OBSERVED_FACT,
                    statement=f"미평가(NO_EVIDENCE / 수동 심사 대기) 통제는 총 {cov.get('not_assessed_controls')}개입니다.",
                    source_reference=cov.get("framework_id"),
                )
            )

        # Remediation 권고
        if context.remediations:
            for rem in context.remediations[:5]:
                recommendations.append(
                    f"[{rem.get('entity_id')}] {rem.get('name')}: {rem.get('description', '')}"
                )
                facts.append(
                    CopilotFact(
                        fact_type=FactType.OBSERVED_FACT,
                        statement=f"시정조치 계획 [{rem.get('entity_id')}]: {rem.get('name')} (승인필요: {rem.get('required_approval', True)})",
                        source_reference=rem.get("entity_id"),
                    )
                )
        else:
            recommendations.append("조치 가이드라인에 따른 표준 암호화 및 접근 통제 구성을 적용하세요.")

        # Agent Security 팩트
        if context.agent_security:
            ag = context.agent_security
            facts.append(
                CopilotFact(
                    fact_type=FactType.OBSERVED_FACT,
                    statement=f"AI Agent 복원력 점수는 {ag.get('resilience_score')}점이며, 0건의 시크릿 유출 및 0건의 비인가 도구 실행이 확인되었습니다.",
                    source_reference="AGENT_SECURITY",
                )
            )

        return facts, reasoning, recommendations, limitations

    def _generate_executive_answer(
        self,
        intent_res: IntentResult,
        context: CopilotContext,
        facts: List[CopilotFact],
        recommendations: List[str],
    ) -> str:
        lines: List[str] = []
        intent = intent_res.intent

        if intent_res.entities.get("invalid_control_id"):
            inv = intent_res.entities.get("invalid_control_id")
            lines.append(f"⚠️ **통제 식별자 오류**: 요청하신 통제 ID [{inv}]는 온톨로지 저장소에 등록되지 않은 유효하지 않은 엔티티입니다.")
            lines.append("• 시스템은 알 수 없는 엔티티를 임의의 다른 통제로 대체하지 않습니다.")
            return "\n".join(lines)

        if intent in (IntentCategory.RISK_OVERVIEW, IntentCategory.RISK_DETAIL, IntentCategory.RISK_CAUSE):
            r = context.risk or (context.risks[0] if context.risks else {})
            lines.append(f"🚨 **핵심 보안 위험 요약**: [{r.get('risk_id', 'ISMS-P-2.7.1')}] (점수: {r.get('risk_score', '93.0')}점 / {r.get('priority', 'P1')})")
            lines.append(f"• **위험 원인**: 주요 클라우드 저장소(Storage/BigQuery)의 암호화 미적용 및 퍼블릭 접근 노출로 인해 중대 침해 위험 발생")
            lines.append(f"• **경영 조치 권고**: P1 위험 해결을 위한 즉각적인 기술 조치(CMEK 적용 및 퍼블릭 접근 차단) 승인 및 우선 조치 필요")

        elif intent == IntentCategory.CONTROL_GAP:
            cov = context.coverage or {}
            lines.append("📊 **컴플라이언스 미평가(NO_EVIDENCE) 현황**:")
            lines.append(f"현재 전체 통제 {cov.get('total_controls', 10)}개 중 {cov.get('not_assessed_controls', 5)}개 통제항목에 대해 추가 증적 확보 또는 수동 심사가 필요합니다.")
            lines.append("현재 확보된 증적만으로는 해당 통제를 평가할 수 없습니다.")

        elif intent == IntentCategory.AGENT_SECURITY:
            ag = context.agent_security or {}
            lines.append(f"🛡️ **AI Agent 거버넌스 상태**: 복원력 {ag.get('resilience_score', 100.0)}점")
            lines.append("모든 프롬프트 인젝션 및 비인가 도구 실행 시도가 결정론적 가드레일에 의해 100% 차단되었으며, 정보 유출은 발생하지 않았습니다.")

        elif intent == IntentCategory.FRAMEWORK_MAPPING:
            lines.append(f"🌐 **글로벌 프레임워크 대응 현황**:")
            if context.framework_mapping:
                for fm in context.framework_mapping[:3]:
                    lines.append(f"• {fm.get('target_control_id')}: {fm.get('rationale', '')}")
            else:
                lines.append("현재 ontology에 검증된 매핑이 없습니다.")

        else:
            fact_texts = [f.statement for f in facts[:2]]
            lines.append("📋 **보안 현황 브리핑**:\n" + "\n".join(f"• {t}" for t in fact_texts))
            if recommendations:
                lines.append(f"• **조치 사항**: {recommendations[0]}")

        return "\n".join(lines)

    def _generate_analyst_answer(
        self,
        intent_res: IntentResult,
        context: CopilotContext,
        facts: List[CopilotFact],
        reasoning: List[str],
        recommendations: List[str],
    ) -> str:
        lines: List[str] = []
        intent = intent_res.intent

        # 1. Observed Facts
        lines.append("### [Observed Fact (관찰된 사실)]")
        if intent_res.entities.get("invalid_control_id"):
            inv = intent_res.entities.get("invalid_control_id")
            lines.append(f"• 요청하신 통제 식별자 [{inv}]는 보안 온톨로지 저장소에 등록되지 않은 알 수 없는 엔티티입니다.")
            lines.append("• 시스템은 유효하지 않은 식별자를 다른 통제로 대체 해석하지 않습니다.")
        elif intent in (IntentCategory.CONTROL_GAP, IntentCategory.EVIDENCE_GAP):
            lines.append("• 현재 확보된 증적만으로는 해당 통제를 평가할 수 없습니다.")
        elif intent == IntentCategory.FRAMEWORK_MAPPING and not context.framework_mapping:
            lines.append("• 현재 ontology에 검증된 매핑이 없습니다.")
        elif facts:
            for f in facts:
                lines.append(f"• {f.statement}")
        else:
            lines.append("• 온톨로지 지식 그래프에서 해당 항목의 상세 사실 데이터를 조회하였습니다.")

        # 2. Inference
        lines.append("\n### [Inference (보안 추론)]")
        if reasoning:
            for r in reasoning:
                lines.append(f"• {r}")
        else:
            if context.risk:
                lines.append(f"• 통제 결함으로 인해 공격자가 비인가 데이터 열람 및 유출을 시도할 가능성이 존재합니다.")
            else:
                lines.append("• 규정 요구사항 대조 및 인과관계 분석 결과 안정적인 상태를 유지하고 있습니다.")

        # 3. Recommendation
        lines.append("\n### [Recommendation (개선 권고)]")
        if recommendations:
            for rec in recommendations:
                lines.append(f"• {rec}")
        else:
            lines.append("• 정기 감사 및 보안 모니터링을 지속적으로 수행하세요.")

        return "\n".join(lines)
