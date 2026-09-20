"""Copilot 질의 실행기(CopilotQueryExecutor) 모듈입니다."""

from typing import Any, Dict, List, Optional, Tuple

from secgrc.copilot.context import CopilotContext
from secgrc.copilot.planner import QueryPlan
from secgrc.copilot.provenance import ProvenanceBuilder
from secgrc.copilot.models import Provenance
from secgrc.ontology.builder import OntologyBuilder
from secgrc.ontology.entities import Control, EvidenceEntity, Finding, RiskEntity
from secgrc.ontology.models import RelationshipType
from secgrc.ontology.repository import OntologyRepository
from secgrc.ontology.resolver import OntologyResolver
from secgrc.redteam.runner import RedTeamRunner


class CopilotQueryExecutor:
    """검증된 읽기 전용 질의 계획을 실행하고 정제된 컨텍스트와 출처(Provenance)를 생성하는 실행기"""

    def __init__(
        self,
        repo: Optional[OntologyRepository] = None,
        resolver: Optional[OntologyResolver] = None,
    ) -> None:
        if repo is None:
            self.repo = OntologyBuilder().build()
            self.resolver = OntologyResolver(self.repo)
        else:
            self.repo = repo
            self.resolver = resolver or OntologyResolver(self.repo)

    def execute(self, plan: QueryPlan) -> Tuple[CopilotContext, List[Provenance]]:
        """QueryPlan을 실행하여 컨텍스트와 근거 출처를 반환합니다."""
        context = CopilotContext()
        prov_builder = ProvenanceBuilder()

        entities = plan.entities

        # 1. 엔티티 온톨로지 사전 유효성 검증
        target_ctrl_id = entities.get("control_id")
        target_risk_id = entities.get("risk_id")
        target_ev_id = entities.get("evidence_id")

        # 2. 작업 순차 실행 (의존성 우선순위에 따라 정렬)
        op_order = {
            "GET_RISKS": 1,
            "GET_CONTROLS": 2,
            "GET_COVERAGE": 3,
            "GET_LINEAGE": 4,
            "GET_EVIDENCE": 5,
            "GET_FINDINGS": 6,
            "GET_REMEDIATIONS": 7,
            "GET_RELATIONSHIPS": 8,
            "GET_FRAMEWORKS": 9,
            "GET_REDTEAM_SUMMARY": 10,
            "GET_AGENT_SECURITY_STATUS": 11,
        }
        sorted_ops = sorted(plan.operations, key=lambda o: op_order.get(o, 50))

        for op in sorted_ops:
            if op == "GET_RISKS":
                self._execute_get_risks(plan, context, prov_builder, target_risk_id, target_ctrl_id)
            elif op == "GET_CONTROLS":
                self._execute_get_controls(plan, context, prov_builder, target_ctrl_id)
            elif op == "GET_LINEAGE":
                self._execute_get_lineage(context, prov_builder, target_ctrl_id, target_risk_id, target_ev_id)
            elif op == "GET_EVIDENCE":
                self._execute_get_evidence(context, prov_builder, target_ctrl_id, target_ev_id)
            elif op == "GET_REMEDIATIONS":
                self._execute_get_remediations(context, prov_builder, target_risk_id, target_ctrl_id)
            elif op == "GET_COVERAGE":
                self._execute_get_coverage(plan, context, prov_builder)
            elif op == "GET_RELATIONSHIPS" or op == "GET_FRAMEWORKS":
                self._execute_get_framework_mappings(plan, context, prov_builder, target_ctrl_id)
            elif op in ("GET_REDTEAM_SUMMARY", "GET_AGENT_SECURITY_STATUS"):
                self._execute_get_agent_security(context, prov_builder)

        return context.sanitize(), prov_builder.build()

    def _execute_get_risks(
        self,
        plan: QueryPlan,
        context: CopilotContext,
        prov_builder: ProvenanceBuilder,
        target_risk_id: Optional[str],
        target_ctrl_id: Optional[str],
    ) -> None:
        all_risks = [
            e for e in self.repo.list_entities("Risk")
            if isinstance(e, RiskEntity)
        ]
        # 결정론적 위험 점수 내림차순 정렬 (동점 시 우선순위)
        all_risks.sort(key=lambda r: (-r.risk_score, r.priority))
        context.risks = [r.model_dump() for r in all_risks]

        # 특정 Risk ID 요청인 경우
        if target_risk_id:
            found = next((r for r in all_risks if r.entity_id == target_risk_id), None)
            if found:
                context.risk = found.model_dump()
                prov_builder.add("Risk", found.entity_id, relationship="TARGET_RISK", confidence=1.0)
        elif target_ctrl_id:
            ctrl_risks = self.resolver.find_risks_for_control(target_ctrl_id)
            if ctrl_risks:
                context.risk = ctrl_risks[0].model_dump()
                prov_builder.add("Risk", ctrl_risks[0].entity_id, relationship="CREATES_RISK", confidence=1.0)
        elif plan.parameters.get("top_k") == 1 and all_risks:
            top_r = all_risks[0]
            context.risk = top_r.model_dump()
            prov_builder.add("Risk", top_r.entity_id, relationship="TOP_RISK", confidence=1.0)

    def _execute_get_controls(
        self,
        plan: QueryPlan,
        context: CopilotContext,
        prov_builder: ProvenanceBuilder,
        target_ctrl_id: Optional[str],
    ) -> None:
        if target_ctrl_id:
            ctrl = self.repo.get_entity(target_ctrl_id)
            if isinstance(ctrl, Control):
                context.control = ctrl.model_dump()
                prov_builder.add("Control", ctrl.entity_id, relationship="TARGET_CONTROL", confidence=1.0)
        else:
            all_ctrls = [
                e.model_dump() for e in self.repo.list_entities("Control")
                if isinstance(e, Control) and e.framework_id == "ISMS-P"
            ]
            context.controls = all_ctrls

    def _execute_get_lineage(
        self,
        context: CopilotContext,
        prov_builder: ProvenanceBuilder,
        target_ctrl_id: Optional[str],
        target_risk_id: Optional[str],
        target_ev_id: Optional[str],
    ) -> None:
        entity_id = target_ctrl_id or target_risk_id or target_ev_id
        if not entity_id and context.risk:
            entity_id = context.risk.get("entity_id")

        if entity_id:
            lineage = self.resolver.get_evidence_lineage(entity_id)
            if "error" not in lineage:
                prov_builder.add_from_lineage(lineage)
                if "cross_mappings" in lineage and not context.framework_mapping:
                    context.framework_mapping = lineage["cross_mappings"]
                if "evidences" in lineage and not context.evidence:
                    context.evidence = lineage["evidences"]

    def _execute_get_evidence(
        self,
        context: CopilotContext,
        prov_builder: ProvenanceBuilder,
        target_ctrl_id: Optional[str],
        target_ev_id: Optional[str],
    ) -> None:
        if target_ctrl_id:
            evs = self.resolver.find_evidence_for_control(target_ctrl_id)
            context.evidence = [e.model_dump() for e in evs]
            for e in evs:
                prov_builder.add("Evidence", e.entity_id, relationship="SUPPORTED_BY", confidence=1.0)
        elif target_ev_id:
            ev = self.repo.get_entity(target_ev_id)
            if isinstance(ev, EvidenceEntity):
                context.evidence = [ev.model_dump()]
                prov_builder.add("Evidence", ev.entity_id, relationship="TARGET_EVIDENCE", confidence=1.0)

    def _execute_get_remediations(
        self,
        context: CopilotContext,
        prov_builder: ProvenanceBuilder,
        target_risk_id: Optional[str],
        target_ctrl_id: Optional[str],
    ) -> None:
        risk_id = target_risk_id
        if not risk_id and target_ctrl_id:
            risks = self.resolver.find_risks_for_control(target_ctrl_id)
            if risks:
                risk_id = risks[0].entity_id
        if not risk_id and context.risk:
            risk_id = context.risk.get("entity_id")

        if not risk_id:
            # 기본값: Top Risk의 ID를 사용
            top_risks = [e for e in self.repo.list_entities("Risk") if isinstance(e, RiskEntity)]
            top_risks.sort(key=lambda r: (-r.risk_score, r.priority))
            if top_risks:
                risk_id = top_risks[0].entity_id
                if not context.risk:
                    context.risk = top_risks[0].model_dump()

        if risk_id:
            rems = self.resolver.find_remediations_for_risk(risk_id)
            context.remediations = [r.model_dump() for r in rems]
            for r in rems:
                prov_builder.add("Remediation", r.entity_id, relationship="MITIGATED_BY", confidence=1.0)

    def _execute_get_coverage(
        self,
        plan: QueryPlan,
        context: CopilotContext,
        prov_builder: ProvenanceBuilder,
    ) -> None:
        fw_id = plan.parameters.get("framework_id", "ISMS-P")
        cov = self.resolver.get_framework_coverage(fw_id)
        context.coverage = cov.model_dump()
        prov_builder.add("Framework", fw_id, relationship="COVERAGE", confidence=1.0)

    def _execute_get_framework_mappings(
        self,
        plan: QueryPlan,
        context: CopilotContext,
        prov_builder: ProvenanceBuilder,
        target_ctrl_id: Optional[str],
    ) -> None:
        if not target_ctrl_id and context.control:
            target_ctrl_id = context.control.get("entity_id")

        if target_ctrl_id:
            target_fw = plan.parameters.get("target_framework")
            ctrl_lineage = self.resolver.get_control_lineage(target_ctrl_id)
            mappings = ctrl_lineage.get("cross_mappings", [])
            if target_fw:
                mappings = [m for m in mappings if target_fw in m.get("target_control_id", "")]
            context.framework_mapping = mappings
            for m in mappings:
                prov_builder.add("Control", m.get("target_control_id", ""), relationship="MAPS_TO", confidence=m.get("confidence", 1.0))

    def _execute_get_agent_security(
        self,
        context: CopilotContext,
        prov_builder: ProvenanceBuilder,
    ) -> None:
        runner = RedTeamRunner()
        summary, _ = runner.run_all()
        context.agent_security = summary.model_dump()
        prov_builder.add("AgentSecurity", "REDTEAM_RUNNER", relationship="RESILIENCE_VERIFIED", confidence=1.0)
