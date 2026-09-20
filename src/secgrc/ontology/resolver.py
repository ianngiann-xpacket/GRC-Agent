"""온톨로지 그래프 질의 해석기 및 혈통(Lineage) 추적기 모듈입니다.

그래프 탐색을 통해 증적-통제-위험-조치 간의 관계를 다각도로 해석하고,
프레임워크별 통제 유효성 커버리지(Framework Coverage)를 계산합니다.
"""

from typing import Any, Dict, List, Optional

from secgrc.ontology.entities import (
    Asset,
    BaseEntity,
    Control,
    EvidenceEntity,
    Finding,
    RemediationEntity,
    RiskEntity,
)
from secgrc.ontology.models import (
    AutomationLevel,
    ControlEffectiveness,
    FrameworkCoverage,
    RelationshipType,
)
from secgrc.ontology.repository import OntologyRepository


class OntologyResolver:
    """온톨로지 그래프 기반 보안 질의 및 혈통(Lineage) 분석기"""

    def __init__(self, repo: OntologyRepository) -> None:
        self.repo = repo

    def find_controls_for_evidence(self, evidence_id: str) -> List[Control]:
        """특정 증적(Evidence)이 매핑된 통제항목 목록 조회"""
        controls: List[Control] = []
        for rel in self.repo.get_outgoing_relationships(
            evidence_id, RelationshipType.MAPS_TO
        ):
            target = self.repo.get_entity(rel.target_id)
            if isinstance(target, Control):
                controls.append(target)
        return controls

    def find_evidence_for_control(self, control_id: str) -> List[EvidenceEntity]:
        """특정 통제항목을 뒷받침하는 증적 목록 조회"""
        evidences: List[EvidenceEntity] = []
        for rel in self.repo.get_outgoing_relationships(
            control_id, RelationshipType.SUPPORTED_BY
        ):
            target = self.repo.get_entity(rel.target_id)
            if isinstance(target, EvidenceEntity):
                evidences.append(target)
        return evidences

    def find_risks_for_control(self, control_id: str) -> List[RiskEntity]:
        """특정 통제항목 결함으로부터 유발된 위험 목록 조회"""
        risks: List[RiskEntity] = []
        for rel in self.repo.get_outgoing_relationships(
            control_id, RelationshipType.CREATES_RISK
        ):
            target = self.repo.get_entity(rel.target_id)
            if isinstance(target, RiskEntity):
                risks.append(target)
        return risks

    def find_controls_for_risk(self, risk_id: str) -> List[Control]:
        """특정 위험을 유발한 근본 통제항목 조회"""
        controls: List[Control] = []
        for rel in self.repo.get_incoming_relationships(
            risk_id, RelationshipType.CREATES_RISK
        ):
            source = self.repo.get_entity(rel.source_id)
            if isinstance(source, Control):
                controls.append(source)
        return controls

    def find_assets_for_finding(self, finding_id: str) -> List[Asset]:
        """특정 결함(Finding)의 영향을 받는 자산 목록 조회"""
        assets: List[Asset] = []
        for rel in self.repo.get_outgoing_relationships(
            finding_id, RelationshipType.AFFECTS
        ):
            target = self.repo.get_entity(rel.target_id)
            if isinstance(target, Asset):
                assets.append(target)
        return assets

    def find_remediations_for_risk(self, risk_id: str) -> List[RemediationEntity]:
        """특정 위험을 완화하기 위해 수립된 조치 목록 조회"""
        remediations: List[RemediationEntity] = []
        for rel in self.repo.get_outgoing_relationships(
            risk_id, RelationshipType.MITIGATED_BY
        ):
            target = self.repo.get_entity(rel.target_id)
            if isinstance(target, RemediationEntity):
                remediations.append(target)
        return remediations

    def get_evidence_lineage(self, entity_id: str) -> Dict[str, Any]:
        """단일 개체(증적, 통제, 위험 등)를 기준으로 연결된 전주기 보안 혈통(Lineage) 경로 추적"""
        target = self.repo.get_entity(entity_id)
        if not target:
            return {"error": f"Entity '{entity_id}' not found in ontology repository"}

        # Evidence 기준 추적
        if isinstance(target, EvidenceEntity):
            findings = []
            for rel in self.repo.get_outgoing_relationships(
                entity_id, RelationshipType.DERIVED_FROM
            ):
                fnd = self.repo.get_entity(rel.target_id)
                if fnd:
                    assets = self.find_assets_for_finding(fnd.entity_id)
                    findings.append(
                        {
                            "finding_id": fnd.entity_id,
                            "name": fnd.name,
                            "severity": getattr(fnd, "severity", "UNKNOWN"),
                            "assets": [a.entity_id for a in assets],
                        }
                    )

            controls = self.find_controls_for_evidence(entity_id)
            ctrl_lineages = []
            for c in controls:
                risks = self.find_risks_for_control(c.entity_id)
                ctrl_lineages.append(
                    {
                        "control_id": c.entity_id,
                        "name": c.name,
                        "effectiveness": c.effectiveness.value,
                        "risks": [
                            {
                                "risk_id": r.entity_id,
                                "priority": r.priority,
                                "score": r.risk_score,
                                "remediations": [
                                    rem.entity_id
                                    for rem in self.find_remediations_for_risk(
                                        r.entity_id
                                    )
                                ],
                            }
                            for r in risks
                        ],
                    }
                )

            return {
                "root_entity": {"id": entity_id, "type": "Evidence", "name": target.name},
                "findings": findings,
                "controls": ctrl_lineages,
                "chain_summary": f"Evidence({entity_id}) -> {len(controls)} Controls -> {len(findings)} Findings",
            }

        # Control 기준 추적
        if isinstance(target, Control):
            return self.get_control_lineage(entity_id)

        # Risk 기준 추적
        if isinstance(target, RiskEntity):
            return self.get_risk_lineage(entity_id)

        return {
            "root_entity": {"id": entity_id, "type": target.entity_type, "name": target.name},
            "outgoing": [r.model_dump() for r in self.repo.get_outgoing_relationships(entity_id)],
            "incoming": [r.model_dump() for r in self.repo.get_incoming_relationships(entity_id)],
        }

    def get_control_lineage(self, control_id: str) -> Dict[str, Any]:
        """통제항목 360도 전주기 혈통 분석 (요구사항, 증적, 결함, 위험, 글로벌 매핑, 조치)"""
        ctrl = self.repo.get_entity(control_id)
        if not ctrl or not isinstance(ctrl, Control):
            return {"error": f"Control '{control_id}' not found"}

        evidences = self.find_evidence_for_control(control_id)
        risks = self.find_risks_for_control(control_id)

        # 타 프레임워크 매핑 조회
        cross_mappings = []
        for rel in self.repo.get_outgoing_relationships(
            control_id, RelationshipType.MAPS_TO
        ):
            mapped_ctrl = self.repo.get_entity(rel.target_id)
            if mapped_ctrl:
                cross_mappings.append(
                    {
                        "target_control_id": mapped_ctrl.entity_id,
                        "target_name": mapped_ctrl.name,
                        "confidence": rel.confidence.score,
                        "rationale": rel.confidence.rationale,
                    }
                )

        remediations = []
        for r in risks:
            for rem in self.find_remediations_for_risk(r.entity_id):
                remediations.append(
                    {
                        "remediation_id": rem.entity_id,
                        "name": rem.name,
                        "plan_type": rem.plan_type,
                        "status": rem.status,
                    }
                )

        return {
            "control_id": ctrl.entity_id,
            "framework_id": ctrl.framework_id,
            "name": ctrl.name,
            "domain": ctrl.domain,
            "effectiveness": ctrl.effectiveness.value,
            "automation_level": ctrl.automation_level.value,
            "evidence_count": len(evidences),
            "evidences": [{"id": e.entity_id, "name": e.name} for e in evidences],
            "risk_count": len(risks),
            "risks": [
                {
                    "risk_id": r.entity_id,
                    "score": r.risk_score,
                    "priority": r.priority,
                    "severity": r.severity,
                }
                for r in risks
            ],
            "cross_mappings": cross_mappings,
            "remediations": remediations,
        }

    def get_risk_lineage(self, risk_id: str) -> Dict[str, Any]:
        """위험 개체(Risk) 중심 근본원인 및 시정조치 혈통 분석"""
        rsk = self.repo.get_entity(risk_id)
        if not rsk or not isinstance(rsk, RiskEntity):
            return {"error": f"Risk '{risk_id}' not found"}

        controls = self.find_controls_for_risk(risk_id)
        remediations = self.find_remediations_for_risk(risk_id)

        ctrl_summaries = []
        for c in controls:
            evs = self.find_evidence_for_control(c.entity_id)
            ctrl_summaries.append(
                {
                    "control_id": c.entity_id,
                    "name": c.name,
                    "effectiveness": c.effectiveness.value,
                    "evidence_count": len(evs),
                    "evidences": [e.entity_id for e in evs],
                }
            )

        return {
            "risk_id": rsk.entity_id,
            "name": rsk.name,
            "risk_score": rsk.risk_score,
            "severity": rsk.severity,
            "priority": rsk.priority,
            "root_cause_controls": ctrl_summaries,
            "mitigating_remediations": [
                {
                    "remediation_id": rem.entity_id,
                    "name": rem.name,
                    "status": rem.status,
                    "plan_type": rem.plan_type,
                }
                for rem in remediations
            ],
        }

    def get_framework_coverage(self, framework_id: str = "ISMS-P") -> FrameworkCoverage:
        """프레임워크별 통제 유효성 및 자동화 평가 커버리지 계산"""
        controls: List[Control] = [
            e
            for e in self.repo.list_entities("Control")
            if isinstance(e, Control) and e.framework_id == framework_id
        ]
        total = len(controls)
        if total == 0:
            return FrameworkCoverage(
                framework_id=framework_id,
                total_controls=0,
                assessed_controls=0,
                effective_controls=0,
                partially_effective_controls=0,
                ineffective_controls=0,
                not_assessed_controls=0,
                coverage_percent=0.0,
                automation_percent=0.0,
            )

        effective = sum(
            1 for c in controls if c.effectiveness == ControlEffectiveness.EFFECTIVE
        )
        partial = sum(
            1
            for c in controls
            if c.effectiveness == ControlEffectiveness.PARTIALLY_EFFECTIVE
        )
        ineffective = sum(
            1 for c in controls if c.effectiveness == ControlEffectiveness.INEFFECTIVE
        )
        not_assessed = sum(
            1 for c in controls if c.effectiveness == ControlEffectiveness.NOT_ASSESSED
        )

        assessed = effective + partial + ineffective
        coverage_pct = round((assessed / total) * 100.0, 2)

        automated_count = sum(
            1
            for c in controls
            if c.automation_level == AutomationLevel.FULLY_AUTOMATED
        )
        auto_pct = round((automated_count / total) * 100.0, 2)

        return FrameworkCoverage(
            framework_id=framework_id,
            total_controls=total,
            assessed_controls=assessed,
            effective_controls=effective,
            partially_effective_controls=partial,
            ineffective_controls=ineffective,
            not_assessed_controls=not_assessed,
            coverage_percent=coverage_pct,
            automation_percent=auto_pct,
        )
