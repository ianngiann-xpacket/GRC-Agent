"""보안 온톨로지 지식 그래프 빌더(OntologyBuilder) 모듈입니다.

기존 GRC-Agent의 검증된 엔진들(ControlRepository, ProwlerEvidenceAdapter,
AuditEngine, RiskEngine, RemediationOrchestrator)의 출력을 바탕으로
결정론적 단일 지식 그래프(Single Knowledge Graph)를 조립합니다.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from secgrc.evidence.prowler_adapter import ProwlerEvidenceAdapter
from secgrc.agent_security.models import ToolType
from secgrc.agent_security.registry import AgentRegistry, ToolRegistry
from secgrc.audit.engine import AuditEngine
from secgrc.closed_loop.providers import MockRemediationProvider
from secgrc.closed_loop.remediation import RemediationOrchestrator
from secgrc.knowledge.repository import ControlRepository
from secgrc.ontology.confidence import MappingConfidence, MappingType
from secgrc.ontology.entities import (
    AgentEntity,
    Asset,
    Control,
    EvidenceEntity,
    Finding,
    Framework,
    PolicyEntity,
    RemediationEntity,
    Requirement,
    RiskEntity,
    ToolEntity,
)
from secgrc.ontology.mapper import CrossFrameworkMapper
from secgrc.ontology.models import AutomationLevel, ControlEffectiveness, RelationshipType
from secgrc.ontology.relationships import Relationship
from secgrc.ontology.repository import OntologyRepository
from secgrc.risk.engine import RiskEngine


class OntologyBuilder:
    """GRC 파이프라인 출력을 지식 그래프로 변환 및 통합하는 빌더 클래스"""

    def __init__(
        self,
        repo: Optional[OntologyRepository] = None,
        control_repo: Optional[ControlRepository] = None,
        cross_mapper: Optional[CrossFrameworkMapper] = None,
    ) -> None:
        self.repo = repo or OntologyRepository()
        self.control_repo = control_repo or ControlRepository()
        self.cross_mapper = cross_mapper or CrossFrameworkMapper()

    def build(
        self,
        evidence_path: Optional[str] = None,
        use_cross_frameworks: bool = True,
    ) -> OntologyRepository:
        """결정론적 온톨로지 지식 그래프를 구성합니다.

        Args:
            evidence_path: Prowler 진단 CSV 파일 경로 (기본값: tests/fixtures/prowler_gcp_sample.csv)
            use_cross_frameworks: 글로벌 프레임워크 크로스 매핑 포함 여부

        Returns:
            OntologyRepository: 완성된 온톨로지 지식 그래프 인메모리 저장소
        """
        # 1. ISMS-P 프레임워크 등록
        self.repo.add_entity(
            Framework(
                entity_id="ISMS-P",
                name="K-ISMS-P (정보보호 및 개인정보보호 관리체계)",
                authority="KISA",
                version="2023",
                description="과학기술정보통신부 및 개인정보보호위원회 고시 정보보호 및 개인정보보호 관리체계 인증기준",
            )
        )

        # 2. ISMS-P 통제항목 및 요구사항 등록
        for ctrl in self.control_repo.controls:
            auto_lvl = (
                AutomationLevel.FULLY_AUTOMATED
                if ctrl.automatable
                else AutomationLevel.PARTIALLY_AUTOMATED
            )
            ctrl_entity = Control(
                entity_id=ctrl.control_id,
                framework_id="ISMS-P",
                name=ctrl.title,
                domain=ctrl.domain,
                category=ctrl.domain,
                description=ctrl.requirement,
                automation_level=auto_lvl,
                effectiveness=ControlEffectiveness.NOT_ASSESSED,
                metadata={"keywords": ctrl.keywords, "risk": ctrl.risk},
            )
            self.repo.add_entity(ctrl_entity)

            # Framework -> Control CONTAINS 관계
            self.repo.add_relationship(
                Relationship(
                    relationship_id=f"rel_contains_ISMS-P_{ctrl.control_id}",
                    source_type="Framework",
                    source_id="ISMS-P",
                    relationship_type=RelationshipType.CONTAINS,
                    target_type="Control",
                    target_id=ctrl.control_id,
                    confidence=MappingConfidence(
                        score=1.0,
                        mapping_type=MappingType.EXPLICIT,
                        source="framework_standard",
                    ),
                )
            )

            # Control Requirement 개체 등록 및 연결
            req_id = f"REQ-{ctrl.control_id}-1"
            self.repo.add_entity(
                Requirement(
                    entity_id=req_id,
                    control_id=ctrl.control_id,
                    name=f"{ctrl.title} 기본 요구사항",
                    description=ctrl.requirement,
                    mandatory=True,
                )
            )
            self.repo.add_relationship(
                Relationship(
                    relationship_id=f"rel_requires_{ctrl.control_id}_{req_id}",
                    source_type="Control",
                    source_id=ctrl.control_id,
                    relationship_type=RelationshipType.REQUIRES,
                    target_type="Requirement",
                    target_id=req_id,
                    confidence=MappingConfidence(
                        score=1.0,
                        mapping_type=MappingType.EXPLICIT,
                        source="control_requirement",
                    ),
                )
            )

        # 3. 글로벌 프레임워크 크로스 매핑 등록
        if use_cross_frameworks:
            self.cross_mapper.populate_cross_frameworks(self.repo)

        # 4. 증적(Evidence) 로드
        if evidence_path is None:
            fixture_file = (
                Path(__file__).resolve().parent.parent.parent.parent
                / "tests"
                / "fixtures"
                / "prowler_gcp_sample.csv"
            )
            evidence_path = str(fixture_file)

        adapter = ProwlerEvidenceAdapter(delimiter=";")
        findings = adapter.load_findings(evidence_path)

        # 5. 감사 엔진(AuditEngine) 실행 및 유효성 업데이트
        audit_engine = AuditEngine(repo=self.control_repo)
        audit_results = audit_engine.assess(findings)

        for ar in audit_results:
            ctrl_entity = self.repo.get_entity(ar.control_id)
            if isinstance(ctrl_entity, Control):
                ctrl_entity.effectiveness = ControlEffectiveness.from_audit_status(
                    ar.status.value
                )

        # 6. 증적, 결함, 자산 개체 및 관계 생성
        for idx, ev in enumerate(findings, start=1):
            raw_ev_id = ev.get("evidence_id") or f"EV-{idx:03d}"
            ev_id = f"EV-{raw_ev_id}" if not raw_ev_id.startswith("EV-") else raw_ev_id
            
            # Evidence 개체 등록
            self.repo.add_entity(
                EvidenceEntity(
                    entity_id=ev_id,
                    name=ev.get("check_title") or f"Prowler Check {ev.get('check_id', '')}",
                    description=ev.get("finding_description") or ev.get("status_extended") or "",
                    source_system="prowler",
                    evidence_type="configuration",
                    metadata={
                        "status": ev.get("status"),
                        "severity": ev.get("severity"),
                        "check_id": ev.get("check_id"),
                        "resource_id": ev.get("resource_id"),
                    },
                )
            )

            # Finding 개체 등록
            fnd_id = f"FND-{raw_ev_id}"
            resource_name = ev.get("resource_name") or ev.get("resource_id") or "gcp-cloud-resource"
            self.repo.add_entity(
                Finding(
                    entity_id=fnd_id,
                    name=ev.get("check_title") or f"Finding for {ev.get('check_id')}",
                    description=ev.get("status_extended") or ev.get("finding_description") or "",
                    severity=str(ev.get("severity", "MEDIUM")).upper(),
                    finding_type="misconfiguration",
                    status="OPEN" if str(ev.get("status")).upper() == "FAIL" else "PASS",
                    source_tool="prowler",
                    resource_id=resource_name,
                )
            )

            # Evidence -> Finding (DERIVED_FROM)
            self.repo.add_relationship(
                Relationship(
                    relationship_id=f"rel_derived_{ev_id}_{fnd_id}",
                    source_type="Evidence",
                    source_id=ev_id,
                    relationship_type=RelationshipType.DERIVED_FROM,
                    target_type="Finding",
                    target_id=fnd_id,
                    confidence=MappingConfidence(
                        score=1.0,
                        mapping_type=MappingType.EXPLICIT,
                        source="prowler_scan",
                    ),
                )
            )

            # Asset 개체 등록
            asset_id = f"ASSET-{resource_name}"
            if not self.repo.get_entity(asset_id):
                self.repo.add_entity(
                    Asset(
                        entity_id=asset_id,
                        name=resource_name,
                        asset_type=ev.get("service_name") or "cloud_resource",
                        criticality="HIGH" if str(ev.get("severity")).upper() in ("CRITICAL", "HIGH") else "MEDIUM",
                        environment="production",
                        metadata={"provider": ev.get("provider", "gcp")},
                    )
                )

            # Finding -> Asset (AFFECTS)
            self.repo.add_relationship(
                Relationship(
                    relationship_id=f"rel_affects_{fnd_id}_{asset_id}",
                    source_type="Finding",
                    source_id=fnd_id,
                    relationship_type=RelationshipType.AFFECTS,
                    target_type="Asset",
                    target_id=asset_id,
                    confidence=MappingConfidence(
                        score=1.0,
                        mapping_type=MappingType.EXPLICIT,
                        source="resource_binding",
                    ),
                )
            )

        # Audit 결과 기반 통제 <-> 증적 및 자산 매핑
        for ar in audit_results:
            for ev_ref in ar.evidence_ids:
                mapped_ev_id = f"EV-{ev_ref}" if not ev_ref.startswith("EV-") else ev_ref
                if self.repo.get_entity(mapped_ev_id):
                    # Control -> Evidence (SUPPORTED_BY)
                    self.repo.add_relationship(
                        Relationship(
                            relationship_id=f"rel_sup_{ar.control_id}_{mapped_ev_id}",
                            source_type="Control",
                            source_id=ar.control_id,
                            relationship_type=RelationshipType.SUPPORTED_BY,
                            target_type="Evidence",
                            target_id=mapped_ev_id,
                            confidence=MappingConfidence(
                                score=ar.mapping_confidence,
                                mapping_type=MappingType.EXPLICIT if ar.mapping_type == "explicit" else MappingType.RULE,
                                rationale=ar.rationale,
                                source="audit_engine",
                            ),
                        )
                    )
                    # Evidence -> Control (MAPS_TO)
                    self.repo.add_relationship(
                        Relationship(
                            relationship_id=f"rel_maps_{mapped_ev_id}_{ar.control_id}",
                            source_type="Evidence",
                            source_id=mapped_ev_id,
                            relationship_type=RelationshipType.MAPS_TO,
                            target_type="Control",
                            target_id=ar.control_id,
                            confidence=MappingConfidence(
                                score=ar.mapping_confidence,
                                mapping_type=MappingType.EXPLICIT if ar.mapping_type == "explicit" else MappingType.RULE,
                                rationale=ar.rationale,
                                source="audit_engine",
                            ),
                        )
                    )

        # 7. 위험 평가(RiskEngine) 실행 및 개체 등록
        risk_engine = RiskEngine()
        risk_results = risk_engine.assess(audit_results, findings)

        for rsk in risk_results:
            risk_entity_id = f"RISK-{rsk.control_id}"
            self.repo.add_entity(
                RiskEntity(
                    entity_id=risk_entity_id,
                    name=f"Risk: {rsk.control_title} ({rsk.priority.value})",
                    description=rsk.rationale,
                    risk_score=rsk.risk_score,
                    severity=rsk.risk_level.value,
                    priority=rsk.priority.value,
                    likelihood=rsk.evidence_confidence,
                    impact=float(rsk.control_impact),
                    metadata={"control_id": rsk.control_id, "status": rsk.audit_status.value},
                )
            )

            # Control -> Risk (CREATES_RISK)
            self.repo.add_relationship(
                Relationship(
                    relationship_id=f"rel_risk_{rsk.control_id}_{risk_entity_id}",
                    source_type="Control",
                    source_id=rsk.control_id,
                    relationship_type=RelationshipType.CREATES_RISK,
                    target_type="Risk",
                    target_id=risk_entity_id,
                    confidence=MappingConfidence(
                        score=1.0,
                        mapping_type=MappingType.EXPLICIT,
                        rationale="결정론적 위험 평가 모델 도출",
                        source="risk_engine",
                    ),
                )
            )

        # 8. 조치 계획(Remediation) 도출 및 개체/관계 등록
        grouped = audit_engine.mapper.group_by_control(findings)
        ev_to_control: Dict[str, str] = {}
        for cid, ev_list in grouped.items():
            for ev_item in ev_list:
                eid = ev_item.get("evidence_id")
                if eid:
                    ev_to_control[eid] = cid

        enriched_findings = []
        for f in findings:
            f_copy = dict(f)
            eid = f.get("evidence_id")
            if eid and eid in ev_to_control:
                f_copy["control_id"] = ev_to_control[eid]
            enriched_findings.append(f_copy)

        orchestrator = RemediationOrchestrator(MockRemediationProvider())
        remediations = orchestrator.plan_remediations(enriched_findings, risk_results)

        for rem in remediations:
            rem_entity_id = f"REM-{rem.action_id}"
            self.repo.add_entity(
                RemediationEntity(
                    entity_id=rem_entity_id,
                    name=f"Remediation: {rem.action_type}",
                    description=rem.reason,
                    plan_type="automated",
                    status="PLANNED",
                    execution_type="MOCK",
                    metadata={
                        "target": rem.target,
                        "risk_id": rem.risk_id,
                        "control_id": rem.control_id,
                        "required_approval": rem.required_approval,
                    },
                )
            )

            # Risk -> Remediation (MITIGATED_BY)
            risk_entity_id = f"RISK-{rem.control_id}"
            if self.repo.get_entity(risk_entity_id):
                self.repo.add_relationship(
                    Relationship(
                        relationship_id=f"rel_mitigated_{risk_entity_id}_{rem_entity_id}",
                        source_type="Risk",
                        source_id=risk_entity_id,
                        relationship_type=RelationshipType.MITIGATED_BY,
                        target_type="Remediation",
                        target_id=rem_entity_id,
                        confidence=MappingConfidence(
                            score=1.0,
                            mapping_type=MappingType.EXPLICIT,
                            source="remediation_orchestrator",
                        ),
                    )
                )

            # Remediation -> Asset (REMEDIATES)
            asset_id = f"ASSET-{rem.target}"
            if self.repo.get_entity(asset_id):
                self.repo.add_relationship(
                    Relationship(
                        relationship_id=f"rel_remediates_{rem_entity_id}_{asset_id}",
                        source_type="Remediation",
                        source_id=rem_entity_id,
                        relationship_type=RelationshipType.REMEDIATES,
                        target_type="Asset",
                        target_id=asset_id,
                        confidence=MappingConfidence(
                            score=1.0,
                            mapping_type=MappingType.EXPLICIT,
                            source="remediation_orchestrator",
                        ),
                    )
                )

            # Remediation -> Policy (REQUIRES_APPROVAL)
            if rem.required_approval:
                self.repo.add_relationship(
                    Relationship(
                        relationship_id=f"rel_appr_{rem_entity_id}_POL-HUMAN-APPROVAL",
                        source_type="Remediation",
                        source_id=rem_entity_id,
                        relationship_type=RelationshipType.REQUIRES_APPROVAL,
                        target_type="Policy",
                        target_id="POL-HUMAN-APPROVAL",
                        confidence=MappingConfidence(
                            score=1.0,
                            mapping_type=MappingType.EXPLICIT,
                            source="approval_policy",
                        ),
                    )
                )

        # 9. 에이전트, 도구, 거버넌스 정책 개체 및 관계 등록
        self._populate_governance()

        return self.repo

    def _populate_governance(self) -> None:
        """에이전트 거버넌스, 도구, 정책 개체 및 연결 관계 등록"""
        # 정책 등록
        policies = [
            PolicyEntity(
                entity_id="POL-HUMAN-APPROVAL",
                name="Human-in-the-Loop Approval Policy",
                description="CRITICAL/HIGH 위험 시정조치 시 인간 승인권자의 사전 결재 필수",
                policy_type="approval",
                enforcement_level="BLOCK",
            ),
            PolicyEntity(
                entity_id="POL-LEAST-PRIVILEGE",
                name="Agent Least Privilege Policy",
                description="인가되지 않은 파괴적 도구 호출 및 권한 밖의 작업 원천 차단",
                policy_type="guardrail",
                enforcement_level="BLOCK",
            ),
            PolicyEntity(
                entity_id="POL-SECRET-PROTECTION",
                name="Canary & Secret Leak Prevention Policy",
                description="카나리 시크릿 및 민감 토큰의 외부 출력/누설 방지",
                policy_type="guardrail",
                enforcement_level="BLOCK",
            ),
        ]
        for pol in policies:
            if not self.repo.get_entity(pol.entity_id):
                self.repo.add_entity(pol)

        # 에이전트 등록
        agent_reg = AgentRegistry()
        for ag in agent_reg.list_all():
            agent_id = f"AGENT-{ag.agent_id}"
            if not self.repo.get_entity(agent_id):
                self.repo.add_entity(
                    AgentEntity(
                        entity_id=agent_id,
                        name=ag.agent_name,
                        role=ag.purpose,
                        model=ag.model,
                        status=ag.status.value,
                        metadata={"description": ag.purpose},
                    )
                )
                # Agent -> Policy (GOVERNED_BY)
                self.repo.add_relationship(
                    Relationship(
                        relationship_id=f"rel_gov_{agent_id}_POL-LEAST-PRIVILEGE",
                        source_type="Agent",
                        source_id=agent_id,
                        relationship_type=RelationshipType.GOVERNED_BY,
                        target_type="Policy",
                        target_id="POL-LEAST-PRIVILEGE",
                        confidence=MappingConfidence(
                            score=1.0,
                            mapping_type=MappingType.EXPLICIT,
                            source="agent_security",
                        ),
                    )
                )

        # 도구 등록
        tool_reg = ToolRegistry()
        for tname, tmeta in tool_reg._tools.items():
            tool_id = f"TOOL-{tname}"
            if not self.repo.get_entity(tool_id):
                self.repo.add_entity(
                    ToolEntity(
                        entity_id=tool_id,
                        name=tname,
                        description=tmeta.description,
                        tool_type=tmeta.tool_type.value,
                        is_destructive=(tmeta.tool_type == ToolType.ACTION),
                    )
                )
                # Agent -> Tool (USES)
                for aid in tmeta.allowed_agents:
                    agent_eid = f"AGENT-{aid}"
                    if self.repo.get_entity(agent_eid):
                        self.repo.add_relationship(
                            Relationship(
                                relationship_id=f"rel_uses_{agent_eid}_{tool_id}",
                                source_type="Agent",
                                source_id=agent_eid,
                                relationship_type=RelationshipType.USES,
                                target_type="Tool",
                                target_id=tool_id,
                                confidence=MappingConfidence(
                                    score=1.0,
                                    mapping_type=MappingType.EXPLICIT,
                                    source="tool_registry",
                                ),
                            )
                        )
