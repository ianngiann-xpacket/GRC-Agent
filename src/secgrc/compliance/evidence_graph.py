"""Evidence Reference Graph & Query APIs (Step 23.5B).

This module manages the evidence reference lineage graph, conflicting evidence states,
and deterministic query APIs for evidence requirements, data requirements, and cross-framework reuse.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import Field, field_validator

from secgrc.compliance.evidence_requirements import (
    ComplianceDataRequirement,
    ComplianceEvidenceRequirement,
    default_evidence_requirement_registry,
)
from secgrc.compliance.models import (
    CanonicalDataType,
    ComplianceBaseModel,
    ProvenanceRecord,
    validate_identifier,
    validate_iso8601_timestamp,
)
from secgrc.compliance.source_bindings import EvidenceSourceBinding


class EvidenceReference(ComplianceBaseModel):
    """실제 관측된 정규 데이터와 규정상 증적 요건 간의 경량 참조 링크."""

    requirement_id: str = Field(description="대상 요구사항 ID")
    evidence_requirement_id: str = Field(description="연계된 증적 요건 ID")
    canonical_record_id: str = Field(description="참조 대상 표준 정규 레코드 ID")
    source_system: str = Field(description="원천 시스템명")
    source_record_id: str = Field(description="원천 레코드 고유 ID")
    observed_at: str = Field(description="관측 일시 (ISO 8601)")
    provenance: ProvenanceRecord = Field(description="출처 계보 레코드")
    conflict_status: Optional[str] = Field(
        default=None,
        description="증적 상충 상태 (예: CONFLICTING, RESOLVED_MANUAL)",
    )

    @field_validator("requirement_id", "evidence_requirement_id", "canonical_record_id", "source_system", "source_record_id")
    @classmethod
    def check_ref_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("observed_at")
    @classmethod
    def check_ref_timestamp(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)


class EvidenceConflict(ComplianceBaseModel):
    """상충되는 두 개 이상의 증적 간 불일치 상태를 명시적으로 보존하는 모델."""

    requirement_id: str = Field(description="상충이 발생한 요구사항 ID")
    primary_evidence_id: str = Field(description="기준(1차) 증적 ID")
    conflicting_evidence_id: str = Field(description="상충되는 다른 증적 ID")
    conflict_reason: str = Field(description="증적 간 불일치/상충 사유 설명")
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="상충 식별 일시 (ISO 8601)",
    )
    status: str = Field(
        default="CONFLICTING",
        description="상충 상태 (CONFLICTING 유지, 자동 해소 금지)",
    )

    @field_validator("requirement_id", "primary_evidence_id", "conflicting_evidence_id", "status")
    @classmethod
    def check_conflict_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("detected_at")
    @classmethod
    def check_conflict_time(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)


class EvidenceReferenceGraph(ComplianceBaseModel):
    """요구사항 - 증적요건 - 데이터요건 - 원천계보 간의 결정론적 계보 그래프."""

    nodes: List[Dict[str, Any]] = Field(default_factory=list, description="그래프 노드 목록")
    edges: List[Dict[str, Any]] = Field(default_factory=list, description="그래프 엣지 목록")
    references: List[EvidenceReference] = Field(default_factory=list, description="참조 링크 목록")
    conflicts: List[EvidenceConflict] = Field(default_factory=list, description="식별된 상충 목록")

    def add_reference(self, ref: EvidenceReference) -> None:
        """증적 참조를 추가하고 계보 노드 및 엣지를 생성합니다."""
        self.references.append(ref)
        # Node: Requirement
        self._ensure_node(ref.requirement_id, "Requirement", {"requirement_id": ref.requirement_id})
        # Node: EvidenceRequirement
        self._ensure_node(ref.evidence_requirement_id, "EvidenceRequirement", {"id": ref.evidence_requirement_id})
        # Node: CanonicalSecurityData
        self._ensure_node(ref.canonical_record_id, "CanonicalSecurityData", {
            "record_id": ref.canonical_record_id,
            "source_system": ref.source_system,
            "source_record_id": ref.source_record_id,
        })
        # Node: Provenance
        prov_node_id = f"PROV-{ref.canonical_record_id}"
        self._ensure_node(prov_node_id, "Provenance", {
            "source_system": ref.provenance.source_system,
            "source_hash": ref.provenance.source_hash,
        })

        # Edges
        self._ensure_edge(ref.requirement_id, ref.evidence_requirement_id, "REQUIRES_EVIDENCE")
        self._ensure_edge(ref.evidence_requirement_id, ref.canonical_record_id, "SATISFIED_BY_RECORD")
        self._ensure_edge(ref.canonical_record_id, prov_node_id, "HAS_PROVENANCE")

    def record_conflict(self, conflict: EvidenceConflict) -> None:
        """상충 증적을 등록하고 CONFLICTS_WITH 엣지를 생성합니다."""
        self.conflicts.append(conflict)
        self._ensure_edge(
            conflict.primary_evidence_id,
            conflict.conflicting_evidence_id,
            "CONFLICTS_WITH",
            {"reason": conflict.conflict_reason, "status": conflict.status},
        )

    def get_references_for_requirement(self, requirement_id: str) -> List[EvidenceReference]:
        """특정 요구사항의 모든 증적 참조를 반환합니다."""
        return [r for r in self.references if r.requirement_id == requirement_id]

    def get_conflicts_for_requirement(self, requirement_id: str) -> List[EvidenceConflict]:
        """특정 요구사항의 모든 상충 기록을 반환합니다."""
        return [c for c in self.conflicts if c.requirement_id == requirement_id]

    def _ensure_node(self, node_id: str, node_type: str, properties: Dict[str, Any]) -> None:
        if not any(n["id"] == node_id for n in self.nodes):
            self.nodes.append({"id": node_id, "type": node_type, "properties": properties})

    def _ensure_edge(self, source: str, target: str, relationship: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        edge = {"source": source, "target": target, "relationship": relationship, "metadata": metadata or {}}
        if edge not in self.edges:
            self.edges.append(edge)


# ---------------------------------------------------------------------------
# Public Query APIs (Section 27)
# ---------------------------------------------------------------------------

def get_requirement_evidence_requirements(
    framework_id: str,
    framework_version: str,
    requirement_id: str,
) -> List[ComplianceEvidenceRequirement]:
    """특정 프레임워크 요구사항에 매핑된 증적 요구사항 목록을 조회합니다."""
    return default_evidence_requirement_registry.list_evidence_requirements(
        framework_id=framework_id,
        framework_version=framework_version,
        requirement_id=requirement_id,
    )


def get_requirement_data_requirements(
    framework_id: str,
    framework_version: str,
    requirement_id: str,
) -> List[ComplianceDataRequirement]:
    """특정 프레임워크 요구사항에 매핑된 데이터 요구사항 목록을 조회합니다."""
    return default_evidence_requirement_registry.list_data_requirements(
        framework_id=framework_id,
        framework_version=framework_version,
        requirement_id=requirement_id,
    )


def get_evidence_source_bindings(
    evidence_requirement_id: str,
) -> List[EvidenceSourceBinding]:
    """특정 증적 요구사항에 허용된 소스 및 어댑터 바인딩 목록을 조회합니다."""
    ev_req = default_evidence_requirement_registry.get_evidence_requirement(evidence_requirement_id)
    if not ev_req:
        return []
    return ev_req.source_bindings


def get_required_inputs(
    requirement_id: str,
    framework_id: str = "ISMS-P",
    framework_version: str = "2024-07",
) -> List[str]:
    """요구사항 평가에 필요한 입력 데이터 및 증적 식별자 목록을 반환합니다."""
    ev_reqs = default_evidence_requirement_registry.list_evidence_requirements(
        framework_id=framework_id,
        framework_version=framework_version,
        requirement_id=requirement_id,
    )
    res: List[str] = []
    for r in ev_reqs:
        if r.mandatory:
            res.append(f"{r.evidence_type} ({r.data_type.value})")
    return sorted(list(set(res)))


def get_evidence_requirement_graph(
    requirement_id: str,
    framework_id: str = "ISMS-P",
    framework_version: str = "2024-07",
) -> EvidenceReferenceGraph:
    """요구사항에 대한 증적 요건, 데이터 요건, 소스 바인딩을 포함하는 계보 그래프를 생성합니다."""
    graph = EvidenceReferenceGraph()
    graph._ensure_node(requirement_id, "Requirement", {
        "framework_id": framework_id,
        "framework_version": framework_version,
        "requirement_id": requirement_id,
    })

    ev_reqs = default_evidence_requirement_registry.list_evidence_requirements(
        framework_id=framework_id,
        framework_version=framework_version,
        requirement_id=requirement_id,
    )
    for ev in ev_reqs:
        graph._ensure_node(ev.id, "EvidenceRequirement", {
            "evidence_id": ev.evidence_id,
            "evidence_type": ev.evidence_type,
            "role": ev.role.value,
            "mandatory": ev.mandatory,
            "automation_level": ev.automation_level.value,
        })
        graph._ensure_edge(requirement_id, ev.id, "REQUIRES_EVIDENCE")

        for binding in ev.source_bindings:
            binding_id = f"SRC-{binding.source_system.replace(' ', '_')}-{binding.adapter_type}"
            graph._ensure_node(binding_id, "SourceBinding", {
                "source_system": binding.source_system,
                "adapter_type": binding.adapter_type,
                "priority": binding.priority,
            })
            graph._ensure_edge(ev.id, binding_id, "BOUND_TO_SOURCE")

    data_reqs = default_evidence_requirement_registry.list_data_requirements(
        framework_id=framework_id,
        framework_version=framework_version,
        requirement_id=requirement_id,
    )
    for dtr in data_reqs:
        graph._ensure_node(dtr.id, "DataRequirement", {
            "data_type": dtr.data_type,
            "canonical_data_type": dtr.canonical_data_type.value,
            "role": dtr.role.value,
        })
        graph._ensure_edge(requirement_id, dtr.id, "REQUIRES_DATA")

    return graph


def get_cross_framework_evidence_reuse(
    canonical_data_type: CanonicalDataType,
) -> List[Dict[str, Any]]:
    """특정 표준 정규 데이터 타입을 공통으로 재사용하는 여러 프레임워크 요구사항들을 조회합니다."""
    reuse_list: List[Dict[str, Any]] = []
    # 모든 등록된 증적 요구사항 중 일치하는 데이터 타입 검색
    for ev in sorted(default_evidence_requirement_registry._evidence_requirements.values(), key=lambda r: r.id):
        if ev.data_type == canonical_data_type:
            reuse_list.append({
                "framework_id": ev.framework_id,
                "framework_version": ev.framework_version,
                "requirement_id": ev.requirement_id,
                "evidence_requirement_id": ev.id,
                "role": ev.role.value,
                "mandatory": ev.mandatory,
                "automation_level": ev.automation_level.value,
            })
    return reuse_list
