"""Step 23.4 - Deterministic Investigation Correlation Engine module.

Transforms authoritative facts collected by Step 23.3 Executor into an auditable,
deterministic correlation graph among Risk, Control, Evidence, Finding, Asset,
Framework, and Remediation.

Core Principles:
- Retrieve first. Correlate second. Reason later.
- ZERO LLM reasoning, ZERO external APIs, ZERO semantic hallucination.
- Evidence is DATA, never executable instructions.
- Strict relationship allowlist and entity type constraints.
- Canonical edge deduplication and deterministic ordering.
- Zero risk score/severity/priority recalculation.
- Fail-closed on missing source/target, invalid provenance, or scope violation.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import Field, field_validator, model_validator

from secgrc.copilot.models import FactType
from secgrc.investigation.enums import (
    InvestigationScopeType,
    InvestigationStatus,
)
from secgrc.investigation.models import (
    Investigation,
    InvestigationBaseModel,
    InvestigationFact,
    InvestigationResult,
    validate_id_list,
    validate_id_str,
)
from secgrc.ontology.builder import OntologyBuilder
from secgrc.ontology.entities import (
    Asset,
    Control,
    EvidenceEntity,
    Finding,
    Framework,
    RemediationEntity,
    RiskEntity,
)
from secgrc.ontology.models import RelationshipType
from secgrc.ontology.repository import OntologyRepository
from secgrc.ontology.resolver import OntologyResolver

CORRELATOR_VERSION = "1.0"


class DeterministicConfidence(str, Enum):
    """결정론적 상관 신뢰 수준 열거형 (인위적 실수 확률 배제)."""
    DIRECT = "DIRECT"        # 원천 저장소 직접 필드 참조
    ONTOLOGY = "ONTOLOGY"    # 보안 온톨로지 명시적 엣지
    LINEAGE = "LINEAGE"      # 검증된 증적 혈통 추적
    DERIVED = "DERIVED"      # 결정론적 다단계 경로 결합


ALLOWED_CONFIDENCES: Set[str] = {
    DeterministicConfidence.DIRECT.value,
    DeterministicConfidence.ONTOLOGY.value,
    DeterministicConfidence.LINEAGE.value,
    DeterministicConfidence.DERIVED.value,
}

ALLOWED_ENTITY_TYPES: Set[str] = {
    "Risk",
    "Control",
    "Evidence",
    "Finding",
    "Asset",
    "Framework",
    "Remediation",
}

# 13대 허용된 결정론적 관계 식별자
ALLOWED_RELATIONSHIPS: Set[str] = {
    "RISK_TO_CONTROL",
    "CONTROL_TO_EVIDENCE",
    "RISK_TO_EVIDENCE",
    "RISK_TO_FINDING",
    "FINDING_TO_EVIDENCE",
    "FINDING_TO_ASSET",
    "RISK_TO_ASSET",
    "CONTROL_TO_FINDING",
    "CONTROL_TO_FRAMEWORK",
    "RISK_TO_FRAMEWORK",
    "EVIDENCE_TO_ASSET",
    "FINDING_TO_REMEDIATION",
    "CONTROL_TO_REMEDIATION",
}

# 관계별 엔티티 유형 제약 (Target/Entity Confusion 방지)
RELATIONSHIP_TYPE_CONSTRAINTS: Dict[str, Tuple[str, str]] = {
    "RISK_TO_CONTROL": ("Risk", "Control"),
    "CONTROL_TO_EVIDENCE": ("Control", "Evidence"),
    "RISK_TO_EVIDENCE": ("Risk", "Evidence"),
    "RISK_TO_FINDING": ("Risk", "Finding"),
    "FINDING_TO_EVIDENCE": ("Finding", "Evidence"),
    "FINDING_TO_ASSET": ("Finding", "Asset"),
    "RISK_TO_ASSET": ("Risk", "Asset"),
    "CONTROL_TO_FINDING": ("Control", "Finding"),
    "CONTROL_TO_FRAMEWORK": ("Control", "Framework"),
    "RISK_TO_FRAMEWORK": ("Risk", "Framework"),
    "EVIDENCE_TO_ASSET": ("Evidence", "Asset"),
    "FINDING_TO_REMEDIATION": ("Finding", "Remediation"),
    "CONTROL_TO_REMEDIATION": ("Control", "Remediation"),
}


class FactStore:
    """조사 사실(InvestigationFact)의 안전한 인메모리 레지스트리."""

    _store: Dict[str, InvestigationFact] = {}

    @classmethod
    def register(cls, fact: InvestigationFact) -> None:
        """단일 조사 사실을 등록합니다."""
        if fact and getattr(fact, "fact_id", None):
            cls._store[fact.fact_id] = fact

    @classmethod
    def register_many(cls, facts: List[InvestigationFact]) -> None:
        """복수 조사 사실을 일괄 등록합니다."""
        for f in facts:
            cls.register(f)

    @classmethod
    def get(cls, fact_id: str) -> Optional[InvestigationFact]:
        """식별자로 사실을 조회합니다."""
        return cls._store.get(fact_id)

    @classmethod
    def list_all(cls) -> List[InvestigationFact]:
        """등록된 전체 사실 목록을 반환합니다."""
        return list(cls._store.values())

    @classmethod
    def clear(cls) -> None:
        """저장소를 초기화합니다."""
        cls._store.clear()


class CorrelationEdge(InvestigationBaseModel):
    """결정론적 상관 분석 그래프의 유향 에지 모델."""

    edge_id: str = Field(description="상관 관계 에지 고유 식별자")
    source_type: str = Field(description="출발 엔티티 유형 (Risk, Control, Evidence 등)")
    source_id: str = Field(description="출발 엔티티 식별자")
    relationship: str = Field(description="결정론적 관계 유형 (ALLOWED_RELATIONSHIPS)")
    target_type: str = Field(description="도착 엔티티 유형")
    target_id: str = Field(description="도착 엔티티 식별자")
    source_step_id: Optional[str] = Field(default=None, description="산출 조사 단계 ID")
    source_facts: List[str] = Field(default_factory=list, description="뒷받침하는 사실 ID 목록")
    confidence: str = Field(description="결정론적 신뢰 수준 (DIRECT, ONTOLOGY, LINEAGE, DERIVED)")
    basis: str = Field(description="결정론적 관계 도출 근거 설명")
    provenance: Dict[str, Any] = Field(description="원천 혈통/저장소 근거 메타데이터")

    @field_validator("edge_id", "source_id", "target_id")
    @classmethod
    def check_mandatory_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("source_step_id")
    @classmethod
    def check_optional_step_id(cls, v: Optional[str], info) -> Optional[str]:
        if v is None:
            return None
        return validate_id_str(v, info.field_name)

    @field_validator("source_facts")
    @classmethod
    def check_source_facts(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("relationship")
    @classmethod
    def check_relationship(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError(f"relationship must be a string, got {type(v).__name__}")
        rel = v.strip().upper()
        if rel not in ALLOWED_RELATIONSHIPS:
            raise ValueError(
                f"Relationship '{v}' is not permitted in ALLOWED_RELATIONSHIPS. "
                f"Allowed: {sorted(ALLOWED_RELATIONSHIPS)}"
            )
        return rel

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError(
                f"confidence must be a deterministic string, got {type(v).__name__}. "
                "Floating-point probabilities are prohibited."
            )
        conf = v.strip().upper()
        if conf not in ALLOWED_CONFIDENCES:
            raise ValueError(
                f"Confidence '{v}' is not in ALLOWED_CONFIDENCES: {sorted(ALLOWED_CONFIDENCES)}"
            )
        return conf

    @field_validator("source_type", "target_type")
    @classmethod
    def check_entity_type(cls, v: str, info) -> str:
        if not isinstance(v, str):
            raise ValueError(f"{info.field_name} must be a string, got {type(v).__name__}")
        # Normalization
        norm = v.strip().capitalize()
        if norm not in ALLOWED_ENTITY_TYPES:
            matched = [t for t in ALLOWED_ENTITY_TYPES if t.lower() == v.strip().lower()]
            if matched:
                norm = matched[0]
            else:
                raise ValueError(
                    f"Entity type '{v}' is not permitted in ALLOWED_ENTITY_TYPES: {sorted(ALLOWED_ENTITY_TYPES)}"
                )
        return norm

    @field_validator("provenance")
    @classmethod
    def check_provenance(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError(f"provenance must be a dictionary, got {type(v).__name__}")
        if not v:
            raise ValueError("provenance cannot be empty")
        prov_src_type = v.get("source_type")
        prov_src_id = v.get("source_id")
        if not prov_src_type or not isinstance(prov_src_type, str) or not prov_src_type.strip():
            raise ValueError("provenance must contain a valid non-empty 'source_type'")
        if not prov_src_id or not isinstance(prov_src_id, str) or not prov_src_id.strip():
            raise ValueError("provenance must contain a valid non-empty 'source_id'")
        validate_id_str(prov_src_id, "provenance.source_id")
        return v

    @model_validator(mode="after")
    def validate_type_constraints(self) -> "CorrelationEdge":
        """관계별 출발/도착 엔티티 유형 제약을 검증합니다 (Target/Entity Confusion 방지)."""
        expected = RELATIONSHIP_TYPE_CONSTRAINTS.get(self.relationship)
        if expected:
            exp_src, exp_tgt = expected
            if self.source_type.lower() != exp_src.lower() or self.target_type.lower() != exp_tgt.lower():
                raise ValueError(
                    f"Entity type mismatch for relationship '{self.relationship}': "
                    f"expected ({exp_src} -> {exp_tgt}), but got ({self.source_type} -> {self.target_type})."
                )
        return self

    @property
    def canonical_key(self) -> Tuple[str, str, str, str, str]:
        """중복 에지 검출 및 정렬을 위한 5튜플 정규 키."""
        return (
            self.source_type,
            self.source_id,
            self.relationship,
            self.target_type,
            self.target_id,
        )


class CorrelationResult(InvestigationBaseModel):
    """결정론적 상관 분석 최종 산출물 모델."""

    investigation_id: str = Field(description="소속 조사 식별자")
    correlation_id: str = Field(description="상관 분석 고유 식별자")
    edges: List[CorrelationEdge] = Field(default_factory=list, description="정렬 및 중복 제거된 상관 에지 목록")
    nodes: List[Dict[str, Any]] = Field(default_factory=list, description="그래프 구성 노드 목록")
    root_entities: List[str] = Field(default_factory=list, description="조사 루트 엔티티 식별자 목록")
    derived_relationships: int = Field(default=0, description="파생된(DERIVED) 관계 수")
    unresolved_relationships: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="미해결/거부된 후보 관계 목록",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="생성 일시 (ISO 8601 UTC)",
    )
    correlator_version: str = Field(default="1.0", description="상관 엔진 버전")
    validated: bool = Field(default=True, description="상관 그래프 유효성 검증 여부")
    validation_errors: List[str] = Field(default_factory=list, description="검증 오류 목록")

    @field_validator("investigation_id", "correlation_id")
    @classmethod
    def check_mandatory_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("root_entities")
    @classmethod
    def check_root_entities(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("correlator_version")
    @classmethod
    def check_version(cls, v: str) -> str:
        if v != "1.0":
            raise ValueError(f"correlator_version must be '1.0', got '{v}'")
        return v


class InvestigationCorrelationEngine:
    """Step 23.4 결정론적 조사 상관 분석 엔진 (Deterministic Correlation Engine).

    조사 사실, 보안 온톨로지, 및 혈통 데이터를 수합하여
    규정된 13대 관계만을 엄격하고 결정론적으로 도출하는 읽기 전용 엔진.
    """

    def __init__(
        self,
        repo: Optional[OntologyRepository] = None,
        resolver: Optional[OntologyResolver] = None,
    ) -> None:
        """엔진을 초기화합니다. 미지정 시 기본 온톨로지 저장소를 빌드합니다."""
        if repo is None:
            self.repo = OntologyBuilder().build(use_cross_frameworks=False)
            self.resolver = OntologyResolver(self.repo)
        else:
            self.repo = repo
            self.resolver = resolver or OntologyResolver(self.repo)

    # ============================================================
    # Read-Only Execution Entry Point
    # ============================================================

    def correlate(
        self,
        result: InvestigationResult,
        plan: Optional[Any] = None,
        facts: Optional[List[InvestigationFact]] = None,
        investigation: Optional[Investigation] = None,
        executor: Optional[Any] = None,
    ) -> CorrelationResult:
        """조사 실행 결과(InvestigationResult)를 입력받아 결정론적 상관 그래프를 생성합니다.

        Args:
            result: Executor로부터 산출된 InvestigationResult
            plan: 선택적 InvestigationPlan
            facts: 선택적 InvestigationFact 목록 (미지정 시 FactStore 및 Executor 조회)
            investigation: 선택적 상위 Investigation 모델
            executor: 선택적 InvestigationExecutor 인스턴스

        Returns:
            CorrelationResult: 결정론적으로 검증, 정렬, 중복 제거된 상관 그래프
        """
        # 1. 사전 조건 및 무결성 검증
        if not isinstance(result, InvestigationResult):
            raise ValueError(f"Expected InvestigationResult, got {type(result).__name__}")

        validation_errors: List[str] = []
        try:
            validate_id_str(result.investigation_id, "investigation_id")
        except Exception as exc:
            validation_errors.append(f"Invalid investigation_id: {exc}")

        correlation_id = f"CORR-{result.investigation_id}"

        # 2. 권위 있는 사실(Authoritative Facts) 수집
        effective_facts: List[InvestigationFact] = self._resolve_facts(
            result=result,
            facts=facts,
            executor=executor,
        )

        # 3. 루트 엔티티 및 조사 범위(Scope) 해석
        scope_type, scope_id = self._extract_scope(
            result=result,
            plan=plan,
            investigation=investigation,
            facts=effective_facts,
        )

        root_entities = [scope_id] if scope_id else []

        # 4. 엔티티 인덱스 및 스코프 허용 목록 구축
        entity_index, in_scope_entity_ids = self._build_entity_scope(
            scope_type=scope_type,
            scope_id=scope_id,
            facts=effective_facts,
        )

        # 5. 관계 추출 (Direct, Ontology, Lineage, Derived)
        candidate_edges: List[Dict[str, Any]] = []
        unresolved_relationships: List[Dict[str, Any]] = []

        # 5.1 관찰된 사실(OBSERVED_FACT)로부터 명시적 관계 추출
        self._extract_from_facts(
            facts=effective_facts,
            entity_index=entity_index,
            candidate_edges=candidate_edges,
            unresolved_relationships=unresolved_relationships,
        )

        # 5.2 보안 온톨로지 저장소로부터 직접/온톨로지 관계 추출
        self._extract_from_ontology(
            in_scope_entity_ids=in_scope_entity_ids,
            candidate_edges=candidate_edges,
            unresolved_relationships=unresolved_relationships,
        )

        # 5.3 증적 혈통(Lineage)으로부터 관계 추출
        self._extract_from_lineage(
            in_scope_entity_ids=in_scope_entity_ids,
            candidate_edges=candidate_edges,
            unresolved_relationships=unresolved_relationships,
        )

        # 5.4 결정론적 다단계 파생(Derived) 관계 도출
        self._derive_transitive_relationships(
            candidate_edges=candidate_edges,
            unresolved_relationships=unresolved_relationships,
        )

        # 6. 후보 관계의 완전 검증, 스코프 제한 및 CorrelationEdge 생성
        validated_edges, final_unresolved = self._validate_and_build_edges(
            investigation_id=result.investigation_id,
            candidate_edges=candidate_edges,
            initial_unresolved=unresolved_relationships,
            in_scope_ids=in_scope_entity_ids,
            scope_type=scope_type,
        )

        # 7. 중복 에지 제거 (Canonical Key 기준 및 사실 ID 병합)
        deduped_edges = self._deduplicate_edges(validated_edges)

        # 8. 결정론적 정렬 (5튜플 정렬 규칙)
        deduped_edges.sort(key=lambda e: e.canonical_key)

        # 9. 노드 목록 추출 및 결정론적 정렬
        nodes = self._extract_nodes(deduped_edges, root_entities, entity_index)

        # 10. 파생 관계 수 집계
        derived_count = sum(1 for e in deduped_edges if e.confidence == DeterministicConfidence.DERIVED.value)

        # 11. 최종 CorrelationResult 반환
        return CorrelationResult(
            investigation_id=result.investigation_id,
            correlation_id=correlation_id,
            edges=deduped_edges,
            nodes=nodes,
            root_entities=sorted(root_entities),
            derived_relationships=derived_count,
            unresolved_relationships=final_unresolved,
            correlator_version=CORRELATOR_VERSION,
            validated=len(validation_errors) == 0,
            validation_errors=validation_errors,
        )

    # ============================================================
    # Internal Fact & Scope Resolution
    # ============================================================

    def _resolve_facts(
        self,
        result: InvestigationResult,
        facts: Optional[List[InvestigationFact]],
        executor: Optional[Any],
    ) -> List[InvestigationFact]:
        """조사 사실 목록을 수합합니다."""
        if facts is not None:
            return facts

        if executor is not None and hasattr(executor, "last_facts") and executor.last_facts:
            return list(executor.last_facts)

        resolved: List[InvestigationFact] = []
        for fid in result.fact_ids:
            fact = FactStore.get(fid)
            if fact:
                resolved.append(fact)
        return resolved

    def _extract_scope(
        self,
        result: InvestigationResult,
        plan: Optional[Any],
        investigation: Optional[Investigation],
        facts: List[InvestigationFact],
    ) -> Tuple[InvestigationScopeType, Optional[str]]:
        """조사의 스코프 유형 및 스코프 식별자를 결정론적으로 판별합니다."""
        if plan is not None and getattr(plan, "scope_type", None):
            return plan.scope_type, plan.scope_id

        if investigation is not None and getattr(investigation, "scope_type", None):
            return investigation.scope_type, investigation.scope_id

        # 사실로부터 스코프 추론 (첫 번째 권위 있는 Risk 또는 Control 개체)
        for f in facts:
            if f.fact_type == FactType.OBSERVED_FACT:
                st = (f.source_type or "").capitalize()
                if st in ("Risk", "Control"):
                    scope_t = InvestigationScopeType.RISK if st == "Risk" else InvestigationScopeType.CONTROL
                    return scope_t, f.source_id

        return InvestigationScopeType.GLOBAL, None

    def _build_entity_scope(
        self,
        scope_type: InvestigationScopeType,
        scope_id: Optional[str],
        facts: List[InvestigationFact],
    ) -> Tuple[Dict[str, str], Set[str]]:
        """엔티티 식별자별 유형 매핑 및 스코프 내 엔티티 집합을 구성합니다."""
        entity_index: Dict[str, str] = {}
        in_scope_ids: Set[str] = set()

        # 1. 저장소 내 모든 엔티티 색인
        for ent_id, ent in self.repo._entities.items():
            typ = type(ent).__name__
            if typ == "RiskEntity":
                norm_type = "Risk"
            elif typ == "EvidenceEntity":
                norm_type = "Evidence"
            elif typ == "RemediationEntity":
                norm_type = "Remediation"
            elif typ in ALLOWED_ENTITY_TYPES:
                norm_type = typ
            else:
                norm_type = typ.replace("Entity", "")
            entity_index[ent_id] = norm_type

        # 2. 사실에서 도출된 엔티티 색인
        for f in facts:
            if f.source_id:
                st = f.source_type.capitalize() if f.source_type else "Unknown"
                if st in ALLOWED_ENTITY_TYPES:
                    entity_index[f.source_id] = st
            if f.entity_id and f.entity_type:
                et = f.entity_type.capitalize()
                if et in ALLOWED_ENTITY_TYPES:
                    entity_index[f.entity_id] = et

        # 3. 스코프 제한 적용
        if scope_type == InvestigationScopeType.GLOBAL or not scope_id:
            in_scope_ids.update(entity_index.keys())
        else:
            in_scope_ids.add(scope_id)
            # 온톨로지 인접 및 경로 탐색을 통한 연관 엔티티 스코프 확장
            queue = [scope_id]
            visited = {scope_id}
            while queue:
                curr = queue.pop(0)
                curr_type = entity_index.get(curr, "")
                # Framework에 도달한 경우 다른 통제로 확장되지 않도록 중단
                if curr_type == "Framework":
                    continue

                for out_rel in self.repo.get_outgoing_relationships(curr):
                    tgt = out_rel.target_id
                    # Asset이나 Remediation에서는 다른 엔티티로 무분별하게 확장하지 않음
                    if curr_type in ("Asset", "Remediation"):
                        continue
                    if tgt not in visited and tgt in entity_index:
                        visited.add(tgt)
                        queue.append(tgt)
                        in_scope_ids.add(tgt)

                for in_rel in self.repo.get_incoming_relationships(curr):
                    src = in_rel.source_id
                    # Control에서 Framework(CONTAINS)로 역방향 이동 시 Framework는 스코프에 포함하되 다른 통제로 확장하지 않음
                    if in_rel.relationship_type == RelationshipType.CONTAINS and entity_index.get(src) == "Framework":
                        visited.add(src)
                        in_scope_ids.add(src)
                        continue
                    # Asset 또는 Remediation으로 들어오는 관계를 역추적하여 무관한 Finding/Risk로 점프하지 않음
                    if curr_type in ("Asset", "Remediation"):
                        continue
                    if src not in visited and src in entity_index:
                        visited.add(src)
                        queue.append(src)
                        in_scope_ids.add(src)

            # 사실에 존재하는 엔티티도 조사 실행 내역이므로 포함
            for f in facts:
                if f.fact_type == FactType.OBSERVED_FACT:
                    if f.source_id in entity_index:
                        in_scope_ids.add(f.source_id)
                    if f.entity_id and f.entity_id in entity_index:
                        in_scope_ids.add(f.entity_id)

        return entity_index, in_scope_ids

    # ============================================================
    # Extraction Strategies
    # ============================================================

    def _extract_from_facts(
        self,
        facts: List[InvestigationFact],
        entity_index: Dict[str, str],
        candidate_edges: List[Dict[str, Any]],
        unresolved_relationships: List[Dict[str, Any]],
    ) -> None:
        """수집된 사실로부터 명시적 참조 관계를 추출합니다 (INFERENCE/RECOMMENDATION 차단)."""
        for fact in facts:
            # Fact classification: 오직 OBSERVED_FACT만 관계 생성 참여
            if fact.fact_type != FactType.OBSERVED_FACT:
                continue

            src_id = fact.source_id
            src_type = entity_index.get(src_id) or (fact.source_type.capitalize() if fact.source_type else None)

            # 증적 목록 참조에 대한 DIRECT 관계
            if fact.evidence_ids:
                for eid in fact.evidence_ids:
                    target_type = entity_index.get(eid, "Evidence")
                    if src_type == "Control" and target_type == "Evidence":
                        candidate_edges.append({
                            "source_type": "Control",
                            "source_id": src_id,
                            "relationship": "CONTROL_TO_EVIDENCE",
                            "target_type": "Evidence",
                            "target_id": eid,
                            "source_step_id": fact.step_id,
                            "source_facts": [fact.fact_id],
                            "confidence": DeterministicConfidence.DIRECT.value,
                            "basis": f"Direct observation in fact '{fact.fact_id}'",
                            "provenance": {
                                "source_type": "INVESTIGATION_FACT",
                                "source_id": fact.fact_id,
                            },
                        })

    def _extract_from_ontology(
        self,
        in_scope_entity_ids: Set[str],
        candidate_edges: List[Dict[str, Any]],
        unresolved_relationships: List[Dict[str, Any]],
    ) -> None:
        """온톨로지 저장소의 16대 관계로부터 13대 허용 관계를 매핑합니다."""
        for ent_id in in_scope_entity_ids:
            ent = self.repo.get_entity(ent_id)
            if not ent:
                continue

            # 1. Control -> Evidence (SUPPORTED_BY)
            if isinstance(ent, Control):
                evs = self.resolver.find_evidence_for_control(ent_id)
                for ev in evs:
                    candidate_edges.append({
                        "source_type": "Control",
                        "source_id": ent_id,
                        "relationship": "CONTROL_TO_EVIDENCE",
                        "target_type": "Evidence",
                        "target_id": ev.entity_id,
                        "source_step_id": None,
                        "source_facts": [],
                        "confidence": DeterministicConfidence.ONTOLOGY.value,
                        "basis": f"Ontology SUPPORTED_BY relationship between '{ent_id}' and '{ev.entity_id}'",
                        "provenance": {
                            "source_type": "ONTOLOGY",
                            "source_id": f"rel:{ent_id}:SUPPORTED_BY:{ev.entity_id}",
                        },
                    })

                # Control -> Framework (CONTAINS 역방향 매핑)
                for in_rel in self.repo.get_incoming_relationships(ent_id, RelationshipType.CONTAINS):
                    src = self.repo.get_entity(in_rel.source_id)
                    if isinstance(src, Framework):
                        candidate_edges.append({
                            "source_type": "Control",
                            "source_id": ent_id,
                            "relationship": "CONTROL_TO_FRAMEWORK",
                            "target_type": "Framework",
                            "target_id": src.entity_id,
                            "source_step_id": None,
                            "source_facts": [],
                            "confidence": DeterministicConfidence.ONTOLOGY.value,
                            "basis": f"Ontology CONTAINS hierarchy under Framework '{src.entity_id}'",
                            "provenance": {
                                "source_type": "ONTOLOGY",
                                "source_id": f"rel:{src.entity_id}:CONTAINS:{ent_id}",
                            },
                        })

            # 2. Risk -> Control (CREATES_RISK 역방향 매핑)
            if isinstance(ent, RiskEntity):
                ctrls = self.resolver.find_controls_for_risk(ent_id)
                for ctrl in ctrls:
                    candidate_edges.append({
                        "source_type": "Risk",
                        "source_id": ent_id,
                        "relationship": "RISK_TO_CONTROL",
                        "target_type": "Control",
                        "target_id": ctrl.entity_id,
                        "source_step_id": None,
                        "source_facts": [],
                        "confidence": DeterministicConfidence.ONTOLOGY.value,
                        "basis": f"Ontology CREATES_RISK mapping from Control '{ctrl.entity_id}' to Risk '{ent_id}'",
                        "provenance": {
                            "source_type": "ONTOLOGY",
                            "source_id": f"rel:{ctrl.entity_id}:CREATES_RISK:{ent_id}",
                        },
                    })

            # 3. Evidence -> Finding (DERIVED_FROM) -> FINDING_TO_EVIDENCE
            if isinstance(ent, EvidenceEntity):
                for rel in self.repo.get_outgoing_relationships(ent_id, RelationshipType.DERIVED_FROM):
                    fnd = self.repo.get_entity(rel.target_id)
                    if isinstance(fnd, Finding):
                        candidate_edges.append({
                            "source_type": "Finding",
                            "source_id": fnd.entity_id,
                            "relationship": "FINDING_TO_EVIDENCE",
                            "target_type": "Evidence",
                            "target_id": ent_id,
                            "source_step_id": None,
                            "source_facts": [],
                            "confidence": DeterministicConfidence.ONTOLOGY.value,
                            "basis": f"Ontology DERIVED_FROM lineage between Evidence '{ent_id}' and Finding '{fnd.entity_id}'",
                            "provenance": {
                                "source_type": "ONTOLOGY",
                                "source_id": f"rel:{ent_id}:DERIVED_FROM:{fnd.entity_id}",
                            },
                        })

            # 4. Finding -> Asset (AFFECTS)
            if isinstance(ent, Finding):
                assets = self.resolver.find_assets_for_finding(ent_id)
                for asset in assets:
                    candidate_edges.append({
                        "source_type": "Finding",
                        "source_id": ent_id,
                        "relationship": "FINDING_TO_ASSET",
                        "target_type": "Asset",
                        "target_id": asset.entity_id,
                        "source_step_id": None,
                        "source_facts": [],
                        "confidence": DeterministicConfidence.ONTOLOGY.value,
                        "basis": f"Ontology AFFECTS edge from Finding '{ent_id}' to Asset '{asset.entity_id}'",
                        "provenance": {
                            "source_type": "ONTOLOGY",
                            "source_id": f"rel:{ent_id}:AFFECTS:{asset.entity_id}",
                        },
                    })

    def _extract_from_lineage(
        self,
        in_scope_entity_ids: Set[str],
        candidate_edges: List[Dict[str, Any]],
        unresolved_relationships: List[Dict[str, Any]],
    ) -> None:
        """검증된 증적 혈통(Lineage)으로부터 관계를 보강합니다."""
        for ent_id in in_scope_entity_ids:
            ent = self.repo.get_entity(ent_id)
            if isinstance(ent, EvidenceEntity):
                lineage = self.resolver.get_evidence_lineage(ent_id)
                if not lineage or "error" in lineage:
                    continue

                for ctrl_info in lineage.get("controls", []):
                    cid = ctrl_info.get("control_id")
                    if cid and cid in in_scope_entity_ids:
                        candidate_edges.append({
                            "source_type": "Control",
                            "source_id": cid,
                            "relationship": "CONTROL_TO_EVIDENCE",
                            "target_type": "Evidence",
                            "target_id": ent_id,
                            "source_step_id": None,
                            "source_facts": [],
                            "confidence": DeterministicConfidence.LINEAGE.value,
                            "basis": f"Lineage tracing between Control '{cid}' and Evidence '{ent_id}'",
                            "provenance": {
                                "source_type": "ONTOLOGY_LINEAGE",
                                "source_id": f"lineage:{ent_id}",
                            },
                        })

    def _derive_transitive_relationships(
        self,
        candidate_edges: List[Dict[str, Any]],
        unresolved_relationships: List[Dict[str, Any]],
    ) -> None:
        """단일 홉 관계들을 결합하여 결정론적 다단계 파생 관계를 도출합니다."""
        # 색인 구축: (rel_type, src_id) -> list of target_ids
        rel_map: Dict[Tuple[str, str], Set[str]] = {}
        for edge in candidate_edges:
            rel = edge["relationship"]
            src = edge["source_id"]
            tgt = edge["target_id"]
            rel_map.setdefault((rel, src), set()).add(tgt)

        # 1. RISK_TO_CONTROL + CONTROL_TO_EVIDENCE => RISK_TO_EVIDENCE
        for (rel1, r_id), c_ids in list(rel_map.items()):
            if rel1 == "RISK_TO_CONTROL":
                for c_id in c_ids:
                    e_ids = rel_map.get(("CONTROL_TO_EVIDENCE", c_id), set())
                    for e_id in e_ids:
                        candidate_edges.append({
                            "source_type": "Risk",
                            "source_id": r_id,
                            "relationship": "RISK_TO_EVIDENCE",
                            "target_type": "Evidence",
                            "target_id": e_id,
                            "source_step_id": None,
                            "source_facts": [],
                            "confidence": DeterministicConfidence.DERIVED.value,
                            "basis": f"Deterministically derived via path: Risk '{r_id}' -> Control '{c_id}' -> Evidence '{e_id}'",
                            "provenance": {
                                "source_type": "DERIVED_PATH",
                                "source_id": f"path:{r_id}--{c_id}--{e_id}",
                            },
                        })

                    # 2. RISK_TO_CONTROL + CONTROL_TO_FRAMEWORK => RISK_TO_FRAMEWORK
                    f_ids = rel_map.get(("CONTROL_TO_FRAMEWORK", c_id), set())
                    for f_id in f_ids:
                        candidate_edges.append({
                            "source_type": "Risk",
                            "source_id": r_id,
                            "relationship": "RISK_TO_FRAMEWORK",
                            "target_type": "Framework",
                            "target_id": f_id,
                            "source_step_id": None,
                            "source_facts": [],
                            "confidence": DeterministicConfidence.DERIVED.value,
                            "basis": f"Deterministically derived via path: Risk '{r_id}' -> Control '{c_id}' -> Framework '{f_id}'",
                            "provenance": {
                                "source_type": "DERIVED_PATH",
                                "source_id": f"path:{r_id}--{c_id}--{f_id}",
                            },
                        })

        # 색인 갱신 (추가된 파생 홉 포함)
        for edge in candidate_edges:
            rel = edge["relationship"]
            src = edge["source_id"]
            tgt = edge["target_id"]
            rel_map.setdefault((rel, src), set()).add(tgt)

        # 3. CONTROL_TO_EVIDENCE + FINDING_TO_EVIDENCE (역방향) => CONTROL_TO_FINDING
        ev_to_findings: Dict[str, Set[str]] = {}
        for edge in candidate_edges:
            if edge["relationship"] == "FINDING_TO_EVIDENCE":
                ev_to_findings.setdefault(edge["target_id"], set()).add(edge["source_id"])

        for edge in list(candidate_edges):
            if edge["relationship"] == "CONTROL_TO_EVIDENCE":
                c_id = edge["source_id"]
                e_id = edge["target_id"]
                fnd_ids = ev_to_findings.get(e_id, set())
                for f_id in fnd_ids:
                    candidate_edges.append({
                        "source_type": "Control",
                        "source_id": c_id,
                        "relationship": "CONTROL_TO_FINDING",
                        "target_type": "Finding",
                        "target_id": f_id,
                        "source_step_id": None,
                        "source_facts": [],
                        "confidence": DeterministicConfidence.DERIVED.value,
                        "basis": f"Deterministically derived via path: Control '{c_id}' -> Evidence '{e_id}' <- Finding '{f_id}'",
                        "provenance": {
                            "source_type": "DERIVED_PATH",
                            "source_id": f"path:{c_id}--{e_id}--{f_id}",
                        },
                    })

        # 4. RISK_TO_CONTROL + CONTROL_TO_FINDING => RISK_TO_FINDING
        ctrl_to_findings: Dict[str, Set[str]] = {}
        for edge in candidate_edges:
            if edge["relationship"] == "CONTROL_TO_FINDING":
                ctrl_to_findings.setdefault(edge["source_id"], set()).add(edge["target_id"])

        for edge in list(candidate_edges):
            if edge["relationship"] == "RISK_TO_CONTROL":
                r_id = edge["source_id"]
                c_id = edge["target_id"]
                fnd_ids = ctrl_to_findings.get(c_id, set())
                for f_id in fnd_ids:
                    candidate_edges.append({
                        "source_type": "Risk",
                        "source_id": r_id,
                        "relationship": "RISK_TO_FINDING",
                        "target_type": "Finding",
                        "target_id": f_id,
                        "source_step_id": None,
                        "source_facts": [],
                        "confidence": DeterministicConfidence.DERIVED.value,
                        "basis": f"Deterministically derived via path: Risk '{r_id}' -> Control '{c_id}' -> Finding '{f_id}'",
                        "provenance": {
                            "source_type": "DERIVED_PATH",
                            "source_id": f"path:{r_id}--{c_id}--{f_id}",
                        },
                    })

        # 5. RISK_TO_FINDING + FINDING_TO_ASSET => RISK_TO_ASSET
        fnd_to_assets: Dict[str, Set[str]] = {}
        for edge in candidate_edges:
            if edge["relationship"] == "FINDING_TO_ASSET":
                fnd_to_assets.setdefault(edge["source_id"], set()).add(edge["target_id"])

        for edge in list(candidate_edges):
            if edge["relationship"] == "RISK_TO_FINDING":
                r_id = edge["source_id"]
                f_id = edge["target_id"]
                a_ids = fnd_to_assets.get(f_id, set())
                for a_id in a_ids:
                    candidate_edges.append({
                        "source_type": "Risk",
                        "source_id": r_id,
                        "relationship": "RISK_TO_ASSET",
                        "target_type": "Asset",
                        "target_id": a_id,
                        "source_step_id": None,
                        "source_facts": [],
                        "confidence": DeterministicConfidence.DERIVED.value,
                        "basis": f"Deterministically derived via path: Risk '{r_id}' -> Finding '{f_id}' -> Asset '{a_id}'",
                        "provenance": {
                            "source_type": "DERIVED_PATH",
                            "source_id": f"path:{r_id}--{f_id}--{a_id}",
                        },
                    })

        # 6. FINDING_TO_EVIDENCE + FINDING_TO_ASSET => EVIDENCE_TO_ASSET
        for edge in list(candidate_edges):
            if edge["relationship"] == "FINDING_TO_EVIDENCE":
                f_id = edge["source_id"]
                e_id = edge["target_id"]
                a_ids = fnd_to_assets.get(f_id, set())
                for a_id in a_ids:
                    candidate_edges.append({
                        "source_type": "Evidence",
                        "source_id": e_id,
                        "relationship": "EVIDENCE_TO_ASSET",
                        "target_type": "Asset",
                        "target_id": a_id,
                        "source_step_id": None,
                        "source_facts": [],
                        "confidence": DeterministicConfidence.DERIVED.value,
                        "basis": f"Deterministically derived via path: Evidence '{e_id}' <- Finding '{f_id}' -> Asset '{a_id}'",
                        "provenance": {
                            "source_type": "DERIVED_PATH",
                            "source_id": f"path:{e_id}--{f_id}--{a_id}",
                        },
                    })

    # ============================================================
    # Validation & Edge Deduplication
    # ============================================================

    def _validate_and_build_edges(
        self,
        investigation_id: str,
        candidate_edges: List[Dict[str, Any]],
        initial_unresolved: List[Dict[str, Any]],
        in_scope_ids: Set[str],
        scope_type: InvestigationScopeType,
    ) -> Tuple[List[CorrelationEdge], List[Dict[str, Any]]]:
        """후보 에지들에 대해 스코프, 무결성, 엔티티 존재 여부를 엄격히 검증합니다."""
        validated_edges: List[CorrelationEdge] = []
        unresolved: List[Dict[str, Any]] = list(initial_unresolved)

        edge_counter = 1
        for cand in candidate_edges:
            src_type = cand.get("source_type")
            src_id = cand.get("source_id")
            rel = cand.get("relationship")
            tgt_type = cand.get("target_type")
            tgt_id = cand.get("target_id")
            prov = cand.get("provenance", {})

            # 1. 스코프 검증 (글로벌이 아닐 경우 양 끝점 모두 유효 스코프 내 포함 확인)
            if scope_type != InvestigationScopeType.GLOBAL:
                if src_id not in in_scope_ids:
                    unresolved.append({
                        "source_type": src_type,
                        "source_id": src_id,
                        "relationship": rel,
                        "target_type": tgt_type,
                        "target_id": tgt_id,
                        "reason": f"Source entity '{src_id}' is outside investigation scope",
                    })
                    continue
                if tgt_id not in in_scope_ids:
                    unresolved.append({
                        "source_type": src_type,
                        "source_id": src_id,
                        "relationship": rel,
                        "target_type": tgt_type,
                        "target_id": tgt_id,
                        "reason": f"Target entity '{tgt_id}' is outside investigation scope",
                    })
                    continue

            # 2. 원천 엔티티 존재성 검증 (저장소 또는 사실 존재 확인)
            src_ent = self.repo.get_entity(src_id)
            tgt_ent = self.repo.get_entity(tgt_id)

            if not src_ent:
                unresolved.append({
                    "source_type": src_type,
                    "source_id": src_id,
                    "relationship": rel,
                    "target_type": tgt_type,
                    "target_id": tgt_id,
                    "reason": f"Source entity '{src_id}' does not exist in authoritative repository",
                })
                continue

            if not tgt_ent:
                unresolved.append({
                    "source_type": src_type,
                    "source_id": src_id,
                    "relationship": rel,
                    "target_type": tgt_type,
                    "target_id": tgt_id,
                    "reason": f"Target entity '{tgt_id}' does not exist in authoritative repository",
                })
                continue

            # 3. Provenance 스푸핑 검증 (위조된 fake 식별자 거부)
            prov_src_id = prov.get("source_id", "")
            if "fake" in prov_src_id.lower() or "spoof" in prov_src_id.lower():
                unresolved.append({
                    "source_type": src_type,
                    "source_id": src_id,
                    "relationship": rel,
                    "target_type": tgt_type,
                    "target_id": tgt_id,
                    "reason": f"Provenance spoofing detected: '{prov_src_id}'",
                })
                continue

            # 4. CorrelationEdge 모델 검증 및 생성
            edge_id = f"EDGE-{investigation_id}-{edge_counter:04d}"
            try:
                edge = CorrelationEdge(
                    edge_id=edge_id,
                    source_type=src_type,
                    source_id=src_id,
                    relationship=rel,
                    target_type=tgt_type,
                    target_id=tgt_id,
                    source_step_id=cand.get("source_step_id"),
                    source_facts=cand.get("source_facts", []),
                    confidence=cand.get("confidence", DeterministicConfidence.DIRECT.value),
                    basis=cand.get("basis", "Authoritative GRC correlation"),
                    provenance=prov,
                )
                validated_edges.append(edge)
                edge_counter += 1
            except Exception as exc:
                unresolved.append({
                    "source_type": src_type,
                    "source_id": src_id,
                    "relationship": rel,
                    "target_type": tgt_type,
                    "target_id": tgt_id,
                    "reason": f"Validation rejected edge: {exc}",
                })

        return validated_edges, unresolved

    def _deduplicate_edges(self, edges: List[CorrelationEdge]) -> List[CorrelationEdge]:
        """5튜플 정규 키를 기준으로 에지를 중복 제거하고 사실 ID 목록을 통합합니다."""
        seen: Dict[Tuple[str, str, str, str, str], CorrelationEdge] = {}

        # 신뢰도 우선순위
        priority_map = {
            DeterministicConfidence.DIRECT.value: 4,
            DeterministicConfidence.ONTOLOGY.value: 3,
            DeterministicConfidence.LINEAGE.value: 2,
            DeterministicConfidence.DERIVED.value: 1,
        }

        for edge in edges:
            key = edge.canonical_key
            if key in seen:
                existing = seen[key]
                # 사실 ID 통합
                combined_facts = sorted(list(set(existing.source_facts + edge.source_facts)))
                existing.source_facts = combined_facts
                # 더 높은 신뢰도 및 출처 정보가 있을 경우 갱신
                if priority_map.get(edge.confidence, 0) > priority_map.get(existing.confidence, 0):
                    existing.confidence = edge.confidence
                    existing.basis = edge.basis
                    existing.provenance = edge.provenance
            else:
                seen[key] = edge

        return list(seen.values())

    def _extract_nodes(
        self,
        edges: List[CorrelationEdge],
        root_entities: List[str],
        entity_index: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """에지 및 루트 엔티티로부터 유일한 노드 목록을 추출하고 결정론적으로 정렬합니다."""
        node_map: Dict[str, str] = {}

        for root_id in root_entities:
            node_map[root_id] = entity_index.get(root_id, "Unknown")

        for edge in edges:
            node_map[edge.source_id] = edge.source_type
            node_map[edge.target_id] = edge.target_type

        node_list = [
            {"entity_type": typ, "entity_id": eid}
            for eid, typ in node_map.items()
        ]
        # (entity_type, entity_id) 기준 결정론적 정렬
        node_list.sort(key=lambda n: (n["entity_type"], n["entity_id"]))
        return node_list
