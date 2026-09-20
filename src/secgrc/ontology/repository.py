"""온톨로지 인메모리 지식 그래프 저장소(Repository) 모듈입니다."""

from collections import deque
from typing import Any, Dict, List, Optional, Set

from secgrc.ontology.entities import BaseEntity
from secgrc.ontology.models import RelationshipType
from secgrc.ontology.relationships import Relationship

# 민감 키워드/카나리 시크릿 패턴 검출용
FORBIDDEN_SECRET_PATTERNS = ["CANARY_SECRET", "AIzaSy", "xoxb-", "ghp_"]


class OntologyRepository:
    """보안 온톨로지 인메모리 그래프 저장소"""

    def __init__(self) -> None:
        self._entities: Dict[str, BaseEntity] = {}
        self._entities_by_type: Dict[str, Set[str]] = {}

        self._relationships: Dict[str, Relationship] = {}
        self._outgoing: Dict[str, List[str]] = {}  # source_id -> [rel_id, ...]
        self._incoming: Dict[str, List[str]] = {}  # target_id -> [rel_id, ...]

    def add_entity(self, entity: BaseEntity) -> None:
        """개체를 저장소에 추가합니다. 중복 ID 검사 및 시크릿 검증 수행."""
        self._validate_secret_safety(entity.name)
        if entity.description:
            self._validate_secret_safety(entity.description)

        self._entities[entity.entity_id] = entity
        if entity.entity_type not in self._entities_by_type:
            self._entities_by_type[entity.entity_type] = set()
        self._entities_by_type[entity.entity_type].add(entity.entity_id)

    def get_entity(self, entity_id: str) -> Optional[BaseEntity]:
        """식별자로 개체를 조회합니다."""
        return self._entities.get(entity_id)

    def list_entities(self, entity_type: Optional[str] = None) -> List[BaseEntity]:
        """전체 개체 또는 특정 유형의 개체 목록을 반환합니다."""
        if entity_type is None:
            return list(self._entities.values())
        entity_ids = self._entities_by_type.get(entity_type, set())
        return [self._entities[eid] for eid in entity_ids if eid in self._entities]

    def add_relationship(self, rel: Relationship) -> None:
        """관계를 저장소에 추가하고 인덱싱합니다."""
        self._relationships[rel.relationship_id] = rel

        if rel.source_id not in self._outgoing:
            self._outgoing[rel.source_id] = []
        self._outgoing[rel.source_id].append(rel.relationship_id)

        if rel.target_id not in self._incoming:
            self._incoming[rel.target_id] = []
        self._incoming[rel.target_id].append(rel.relationship_id)

    def get_relationship(self, rel_id: str) -> Optional[Relationship]:
        """식별자로 관계를 조회합니다."""
        return self._relationships.get(rel_id)

    def list_relationships(
        self, relationship_type: Optional[RelationshipType] = None
    ) -> List[Relationship]:
        """전체 관계 또는 특정 유형의 관계 목록을 반환합니다."""
        if relationship_type is None:
            return list(self._relationships.values())
        return [
            r for r in self._relationships.values()
            if r.relationship_type == relationship_type
        ]

    def get_outgoing_relationships(
        self, source_id: str, rel_type: Optional[RelationshipType] = None
    ) -> List[Relationship]:
        """특정 노드로부터 출발하는 관계 목록을 조회합니다."""
        rel_ids = self._outgoing.get(source_id, [])
        rels = [self._relationships[rid] for rid in rel_ids if rid in self._relationships]
        if rel_type is not None:
            rels = [r for r in rels if r.relationship_type == rel_type]
        return rels

    def get_incoming_relationships(
        self, target_id: str, rel_type: Optional[RelationshipType] = None
    ) -> List[Relationship]:
        """특정 노드로 들어오는 관계 목록을 조회합니다."""
        rel_ids = self._incoming.get(target_id, [])
        rels = [self._relationships[rid] for rid in rel_ids if rid in self._relationships]
        if rel_type is not None:
            rels = [r for r in rels if r.relationship_type == rel_type]
        return rels

    def get_neighbors(
        self, entity_id: str, direction: str = "both"
    ) -> List[BaseEntity]:
        """인접 개체 목록을 반환합니다 (direction: 'out', 'in', 'both')."""
        neighbor_ids: Set[str] = set()
        if direction in ("out", "both"):
            for rel in self.get_outgoing_relationships(entity_id):
                neighbor_ids.add(rel.target_id)
        if direction in ("in", "both"):
            for rel in self.get_incoming_relationships(entity_id):
                neighbor_ids.add(rel.source_id)

        return [self._entities[nid] for nid in neighbor_ids if nid in self._entities]

    def find_paths(
        self, source_id: str, target_id: str, max_depth: int = 5
    ) -> List[List[str]]:
        """BFS 기반으로 두 개체 사이의 모든 경로(ID 목록)를 탐색합니다."""
        if source_id not in self._entities or target_id not in self._entities:
            return []
        if source_id == target_id:
            return [[source_id]]

        results: List[List[str]] = []
        queue: deque = deque([([source_id], {source_id})])

        while queue:
            current_path, visited = queue.popleft()
            if len(current_path) > max_depth:
                continue

            current_node = current_path[-1]
            if current_node == target_id:
                results.append(current_path)
                continue

            for rel in self.get_outgoing_relationships(current_node):
                nxt = rel.target_id
                if nxt not in visited:
                    queue.append((current_path + [nxt], visited | {nxt}))

        return results

    def get_summary(self) -> Dict[str, Any]:
        """온톨로지 그래프 요약 통계를 반환합니다."""
        entities_by_type = {
            etype: len(eids) for etype, eids in self._entities_by_type.items()
        }
        relationships_by_type: Dict[str, int] = {}
        for rel in self._relationships.values():
            rtype = rel.relationship_type.value
            relationships_by_type[rtype] = relationships_by_type.get(rtype, 0) + 1

        return {
            "total_entities": len(self._entities),
            "total_relationships": len(self._relationships),
            "entities_by_type": entities_by_type,
            "relationships_by_type": relationships_by_type,
        }

    def clear(self) -> None:
        """저장소의 모든 데이터를 초기화합니다."""
        self._entities.clear()
        self._entities_by_type.clear()
        self._relationships.clear()
        self._outgoing.clear()
        self._incoming.clear()

    def _validate_secret_safety(self, text: str) -> None:
        """시크릿 및 카나리 정보 유출 방지 검증"""
        for pattern in FORBIDDEN_SECRET_PATTERNS:
            if pattern in text:
                raise ValueError(
                    f"Ontology security guardrail violation: text contains forbidden pattern '{pattern}'"
                )
