"""온톨로지 관계(Relationship) 정의 모듈입니다."""

from typing import Any, Dict
from pydantic import BaseModel, Field

from secgrc.ontology.confidence import MappingConfidence, MappingType
from secgrc.ontology.models import RelationshipType


class Relationship(BaseModel):
    """온톨로지 그래프 상의 단방향 간선(Edge) 정의 모델"""
    relationship_id: str = Field(description="고유 관계 식별자")
    source_type: str = Field(description="출발 노드 개체 유형")
    source_id: str = Field(description="출발 노드 개체 ID")
    relationship_type: RelationshipType = Field(description="관계 유형")
    target_type: str = Field(description="도착 노드 개체 유형")
    target_id: str = Field(description="도착 노드 개체 ID")
    confidence: MappingConfidence = Field(
        default_factory=lambda: MappingConfidence(
            score=1.0,
            mapping_type=MappingType.EXPLICIT,
            source="deterministic"
        ),
        description="관계 매핑 신뢰도 메타데이터"
    )
    source: str = Field(default="deterministic", description="관계 생성 출처")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="추가 메타데이터")
