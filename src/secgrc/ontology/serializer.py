"""온톨로지 지식 그래프 직렬화(Serialization / Deserialization) 모듈입니다."""

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from secgrc.ontology.confidence import MappingConfidence, MappingType
from secgrc.ontology.entities import (
    AgentEntity,
    Asset,
    BaseEntity,
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
from secgrc.ontology.models import AutomationLevel, ControlEffectiveness, RelationshipType
from secgrc.ontology.relationships import Relationship
from secgrc.ontology.repository import OntologyRepository

# 개체 타입 매핑 테이블
ENTITY_CLASS_MAP = {
    "Framework": Framework,
    "Control": Control,
    "Requirement": Requirement,
    "Evidence": EvidenceEntity,
    "Finding": Finding,
    "Asset": Asset,
    "Risk": RiskEntity,
    "Remediation": RemediationEntity,
    "Agent": AgentEntity,
    "Tool": ToolEntity,
    "Policy": PolicyEntity,
}


def _mask_secrets(text: str) -> str:
    """민감 문자열 마스킹"""
    patterns = ["CANARY_SECRET", "AIzaSy", "ghp_"]
    for p in patterns:
        if p in text:
            text = text.replace(p, "[MASKED_SECRET]")
    return text


def to_dict(repo: OntologyRepository) -> Dict[str, Any]:
    """저장소를 직렬화 가능한 딕셔너리로 변환합니다."""
    entities = [e.model_dump() for e in repo.list_entities()]
    relationships = [r.model_dump() for r in repo.list_relationships()]

    return {
        "version": "1.0",
        "summary": repo.get_summary(),
        "entities": entities,
        "relationships": relationships,
    }


def to_json(repo: OntologyRepository, indent: int = 2) -> str:
    """저장소를 안전하게 마스킹된 JSON 문자열로 직렬화합니다."""
    data = to_dict(repo)
    raw_json = json.dumps(data, indent=indent, ensure_ascii=False)
    return _mask_secrets(raw_json)


def from_dict(data: Dict[str, Any]) -> OntologyRepository:
    """딕셔너리로부터 온톨로지 저장소를 복원합니다."""
    repo = OntologyRepository()

    for item in data.get("entities", []):
        etype = item.get("entity_type", "BaseEntity")
        cls = ENTITY_CLASS_MAP.get(etype, BaseEntity)
        entity = cls(**item)
        repo.add_entity(entity)

    for rel_item in data.get("relationships", []):
        rel = Relationship(**rel_item)
        repo.add_relationship(rel)

    return repo


def from_json(json_str: str) -> OntologyRepository:
    """JSON 문자열로부터 온톨로지 저장소를 복원합니다."""
    data = json.loads(json_str)
    return from_dict(data)


def save_to_file(repo: OntologyRepository, filepath: Union[str, Path]) -> None:
    """저장소를 JSON 파일로 저장합니다."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_json(repo))


def load_from_file(filepath: Union[str, Path]) -> OntologyRepository:
    """JSON 파일로부터 온톨로지 저장소를 로드합니다."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Ontology file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return from_json(f.read())
