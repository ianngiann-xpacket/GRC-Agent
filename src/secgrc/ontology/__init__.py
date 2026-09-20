"""보안 온톨로지 및 지식 그래프(Security Knowledge Graph / Control Ontology) 패키지"""

from secgrc.ontology.builder import OntologyBuilder
from secgrc.ontology.confidence import (
    CONFIDENCE_SCORES,
    MappingConfidence,
    MappingType,
)
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
from secgrc.ontology.mapper import CrossFrameworkMapper
from secgrc.ontology.models import (
    AutomationLevel,
    ControlEffectiveness,
    FrameworkCoverage,
    RelationshipType,
)
from secgrc.ontology.relationships import Relationship
from secgrc.ontology.repository import OntologyRepository
from secgrc.ontology.resolver import OntologyResolver
from secgrc.ontology.serializer import (
    from_dict,
    from_json,
    load_from_file,
    save_to_file,
    to_dict,
    to_json,
)

__all__ = [
    # Confidence
    "MappingType",
    "MappingConfidence",
    "CONFIDENCE_SCORES",
    # Models
    "ControlEffectiveness",
    "AutomationLevel",
    "RelationshipType",
    "FrameworkCoverage",
    # Entities
    "BaseEntity",
    "Framework",
    "Control",
    "Requirement",
    "EvidenceEntity",
    "Finding",
    "Asset",
    "RiskEntity",
    "RemediationEntity",
    "AgentEntity",
    "ToolEntity",
    "PolicyEntity",
    # Relationships
    "Relationship",
    # Repository
    "OntologyRepository",
    # Mapper
    "CrossFrameworkMapper",
    # Builder
    "OntologyBuilder",
    # Resolver
    "OntologyResolver",
    # Serializer
    "to_dict",
    "to_json",
    "from_dict",
    "from_json",
    "save_to_file",
    "load_from_file",
]
