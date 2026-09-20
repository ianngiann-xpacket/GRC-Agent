"""Step 33-D: GCP Asset / Entity Resolution & Evidence Integration Package."""

from secgrc.connectors.resolution.models import (
    EntityResolutionResult,
    EntityResolutionStatus,
    EvidenceEntityLineageRecord,
    GCPResourceIdentity,
    MatchMethod,
    ResolutionConfidenceClass,
    compute_canonical_resource_key,
    compute_lineage_hash,
    compute_resolution_hash,
)
from secgrc.connectors.resolution.normalizer import GCPIdentityNormalizer
from secgrc.connectors.resolution.registry import (
    GCPResourceIdentityRegistry,
    RegistryEntry,
)
from secgrc.connectors.resolution.resolver import DeterministicGCPResolver
from secgrc.connectors.resolution.lineage import EvidenceLineageTracker
from secgrc.connectors.resolution.bridge_integration import (
    EvidenceValidityDimension,
    IntegratedEvidenceResolver,
    IntegratedResolutionOutput,
)

__all__ = [
    "EntityResolutionResult",
    "EntityResolutionStatus",
    "EvidenceEntityLineageRecord",
    "GCPResourceIdentity",
    "MatchMethod",
    "ResolutionConfidenceClass",
    "compute_canonical_resource_key",
    "compute_lineage_hash",
    "compute_resolution_hash",
    "GCPIdentityNormalizer",
    "GCPResourceIdentityRegistry",
    "RegistryEntry",
    "DeterministicGCPResolver",
    "EvidenceLineageTracker",
    "EvidenceValidityDimension",
    "IntegratedEvidenceResolver",
    "IntegratedResolutionOutput",
]
