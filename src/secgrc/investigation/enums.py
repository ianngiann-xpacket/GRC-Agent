"""GRC Investigation enums and classifications module.

Defines the life cycle statuses, investigation types, finding classifications,
evidence roles, and scopes for the GRC Investigation Data Model.
"""

from enum import Enum
from secgrc.copilot.models import FactType, UserRole


class InvestigationStatus(str, Enum):
    """Investigation lifecycle status."""
    CREATED = "CREATED"
    PLANNING = "PLANNING"
    INVESTIGATING = "INVESTIGATING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class InvestigationType(str, Enum):
    """Types of GRC investigations."""
    RISK_ANALYSIS = "RISK_ANALYSIS"
    CONTROL_INVESTIGATION = "CONTROL_INVESTIGATION"
    EVIDENCE_INVESTIGATION = "EVIDENCE_INVESTIGATION"
    INCIDENT_INVESTIGATION = "INCIDENT_INVESTIGATION"
    FINDING_INVESTIGATION = "FINDING_INVESTIGATION"
    ASSET_INVESTIGATION = "ASSET_INVESTIGATION"
    FRAMEWORK_INVESTIGATION = "FRAMEWORK_INVESTIGATION"
    AGENT_SECURITY_INVESTIGATION = "AGENT_SECURITY_INVESTIGATION"
    GENERAL_GRC = "GENERAL_GRC"


class HypothesisStatus(str, Enum):
    """Investigation hypothesis evaluation status."""
    PROPOSED = "PROPOSED"
    TESTING = "TESTING"
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    REJECTED = "REJECTED"
    UNRESOLVED = "UNRESOLVED"


class FindingType(str, Enum):
    """Categorization of investigation findings."""
    ROOT_CAUSE = "ROOT_CAUSE"
    CONTRIBUTING_FACTOR = "CONTRIBUTING_FACTOR"
    CONTROL_GAP = "CONTROL_GAP"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    CONFIGURATION_ISSUE = "CONFIGURATION_ISSUE"
    SECURITY_FINDING = "SECURITY_FINDING"
    COMPLIANCE_FINDING = "COMPLIANCE_FINDING"
    DATA_QUALITY_ISSUE = "DATA_QUALITY_ISSUE"
    UNKNOWN = "UNKNOWN"


class EvidenceRole(str, Enum):
    """Role of evidence within an investigation evidence chain."""
    PRIMARY = "PRIMARY"
    SUPPORTING = "SUPPORTING"
    CONTRADICTING = "CONTRADICTING"
    CONTEXT = "CONTEXT"


class InvestigationStepStatus(str, Enum):
    """Execution status of an individual investigation step."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class InvestigationScopeType(str, Enum):
    """Target scope category of an investigation."""
    RISK = "RISK"
    CONTROL = "CONTROL"
    EVIDENCE = "EVIDENCE"
    FINDING = "FINDING"
    ASSET = "ASSET"
    FRAMEWORK = "FRAMEWORK"
    AGENT = "AGENT"
    GLOBAL = "GLOBAL"


__all__ = [
    "InvestigationStatus",
    "InvestigationType",
    "HypothesisStatus",
    "FindingType",
    "EvidenceRole",
    "InvestigationStepStatus",
    "InvestigationScopeType",
    "FactType",
    "UserRole",
]
