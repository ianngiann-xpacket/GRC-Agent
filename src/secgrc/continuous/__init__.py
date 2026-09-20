"""Continuous GRC / Continuous Compliance 패키지입니다.

Step 25: Continuous Compliance & Change Impact Engine.
"""

from secgrc.continuous.alert import AlertManager
from secgrc.continuous.delta import ComplianceDeltaEngine
from secgrc.continuous.detector import ChangeDetector, compute_change_hash
from secgrc.continuous.evaluator import TargetedEvaluator
from secgrc.continuous.events import (
    EventDeduplicator,
    EventSource,
    MockEventSource,
)
from secgrc.continuous.impact import ComplianceImpactAnalyzer, ImpactAnalyzer
from secgrc.continuous.impact_rules import create_impact_rule
from secgrc.continuous.ledger import ChangeLedger, default_change_ledger
from secgrc.continuous.models import (
    ChangeBatch,
    ChangeClassification,
    ChangeEvent,
    ChangeType,
    ComplianceDelta,
    ComplianceHealthSnapshot,
    ComplianceTimeline,
    ComplianceTimelineEntry,
    ContinuousAlert,
    ContinuousComplianceState,
    ContinuousStatus,
    ControlImpactMapping,
    ControlSnapshot,
    FieldChange,
    ImpactAnalysis,
    ImpactLevel,
    ImpactRule,
    ImpactType,
    InvestigationTriggerCandidate,
    NormalizedChangeEvent,
    RiskChangeType,
    StateSnapshot,
    TrendDirection,
)
from secgrc.continuous.normalizer import EventNormalizer
from secgrc.continuous.query import (
    clear_delta_store,
    get_affected_requirements,
    get_change,
    get_changes,
    get_compliance_deltas,
    get_entity_changes,
    get_impacts,
    get_reassessment_history,
    get_recent_compliance_changes,
    get_requirement_timeline,
    record_delta_for_query,
)
from secgrc.continuous.reassessment import IncrementalAssessmentEngine, compute_reassessment_id
from secgrc.continuous.registry import ImpactRuleRegistry, default_impact_rule_registry
from secgrc.continuous.replay import replay_changes
from secgrc.continuous.risk_monitor import ContinuousRiskMonitor
from secgrc.continuous.scheduler import ContinuousScheduler
from secgrc.continuous.state import (
    ContinuousComplianceStateManager,
    ContinuousState,
    default_state_manager,
)
from secgrc.continuous.timeline import ComplianceTimelineManager, default_timeline_manager
from secgrc.continuous.workflow import build_continuous_graph

__all__ = [
    # Step 25 Models
    "ChangeEvent",
    "FieldChange",
    "ChangeType",
    "ImpactLevel",
    "ImpactType",
    "ImpactRule",
    "ImpactAnalysis",
    "ComplianceDelta",
    "ComplianceTimeline",
    "ComplianceTimelineEntry",
    "InvestigationTriggerCandidate",
    "StateSnapshot",
    "ContinuousComplianceState",
    "ChangeBatch",
    # Step 25 Components
    "ChangeDetector",
    "compute_change_hash",
    "ChangeLedger",
    "default_change_ledger",
    "create_impact_rule",
    "ImpactRuleRegistry",
    "default_impact_rule_registry",
    "ComplianceImpactAnalyzer",
    "IncrementalAssessmentEngine",
    "compute_reassessment_id",
    "ComplianceDeltaEngine",
    "ComplianceTimelineManager",
    "default_timeline_manager",
    "ContinuousComplianceStateManager",
    "default_state_manager",
    "replay_changes",
    # Step 25 Queries
    "get_changes",
    "get_change",
    "get_entity_changes",
    "get_impacts",
    "get_affected_requirements",
    "get_compliance_deltas",
    "get_requirement_timeline",
    "get_recent_compliance_changes",
    "get_reassessment_history",
    "record_delta_for_query",
    "clear_delta_store",
    # Backward Compatibility
    "ChangeClassification",
    "RiskChangeType",
    "ContinuousStatus",
    "TrendDirection",
    "NormalizedChangeEvent",
    "ControlImpactMapping",
    "ControlSnapshot",
    "ContinuousAlert",
    "ComplianceHealthSnapshot",
    "EventSource",
    "MockEventSource",
    "EventDeduplicator",
    "EventNormalizer",
    "ImpactAnalyzer",
    "TargetedEvaluator",
    "ContinuousRiskMonitor",
    "AlertManager",
    "ContinuousScheduler",
    "ContinuousState",
    "build_continuous_graph",
]
