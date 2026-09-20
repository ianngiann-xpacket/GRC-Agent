"""Enterprise Compliance Input Universe & Canonical Security Data Models (Step 23.5A)."""

from secgrc.compliance.adapters import (
    BaseSecurityDataAdapter,
    FirewallPolicyDataAdapter,
    IAMPolicyDataAdapter,
    NessusDataAdapter,
    NmapDataAdapter,
    PolicyDocumentDataAdapter,
    ProwlerDataAdapter,
    SIEMEventDataAdapter,
    SecurityDataAdapter,
    WindowsEventDataAdapter,
)
from secgrc.compliance.coverage import (
    InputCoverage,
    InputCoverageEvaluator,
    default_coverage_evaluator,
    get_framework_input_coverage,
    get_input_requirements,
    get_missing_inputs,
    get_requirement_input_coverage,
    get_supported_data_types,
    get_supported_sources,
)
from secgrc.compliance.frameworks import (
    Framework,
    FrameworkRegistry,
    FrameworkVersion,
    default_framework_registry,
)
from secgrc.compliance.input_requirements import (
    ComplianceInputRequirement,
    InputRequirementRegistry,
    default_input_requirement_registry,
)
from secgrc.compliance.models import (
    AutomationLevel,
    CanonicalDataType,
    CanonicalSecurityData,
    ClassificationLevel,
    EnterpriseDomain,
    EntityReference,
    EvidenceState,
    FrameworkStatus,
    InputCoverageState,
    ProvenanceRecord,
)
from secgrc.compliance.registry import (
    SchemaRegistry,
    default_schema_registry,
)
from secgrc.compliance.requirements import (
    Requirement,
    RequirementRegistry,
    default_requirement_registry,
)
from secgrc.compliance.schemas import (
    AdapterSchema,
    FIREWALL_SCHEMA,
    IAM_SCHEMA,
    NESSUS_SCHEMA,
    NMAP_SCHEMA,
    POLICY_DOCUMENT_SCHEMA,
    PROWLER_SCHEMA,
    SIEM_SCHEMA,
    WINDOWS_EVENT_SCHEMA,
)

from secgrc.compliance.applicability import (
    ApplicabilityProfile,
    EvidenceCondition,
    EvidenceConditionType,
    EvidenceScope,
    EvidenceScopeType,
)
from secgrc.compliance.evidence_graph import (
    EvidenceConflict,
    EvidenceReference,
    EvidenceReferenceGraph,
    get_cross_framework_evidence_reuse,
    get_evidence_requirement_graph,
    get_evidence_source_bindings,
    get_requirement_data_requirements,
    get_requirement_evidence_requirements,
)
from secgrc.compliance.evidence_requirements import (
    ComplianceDataRequirement,
    ComplianceEvidenceRequirement,
    EvidenceRequirementRegistry,
    EvidenceRole,
    EvidenceSufficiencyProfile,
    RequirementAssessmentPrerequisite,
    default_evidence_requirement_registry,
)
from secgrc.compliance.evidence_sets import (
    EvidenceSet,
    EvidenceSetOperator,
)
from secgrc.compliance.freshness import (
    EvidenceFreshness,
    EvidenceFreshnessType,
)
from secgrc.compliance.source_bindings import (
    EvidenceSourceBinding,
)
from secgrc.compliance.temporal import (
    TemporalCoverage,
    TemporalCoverageType,
)
from secgrc.compliance.assessment_rules import (
    AssessmentStatus,
    ComplianceAssessmentRule,
    RuleType,
)
from secgrc.compliance.assessment_conditions import (
    ConditionOperator,
    RuleCondition,
)
from secgrc.compliance.field_registry import (
    CanonicalFieldRegistry,
    default_field_registry,
)
from secgrc.compliance.assessment_registry import (
    AssessmentRuleRegistry,
    default_rule_registry,
)
from secgrc.compliance.assessment_history import (
    AssessmentHistoryStore,
    default_assessment_history,
)
from secgrc.compliance.assessment import (
    ComplianceAssessment,
    ComplianceAssessmentBatch,
    ComplianceAssessmentEngine,
    default_assessment_engine,
    assess_requirement,
    assess_requirements,
    get_assessment,
    get_assessment_history,
    get_assessment_rule,
    validate_assessment_rule,
)

__all__ = [
    # Models
    "EnterpriseDomain",
    "CanonicalDataType",
    "ClassificationLevel",
    "AutomationLevel",
    "InputCoverageState",
    "EvidenceState",
    "FrameworkStatus",
    "ProvenanceRecord",
    "EntityReference",
    "CanonicalSecurityData",
    # Frameworks
    "Framework",
    "FrameworkVersion",
    "FrameworkRegistry",
    "default_framework_registry",
    # Requirements
    "Requirement",
    "RequirementRegistry",
    "default_requirement_registry",
    # Input Requirements
    "ComplianceInputRequirement",
    "InputRequirementRegistry",
    "default_input_requirement_registry",
    # Coverage
    "InputCoverage",
    "InputCoverageEvaluator",
    "default_coverage_evaluator",
    "get_framework_input_coverage",
    "get_requirement_input_coverage",
    "get_missing_inputs",
    "get_supported_data_types",
    "get_supported_sources",
    "get_input_requirements",
    # Schemas & Registry
    "AdapterSchema",
    "SchemaRegistry",
    "default_schema_registry",
    "PROWLER_SCHEMA",
    "NMAP_SCHEMA",
    "NESSUS_SCHEMA",
    "IAM_SCHEMA",
    "FIREWALL_SCHEMA",
    "SIEM_SCHEMA",
    "WINDOWS_EVENT_SCHEMA",
    "POLICY_DOCUMENT_SCHEMA",
    # Adapters
    "SecurityDataAdapter",
    "BaseSecurityDataAdapter",
    "ProwlerDataAdapter",
    "NmapDataAdapter",
    "NessusDataAdapter",
    "IAMPolicyDataAdapter",
    "FirewallPolicyDataAdapter",
    "SIEMEventDataAdapter",
    "WindowsEventDataAdapter",
    "PolicyDocumentDataAdapter",
    # Step 23.5B: Evidence Requirements & Assessment Inputs
    "EvidenceRole",
    "EvidenceSufficiencyProfile",
    "ComplianceDataRequirement",
    "ComplianceEvidenceRequirement",
    "RequirementAssessmentPrerequisite",
    "EvidenceRequirementRegistry",
    "default_evidence_requirement_registry",
    "EvidenceSet",
    "EvidenceSetOperator",
    "EvidenceFreshness",
    "EvidenceFreshnessType",
    "TemporalCoverage",
    "TemporalCoverageType",
    "EvidenceCondition",
    "EvidenceConditionType",
    "EvidenceScope",
    "EvidenceScopeType",
    "ApplicabilityProfile",
    "EvidenceSourceBinding",
    "EvidenceReference",
    "EvidenceConflict",
    "EvidenceReferenceGraph",
    "get_requirement_evidence_requirements",
    "get_requirement_data_requirements",
    "get_evidence_source_bindings",
    "get_evidence_requirement_graph",
    "get_cross_framework_evidence_reuse",
    # Step 23.5C: Deterministic Compliance Assessment Engine
    "AssessmentStatus",
    "RuleType",
    "ComplianceAssessmentRule",
    "ConditionOperator",
    "RuleCondition",
    "CanonicalFieldRegistry",
    "default_field_registry",
    "AssessmentRuleRegistry",
    "default_rule_registry",
    "AssessmentHistoryStore",
    "default_assessment_history",
    "ComplianceAssessment",
    "ComplianceAssessmentBatch",
    "ComplianceAssessmentEngine",
    "default_assessment_engine",
    "assess_requirement",
    "assess_requirements",
    "get_assessment",
    "get_assessment_history",
    "get_assessment_rule",
    "validate_assessment_rule",
    # Step 23.6: Compliance & Investigation Reporting Layer
    "ReportType",
    "ReportSortKey",
    "ReportFilter",
    "ReportMetric",
    "ReportFinding",
    "ReportEvidence",
    "ReportGap",
    "ReportRisk",
    "ReportConflict",
    "ReportManualReview",
    "ReportProvenance",
    "ReportSection",
    "ReportAssessmentSummary",
    "ReportEvidenceSummary",
    "ComplianceReport",
    "redact_secrets",
    "escape_report_text",
    "escape_markdown",
    "ReportHistoryStore",
    "default_report_history",
    "ComplianceReportBuilder",
    "compute_report_hash",
    "generate_compliance_report",
    "generate_investigation_report",
    "get_report",
    "list_reports",
    "export_report_json",
    "export_report_markdown",
]

from secgrc.compliance.reporting_models import (
    ComplianceReport,
    ReportAssessmentSummary,
    ReportConflict,
    ReportEvidence,
    ReportEvidenceSummary,
    ReportFilter,
    ReportFinding,
    ReportGap,
    ReportManualReview,
    ReportMetric,
    ReportProvenance,
    ReportRisk,
    ReportSection,
    ReportSortKey,
    ReportType,
)
from secgrc.compliance.reporting_security import (
    escape_markdown,
    escape_report_text,
    redact_secrets,
)
from secgrc.compliance.reporting_history import (
    ReportHistoryStore,
    default_report_history,
)
from secgrc.compliance.reporting_builder import (
    ComplianceReportBuilder,
    compute_report_hash,
)
from secgrc.compliance.reporting import (
    export_report_json,
    export_report_markdown,
    generate_compliance_report,
    generate_investigation_report,
    get_report,
    list_reports,
)

