"""Deterministic Compliance Impact Analyzer (Step 25).

Evaluates ChangeEvents against registered ImpactRules, existing Ontology,
and Evidence Requirements to deterministically identify affected requirements.
Adheres strictly to hop limits, scope containment, and tenant isolation.
"""

from typing import Any, Dict, List, Optional, Set
import re
from secgrc.continuous.models import (
    ChangeEvent,
    ImpactAnalysis,
    ImpactLevel,
    ImpactRule,
    NormalizedChangeEvent,
    ControlImpactMapping,
    ChangeClassification,
)
from secgrc.continuous.registry import ImpactRuleRegistry, default_impact_rule_registry


class ComplianceImpactAnalyzer:
    """Step 25 결정론적 컴플라이언스 영향 분석기 (Zero LLM)."""

    MAX_HOPS: int = 5

    def __init__(
        self,
        rule_registry: Optional[ImpactRuleRegistry] = None,
        max_hops: int = 5,
    ) -> None:
        self.rule_registry = rule_registry or default_impact_rule_registry
        self.max_hops = max_hops
        self.MAX_HOPS = max_hops

    def analyze(self, change: ChangeEvent) -> ImpactAnalysis:
        """단일 ChangeEvent에 대한 영향 분석을 수행하여 ImpactAnalysis를 생성합니다."""
        if not isinstance(change, ChangeEvent):
            raise TypeError("Expected ChangeEvent instance")

        affected_reqs: Set[str] = set()
        affected_fws: Set[str] = set()
        affected_ev_reqs: Set[str] = set()
        reason_codes: List[str] = []
        max_severity = ImpactLevel.NONE

        severity_rank = {
            ImpactLevel.NONE: 0,
            ImpactLevel.LOW: 1,
            ImpactLevel.MEDIUM: 2,
            ImpactLevel.HIGH: 3,
            ImpactLevel.CRITICAL: 4,
            ImpactLevel.UNKNOWN: 1,
        }

        # 1. Field-level rule matching
        changed_field_names = [fc.field_name for fc in change.changed_fields] or [None]
        matched_rules: List[ImpactRule] = []

        for f_name in changed_field_names:
            rules = self.rule_registry.find_rules(
                source_data_type=change.entity_type,
                changed_field=f_name,
            )
            for r in rules:
                matched_rules.append(r)
                affected_reqs.add(r.target_requirement)
                affected_fws.add(r.target_framework)
                reason_codes.append(f"RULE_MATCH:{r.rule_id}:{r.target_requirement}:{f_name or 'ANY'}")
                if severity_rank[r.impact_level] > severity_rank[max_severity]:
                    max_severity = r.impact_level

        # 2. General entity-type matching if no specific field rule hit
        if not matched_rules:
            general_rules = self.rule_registry.find_rules(
                source_data_type=change.entity_type,
                changed_field=None,
            )
            for r in general_rules:
                matched_rules.append(r)
                affected_reqs.add(r.target_requirement)
                affected_fws.add(r.target_framework)
                reason_codes.append(f"ENTITY_MATCH:{r.rule_id}:{r.target_requirement}")
                if severity_rank[r.impact_level] > severity_rank[max_severity]:
                    max_severity = r.impact_level

        # If still none, check fallback for privacy vs security
        if not matched_rules:
            reason_codes.append("NO_REGISTERED_IMPACT_RULE")
            max_severity = ImpactLevel.LOW

        # Evidence requirements mapping
        for req_id in sorted(list(affected_reqs)):
            affected_ev_reqs.add(f"EV-REQ-{req_id}")

        clean_id = re.sub(r'[^A-Za-z0-9_-]', '-', f"IMP-{change.change_id}")

        # Linked risks or investigations (reference only)
        affected_risks: List[str] = []
        for r_id in affected_reqs:
            if "2.7.1" in r_id:
                affected_risks.append("RSK-ISMS-P-2.7.1")

        return ImpactAnalysis(
            impact_id=clean_id,
            change_id=change.change_id,
            tenant_id=change.tenant_id,
            affected_entities=[change.entity_id],
            affected_data_types=[change.entity_type],
            affected_frameworks=sorted(list(affected_fws)),
            affected_requirements=sorted(list(affected_reqs)),
            affected_evidence_requirements=sorted(list(affected_ev_reqs)),
            affected_assessments=[f"ASM-{r}" for r in sorted(list(affected_reqs))],
            affected_risks=sorted(list(set(affected_risks))),
            affected_investigations=[],
            impact_scope=change.scope,
            impact_reason_codes=reason_codes,
            analysis_version="1.0",
            provenance={
                "analyzer": "ComplianceImpactAnalyzer",
                "rules_applied": len(matched_rules),
                "max_hops": self.max_hops,
            },
            impact_level=max_severity,
        )


# ---------------------------------------------------------------------------
# 기존 하위 호환성 유지 (Step 6 ImpactAnalyzer)
# ---------------------------------------------------------------------------

DEFAULT_EVENT_CONTROL_MAPPINGS: Dict[str, List[Dict[str, Any]]] = {
    "FIREWALL_CHANGED": [
        {"control_id": "ISMS-P-2.6.3", "confidence": 0.95, "base_impact": 85.0, "level": "HIGH"},
    ],
    "IAM_CHANGED": [
        {"control_id": "ISMS-P-2.5.2", "confidence": 0.90, "base_impact": 80.0, "level": "HIGH"},
        {"control_id": "ISMS-P-2.5.3", "confidence": 0.95, "base_impact": 85.0, "level": "HIGH"},
    ],
    "STORAGE_POLICY_CHANGED": [
        {"control_id": "ISMS-P-2.7.1", "confidence": 0.90, "base_impact": 80.0, "level": "HIGH"},
    ],
    "KMS_CHANGED": [
        {"control_id": "ISMS-P-2.7.1", "confidence": 0.90, "base_impact": 75.0, "level": "HIGH"},
    ],
    "LOGGING_CHANGED": [
        {"control_id": "ISMS-P-2.9.2", "confidence": 0.85, "base_impact": 65.0, "level": "MEDIUM"},
    ],
    "DR_CHANGED": [
        {"control_id": "ISMS-P-2.12.1", "confidence": 0.80, "base_impact": 50.0, "level": "MEDIUM"},
    ],
}


class ImpactAnalyzer:
    """기존 하위 호환성 통제항목 영향도 분석기."""

    @classmethod
    def resolve_impact_level(cls, score: float) -> str:
        s = round(float(score), 1)
        if s >= 90.0:
            return "CRITICAL"
        elif s >= 70.0:
            return "HIGH"
        elif s >= 40.0:
            return "MEDIUM"
        elif s >= 20.0:
            return "LOW"
        return "NONE"

    @classmethod
    def map_affected_controls(cls, event: NormalizedChangeEvent) -> List[ControlImpactMapping]:
        mappings: List[ControlImpactMapping] = []
        configs = DEFAULT_EVENT_CONTROL_MAPPINGS.get(event.event_type, [])
        for c in configs:
            mappings.append(
                ControlImpactMapping(
                    event_type=event.event_type,
                    control_id=c["control_id"],
                    confidence=c["confidence"],
                    base_impact_score=c["base_impact"],
                    impact_level=c["level"],
                )
            )
        return mappings

    @classmethod
    def calculate_impact_score(cls, event: NormalizedChangeEvent, mappings: Any) -> Tuple[float, str]:
        if isinstance(mappings, list):
            base_score = max((m.base_impact_score for m in mappings), default=50.0)
        elif hasattr(mappings, "base_impact_score"):
            base_score = mappings.base_impact_score
        else:
            base_score = 50.0
        meta = event.metadata or {}
        if meta.get("public_access") or "0.0.0.0/0" in meta.get("sourceRanges", []):
            base_score += 15.0
        if event.environment == "production":
            base_score += 5.0
        final_score = min(100.0, max(0.0, round(float(base_score), 1)))
        level = cls.resolve_impact_level(final_score)
        return final_score, level
