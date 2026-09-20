"""Deterministic Impact Rules Definition & Metadata (Step 25).

Defines explicit, immutable mappings between Canonical Data Types / fields
and compliance framework requirements. Prohibits dynamic/unregistered rules.
"""

from typing import List, Optional
from secgrc.continuous.models import ImpactLevel, ImpactRule, ImpactType


def create_impact_rule(
    rule_id: str,
    source_data_type: str,
    target_framework: str,
    target_requirement: str,
    changed_field: Optional[str] = None,
    impact_type: ImpactType = ImpactType.DIRECT_REQUIREMENT,
    priority: str = "P1",
    source_reference: str = "RULE",
    impact_level: ImpactLevel = ImpactLevel.HIGH,
    rule_version: str = "1.0",
) -> ImpactRule:
    """엄격한 유효성 검증을 거쳐 불변 ImpactRule 인스턴스를 생성합니다."""
    return ImpactRule(
        rule_id=rule_id,
        rule_version=rule_version,
        source_data_type=source_data_type,
        changed_field=changed_field,
        target_framework=target_framework,
        target_requirement=target_requirement,
        impact_type=impact_type,
        priority=priority,
        source_reference=source_reference,
        impact_level=impact_level,
    )
