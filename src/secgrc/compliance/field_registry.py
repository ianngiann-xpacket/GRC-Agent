"""Canonical Field Registry (Step 23.5C).

This module defines the explicit allow-list of canonical data attributes that
assessment rules may inspect, strictly preventing arbitrary object traversal or attribute access.
"""

from typing import Dict, FrozenSet, Optional, Set
from pydantic import Field

from secgrc.compliance.models import (
    CanonicalDataType,
    ComplianceBaseModel,
    validate_identifier,
)


class CanonicalFieldRegistry(ComplianceBaseModel):
    """표준 정규 데이터 유형별 접근 허용 필드 레지스트리 (화이트리스트)."""

    # 정규 데이터 유형별 허용 필드 매핑
    _allowed_fields: Dict[str, FrozenSet[str]] = {
        CanonicalDataType.IAM_POLICY.value: frozenset({
            "effect", "action", "resource", "principal", "condition",
            "policy_name", "policy_id", "is_admin",
        }),
        CanonicalDataType.MFA_CONFIGURATION.value: frozenset({
            "enabled", "enforced", "method", "user_id", "admin_only",
            "mfa_type", "grace_period_days",
        }),
        CanonicalDataType.AUTHENTICATION_CONFIGURATION.value: frozenset({
            "password_length", "mfa_enabled", "lockout_threshold",
            "session_timeout", "complexity_required", "max_age_days",
        }),
        CanonicalDataType.PAM_RECORD.value: frozenset({
            "user_id", "session_id", "second_factor_verified", "session_recorded",
            "approval_id", "access_duration_minutes",
        }),
        CanonicalDataType.FIREWALL_RULE.value: frozenset({
            "source", "destination", "service", "action", "port",
            "protocol", "rule_id", "rule_name", "direction",
        }),
        CanonicalDataType.FIREWALL_POLICY.value: frozenset({
            "policy_id", "rules", "default_action", "inspection_enabled",
        }),
        CanonicalDataType.PORT_OBSERVATION.value: frozenset({
            "port", "protocol", "state", "service", "banner", "host",
        }),
        CanonicalDataType.SECURITY_EVENT.value: frozenset({
            "event_type", "severity", "principal", "source", "destination",
            "action", "outcome", "timestamp",
        }),
        CanonicalDataType.ALERT.value: frozenset({
            "alert_id", "severity", "status", "rule_name", "source",
            "title", "description", "category",
        }),
        CanonicalDataType.VULNERABILITY_FINDING.value: frozenset({
            "vulnerability_id", "severity", "asset_id", "status", "cvss",
            "cve", "remediation", "patch_available",
        }),
        CanonicalDataType.SECURITY_CONFIGURATION.value: frozenset({
            "cmek_enabled", "kms_key_id", "encryption_algorithm", "status",
            "resource_id", "tls_version", "enforce_ssl", "public_access_blocked",
        }),
        CanonicalDataType.SECURITY_PLAN.value: frozenset({
            "plan_id", "title", "approved_by", "approved_at", "status",
            "budget_approved", "year",
        }),
        CanonicalDataType.POLICY.value: frozenset({
            "policy_id", "title", "version", "status", "review_cycle",
            "approved_by", "effective_date",
        }),
        CanonicalDataType.CONSENT.value: frozenset({
            "consent_id", "user_id", "purposes", "status", "obtained_at",
            "third_party_consent", "sensitive_consent",
        }),
        CanonicalDataType.PROCESSING_ACTIVITY.value: frozenset({
            "activity_id", "purpose", "data_categories", "recipients",
            "retention_period", "dpo_reviewed", "status",
        }),
        CanonicalDataType.DPA.value: frozenset({
            "dpa_id", "processor", "controller", "status", "clauses",
            "security_measures_annexed", "effective_date",
        }),
        CanonicalDataType.DPIA.value: frozenset({
            "dpia_id", "risk_level", "mitigations_approved", "status",
            "dpo_opinion", "high_risk_identified",
        }),
        CanonicalDataType.PRIVACY_INCIDENT.value: frozenset({
            "incident_id", "severity", "notification_time_hours",
            "authority_notified", "data_subjects_notified", "remedial_measures",
        }),
    }

    def is_field_allowed(self, data_type: str, field_name: str) -> bool:
        """데이터 유형에 대해 해당 필드가 허용 목록에 존재하는지 엄격히 검증합니다."""
        if not data_type or not field_name:
            return False
        allowed = self._allowed_fields.get(data_type)
        if not allowed:
            return False
        return field_name in allowed

    def get_allowed_fields(self, data_type: str) -> FrozenSet[str]:
        """특정 데이터 유형에 허용된 필드 목록을 반환합니다."""
        return self._allowed_fields.get(data_type, frozenset())

    def __init__(self, **data) -> None:
        super().__init__(**data)
        self._allowed_fields = {k: v for k, v in self._allowed_fields.items()}

    def register_field(self, data_type: str, field_name: str) -> None:
        """새로운 허용 필드를 레지스트리에 등록합니다 (화이트리스트 확장)."""
        clean_dt = validate_identifier(data_type, "data_type")
        clean_field = validate_identifier(field_name, "field_name")
        current = set(self._allowed_fields.get(clean_dt, frozenset()))
        current.add(clean_field)
        self._allowed_fields[clean_dt] = frozenset(current)

    def register_fields(self, data_type: str, fields: Any) -> None:
        """복수 허용 필드를 레지스트리에 일괄 등록합니다."""
        for f in fields:
            self.register_field(data_type, f)


# 기본 전역 싱글톤 필드 레지스트리
default_field_registry = CanonicalFieldRegistry()
