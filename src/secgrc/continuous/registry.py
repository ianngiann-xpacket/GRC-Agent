"""Immutable Impact Rule Registry (Step 25).

Maintains versioned, deterministic impact rules. Prohibits arbitrary runtime mutations.
Historical impacts remain linked to their original rule versions (Section 59).
"""

from copy import deepcopy
from typing import Dict, List, Optional, Tuple

from secgrc.continuous.impact_rules import create_impact_rule
from secgrc.continuous.models import ImpactLevel, ImpactRule, ImpactType


class ImpactRuleRegistry:
    """영향 분석 규칙 레지스트리."""

    def __init__(self) -> None:
        # (rule_id, rule_version) -> ImpactRule
        self._rules_by_version: Dict[Tuple[str, str], ImpactRule] = {}
        # source_data_type (lowercase) -> list of rules
        self._by_data_type: Dict[str, List[ImpactRule]] = {}
        self._load_baseline_rules()

    def _load_baseline_rules(self) -> None:
        """결정론적 베이스라인 영향 규칙 등록 (Section 16-24)."""
        baseline: List[ImpactRule] = [
            # 1. IAM Policy & Access Control (ISMS-P-2.7.1, ISO-27001-A.9.2, GDPR-Art.32)
            create_impact_rule("R-IAM-001", "IAMPolicy", "ISMS-P", "ISMS-P-2.7.1", changed_field="action", impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-IAM-002", "IAMPolicy", "ISMS-P", "ISMS-P-2.7.1", changed_field="effect", impact_level=ImpactLevel.CRITICAL),
            create_impact_rule("R-IAM-003", "IAMPolicy", "ISMS-P", "ISMS-P-2.7.1", changed_field="principal", impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-IAM-004", "IAMPolicy", "ISO-27001", "ISO-27001-A.9.2", changed_field="action", impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-IAM-005", "IAMPolicy", "GDPR", "GDPR-Art.32", changed_field="effect", impact_level=ImpactLevel.HIGH),

            # 2. MFA Configuration (ISMS-P-2.7.1, ISO-27001-A.9.4)
            create_impact_rule("R-MFA-001", "MFAConfiguration", "ISMS-P", "ISMS-P-2.7.1", changed_field="enabled", impact_level=ImpactLevel.CRITICAL),
            create_impact_rule("R-MFA-002", "MFAConfiguration", "ISMS-P", "ISMS-P-2.7.1", changed_field="status", impact_level=ImpactLevel.CRITICAL),
            create_impact_rule("R-MFA-003", "MFAConfiguration", "ISO-27001", "ISO-27001-A.9.4", changed_field="enabled", impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-MFA-004", "MFAConfiguration", "ISMS-P", "ISMS-P-2.7.1", changed_field="mfa_enabled", impact_level=ImpactLevel.CRITICAL),

            # 3. Firewall Rules (ISMS-P-2.8.1, ISO-27001-A.13.1)
            create_impact_rule("R-FW-001", "FirewallRule", "ISMS-P", "ISMS-P-2.8.1", changed_field="destination", impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-FW-002", "FirewallRule", "ISMS-P", "ISMS-P-2.8.1", changed_field="action", impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-FW-003", "FirewallPolicy", "ISMS-P", "ISMS-P-2.8.1", changed_field="destination", impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-FW-004", "FirewallRule", "ISO-27001", "ISO-27001-A.13.1", changed_field="action", impact_level=ImpactLevel.HIGH),

            # 4. Vulnerability Findings (ISMS-P-2.10.1, ISO-27001-A.12.6)
            create_impact_rule("R-VULN-001", "VulnerabilityFinding", "ISMS-P", "ISMS-P-2.10.1", changed_field="status", impact_type=ImpactType.VULNERABILITY_STATE, impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-VULN-002", "VulnerabilityFinding", "ISO-27001", "ISO-27001-A.12.6", changed_field="status", impact_type=ImpactType.VULNERABILITY_STATE, impact_level=ImpactLevel.HIGH),

            # 5. Prowler / CSPM Findings
            create_impact_rule("R-PROWLER-001", "ProwlerFinding", "ISMS-P", "ISMS-P-2.7.1", changed_field="status", impact_type=ImpactType.SECURITY_CONTROL, impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-PROWLER-002", "ProwlerFinding", "ISMS-P", "ISMS-P-2.8.1", changed_field="status", impact_type=ImpactType.SECURITY_CONTROL, impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-PROWLER-003", "ConfigurationFinding", "ISMS-P", "ISMS-P-2.7.1", changed_field="status", impact_type=ImpactType.SECURITY_CONTROL, impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-PROWLER-004", "ConfigurationFinding", "ISMS-P", "ISMS-P-2.8.1", changed_field="status", impact_type=ImpactType.SECURITY_CONTROL, impact_level=ImpactLevel.HIGH),

            # 6. Access Review Records (ISMS-P-2.5.2)
            create_impact_rule("R-AR-001", "AccessReview", "ISMS-P", "ISMS-P-2.5.2", changed_field="status", impact_type=ImpactType.EVIDENCE_AVAILABILITY, impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-AR-002", "AccessReview", "ISMS-P", "ISMS-P-2.5.2", changed_field="completed_at", impact_type=ImpactType.EVIDENCE_FRESHNESS, impact_level=ImpactLevel.MEDIUM),

            # 7. Privacy / Processing Activity (GDPR Only - Section 24, 66)
            create_impact_rule("R-GDPR-001", "ProcessingActivity", "GDPR", "GDPR-Art.30", changed_field="purpose", impact_type=ImpactType.PRIVACY_OBLIGATION, impact_level=ImpactLevel.MEDIUM),
            create_impact_rule("R-GDPR-002", "ProcessingActivity", "GDPR", "GDPR-Art.44", changed_field="international_transfer", impact_type=ImpactType.PRIVACY_OBLIGATION, impact_level=ImpactLevel.HIGH),
            create_impact_rule("R-GDPR-003", "ProcessingActivity", "GDPR", "GDPR-Art.44", changed_field="cross_border", impact_type=ImpactType.PRIVACY_OBLIGATION, impact_level=ImpactLevel.HIGH),

            # 8. Evidence Records
            create_impact_rule("R-EV-001", "EvidenceRecord", "ISMS-P", "ISMS-P-2.7.1", changed_field="freshness", impact_type=ImpactType.EVIDENCE_FRESHNESS, impact_level=ImpactLevel.MEDIUM),
            create_impact_rule("R-EV-002", "EvidenceRecord", "ISMS-P", "ISMS-P-2.5.2", changed_field="deleted", impact_type=ImpactType.EVIDENCE_AVAILABILITY, impact_level=ImpactLevel.HIGH),

            # 9. Server / Asset Configuration (ISMS-P-2.4.1)
            create_impact_rule("R-ASSET-001", "Server", "ISMS-P", "ISMS-P-2.4.1", changed_field="status", impact_level=ImpactLevel.MEDIUM),

            # 10. Encryption Key / KMS (ISMS-P-2.9.1)
            create_impact_rule("R-KMS-001", "EncryptionKey", "ISMS-P", "ISMS-P-2.9.1", changed_field="status", impact_level=ImpactLevel.HIGH),
        ]

        for r in baseline:
            self.register(r)

    @staticmethod
    def _norm_type(t: str) -> str:
        return t.lower().replace("_", "")

    def register(self, rule: ImpactRule) -> None:
        """규칙을 등록합니다 (동일 버전 중복 등록 시 불변성 유지)."""
        key = (rule.rule_id, rule.rule_version)
        self._rules_by_version[key] = rule

        dt = self._norm_type(rule.source_data_type)
        if dt not in self._by_data_type:
            self._by_data_type[dt] = []
        
        # Avoid duplicate rule in same data_type list
        existing_keys = {(r.rule_id, r.rule_version) for r in self._by_data_type[dt]}
        if key not in existing_keys:
            self._by_data_type[dt].append(rule)

    def get_rule(self, rule_id: str, rule_version: str = "1.0") -> Optional[ImpactRule]:
        """버전별 규칙을 조회합니다."""
        r = self._rules_by_version.get((rule_id, rule_version))
        return deepcopy(r) if r else None

    def find_rules(
        self,
        source_data_type: str,
        changed_field: Optional[str] = None,
        target_framework: Optional[str] = None,
    ) -> List[ImpactRule]:
        """데이터 유형 및 필드 변경에 부합하는 규칙 목록을 결정론적으로 조회합니다."""
        dt = self._norm_type(source_data_type)
        rules = self._by_data_type.get(dt, [])

        matching: List[ImpactRule] = []
        for r in rules:
            # Check framework filter
            if target_framework and r.target_framework.upper() != target_framework.upper():
                continue

            # Check field match
            if changed_field is not None:
                if r.changed_field is None or r.changed_field.lower() == changed_field.lower():
                    matching.append(deepcopy(r))
            else:
                # caller passed None -> return all rules for this data type
                matching.append(deepcopy(r))

        return matching

    def list_all(self) -> List[ImpactRule]:
        """모든 등록된 규칙 목록을 반환합니다."""
        return [deepcopy(r) for r in self._rules_by_version.values()]


default_impact_rule_registry = ImpactRuleRegistry()
