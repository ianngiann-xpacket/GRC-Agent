"""Assessment Rule Registry (Step 23.5C).

This module manages registration, retrieval, and validation of deterministic assessment rules,
housing authoritative reference rules for ISMS-P and GDPR.
"""

from typing import Dict, List, Optional
from pydantic import ValidationError

from secgrc.compliance.assessment_conditions import ConditionOperator, RuleCondition
from secgrc.compliance.assessment_rules import (
    AssessmentStatus,
    ComplianceAssessmentRule,
    RuleType,
)
from secgrc.compliance.field_registry import default_field_registry
from secgrc.compliance.frameworks import default_framework_registry
from secgrc.compliance.models import (
    CanonicalDataType,
    validate_identifier,
)


class AssessmentRuleRegistry:
    """컴플라이언스 평가 규칙 중앙 등록 및 검증 레지스트리."""

    def __init__(self) -> None:
        # key: f"{rule_id}:{version}"
        self._rules: Dict[str, ComplianceAssessmentRule] = {}
        self._initialize_reference_rules()

    def register(self, rule: ComplianceAssessmentRule) -> None:
        """평가 규칙을 유효성 검증 후 등록합니다. 중복 식별자는 거부됩니다."""
        self.validate(rule)
        key = self._make_key(rule.rule_id, rule.version)
        if key in self._rules:
            raise ValueError(f"Duplicate rule registration: {key} already exists")
        self._rules[key] = rule

    def get(self, rule_id: str, version: Optional[str] = None) -> Optional[ComplianceAssessmentRule]:
        """규칙 ID 및 버전으로 규칙을 조회합니다. 버전 미지정 시 최신 규칙을 반환합니다."""
        clean_id = validate_identifier(rule_id, "rule_id")
        if version:
            return self._rules.get(self._make_key(clean_id, version))

        # 버전 미지정 시 가장 높은 버전 우선 반환
        matching = [r for r in self._rules.values() if r.rule_id == clean_id]
        if not matching:
            return None
        return sorted(matching, key=lambda r: r.version, reverse=True)[0]

    def list_by_requirement(
        self,
        requirement_id: str,
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
    ) -> List[ComplianceAssessmentRule]:
        """특정 요구사항에 매핑된 규칙 목록을 우선순위 순으로 반환합니다."""
        res = [
            r for r in self._rules.values()
            if r.framework_id == framework_id
            and r.framework_version == framework_version
            and r.requirement_id == requirement_id
        ]
        return sorted(res, key=lambda r: (r.priority, r.rule_id))

    def list_by_framework(
        self,
        framework_id: str,
        framework_version: Optional[str] = None,
    ) -> List[ComplianceAssessmentRule]:
        """특정 프레임워크에 매핑된 규칙 목록을 반환합니다."""
        res = [
            r for r in self._rules.values()
            if r.framework_id == framework_id
            and (framework_version is None or r.framework_version == framework_version)
        ]
        return sorted(res, key=lambda r: (r.priority, r.rule_id))

    def list_by_type(self, rule_type: RuleType) -> List[ComplianceAssessmentRule]:
        """특정 규칙 유형에 해당하는 규칙 목록을 반환합니다."""
        return [r for r in self._rules.values() if r.rule_type == rule_type]

    def unregister(self, rule_id: str, version: Optional[str] = None) -> bool:
        """규칙을 레지스트리에서 제거합니다."""
        clean_id = validate_identifier(rule_id, "rule_id")
        if version:
            key = self._make_key(clean_id, version)
            return self._rules.pop(key, None) is not None
        removed = False
        keys_to_del = [k for k, r in self._rules.items() if r.rule_id == clean_id]
        for k in keys_to_del:
            del self._rules[k]
            removed = True
        return removed

    def clear(self) -> None:
        """레지스트리 내의 모든 규칙을 제거합니다."""
        self._rules.clear()

    def validate(self, rule: ComplianceAssessmentRule) -> bool:
        """규칙의 구조적 안전성과 유효성을 결정론적으로 검증합니다."""
        # 1. 프레임워크 유효성 확인
        fw = default_framework_registry.get_framework(rule.framework_id)
        if not fw:
            raise ValueError(f"Unknown framework_id: {rule.framework_id}")

        # 2. 규칙 내 조건 필드가 CanonicalFieldRegistry에 등록되어 있는지 확인
        for cond in rule.conditions:
            if not default_field_registry.is_field_allowed(cond.data_type, cond.field):
                raise ValueError(
                    f"Forbidden field '{cond.field}' for data_type '{cond.data_type}' in rule {rule.rule_id}"
                )

        return True

    def _make_key(self, rule_id: str, version: str) -> str:
        return f"{rule_id}:{version}"

    def _initialize_reference_rules(self) -> None:
        """검증된 권위 참조 평가 규칙 초기화 (ISMS-P & GDPR)."""
        rules = [
            # 1. ISMS-P-2.5.2 사용자 인증 - MFA 활성화 성공 규칙 (PASS)
            ComplianceAssessmentRule(
                rule_id="RULE-IAM-MFA-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.5.2",
                rule_type=RuleType.CONFIGURATION_STATE,
                version="1.0",
                priority=1,
                conditions=[
                    RuleCondition(
                        data_type=CanonicalDataType.MFA_CONFIGURATION.value,
                        field="enabled",
                        operator=ConditionOperator.TRUE,
                        description="MFA 설정이 활성화되어 있어야 함",
                    )
                ],
                pass_state=AssessmentStatus.PASS,
                fail_state=AssessmentStatus.FAIL,
                required_data=[CanonicalDataType.MFA_CONFIGURATION],
                source_reference="KISA-ISMS-P-2024-2.5.2",
            ),
            # 2. ISMS-P-2.5.2 사용자 인증 - MFA 비활성화 위반 규칙 (FAIL)
            ComplianceAssessmentRule(
                rule_id="RULE-IAM-MFA-FAIL-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.5.2",
                rule_type=RuleType.CONFIGURATION_STATE,
                version="1.0",
                priority=2,
                conditions=[
                    RuleCondition(
                        data_type=CanonicalDataType.MFA_CONFIGURATION.value,
                        field="enabled",
                        operator=ConditionOperator.FALSE,
                        description="MFA가 비활성화된 경우 명시적 위반",
                    )
                ],
                pass_state=AssessmentStatus.UNDETERMINED,
                fail_state=AssessmentStatus.FAIL,
                required_data=[CanonicalDataType.MFA_CONFIGURATION],
                source_reference="KISA-ISMS-P-2024-2.5.2",
            ),
            # 3. ISMS-P-2.6.3 외부망 접근통제 - Any-to-Any Allow 위반 규칙 (FAIL)
            ComplianceAssessmentRule(
                rule_id="RULE-FW-ANY-ANY-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.6.3",
                rule_type=RuleType.CONFIGURATION_STATE,
                version="1.0",
                priority=1,
                conditions=[
                    RuleCondition(
                        data_type=CanonicalDataType.FIREWALL_RULE.value,
                        field="source",
                        operator=ConditionOperator.EQ,
                        value="ANY",
                        description="출발지가 ANY",
                    ),
                    RuleCondition(
                        data_type=CanonicalDataType.FIREWALL_RULE.value,
                        field="destination",
                        operator=ConditionOperator.EQ,
                        value="ANY",
                        description="도착지가 ANY",
                    ),
                    RuleCondition(
                        data_type=CanonicalDataType.FIREWALL_RULE.value,
                        field="action",
                        operator=ConditionOperator.EQ,
                        value="ALLOW",
                        description="행위가 허용(ALLOW)",
                    ),
                ],
                pass_state=AssessmentStatus.UNDETERMINED,
                fail_state=AssessmentStatus.FAIL,
                required_data=[CanonicalDataType.FIREWALL_RULE],
                source_reference="KISA-ISMS-P-2024-2.6.3",
            ),
            # 4. ISMS-P-2.7.1 암호화 적용 - CMEK 암호화 적용 성공 규칙 (PASS)
            ComplianceAssessmentRule(
                rule_id="RULE-ENC-CMEK-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.7.1",
                rule_type=RuleType.CONFIGURATION_STATE,
                version="1.0",
                priority=1,
                conditions=[
                    RuleCondition(
                        data_type=CanonicalDataType.SECURITY_CONFIGURATION.value,
                        field="cmek_enabled",
                        operator=ConditionOperator.TRUE,
                        description="고객 관리형 암호키(CMEK)가 활성화되어야 함",
                    )
                ],
                pass_state=AssessmentStatus.PASS,
                fail_state=AssessmentStatus.FAIL,
                required_data=[CanonicalDataType.SECURITY_CONFIGURATION],
                source_reference="KISA-ISMS-P-2024-2.7.1",
            ),
            # 5. GDPR-Art-32 보안 조치 - 암호화 적용 성공 규칙 (PASS)
            ComplianceAssessmentRule(
                rule_id="RULE-GDPR-ART32-001",
                framework_id="GDPR",
                framework_version="2016-679",
                requirement_id="GDPR-Art-32",
                rule_type=RuleType.CONFIGURATION_STATE,
                version="1.0",
                priority=1,
                conditions=[
                    RuleCondition(
                        data_type=CanonicalDataType.SECURITY_CONFIGURATION.value,
                        field="cmek_enabled",
                        operator=ConditionOperator.TRUE,
                        description="GDPR Article 32 암호화 조치 충족",
                    )
                ],
                pass_state=AssessmentStatus.PASS,
                fail_state=AssessmentStatus.FAIL,
                required_data=[CanonicalDataType.SECURITY_CONFIGURATION],
                source_reference="EUR-Lex-GDPR-Art-32",
            ),
            # 6. GDPR-Art-30 처리활동기록 - RoPA 활동 상태 성공 규칙 (PASS)
            ComplianceAssessmentRule(
                rule_id="RULE-GDPR-ART30-001",
                framework_id="GDPR",
                framework_version="2016-679",
                requirement_id="GDPR-Art-30",
                rule_type=RuleType.DATA_ATTRIBUTE,
                version="1.0",
                priority=1,
                conditions=[
                    RuleCondition(
                        data_type=CanonicalDataType.PROCESSING_ACTIVITY.value,
                        field="status",
                        operator=ConditionOperator.EQ,
                        value="ACTIVE",
                        description="처리활동기록이 활성 상태로 유지 관리되어야 함",
                    )
                ],
                pass_state=AssessmentStatus.PASS,
                fail_state=AssessmentStatus.FAIL,
                required_data=[CanonicalDataType.PROCESSING_ACTIVITY],
                source_reference="EUR-Lex-GDPR-Art-30",
            ),
        ]

        for r in rules:
            self._rules[self._make_key(r.rule_id, r.version)] = r


# 기본 싱글톤 규칙 레지스트리
default_rule_registry = AssessmentRuleRegistry()
