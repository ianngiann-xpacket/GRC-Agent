"""Assessment Rule Conditions & Deterministic Operators (Step 23.5C).

This module defines strongly typed, declarative conditions and safe operators.
No eval(), exec(), or arbitrary dynamic expressions are permitted.
"""

from enum import Enum
from typing import Any, List, Optional
from pydantic import Field, field_validator, model_validator

from secgrc.compliance.field_registry import default_field_registry
from secgrc.compliance.models import (
    ComplianceBaseModel,
    validate_identifier,
)


class ConditionOperator(str, Enum):
    """결정론적 조건 연산자."""
    EQ = "EQ"
    NEQ = "NEQ"
    GT = "GT"
    GTE = "GTE"
    LT = "LT"
    LTE = "LTE"
    IN = "IN"
    NOT_IN = "NOT_IN"
    EXISTS = "EXISTS"
    NOT_EXISTS = "NOT_EXISTS"
    TRUE = "TRUE"
    FALSE = "FALSE"
    MATCH_ENUM = "MATCH_ENUM"
    COUNT_EQ = "COUNT_EQ"
    COUNT_GT = "COUNT_GT"
    COUNT_GTE = "COUNT_GTE"
    COUNT_LT = "COUNT_LT"
    COUNT_LTE = "COUNT_LTE"


class RuleCondition(ComplianceBaseModel):
    """결정론적 규칙 조건 명세."""

    data_type: str = Field(description="대상 정규 데이터 유형 (예: MFA_CONFIGURATION, FIREWALL_RULE)")
    field: str = Field(description="대상 정규 필드명 (CanonicalFieldRegistry 검증 대상)")
    operator: ConditionOperator = Field(description="조건 연산자")
    value: Any = Field(default=None, description="비교 기준값 (비실행 순수 데이터)")
    description: str = Field(default="", description="조건 설명")

    @field_validator("data_type", "field")
    @classmethod
    def check_condition_identifiers(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @model_validator(mode="after")
    def validate_field_in_registry(self) -> "RuleCondition":
        if not default_field_registry.is_field_allowed(self.data_type, self.field):
            raise ValueError(
                f"Field '{self.field}' is not permitted for data_type '{self.data_type}' "
                f"in CanonicalFieldRegistry"
            )
        return self

    def evaluate(self, payload: Any) -> bool:
        """주어진 페이로드에 대해 조건을 결정론적으로 평가합니다. (eval/exec 사용 금지)"""
        if not isinstance(payload, dict):
            return False

        field_val = payload.get(self.field)
        op = self.operator

        if op == ConditionOperator.EXISTS:
            return field_val is not None
        if op == ConditionOperator.NOT_EXISTS:
            return field_val is None

        if op == ConditionOperator.TRUE:
            return field_val is True or str(field_val).lower() == "true"
        if op == ConditionOperator.FALSE:
            return field_val is False or str(field_val).lower() == "false"

        if op == ConditionOperator.EQ:
            return self._compare_eq(field_val, self.value)
        if op == ConditionOperator.NEQ:
            return not self._compare_eq(field_val, self.value)

        if op == ConditionOperator.IN:
            if isinstance(self.value, (list, tuple, set)):
                return field_val in self.value
            return False
        if op == ConditionOperator.NOT_IN:
            if isinstance(self.value, (list, tuple, set)):
                return field_val not in self.value
            return True

        if op in (ConditionOperator.GT, ConditionOperator.GTE, ConditionOperator.LT, ConditionOperator.LTE):
            if field_val is None or self.value is None:
                return False
            try:
                num_val = float(field_val)
                ref_val = float(self.value)
                if op == ConditionOperator.GT:
                    return num_val > ref_val
                if op == ConditionOperator.GTE:
                    return num_val >= ref_val
                if op == ConditionOperator.LT:
                    return num_val < ref_val
                if op == ConditionOperator.LTE:
                    return num_val <= ref_val
            except (ValueError, TypeError):
                return False

        if op in (
            ConditionOperator.COUNT_EQ,
            ConditionOperator.COUNT_GT,
            ConditionOperator.COUNT_GTE,
            ConditionOperator.COUNT_LT,
            ConditionOperator.COUNT_LTE,
        ):
            count = len(field_val) if isinstance(field_val, (list, tuple, set, dict)) else 0
            try:
                ref_count = int(self.value)
                if op == ConditionOperator.COUNT_EQ:
                    return count == ref_count
                if op == ConditionOperator.COUNT_GT:
                    return count > ref_count
                if op == ConditionOperator.COUNT_GTE:
                    return count >= ref_count
                if op == ConditionOperator.COUNT_LT:
                    return count < ref_count
                if op == ConditionOperator.COUNT_LTE:
                    return count <= ref_count
            except (ValueError, TypeError):
                return False

        if op == ConditionOperator.MATCH_ENUM:
            return str(field_val).upper() == str(self.value).upper()

        return False

    @staticmethod
    def _compare_eq(val1: Any, val2: Any) -> bool:
        if val1 == val2:
            return True
        if isinstance(val1, str) and isinstance(val2, str):
            return val1.strip().upper() == val2.strip().upper()
        if isinstance(val1, bool) or isinstance(val2, bool):
            return bool(val1) == bool(val2)
        return False
