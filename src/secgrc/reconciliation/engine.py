"""정합성 엔진 - 정책↔설정, 요구↔증적, 범위↔자산 대사"""

from enum import Enum
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from pydantic import BaseModel, Field
import re
import json


class ReconciliationType(str, Enum):
    """정합성 검사 유형"""
    POLICY_TO_CONFIG = "POLICY_TO_CONFIG"       # 정책 ↔ 설정
    REQUIREMENT_TO_EVIDENCE = "REQUIREMENT_TO_EVIDENCE"  # 요구 ↔ 증적
    SCOPE_TO_ASSET = "SCOPE_TO_ASSET"           # 범위 ↔ 자산


class ReconciliationStatus(str, Enum):
    """정합성 상태"""
    MATCH = "MATCH"                 # 일치
    MISMATCH = "MISMATCH"           # 불일치
    MISSING = "MISSING"             # 누락
    EXCESS = "EXCESS"               # 초과
    UNKNOWN = "UNKNOWN"             # 알 수 없음


class PolicyRule(BaseModel):
    """정책 규칙"""
    rule_id: str = Field(description="규칙 ID")
    control_id: str = Field(description="통제 ID")
    policy_section: str = Field(description="정책 조항")
    rule_type: str = Field(description="규칙 유형 (numeric, boolean, enum, text)")
    expected_value: Any = Field(description="예상 값")
    operator: str = Field(default="equals", description="비교 연산자")
    description: str = Field(description="규칙 설명")


class ConfigObservation(BaseModel):
    """설정 관측 결과"""
    observation_id: str = Field(description="관측 ID")
    system_id: str = Field(description="시스템 ID")
    config_key: str = Field(description="설정 키")
    actual_value: Any = Field(description="실제 값")
    collected_at: datetime = Field(default_factory=datetime.now)
    source_query: Optional[str] = Field(default=None, description="조회 쿼리")


class ReconciliationResult(BaseModel):
    """정합성 검사 결과"""
    result_id: str = Field(description="결과 ID")
    reconciliation_type: ReconciliationType = Field(description="검사 유형")
    control_id: str = Field(description="통제 ID")
    policy_rule: Optional[PolicyRule] = Field(default=None, description="정책 규칙")
    config_observation: Optional[ConfigObservation] = Field(default=None, description="설정 관측")
    status: ReconciliationStatus = Field(description="정합성 상태")
    severity: str = Field(default="MEDIUM", description="심각도")
    description: str = Field(description="결과 설명")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="증적")
    recommendations: List[str] = Field(default_factory=list, description="권고사항")
    checked_at: datetime = Field(default_factory=datetime.now)


class ReconciliationEngine:
    """정합성 엔진"""

    def __init__(self):
        self.policy_rules: Dict[str, PolicyRule] = {}
        self.config_observations: Dict[str, ConfigObservation] = {}
        self.results: List[ReconciliationResult] = []
        self._initialize_policy_rules()

    def _initialize_policy_rules(self):
        """기본 정책 규칙 초기화"""
        # ISMS-P 주요 통제의 정책 규칙 정의
        rules = [
            # 비밀번호 정책 (2.5.4)
            PolicyRule(
                rule_id="RULE-2.5.4-001",
                control_id="ISMS-P-2.5.4",
                policy_section="비밀번호 정책 3.2절",
                rule_type="numeric",
                expected_value=8,
                operator=">=",
                description="최소 비밀번호 길이"
            ),
            PolicyRule(
                rule_id="RULE-2.5.4-002",
                control_id="ISMS-P-2.5.4",
                policy_section="비밀번호 정책 3.3절",
                rule_type="numeric",
                expected_value=90,
                operator="<=",
                description="비밀번호 최대 사용 기간 (일)"
            ),
            PolicyRule(
                rule_id="RULE-2.5.4-003",
                control_id="ISMS-P-2.5.4",
                policy_section="비밀번호 정책 3.4절",
                rule_type="boolean",
                expected_value=True,
                operator="equals",
                description="비밀번호 복잡도 요구사항"
            ),
            # MFA 정책 (2.5.2)
            PolicyRule(
                rule_id="RULE-2.5.2-001",
                control_id="ISMS-P-2.5.2",
                policy_section="인증 정책 2.1절",
                rule_type="boolean",
                expected_value=True,
                operator="equals",
                description="관리자 계정 MFA 필수 적용"
            ),
            # 로그 보관 정책 (2.9.4)
            PolicyRule(
                rule_id="RULE-2.9.4-001",
                control_id="ISMS-P-2.9.4",
                policy_section="로그 관리 정책 4.1절",
                rule_type="numeric",
                expected_value=365,
                operator=">=",
                description="로그 최소 보관 기간 (일)"
            ),
            # 백업 정책 (2.8.1)
            PolicyRule(
                rule_id="RULE-2.8.1-001",
                control_id="ISMS-P-2.8.1",
                policy_section="백업 정책 3.1절",
                rule_type="enum",
                expected_value=["daily", "weekly"],
                operator="in",
                description="백업 주기"
            ),
        ]
        
        for rule in rules:
            self.policy_rules[rule.rule_id] = rule

    def add_config_observation(self, system_id: str, config_key: str, 
                             actual_value: Any, source_query: Optional[str] = None) -> ConfigObservation:
        """설정 관측 결과 추가"""
        observation = ConfigObservation(
            observation_id=f"OBS-{len(self.config_observations)+1:04d}",
            system_id=system_id,
            config_key=config_key,
            actual_value=actual_value,
            source_query=source_query
        )
        self.config_observations[observation.observation_id] = observation
        return observation

    def reconcile_policy_to_config(self, control_id: str) -> List[ReconciliationResult]:
        """정책 ↔ 설정 정합성 검사"""
        results = []
        
        # 해당 통제의 정책 규칙 조회
        rules = [r for r in self.policy_rules.values() if r.control_id == control_id]
        
        for rule in rules:
            # 설정 관측 결과에서 해당 설정 찾기
            matching_obs = [
                obs for obs in self.config_observations.values()
                if rule.rule_id.split("-")[1] in obs.config_key  # 간단한 매칭 로직
            ]
            
            if not matching_obs:
                # 설정 관측 결과가 없는 경우
                result = ReconciliationResult(
                    result_id=f"REC-{len(self.results)+1:04d}",
                    reconciliation_type=ReconciliationType.POLICY_TO_CONFIG,
                    control_id=control_id,
                    policy_rule=rule,
                    status=ReconciliationStatus.MISSING,
                    severity="HIGH",
                    description=f"정책 '{rule.description}'에 대한 설정 관측 결과가 없습니다.",
                    recommendations=[
                        "해당 설정을 시스템에서 조회하여 등록하세요.",
                        "설정 관측 프로세스를 자동화하세요."
                    ]
                )
                results.append(result)
                self.results.append(result)
                continue
            
            # 각 관측 결과와 정책 규칙 비교
            for obs in matching_obs:
                match_status = self._compare_values(rule.expected_value, obs.actual_value, rule.operator)
                
                if match_status == ReconciliationStatus.MATCH:
                    status = ReconciliationStatus.MATCH
                    severity = "LOW"
                    description = f"정책 '{rule.description}'이 설정과 일치합니다."
                    recommendations = []
                else:
                    status = ReconciliationStatus.MISMATCH
                    severity = "HIGH"
                    description = f"정책 '{rule.description}'과 설정이 불일치합니다. 정책: {rule.expected_value}, 실제: {obs.actual_value}"
                    recommendations = [
                        f"시스템 설정을 정책에 맞게 수정하세요: {rule.expected_value}",
                        "정책 변경 시 시스템 설정도 함께 업데이트하는 프로세스를 구축하세요."
                    ]
                
                result = ReconciliationResult(
                    result_id=f"REC-{len(self.results)+1:04d}",
                    reconciliation_type=ReconciliationType.POLICY_TO_CONFIG,
                    control_id=control_id,
                    policy_rule=rule,
                    config_observation=obs,
                    status=status,
                    severity=severity,
                    description=description,
                    evidence={
                        "policy_value": rule.expected_value,
                        "actual_value": obs.actual_value,
                        "operator": rule.operator,
                        "system_id": obs.system_id
                    },
                    recommendations=recommendations
                )
                results.append(result)
                self.results.append(result)
        
        return results

    def _compare_values(self, expected: Any, actual: Any, operator: str) -> ReconciliationStatus:
        """값 비교"""
        try:
            if operator == "equals":
                return ReconciliationStatus.MATCH if expected == actual else ReconciliationStatus.MISMATCH
            elif operator == ">=":
                return ReconciliationStatus.MATCH if actual >= expected else ReconciliationStatus.MISMATCH
            elif operator == "<=":
                return ReconciliationStatus.MATCH if actual <= expected else ReconciliationStatus.MISMATCH
            elif operator == "in":
                return ReconciliationStatus.MATCH if actual in expected else ReconciliationStatus.MISMATCH
            elif operator == "contains":
                return ReconciliationStatus.MATCH if expected in actual else ReconciliationStatus.MISMATCH
            else:
                return ReconciliationStatus.UNKNOWN
        except Exception:
            return ReconciliationStatus.UNKNOWN

    def reconcile_requirement_to_evidence(self, control_id: str, 
                                       required_evidence: List[str],
                                       available_evidence: List[str]) -> List[ReconciliationResult]:
        """요구 ↔ 증적 정합성 검사"""
        results = []
        
        missing_evidence = set(required_evidence) - set(available_evidence)
        excess_evidence = set(available_evidence) - set(required_evidence)
        
        # 누락된 증적
        if missing_evidence:
            result = ReconciliationResult(
                result_id=f"REC-{len(self.results)+1:04d}",
                reconciliation_type=ReconciliationType.REQUIREMENT_TO_EVIDENCE,
                control_id=control_id,
                status=ReconciliationStatus.MISSING,
                severity="HIGH",
                description=f"통제 {control_id}에 필요한 증적이 누락되었습니다: {', '.join(missing_evidence)}",
                evidence={
                    "required": list(required_evidence),
                    "available": list(available_evidence),
                    "missing": list(missing_evidence)
                },
                recommendations=[
                    "누락된 증적을 수집하거나 생성하세요.",
                    "증적 수집 프로세스를 점검하세요."
                ]
            )
            results.append(result)
            self.results.append(result)
        
        # 초과된 증적
        if excess_evidence:
            result = ReconciliationResult(
                result_id=f"REC-{len(self.results)+1:04d}",
                reconciliation_type=ReconciliationType.REQUIREMENT_TO_EVIDENCE,
                control_id=control_id,
                status=ReconciliationStatus.EXCESS,
                severity="LOW",
                description=f"통제 {control_id}에 불필요한 증적이 존재합니다: {', '.join(excess_evidence)}",
                evidence={
                    "required": list(required_evidence),
                    "available": list(available_evidence),
                    "excess": list(excess_evidence)
                },
                recommendations=[
                    "불필요한 증적을 정리하거나 문서화하세요."
                ]
            )
            results.append(result)
            self.results.append(result)
        
        # 모든 증적이 충족된 경우
        if not missing_evidence and not excess_evidence:
            result = ReconciliationResult(
                result_id=f"REC-{len(self.results)+1:04d}",
                reconciliation_type=ReconciliationType.REQUIREMENT_TO_EVIDENCE,
                control_id=control_id,
                status=ReconciliationStatus.MATCH,
                severity="LOW",
                description=f"통제 {control_id}의 증적이 모두 충족되었습니다.",
                evidence={
                    "required": list(required_evidence),
                    "available": list(available_evidence)
                }
            )
            results.append(result)
            self.results.append(result)
        
        return results

    def reconcile_scope_to_asset(self, scope_definition: Dict[str, Any],
                                actual_assets: List[Dict[str, Any]]) -> List[ReconciliationResult]:
        """범위 ↔ 자산 정합성 검사"""
        results = []
        
        scope_assets = set(scope_definition.get("asset_ids", []))
        actual_asset_ids = set(asset.get("asset_id") for asset in actual_assets)
        
        missing_assets = scope_assets - actual_asset_ids
        excess_assets = actual_asset_ids - scope_assets
        
        # 범위 내 누락된 자산
        if missing_assets:
            result = ReconciliationResult(
                result_id=f"REC-{len(self.results)+1:04d}",
                reconciliation_type=ReconciliationType.SCOPE_TO_ASSET,
                control_id="SCOPE",
                status=ReconciliationStatus.MISSING,
                severity="CRITICAL",
                description=f"인증 범위에 포함되어야 할 자산이 누락되었습니다: {', '.join(missing_assets)}",
                evidence={
                    "scope_assets": list(scope_assets),
                    "actual_assets": list(actual_asset_ids),
                    "missing": list(missing_assets)
                },
                recommendations=[
                    "누락된 자산을 인증 범위에 추가하거나 범위를 재정의하세요.",
                    "자산 목록을 정기적으로 점검하세요."
                ]
            )
            results.append(result)
            self.results.append(result)
        
        # 범위 외 초과 자산
        if excess_assets:
            result = ReconciliationResult(
                result_id=f"REC-{len(self.results)+1:04d}",
                reconciliation_type=ReconciliationType.SCOPE_TO_ASSET,
                control_id="SCOPE",
                status=ReconciliationStatus.EXCESS,
                severity="MEDIUM",
                description=f"인증 범위에 포함되지 않은 자산이 발견되었습니다: {', '.join(excess_assets)}",
                evidence={
                    "scope_assets": list(scope_assets),
                    "actual_assets": list(actual_asset_ids),
                    "excess": list(excess_assets)
                },
                recommendations=[
                    "범위를 확장하거나 해당 자산을 제외하세요.",
                    "자산 범위 정의를 명확히 문서화하세요."
                ]
            )
            results.append(result)
            self.results.append(result)
        
        # 범위와 자산이 일치하는 경우
        if not missing_assets and not excess_assets:
            result = ReconciliationResult(
                result_id=f"REC-{len(self.results)+1:04d}",
                reconciliation_type=ReconciliationType.SCOPE_TO_ASSET,
                control_id="SCOPE",
                status=ReconciliationStatus.MATCH,
                severity="LOW",
                description="인증 범위와 자산이 일치합니다.",
                evidence={
                    "scope_assets": list(scope_assets),
                    "actual_assets": list(actual_asset_ids)
                }
            )
            results.append(result)
            self.results.append(result)
        
        return results

    def get_reconciliation_summary(self) -> Dict[str, Any]:
        """정합성 검사 결과 요약"""
        total = len(self.results)
        
        by_status = {}
        by_type = {}
        by_severity = {}
        
        for result in self.results:
            status = result.status.value
            rec_type = result.reconciliation_type.value
            severity = result.severity
            
            by_status[status] = by_status.get(status, 0) + 1
            by_type[rec_type] = by_type.get(rec_type, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            "total_checks": total,
            "by_status": by_status,
            "by_type": by_type,
            "by_severity": by_severity,
            "match_rate": (by_status.get("MATCH", 0) / total) * 100 if total > 0 else 0,
            "critical_issues": by_severity.get("CRITICAL", 0),
            "high_issues": by_severity.get("HIGH", 0)
        }

    def get_mismatched_controls(self) -> List[str]:
        """불일치 통제 목록"""
        mismatched = set()
        for result in self.results:
            if result.status in [ReconciliationStatus.MISMATCH, ReconciliationStatus.MISSING]:
                mismatched.add(result.control_id)
        return list(mismatched)


# 전역 인스턴스
reconciliation_engine = ReconciliationEngine()
