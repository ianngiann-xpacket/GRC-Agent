"""Deterministic Compliance Assessment Engine (Step 23.5C).

This module implements the 16-step deterministic compliance assessment engine,
comparing requirement specifications against available canonical data and evaluating
explicit rules without LLMs, external APIs, network, shell, or repository mutations.
"""

from datetime import datetime, timezone
import hashlib
import uuid
from typing import Any, Dict, List, Optional
from pydantic import Field, field_validator

from secgrc.compliance.applicability import EvidenceConditionType, EvidenceScopeType
from secgrc.compliance.assessment_history import default_assessment_history
from secgrc.compliance.assessment_registry import default_rule_registry
from secgrc.compliance.assessment_rules import (
    AssessmentStatus,
    ComplianceAssessmentRule,
    RuleType,
)
from secgrc.compliance.evidence_graph import EvidenceConflict, EvidenceReference
from secgrc.compliance.evidence_requirements import (
    ComplianceEvidenceRequirement,
    EvidenceRole,
    default_evidence_requirement_registry,
)
from secgrc.compliance.evidence_sets import EvidenceSetOperator
from secgrc.compliance.frameworks import default_framework_registry
from secgrc.compliance.freshness import EvidenceFreshnessType
from secgrc.compliance.models import (
    CanonicalDataType,
    CanonicalSecurityData,
    ComplianceBaseModel,
    validate_identifier,
    validate_iso8601_timestamp,
)
from secgrc.compliance.requirements import default_requirement_registry
from secgrc.compliance.temporal import TemporalCoverageType


class ComplianceAssessment(ComplianceBaseModel):
    """결정론적 컴플라이언스 평가 결과 모델 (불변 결과 객체)."""

    assessment_id: str = Field(description="평가 결과 고유 식별자 (예: ASM-ISMS-P-2.5.2-<UUID>)")
    framework_id: str = Field(description="소속 프레임워크 식별자")
    framework_version: str = Field(description="소속 프레임워크 버전")
    requirement_id: str = Field(description="대상 요구사항 식별자")
    status: AssessmentStatus = Field(description="도출된 최종 평가 상태")
    assessment_level: str = Field(default="REQUIREMENT", description="평가 수준")
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="평가 완료 일시 (ISO 8601)",
    )
    rule_id: Optional[str] = Field(default=None, description="적용된 평가 규칙 ID")
    rule_version: Optional[str] = Field(default=None, description="적용된 평가 규칙 버전")
    evidence_refs: List[str] = Field(default_factory=list, description="참조된 증적 레코드 ID 목록")
    data_refs: List[str] = Field(default_factory=list, description="참조된 표준 정규 데이터 ID 목록")
    required_items: List[str] = Field(default_factory=list, description="요구된 증적/데이터 항목 목록")
    available_items: List[str] = Field(default_factory=list, description="실제 확보된 증적/데이터 항목 목록")
    missing_items: List[str] = Field(default_factory=list, description="미확보 누락 증적/데이터 항목 목록")
    failed_conditions: List[str] = Field(default_factory=list, description="위반된 조건 설명 목록")
    satisfied_conditions: List[str] = Field(default_factory=list, description="충족된 조건 설명 목록")
    unresolved_conditions: List[str] = Field(default_factory=list, description="미해결 조건 설명 목록")
    conflicts: List[str] = Field(default_factory=list, description="식별된 증적 상충 내역")
    applicability_result: str = Field(default="APPLICABLE", description="적용성 판정 결과")
    freshness_result: str = Field(default="NOT_SPECIFIED", description="신선도 검증 결과 (FRESH, STALE, NOT_SPECIFIED)")
    temporal_result: str = Field(default="NOT_SPECIFIED", description="시간적 커버리지 결과 (SATISFIED, INSUFFICIENT, NOT_SPECIFIED)")
    scope_result: str = Field(default="NOT_SPECIFIED", description="스코프 검증 결과 (MATCHED, MISMATCHED, NOT_SPECIFIED)")
    provenance_result: str = Field(default="NOT_SPECIFIED", description="출처 계보 검증 결과 (VALID, INVALID, NOT_SPECIFIED)")
    human_review_required: bool = Field(default=False, description="인간 심사관 수동 확인 필요 여부")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="평가 결정론적 완결성 점수 (0.0~1.0)")
    explanation_code: str = Field(description="결정론적 판정 사유 코드 (LLM 비사용)")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="평가 결정 계보 스냅샷")
    schema_version: str = Field(default="1.0", description="평가 모델 스키마 버전")

    @field_validator("assessment_id", "framework_id", "framework_version", "requirement_id", "explanation_code", "schema_version")
    @classmethod
    def check_assessment_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("evaluated_at")
    @classmethod
    def check_evaluated_at(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)


class ComplianceAssessmentBatch(ComplianceBaseModel):
    """복수 요구사항에 대한 일괄 평가 결과 묶음."""

    framework_id: str = Field(description="소속 프레임워크 식별자")
    framework_version: str = Field(description="소속 프레임워크 버전")
    requirement_ids: List[str] = Field(description="평가 대상 요구사항 ID 목록")
    assessment_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="배치 평가 수행 시각 (ISO 8601)",
    )
    results: List[ComplianceAssessment] = Field(description="개별 요구사항별 평가 결과 목록")
    summary: Dict[str, int] = Field(description="평가 상태별 집계 요약")


class ComplianceAssessmentEngine:
    """16단계 결정론적 컴플라이언스 평가 엔진."""

    def __init__(self, history_store: Optional[AssessmentHistoryStore] = None) -> None:
        self.history_store = history_store or default_assessment_history

    def assess(
        self,
        framework_id: str,
        framework_version: str,
        requirement_id: str,
        available_data: List[CanonicalSecurityData],
        target_scope: Optional[str] = None,
        conflicts: Optional[List[EvidenceConflict]] = None,
    ) -> ComplianceAssessment:
        """16단계 파이프라인에 따라 단일 요구사항의 준거성 상태를 결정론적으로 평가합니다."""

        # 1. Validate assessment input
        clean_fw_id = validate_identifier(framework_id, "framework_id")
        clean_fw_ver = validate_identifier(framework_version, "framework_version")
        clean_req_id = validate_identifier(requirement_id, "requirement_id")
        clean_target_scope = validate_identifier(target_scope, "target_scope") if target_scope is not None else None

        # 2. Validate Framework / Version / Requirement
        fw = default_framework_registry.get_framework(clean_fw_id)
        if not fw:
            return self._build_undetermined(
                clean_fw_id, clean_fw_ver, clean_req_id,
                "UNDETERMINED_UNKNOWN_FRAMEWORK",
            )

        req = default_requirement_registry.get(clean_req_id, clean_fw_id, clean_fw_ver)
        if not req:
            return self._build_undetermined(
                clean_fw_id, clean_fw_ver, clean_req_id,
                "UNDETERMINED_UNKNOWN_REQUIREMENT",
            )

        # 3. Load Evidence Requirements
        ev_reqs = default_evidence_requirement_registry.list_evidence_requirements(
            clean_fw_id, clean_fw_ver, clean_req_id,
        )

        # 4. Load Data Requirements
        data_reqs = default_evidence_requirement_registry.list_data_requirements(
            clean_fw_id, clean_fw_ver, clean_req_id,
        )

        # 5. Evaluate applicability
        prereq = default_evidence_requirement_registry.get_prerequisite(
            clean_req_id, clean_fw_id, clean_fw_ver,
        )
        if prereq and prereq.applicability_profile:
            app_prof = prereq.applicability_profile
            # Check jurisdiction if specified
            if app_prof.jurisdiction and fw.jurisdiction != "GLOBAL" and app_prof.jurisdiction != fw.jurisdiction:
                return self._create_assessment(
                    clean_fw_id, clean_fw_ver, clean_req_id,
                    status=AssessmentStatus.NOT_APPLICABLE,
                    explanation_code="NOT_APPLICABLE_JURISDICTION_EXCLUDED",
                    applicability_result="NOT_APPLICABLE",
                )

        # 6. Resolve required evidence/data against available data
        required_types = {r.data_type for r in ev_reqs if r.mandatory}
        for d in data_reqs:
            if d.required:
                required_types.add(d.canonical_data_type)

        matched_data: List[CanonicalSecurityData] = []
        for record in available_data:
            if record.data_type in required_types:
                matched_data.append(record)

        available_types = {r.data_type for r in matched_data}
        missing_types = required_types - available_types

        required_items_str = sorted([t.value for t in required_types])
        available_items_str = sorted([t.value for t in available_types])
        missing_items_str = sorted([t.value for t in missing_types])

        # 7. Check scope
        scope_result = "NOT_SPECIFIED"
        if clean_target_scope:
            out_of_scope = [r for r in matched_data if r.scope != "GLOBAL" and r.scope != clean_target_scope]
            if out_of_scope:
                matched_data = [r for r in matched_data if r.scope == "GLOBAL" or r.scope == clean_target_scope]
                scope_result = "MISMATCHED"
            else:
                scope_result = "MATCHED"

        evidence_refs = [r.record_id for r in matched_data]
        data_refs = [r.data_type.value for r in matched_data]

        # 8. Check provenance & integrity
        provenance_result = "VALID"
        for record in matched_data:
            prov = record.provenance
            if not prov.source_system or not prov.source_hash or not prov.source_record_id:
                provenance_result = "INVALID"
                return self._create_assessment(
                    clean_fw_id, clean_fw_ver, clean_req_id,
                    status=AssessmentStatus.UNDETERMINED,
                    explanation_code="UNDETERMINED_INVALID_PROVENANCE",
                    evidence_refs=evidence_refs,
                    provenance_result="INVALID",
                )

            # Check integrity hash
            computed = CanonicalSecurityData.compute_integrity_hash(record.payload, record.provenance)
            if computed != record.integrity_hash:
                return self._create_assessment(
                    clean_fw_id, clean_fw_ver, clean_req_id,
                    status=AssessmentStatus.UNDETERMINED,
                    explanation_code="UNDETERMINED_INTEGRITY_TAMPERED",
                    evidence_refs=evidence_refs,
                    provenance_result="INVALID",
                )

        # 9. Check freshness
        freshness_result = "NOT_SPECIFIED"
        now_utc = datetime.now(timezone.utc)
        for ev_req in ev_reqs:
            if ev_req.freshness and ev_req.freshness.freshness_type == EvidenceFreshnessType.WITHIN_DAYS:
                max_days = ev_req.freshness.freshness_value or 30
                for r in matched_data:
                    if r.data_type == ev_req.data_type:
                        try:
                            obs_time = datetime.fromisoformat(r.observed_at.replace("Z", "+00:00"))
                            age_days = (now_utc - obs_time).days
                            if age_days > max_days:
                                freshness_result = "STALE"
                                # Stale evidence cannot satisfy the requirement -> NO_EVIDENCE
                                return self._create_assessment(
                                    clean_fw_id, clean_fw_ver, clean_req_id,
                                    status=AssessmentStatus.NO_EVIDENCE,
                                    explanation_code="NO_EVIDENCE_STALE_INPUT",
                                    evidence_refs=evidence_refs,
                                    required_items=required_items_str,
                                    available_items=available_items_str,
                                    missing_items=missing_items_str,
                                    freshness_result="STALE",
                                )
                            else:
                                freshness_result = "FRESH"
                        except Exception:
                            freshness_result = "UNDETERMINED"

        # 10. Check temporal coverage
        temporal_result = "NOT_SPECIFIED"
        for ev_req in ev_reqs:
            if ev_req.temporal_coverage:
                t_cov = ev_req.temporal_coverage
                if t_cov.temporal_type in (TemporalCoverageType.CONTINUOUS, TemporalCoverageType.PERIOD):
                    # Operational records required spanning periods
                    # If only single point-in-time configuration is provided
                    has_operational = any(
                        r.data_type in (CanonicalDataType.SECURITY_LOG, CanonicalDataType.ALERT, CanonicalDataType.SECURITY_EVENT)
                        for r in matched_data
                    )
                    if not has_operational and ev_req.mandatory:
                        temporal_result = "INSUFFICIENT"
                        return self._create_assessment(
                            clean_fw_id, clean_fw_ver, clean_req_id,
                            status=AssessmentStatus.NO_EVIDENCE,
                            explanation_code="NO_EVIDENCE_INSUFFICIENT_TEMPORAL_COVERAGE",
                            evidence_refs=evidence_refs,
                            required_items=required_items_str,
                            available_items=available_items_str,
                            missing_items=missing_items_str,
                            temporal_result="INSUFFICIENT",
                        )
                    temporal_result = "SATISFIED"

        # 11. Evaluate conflicts
        conflict_list: List[str] = []
        if conflicts:
            for c in conflicts:
                if c.requirement_id == clean_req_id and c.status == "CONFLICTING":
                    conflict_list.append(f"{c.primary_evidence_id} vs {c.conflicting_evidence_id}: {c.conflict_reason}")

        if conflict_list:
            return self._create_assessment(
                clean_fw_id, clean_fw_ver, clean_req_id,
                status=AssessmentStatus.CONFLICTING,
                explanation_code="CONFLICTING_TRUSTED_EVIDENCE",
                evidence_refs=evidence_refs,
                conflicts=conflict_list,
                required_items=required_items_str,
                available_items=available_items_str,
                missing_items=missing_items_str,
            )

        # 12. Evaluate explicit assessment rules
        rules = default_rule_registry.list_by_requirement(clean_req_id, clean_fw_id, clean_fw_ver)

        # If required items are missing and no matching data
        if not matched_data and required_types:
            return self._create_assessment(
                clean_fw_id, clean_fw_ver, clean_req_id,
                status=AssessmentStatus.NO_EVIDENCE,
                explanation_code="NO_EVIDENCE_REQUIRED_INPUT_MISSING",
                required_items=required_items_str,
                available_items=[],
                missing_items=required_items_str,
                confidence=0.0,
                scope_result=scope_result,
                freshness_result=freshness_result,
                temporal_result=temporal_result,
                provenance_result=provenance_result,
            )

        # Check for explicit failure rules first
        failed_conditions: List[str] = []
        satisfied_conditions: List[str] = []
        applied_rule: Optional[ComplianceAssessmentRule] = None

        # 1. Evaluate explicit violation rules (fail_state == FAIL and pass_state != PASS)
        for rule in rules:
            if rule.fail_state == AssessmentStatus.FAIL and rule.pass_state != AssessmentStatus.PASS:
                for record in matched_data:
                    applicable_conds = [c for c in rule.conditions if c.data_type == record.data_type.value]
                    if not applicable_conds:
                        continue
                    if all(c.evaluate(record.payload) for c in applicable_conds):
                        applied_rule = rule
                        failed_conditions.append(f"Violation rule {rule.rule_id} triggered on {record.record_id}")
                        return self._create_assessment(
                            clean_fw_id, clean_fw_ver, clean_req_id,
                            status=AssessmentStatus.FAIL,
                            rule_id=rule.rule_id,
                            rule_version=rule.version,
                            evidence_refs=evidence_refs,
                            data_refs=data_refs,
                            required_items=required_items_str,
                            available_items=available_items_str,
                            missing_items=missing_items_str,
                            failed_conditions=failed_conditions,
                            satisfied_conditions=satisfied_conditions,
                            explanation_code="FAIL_EXPLICIT_RULE_VIOLATION",
                            scope_result=scope_result,
                            freshness_result=freshness_result,
                            temporal_result=temporal_result,
                            provenance_result=provenance_result,
                        )

        # 2. Evaluate positive compliance rules (pass_state == PASS)
        pass_rules = [r for r in rules if r.pass_state == AssessmentStatus.PASS]
        for rule in pass_rules:
            applicable_records = [
                r for r in matched_data
                if any(c.data_type == r.data_type.value for c in rule.conditions)
            ]
            if applicable_records:
                for record in applicable_records:
                    applicable_conds = [c for c in rule.conditions if c.data_type == record.data_type.value]
                    if not applicable_conds:
                        continue
                    if all(c.evaluate(record.payload) for c in applicable_conds):
                        applied_rule = rule
                        for cond in applicable_conds:
                            satisfied_conditions.append(f"{cond.field} {cond.operator.value} {cond.value}")
                    else:
                        for cond in applicable_conds:
                            if not cond.evaluate(record.payload):
                                failed_conditions.append(f"{cond.field} {cond.operator.value} {cond.value} (Actual: {record.payload.get(cond.field)})")
                        return self._create_assessment(
                            clean_fw_id, clean_fw_ver, clean_req_id,
                            status=AssessmentStatus.FAIL,
                            rule_id=rule.rule_id,
                            rule_version=rule.version,
                            evidence_refs=evidence_refs,
                            data_refs=data_refs,
                            required_items=required_items_str,
                            available_items=available_items_str,
                            missing_items=missing_items_str,
                            failed_conditions=failed_conditions,
                            satisfied_conditions=satisfied_conditions,
                            explanation_code="FAIL_EXPLICIT_RULE_VIOLATION",
                            scope_result=scope_result,
                            freshness_result=freshness_result,
                            temporal_result=temporal_result,
                            provenance_result=provenance_result,
                        )

        # If mandatory items are missing
        if missing_types:
            return self._create_assessment(
                clean_fw_id, clean_fw_ver, clean_req_id,
                status=AssessmentStatus.NO_EVIDENCE,
                explanation_code="NO_EVIDENCE_REQUIRED_INPUT_MISSING",
                evidence_refs=evidence_refs,
                data_refs=data_refs,
                required_items=required_items_str,
                available_items=available_items_str,
                missing_items=missing_items_str,
                scope_result=scope_result,
                freshness_result=freshness_result,
                temporal_result=temporal_result,
                provenance_result=provenance_result,
            )

        # 13. Determine status (PASS vs MANUAL)
        mandatory_ev_reqs = [e for e in ev_reqs if e.mandatory]
        is_human_required = (
            any(e.human_verification_required for e in mandatory_ev_reqs)
            if mandatory_ev_reqs
            else any(e.human_verification_required for e in ev_reqs)
        )
        if any(r.rule_type == RuleType.MANUAL for r in rules):
            is_human_required = True

        if is_human_required:
            return self._create_assessment(
                clean_fw_id, clean_fw_ver, clean_req_id,
                status=AssessmentStatus.MANUAL,
                rule_id=applied_rule.rule_id if applied_rule else None,
                rule_version=applied_rule.version if applied_rule else None,
                evidence_refs=evidence_refs,
                data_refs=data_refs,
                required_items=required_items_str,
                available_items=available_items_str,
                missing_items=[],
                satisfied_conditions=satisfied_conditions,
                human_review_required=True,
                explanation_code="MANUAL_HUMAN_VERIFICATION_REQUIRED",
                scope_result=scope_result,
                freshness_result=freshness_result,
                temporal_result=temporal_result,
                provenance_result=provenance_result,
            )

        # If rule was satisfied and no missing items
        if applied_rule and applied_rule.pass_state == AssessmentStatus.PASS:
            return self._create_assessment(
                clean_fw_id, clean_fw_ver, clean_req_id,
                status=AssessmentStatus.PASS,
                rule_id=applied_rule.rule_id,
                rule_version=applied_rule.version,
                evidence_refs=evidence_refs,
                data_refs=data_refs,
                required_items=required_items_str,
                available_items=available_items_str,
                missing_items=[],
                satisfied_conditions=satisfied_conditions,
                explanation_code="PASS_ALL_REQUIRED_CONDITIONS_SATISFIED",
                scope_result=scope_result,
                freshness_result=freshness_result,
                temporal_result=temporal_result,
                provenance_result=provenance_result,
            )

        # Default fallback
        return self._create_assessment(
            clean_fw_id, clean_fw_ver, clean_req_id,
            status=AssessmentStatus.UNDETERMINED,
            explanation_code="UNDETERMINED_RULE_NOT_AVAILABLE",
            evidence_refs=evidence_refs,
            data_refs=data_refs,
            required_items=required_items_str,
            available_items=available_items_str,
            missing_items=missing_items_str,
            scope_result=scope_result,
            freshness_result=freshness_result,
            temporal_result=temporal_result,
            provenance_result=provenance_result,
        )

    def assess_batch(
        self,
        framework_id: str,
        framework_version: str,
        requirement_ids: List[str],
        available_data: List[CanonicalSecurityData],
        target_scope: Optional[str] = None,
        conflicts: Optional[List[EvidenceConflict]] = None,
    ) -> ComplianceAssessmentBatch:
        """복수 요구사항에 대한 일괄 평가를 수행하고 요약 집계를 생성합니다."""
        results: List[ComplianceAssessment] = []
        summary: Dict[str, int] = {st.value: 0 for st in AssessmentStatus}

        for req_id in sorted(requirement_ids):
            asm = self.assess(
                framework_id=framework_id,
                framework_version=framework_version,
                requirement_id=req_id,
                available_data=available_data,
                target_scope=target_scope,
                conflicts=conflicts,
            )
            results.append(asm)
            summary[asm.status.value] = summary.get(asm.status.value, 0) + 1

        summary["total"] = len(results)
        return ComplianceAssessmentBatch(
            framework_id=framework_id,
            framework_version=framework_version,
            requirement_ids=requirement_ids,
            results=results,
            summary=summary,
        )

    def _create_assessment(
        self,
        framework_id: str,
        framework_version: str,
        requirement_id: str,
        status: AssessmentStatus,
        explanation_code: str,
        rule_id: Optional[str] = None,
        rule_version: Optional[str] = None,
        evidence_refs: Optional[List[str]] = None,
        data_refs: Optional[List[str]] = None,
        required_items: Optional[List[str]] = None,
        available_items: Optional[List[str]] = None,
        missing_items: Optional[List[str]] = None,
        failed_conditions: Optional[List[str]] = None,
        satisfied_conditions: Optional[List[str]] = None,
        unresolved_conditions: Optional[List[str]] = None,
        conflicts: Optional[List[str]] = None,
        applicability_result: str = "APPLICABLE",
        freshness_result: str = "NOT_SPECIFIED",
        temporal_result: str = "NOT_SPECIFIED",
        scope_result: str = "NOT_SPECIFIED",
        provenance_result: str = "NOT_SPECIFIED",
        human_review_required: bool = False,
        confidence: float = 1.0,
    ) -> ComplianceAssessment:
        asm_id = f"ASM-{framework_id}-{requirement_id}-{uuid.uuid4().hex[:8]}"
        provenance_snapshot = {
            "engine": "ComplianceAssessmentEngine",
            "version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule_id": rule_id,
            "rule_version": rule_version,
            "evidence_count": len(evidence_refs or []),
        }

        assessment = ComplianceAssessment(
            assessment_id=asm_id,
            framework_id=framework_id,
            framework_version=framework_version,
            requirement_id=requirement_id,
            status=status,
            rule_id=rule_id,
            rule_version=rule_version,
            evidence_refs=evidence_refs or [],
            data_refs=data_refs or [],
            required_items=required_items or [],
            available_items=available_items or [],
            missing_items=missing_items or [],
            failed_conditions=failed_conditions or [],
            satisfied_conditions=satisfied_conditions or [],
            unresolved_conditions=unresolved_conditions or [],
            conflicts=conflicts or [],
            applicability_result=applicability_result,
            freshness_result=freshness_result,
            temporal_result=temporal_result,
            scope_result=scope_result,
            provenance_result=provenance_result,
            human_review_required=human_review_required,
            confidence=confidence,
            explanation_code=explanation_code,
            provenance=provenance_snapshot,
        )

        # 불변 이력 저장소에 자동 기록
        self.history_store.record(assessment)
        return assessment

    def _build_undetermined(
        self,
        framework_id: str,
        framework_version: str,
        requirement_id: str,
        explanation_code: str,
    ) -> ComplianceAssessment:
        return self._create_assessment(
            framework_id=framework_id,
            framework_version=framework_version,
            requirement_id=requirement_id,
            status=AssessmentStatus.UNDETERMINED,
            explanation_code=explanation_code,
            confidence=0.0,
        )


# 기본 전역 싱글톤 평가 엔진
default_assessment_engine = ComplianceAssessmentEngine()


# ---------------------------------------------------------------------------
# Public APIs (Section 44)
# ---------------------------------------------------------------------------

def assess_requirement(
    framework_id: str,
    framework_version: str,
    requirement_id: str,
    available_data: List[CanonicalSecurityData],
    target_scope: Optional[str] = None,
    conflicts: Optional[List[EvidenceConflict]] = None,
) -> ComplianceAssessment:
    """단일 요구사항에 대한 결정론적 컴플라이언스 평가를 수행합니다."""
    return default_assessment_engine.assess(
        framework_id=framework_id,
        framework_version=framework_version,
        requirement_id=requirement_id,
        available_data=available_data,
        target_scope=target_scope,
        conflicts=conflicts,
    )


def assess_requirements(
    framework_id: str,
    framework_version: str,
    requirement_ids: List[str],
    available_data: List[CanonicalSecurityData],
    target_scope: Optional[str] = None,
    conflicts: Optional[List[EvidenceConflict]] = None,
) -> ComplianceAssessmentBatch:
    """복수 요구사항에 대한 일괄 결정론적 컴플라이언스 평가를 수행합니다."""
    return default_assessment_engine.assess_batch(
        framework_id=framework_id,
        framework_version=framework_version,
        requirement_ids=requirement_ids,
        available_data=available_data,
        target_scope=target_scope,
        conflicts=conflicts,
    )


def get_assessment(assessment_id: str) -> Optional[ComplianceAssessment]:
    """과거 평가 ID로 평가 결과를 조회합니다."""
    return default_assessment_history.get(assessment_id)


def get_assessment_history(
    requirement_id: str,
    framework_id: Optional[str] = None,
) -> List[ComplianceAssessment]:
    """특정 요구사항의 과거 평가 이력을 시간순으로 조회합니다."""
    return default_assessment_history.list_by_requirement(requirement_id, framework_id)


def get_assessment_rule(
    rule_id: str,
    version: Optional[str] = None,
) -> Optional[ComplianceAssessmentRule]:
    """평가 규칙 ID 및 버전으로 규칙을 조회합니다."""
    return default_rule_registry.get(rule_id, version)


def validate_assessment_rule(rule: ComplianceAssessmentRule) -> bool:
    """평가 규칙의 유효성을 검증합니다."""
    return default_rule_registry.validate(rule)
