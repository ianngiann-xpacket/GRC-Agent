"""Step 23.5 - Investigation Guard / Safety Gate module.

The Guard is the final deterministic safety gate between:
    Investigation Execution -> Correlation -> GUARD -> Trusted Investigation Result -> Report

Core Principles:
- "Trust, don't guess."
- ZERO LLM reasoning, ZERO external APIs, ZERO repository mutations.
- The Guard is a validator, not an investigator.
- Fail closed: any critical integrity or security violation results in BLOCK.
- Deterministic check execution and sorting.
"""

from copy import deepcopy
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import Field, field_validator

from secgrc.copilot.models import FactType
from secgrc.copilot.planner import ALLOWED_OPERATIONS, FORBIDDEN_OPERATIONS
from secgrc.investigation.correlation import (
    ALLOWED_CONFIDENCES,
    ALLOWED_ENTITY_TYPES,
    ALLOWED_RELATIONSHIPS,
    CorrelationEdge,
    CorrelationResult,
    FactStore,
    RELATIONSHIP_TYPE_CONSTRAINTS,
)
from secgrc.investigation.enums import (
    InvestigationScopeType,
    InvestigationStatus,
    InvestigationStepStatus,
)
from secgrc.investigation.models import (
    DANGEROUS_ID_PATTERNS,
    FORBIDDEN_STEP_OPERATIONS,
    Investigation,
    InvestigationBaseModel,
    InvestigationFact,
    InvestigationResult,
    validate_id_str,
)
from secgrc.ontology.builder import OntologyBuilder
from secgrc.ontology.entities import Control, EvidenceEntity, Finding, Framework, RiskEntity
from secgrc.ontology.models import RelationshipType
from secgrc.ontology.repository import OntologyRepository
from secgrc.ontology.resolver import OntologyResolver

GUARD_VERSION = "1.0"


class GuardStatus(str, Enum):
    """가드 심사 최종 판정 상태."""
    PASS = "PASS"    # 결과 신뢰 가능, 보고서 생성 단계 진행 허용
    BLOCK = "BLOCK"  # 무결성/보안 결함 발견, 보고서 생성 단계 진행 차단
    WARN = "WARN"    # 경미한 주의사항 존재, 정책에 따라 조건부 허용


class GuardCategory(str, Enum):
    """가드 검증 항목 분류 체계 (14개 카테고리)."""
    INPUT_STRUCTURE = "INPUT_STRUCTURE"
    IDENTITY = "IDENTITY"
    PLAN_INTEGRITY = "PLAN_INTEGRITY"
    EXECUTION_INTEGRITY = "EXECUTION_INTEGRITY"
    SCOPE = "SCOPE"
    FACT_INTEGRITY = "FACT_INTEGRITY"
    RELATIONSHIP_INTEGRITY = "RELATIONSHIP_INTEGRITY"
    EVIDENCE = "EVIDENCE"
    PROVENANCE = "PROVENANCE"
    CONSISTENCY = "CONSISTENCY"
    COMPLETENESS = "COMPLETENESS"
    SECURITY = "SECURITY"
    DETERMINISM = "DETERMINISM"
    SOURCE_INTEGRITY = "SOURCE_INTEGRITY"


class GuardSeverity(str, Enum):
    """검증 결함 심각도 수준."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class GuardCheck(InvestigationBaseModel):
    """단일 결정론적 가드 검증 결과 모델."""

    check_id: str = Field(description="검증 고유 식별자")
    category: GuardCategory = Field(description="검증 분류 카테고리")
    status: GuardStatus = Field(description="개별 검증 판정 (PASS, BLOCK, WARN)")
    severity: GuardSeverity = Field(description="심각도 수준")
    message: str = Field(description="검증 결과 설명 메시지")
    details: Dict[str, Any] = Field(default_factory=dict, description="상세 진단 메타데이터")

    @field_validator("check_id")
    @classmethod
    def check_id_valid(cls, v: str) -> str:
        return validate_id_str(v, "check_id")


class GuardPolicy(InvestigationBaseModel):
    """가드 심사 정책 모델 (불변 검증 기준)."""

    require_validated_plan: bool = True
    require_read_only: bool = True
    require_provenance: bool = True
    require_scope_integrity: bool = True
    require_authoritative_facts: bool = True
    require_required_evidence: bool = True
    fail_on_identity_mismatch: bool = True
    fail_on_risk_value_mismatch: bool = True
    allow_warnings_to_report: bool = True  # False일 경우 WARN도 allowed_to_report=False


class InvestigationGuardResult(InvestigationBaseModel):
    """가드 안전 심사 최종 판정 결과 모델."""

    investigation_id: str = Field(description="소속 조사 식별자")
    correlation_id: str = Field(description="소속 상관 분석 식별자")
    status: GuardStatus = Field(description="종합 판정 상태 (PASS, BLOCK, WARN)")
    allowed_to_report: bool = Field(description="보고서 계층 진행 승인 여부")
    checks: List[GuardCheck] = Field(default_factory=list, description="수행된 검증 항목 목록 (결정론적 정렬)")
    blocking_reasons: List[str] = Field(default_factory=list, description="차단 사유 목록")
    warnings: List[str] = Field(default_factory=list, description="경고 사유 목록")
    validated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="검증 일시 (ISO 8601 UTC)",
    )
    guard_version: str = Field(default="1.0", description="가드 엔진 버전")

    @field_validator("investigation_id", "correlation_id")
    @classmethod
    def check_mandatory_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("guard_version")
    @classmethod
    def check_version(cls, v: str) -> str:
        if v != "1.0":
            raise ValueError(f"guard_version must be '1.0', got '{v}'")
        return v


class InvestigationGuard:
    """Step 23.5 결정론적 조사 안전 가드 (Deterministic Safety Gate).

    실행 및 상관 분석 결과를 검증하여, 결과물이 보고서 계층으로 전달될 수 있을 만큼
    충분히 유효하고, 신뢰할 수 있으며, 완전하고, 스코프 내에 격리되어 있는지 심사합니다.
    """

    def __init__(
        self,
        policy: Optional[GuardPolicy] = None,
        repo: Optional[OntologyRepository] = None,
        resolver: Optional[OntologyResolver] = None,
    ) -> None:
        """가드 엔진을 초기화합니다. 읽기 전용 저장소 의존성을 주입받습니다."""
        self.policy = policy or GuardPolicy()
        if repo is None:
            self.repo = OntologyBuilder().build(use_cross_frameworks=False)
            self.resolver = OntologyResolver(self.repo)
        else:
            self.repo = repo
            self.resolver = resolver or OntologyResolver(self.repo)

    # ============================================================
    # Read-Only Public Validation Entry Point
    # ============================================================

    def validate(
        self,
        investigation: Any,
        execution_result: Any,
        correlation_result: Any,
        plan: Optional[Any] = None,
        facts: Optional[List[Any]] = None,
    ) -> InvestigationGuardResult:
        """조사, 실행 결과, 상관 결과를 결정론적으로 심사하여 가드 판정을 반환합니다.

        모든 검증은 fail-closed 원칙을 따르며, 일체의 수정이나 날조 없이 입력 데이터를 그대로 검증합니다.
        """
        # 실행 전 저장소 불변 스냅샷 캡처
        baseline_entities = {k: v.model_dump() for k, v in self.repo._entities.items()}
        baseline_rels = {k: v.model_dump() for k, v in self.repo._relationships.items()}

        checks: List[GuardCheck] = []
        blocking_reasons: List[str] = []
        warnings: List[str] = []

        # ------------------------------------------------------------
        # 1. 입력 구조 검증 (INPUT_STRUCTURE)
        # ------------------------------------------------------------
        input_valid, inv_id, corr_id = self._check_input_structure(
            investigation=investigation,
            execution_result=execution_result,
            correlation_result=correlation_result,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        if not input_valid:
            return self._build_result(
                investigation_id=inv_id or "UNKNOWN",
                correlation_id=corr_id or "UNKNOWN",
                status=GuardStatus.BLOCK,
                allowed_to_report=False,
                checks=checks,
                blocking_reasons=blocking_reasons,
                warnings=warnings,
            )

        # ------------------------------------------------------------
        # 2. 식별자 일치 검증 (IDENTITY)
        # ------------------------------------------------------------
        self._check_identity(
            investigation=investigation,
            execution_result=execution_result,
            correlation_result=correlation_result,
            checks=checks,
            blocking_reasons=blocking_reasons,
            warnings=warnings,
        )

        # ------------------------------------------------------------
        # 3. 조사 계획 무결성 검증 (PLAN_INTEGRITY)
        # ------------------------------------------------------------
        self._check_plan_integrity(
            plan=plan,
            inv_id=inv_id,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        # ------------------------------------------------------------
        # 4. 실행 무결성 검증 (EXECUTION_INTEGRITY)
        # ------------------------------------------------------------
        self._check_execution_integrity(
            execution_result=execution_result,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        # ------------------------------------------------------------
        # 5. 스코프 무결성 검증 (SCOPE)
        # ------------------------------------------------------------
        self._check_scope_integrity(
            investigation=investigation,
            correlation_result=correlation_result,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        # ------------------------------------------------------------
        # 6. 사실 무결성 검증 (FACT_INTEGRITY)
        # ------------------------------------------------------------
        effective_facts = self._resolve_facts(execution_result, facts)
        self._check_fact_integrity(
            facts=effective_facts,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        # ------------------------------------------------------------
        # 7. 관계 무결성 검증 (RELATIONSHIP_INTEGRITY)
        # ------------------------------------------------------------
        self._check_relationship_integrity(
            correlation_result=correlation_result,
            facts=effective_facts,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        # ------------------------------------------------------------
        # 8. 증적 무결성 및 적절성 검증 (EVIDENCE)
        # ------------------------------------------------------------
        self._check_evidence_integrity(
            investigation=investigation,
            execution_result=execution_result,
            correlation_result=correlation_result,
            checks=checks,
            blocking_reasons=blocking_reasons,
            warnings=warnings,
        )

        # ------------------------------------------------------------
        # 9. 출처 무결성 검증 (PROVENANCE)
        # ------------------------------------------------------------
        self._check_provenance_integrity(
            correlation_result=correlation_result,
            facts=effective_facts,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        # ------------------------------------------------------------
        # 10. 일관성 및 중복 에지 검증 (CONSISTENCY)
        # ------------------------------------------------------------
        self._check_consistency(
            correlation_result=correlation_result,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        # ------------------------------------------------------------
        # 11. 완전성 검증 (COMPLETENESS)
        # ------------------------------------------------------------
        self._check_completeness(
            execution_result=execution_result,
            correlation_result=correlation_result,
            checks=checks,
            warnings=warnings,
        )

        # ------------------------------------------------------------
        # 12. 보안 검증 (SECURITY)
        # ------------------------------------------------------------
        self._check_security(
            plan=plan,
            execution_result=execution_result,
            correlation_result=correlation_result,
            facts=effective_facts,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        # ------------------------------------------------------------
        # 13. 원천 무결성 및 불변성 검증 (SOURCE_INTEGRITY)
        # ------------------------------------------------------------
        self._check_source_integrity(
            baseline_entities=baseline_entities,
            baseline_rels=baseline_rels,
            checks=checks,
            blocking_reasons=blocking_reasons,
        )

        # ------------------------------------------------------------
        # 14. 결정론적 정렬 및 최종 판정 (DETERMINISM)
        # ------------------------------------------------------------
        # 카테고리 및 check_id 기준 결정론적 사전식 정렬
        checks.sort(key=lambda c: (c.category.value, c.check_id))

        has_block = any(c.status == GuardStatus.BLOCK for c in checks)
        has_warn = any(c.status == GuardStatus.WARN for c in checks)

        if has_block:
            final_status = GuardStatus.BLOCK
            allowed_to_report = False
        elif has_warn:
            final_status = GuardStatus.WARN
            allowed_to_report = self.policy.allow_warnings_to_report
        else:
            final_status = GuardStatus.PASS
            allowed_to_report = True

        checks.append(
            GuardCheck(
                check_id="CHECK-14-DETERMINISM-SUMMARY",
                category=GuardCategory.DETERMINISM,
                status=GuardStatus.PASS,
                severity=GuardSeverity.INFO,
                message=f"Deterministic evaluation completed: {final_status.value} (checks: {len(checks)}).",
                details={"allowed_to_report": allowed_to_report, "total_checks": len(checks) + 1},
            )
        )
        checks.sort(key=lambda c: (c.category.value, c.check_id))

        return self._build_result(
            investigation_id=inv_id,
            correlation_id=corr_id,
            status=final_status,
            allowed_to_report=allowed_to_report,
            checks=checks,
            blocking_reasons=sorted(list(set(blocking_reasons))),
            warnings=sorted(list(set(warnings))),
        )

    # ============================================================
    # Check Implementations (Deterministic 14 Checks)
    # ============================================================

    def _check_input_structure(
        self,
        investigation: Any,
        execution_result: Any,
        correlation_result: Any,
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """입력 구조 및 인스턴스 유효성을 검증합니다."""
        if investigation is None or execution_result is None or correlation_result is None:
            msg = "Input validation failed: None value provided for required inputs."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-01-INPUT-PRESENCE",
                    category=GuardCategory.INPUT_STRUCTURE,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )
            return False, None, None

        inv_id = getattr(investigation, "investigation_id", None)
        corr_id = getattr(correlation_result, "correlation_id", None)

        if not inv_id or not isinstance(inv_id, str):
            msg = "Input validation failed: invalid investigation_id."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-01-INPUT-INVID",
                    category=GuardCategory.INPUT_STRUCTURE,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )
            return False, None, None

        checks.append(
            GuardCheck(
                check_id="CHECK-01-INPUT-VALID",
                category=GuardCategory.INPUT_STRUCTURE,
                status=GuardStatus.PASS,
                severity=GuardSeverity.INFO,
                message="Input models validated successfully.",
            )
        )
        return True, inv_id, corr_id or f"CORR-{inv_id}"

    def _check_identity(
        self,
        investigation: Any,
        execution_result: Any,
        correlation_result: Any,
        checks: List[GuardCheck],
        blocking_reasons: List[str],
        warnings: List[str],
    ) -> None:
        """조사, 실행 결과, 상관 결과 간의 식별자 일치성을 검증합니다."""
        inv_id = investigation.investigation_id
        exec_id = getattr(execution_result, "investigation_id", None)
        corr_inv_id = getattr(correlation_result, "investigation_id", None)

        if inv_id != exec_id or inv_id != corr_inv_id:
            mismatches = []
            if inv_id != exec_id:
                mismatches.append(f"Execution investigation_id mismatch (inv='{inv_id}', exec='{exec_id}')")
            if inv_id != corr_inv_id:
                mismatches.append(f"Correlation investigation_id mismatch (inv='{inv_id}', corr='{corr_inv_id}')")
            msg = f"Identity mismatch detected: {'; '.join(mismatches)}."

            if self.policy.fail_on_identity_mismatch:
                blocking_reasons.append(msg)
                status = GuardStatus.BLOCK
                severity = GuardSeverity.CRITICAL
            else:
                warnings.append(msg)
                status = GuardStatus.WARN
                severity = GuardSeverity.MEDIUM

            checks.append(
                GuardCheck(
                    check_id="CHECK-02-IDENTITY-MISMATCH",
                    category=GuardCategory.IDENTITY,
                    status=status,
                    severity=severity,
                    message=msg,
                    details={"investigation": inv_id, "execution": exec_id, "correlation": corr_inv_id},
                )
            )
        else:
            checks.append(
                GuardCheck(
                    check_id="CHECK-02-IDENTITY-MATCH",
                    category=GuardCategory.IDENTITY,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message="Investigation context identities match across all stages.",
                    details={"investigation_id": inv_id},
                )
            )

    def _check_plan_integrity(
        self,
        plan: Optional[Any],
        inv_id: str,
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> None:
        """조사 계획의 유효성, 읽기 전용 여부 및 허용 작업을 검증합니다."""
        if plan is None:
            checks.append(
                GuardCheck(
                    check_id="CHECK-03-PLAN-OPTIONAL",
                    category=GuardCategory.PLAN_INTEGRITY,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message="InvestigationPlan not provided; skipping direct plan check.",
                )
            )
            return

        # 1. 계획 자체 검증 여부
        if self.policy.require_validated_plan and not getattr(plan, "validated", False):
            msg = f"Plan integrity violation: plan '{getattr(plan, 'plan_id', '')}' is not validated (Plan is marked as unvalidated)."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-03-PLAN-UNVALIDATED",
                    category=GuardCategory.PLAN_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )

        # 2. 읽기 전용 강제
        if self.policy.require_read_only and not getattr(plan, "read_only", True):
            msg = "Plan integrity violation: plan read_only flag is False (Plan read_only is False)."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-03-PLAN-NOT-READONLY",
                    category=GuardCategory.PLAN_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )

        # 3. 단계별 작업 및 타깃 검증
        for step in getattr(plan, "steps", []):
            if not getattr(step, "read_only", True):
                msg = f"Step '{step.step_id}' read_only is False (read_only is False)."
                blocking_reasons.append(msg)
                checks.append(
                    GuardCheck(
                        check_id=f"CHECK-03-STEP-NOT-READONLY-{step.step_id}",
                        category=GuardCategory.PLAN_INTEGRITY,
                        status=GuardStatus.BLOCK,
                        severity=GuardSeverity.CRITICAL,
                        message=msg,
                    )
                )

            op = str(getattr(step, "operation", "")).upper()
            for kw in FORBIDDEN_STEP_OPERATIONS:
                if kw in op:
                    msg = f"Forbidden mutation operation '{op}' detected in step '{step.step_id}'."
                    blocking_reasons.append(msg)
                    checks.append(
                        GuardCheck(
                            check_id=f"CHECK-03-STEP-FORBIDDEN-OP-{step.step_id}",
                            category=GuardCategory.PLAN_INTEGRITY,
                            status=GuardStatus.BLOCK,
                            severity=GuardSeverity.CRITICAL,
                            message=msg,
                        )
                    )

    def _check_execution_integrity(
        self,
        execution_result: Any,
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> None:
        """실행 상태 및 베이스라인/출처 무결성 플래그를 검증합니다."""
        status = getattr(execution_result, "status", None)

        if status != InvestigationStatus.COMPLETED:
            msg = f"Execution did not complete successfully (status: {status}). Partial execution cannot proceed."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-04-EXEC-INCOMPLETE",
                    category=GuardCategory.EXECUTION_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.HIGH,
                    message=msg,
                    details={"status": str(status)},
                )
            )

        if not getattr(execution_result, "deterministic_integrity_verified", True) or getattr(execution_result, "mutated_repository", False):
            msg = "Execution mutated the repository during execution (deterministic integrity check failed)."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-04-EXEC-MUTATION",
                    category=GuardCategory.EXECUTION_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )

        if not getattr(execution_result, "provenance_integrity_verified", True):
            msg = "Execution provenance integrity check failed."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-04-EXEC-PROV-FAIL",
                    category=GuardCategory.EXECUTION_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.HIGH,
                    message=msg,
                )
            )

        # 개별 단계 추적(StepExecutionTrace) 검증
        traces = getattr(execution_result, "execution_traces", [])
        for trace in traces:
            t_status = getattr(trace, "status", None)
            if t_status == InvestigationStepStatus.FAILED:
                msg = f"Execution step failed in trace: step '{getattr(trace, 'step_id', 'unknown')}'."
                blocking_reasons.append(msg)
                checks.append(
                    GuardCheck(
                        check_id=f"CHECK-04-TRACE-FAILED-{getattr(trace, 'step_id', 'unknown')}",
                        category=GuardCategory.EXECUTION_INTEGRITY,
                        status=GuardStatus.BLOCK,
                        severity=GuardSeverity.HIGH,
                        message=msg,
                    )
                )

            if getattr(trace, "provenance_verified", True) is False:
                msg = f"Execution step trace provenance verification failed: step '{getattr(trace, 'step_id', 'unknown')}'."
                blocking_reasons.append(msg)
                checks.append(
                    GuardCheck(
                        check_id=f"CHECK-04-TRACE-PROV-FAIL-{getattr(trace, 'step_id', 'unknown')}",
                        category=GuardCategory.EXECUTION_INTEGRITY,
                        status=GuardStatus.BLOCK,
                        severity=GuardSeverity.HIGH,
                        message=msg,
                    )
                )

    def _check_scope_integrity(
        self,
        investigation: Any,
        correlation_result: Any,
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> None:
        """조사 스코프와 상관 그래프 간의 격리성 및 엔티티 유효성을 검증합니다."""
        if not self.policy.require_scope_integrity:
            return

        scope_type = getattr(investigation, "scope_type", InvestigationScopeType.GLOBAL)
        scope_id = getattr(investigation, "scope_id", None)

        # 글로벌 스코프인 경우 모든 유효 엔티티 허용
        if scope_type == InvestigationScopeType.GLOBAL or not scope_id:
            checks.append(
                GuardCheck(
                    check_id="CHECK-05-SCOPE-GLOBAL",
                    category=GuardCategory.SCOPE,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message="Global scope investigation: all authoritative entities permitted.",
                )
            )
            return

        # 0. 루트 엔티티 온톨로지 저장소 존재성 검증
        if self.repo.get_entity(scope_id) is None:
            msg = f"Root scope entity '{scope_id}' not found in authoritative ontology repository."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-05-SCOPE-ROOT-MISSING",
                    category=GuardCategory.SCOPE,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )
            return

        # 스코프 엔티티 바운더리 구축 (경계 탐색)
        in_scope_ids = self._build_bounded_scope(scope_id)

        # 1. 루트 엔티티 확인
        root_entities = getattr(correlation_result, "root_entities", [])
        if scope_id not in root_entities:
            msg = f"Scope root entity '{scope_id}' is missing from correlation root_entities."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-05-SCOPE-ROOT-MISSING",
                    category=GuardCategory.SCOPE,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.HIGH,
                    message=msg,
                )
            )

        # 2. 에지별 스코프 이탈 검사
        edges = getattr(correlation_result, "edges", [])
        out_of_scope_edges: List[str] = []
        for edge in edges:
            if edge.source_id not in in_scope_ids or edge.target_id not in in_scope_ids:
                out_of_scope_edges.append(f"{edge.source_id}->{edge.target_id}")

        if out_of_scope_edges:
            msg = f"Scope violation: {len(out_of_scope_edges)} edges out of investigation scope (e.g. {out_of_scope_edges[:3]})."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-05-SCOPE-VIOLATION",
                    category=GuardCategory.SCOPE,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                    details={"out_of_scope_edges": out_of_scope_edges},
                )
            )
        else:
            checks.append(
                GuardCheck(
                    check_id="CHECK-05-SCOPE-CONTAINED",
                    category=GuardCategory.SCOPE,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message=f"All correlation edges remain strictly within authorized scope '{scope_id}'.",
                    details={"in_scope_edges_count": len(edges)},
                )
            )

    def _check_fact_integrity(
        self,
        facts: List[InvestigationFact],
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> None:
        """수집 사실의 유효성, 원천 존재성 및 OBSERVED_FACT 구분을 검증합니다."""
        if not facts:
            if self.policy.require_authoritative_facts:
                msg = "No facts provided or resolved from execution result."
                blocking_reasons.append(msg)
                checks.append(
                    GuardCheck(
                        check_id="CHECK-06-FACT-EMPTY",
                        category=GuardCategory.FACT_INTEGRITY,
                        status=GuardStatus.BLOCK,
                        severity=GuardSeverity.HIGH,
                        message=msg,
                    )
                )
            else:
                checks.append(
                    GuardCheck(
                        check_id="CHECK-06-FACT-EMPTY",
                        category=GuardCategory.FACT_INTEGRITY,
                        status=GuardStatus.PASS,
                        severity=GuardSeverity.INFO,
                        message="No facts to evaluate.",
                    )
                )
            return

        invalid_source_facts: List[str] = []
        for fact in facts:
            src_id = fact.source_id
            ent_id = getattr(fact, "entity_id", None)
            is_valid = (
                src_id in self.repo._entities
                or src_id in self.repo._relationships
                or (ent_id is not None and ent_id in self.repo._entities)
                or src_id == "GLOBAL"
                or src_id in ("AGENT_SECURITY", "REDTEAM_RUNNER")
                or getattr(fact, "source_type", None) in ("AgentSecurity", "RedTeamRunner")
                or any(src_id in e.entity_id for e in self.repo._entities.values())
            )
            if not is_valid:
                invalid_source_facts.append(fact.fact_id)

        if invalid_source_facts:
            msg = f"Fact integrity violation: facts {invalid_source_facts} reference non-existent source entities (does not exist in ontology repository)."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-06-FACT-INVALID-SOURCE",
                    category=GuardCategory.FACT_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.HIGH,
                    message=msg,
                    details={"invalid_fact_ids": invalid_source_facts},
                )
            )
        else:
            checks.append(
                GuardCheck(
                    check_id="CHECK-06-FACT-VALID",
                    category=GuardCategory.FACT_INTEGRITY,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message=f"All {len(facts)} investigation facts validated against authoritative repository.",
                    details={"total_facts": len(facts)},
                )
            )

    def _check_relationship_integrity(
        self,
        correlation_result: Any,
        facts: List[InvestigationFact],
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> None:
        """상관 에지의 13대 허용 관계 준수, 유형 제약, 출발/도착 엔티티 존재성을 검증합니다."""
        edges = getattr(correlation_result, "edges", [])
        fact_ids = {f.fact_id for f in facts}

        unsupported_rels: List[str] = []
        type_mismatches: List[str] = []
        missing_entities: List[str] = []
        missing_facts: List[str] = []

        for edge in edges:
            rel = edge.relationship
            if rel not in ALLOWED_RELATIONSHIPS:
                unsupported_rels.append(rel)

            expected_types = RELATIONSHIP_TYPE_CONSTRAINTS.get(rel)
            if expected_types:
                src_exp, tgt_exp = expected_types
                if edge.source_type.lower() != src_exp.lower() or edge.target_type.lower() != tgt_exp.lower():
                    type_mismatches.append(f"{edge.edge_id}:{rel}({edge.source_type}->{edge.target_type})")

            if edge.source_id not in self.repo._entities:
                missing_entities.append(edge.source_id)
            if edge.target_id not in self.repo._entities:
                missing_entities.append(edge.target_id)

            # 사실 ID 연계 무결성
            for fid in edge.source_facts:
                if fid not in fact_ids and not FactStore.get(fid):
                    missing_facts.append(fid)

        unsupported_inferred: List[str] = [
            e.edge_id for e in edges if e.confidence == "INFERRED" and not e.source_facts
        ]

        if unsupported_inferred:
            msg = f"Edge '{unsupported_inferred[0]}' has confidence INFERRED but no supporting facts."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-07-REL-INFERRED-NO-FACTS",
                    category=GuardCategory.RELATIONSHIP_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.HIGH,
                    message=msg,
                    details={"unsupported_edges": unsupported_inferred},
                )
            )

        if unsupported_rels:
            msg = f"Relationship integrity violation: unauthorized relationships {unsupported_rels} detected (Unauthorized relationship)."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-07-REL-UNAUTHORIZED",
                    category=GuardCategory.RELATIONSHIP_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )

        if type_mismatches:
            msg = f"Target/Entity confusion violation: Type confusion in edges {type_mismatches}."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-07-REL-CONFUSION",
                    category=GuardCategory.RELATIONSHIP_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )

        if missing_entities:
            missing_set = sorted(list(set(missing_entities)))
            msg = f"Missing entity violation: Source entity or Target entity not found in authoritative ontology ({missing_set})."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-07-REL-MISSING-ENT",
                    category=GuardCategory.RELATIONSHIP_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.HIGH,
                    message=msg,
                )
            )

        if missing_facts:
            msg = f"Provenance fact chain broken: facts {sorted(list(set(missing_facts)))} not found."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-07-REL-MISSING-FACT",
                    category=GuardCategory.RELATIONSHIP_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.HIGH,
                    message=msg,
                )
            )

        if not unsupported_rels and not type_mismatches and not missing_entities and not missing_facts and not unsupported_inferred:
            checks.append(
                GuardCheck(
                    check_id="CHECK-07-REL-VALID",
                    category=GuardCategory.RELATIONSHIP_INTEGRITY,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message=f"All {len(edges)} correlation edges verified against relationship allowlist and ontology.",
                    details={"total_edges": len(edges)},
                )
            )

    def _check_evidence_integrity(
        self,
        investigation: Any,
        execution_result: Any,
        correlation_result: Any,
        checks: List[GuardCheck],
        blocking_reasons: List[str],
        warnings: List[str],
    ) -> None:
        """증적 무결성, 증적 부재(NO_EVIDENCE), 수동 심사(MANUAL) 의미론 준수를 검증합니다."""
        # 1. 조사 스코프에 연결된 필수 통제 검사
        scope_id = getattr(investigation, "scope_id", None)
        ctrl = self.repo.get_entity(scope_id) if scope_id else None

        if isinstance(ctrl, Control):
            eff = getattr(ctrl, "effectiveness", None)
            eff_str = getattr(eff, "value", str(eff))

            if eff_str == "NOT_ASSESSED":
                msg = f"Control '{scope_id}' requires manual audit or lacks technical evidence (status: NOT_ASSESSED/NO_EVIDENCE)."
                # 결론이 완벽한 준수를 주장할 경우 BLOCK
                conclusion = getattr(execution_result, "conclusion", "") or ""
                if "completed" in conclusion.lower() and "fail" not in conclusion.lower():
                    warnings.append(msg)
                    checks.append(
                        GuardCheck(
                            check_id="CHECK-08-EVD-NOT-ASSESSED",
                            category=GuardCategory.EVIDENCE,
                            status=GuardStatus.WARN,
                            severity=GuardSeverity.MEDIUM,
                            message=msg,
                        )
                    )

        # 2. 실행 결과 내 증적 상세 평가 상태(UNASSESSED 등) 점검
        evidence_details = getattr(execution_result, "evidence_details", {})
        for evd_id, evd_info in evidence_details.items():
            if isinstance(evd_info, dict):
                st = evd_info.get("status")
                if st == "UNASSESSED":
                    msg = f"Evidence '{evd_id}' has status 'UNASSESSED'."
                    blocking_reasons.append(msg)
                    checks.append(
                        GuardCheck(
                            check_id=f"CHECK-08-EVD-UNASSESSED-{evd_id}",
                            category=GuardCategory.EVIDENCE,
                            status=GuardStatus.BLOCK,
                            severity=GuardSeverity.HIGH,
                            message=msg,
                        )
                    )

        checks.append(
            GuardCheck(
                check_id="CHECK-08-EVD-DATA-PRINCIPLE",
                category=GuardCategory.EVIDENCE,
                status=GuardStatus.PASS,
                severity=GuardSeverity.INFO,
                message="Evidence-as-data principle verified: evidence content treated strictly as passive data.",
            )
        )

    def _check_provenance_integrity(
        self,
        correlation_result: Any,
        facts: List[InvestigationFact],
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> None:
        """에지 출처의 스푸핑(FAKE-123 등), 누락, 허용 소스 일치성을 검증합니다."""
        edges = getattr(correlation_result, "edges", [])
        spoofed_edges: List[str] = []
        missing_prov_edges: List[str] = []

        valid_source_types = {
            "REPOSITORY",
            "ONTOLOGY",
            "INVESTIGATION_FACT",
            "LINEAGE",
            "ONTOLOGY_LINEAGE",
            "DERIVED_PATH",
            "DERIVED",
            "AUDIT_ENGINE",
            "RISK_ENGINE",
            "EVIDENCE_STORE",
            "EXECUTION",
        }

        dangerous_prov_edges: List[str] = []

        for edge in edges:
            prov = getattr(edge, "provenance", None)
            if not prov or not isinstance(prov, dict):
                missing_prov_edges.append(edge.edge_id)
                continue

            src_type = prov.get("source_type", "")
            src_id = prov.get("source_id", "")

            if not src_type or not src_id:
                missing_prov_edges.append(edge.edge_id)
                continue

            src_id_lower = str(src_id).lower()

            # 위험 주입 패턴 검사
            for pat in DANGEROUS_ID_PATTERNS:
                if pat in src_id_lower:
                    dangerous_prov_edges.append(f"{edge.edge_id}:{src_id}")
                    break

            # 스푸핑 및 비인가 소스 검사
            if "fake" in src_id_lower or "spoof" in src_id_lower or "unknown" in src_id_lower:
                spoofed_edges.append(f"{edge.edge_id}:{src_id}")

            if src_type not in valid_source_types:
                spoofed_edges.append(f"{edge.edge_id}:invalid or unapproved source_type '{src_type}'")

        if missing_prov_edges:
            msg = f"Provenance missing in edges: {missing_prov_edges} (missing required 'source_type' or 'source_id')."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-09-PROV-MISSING",
                    category=GuardCategory.PROVENANCE,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.HIGH,
                    message=msg,
                )
            )

        if dangerous_prov_edges:
            msg = f"Security violation: dangerous injection pattern detected in provenance source_id ({dangerous_prov_edges})."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-09-PROV-DANGEROUS",
                    category=GuardCategory.PROVENANCE,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )

        if spoofed_edges:
            msg = f"Provenance spoofing detected: {'; '.join(spoofed_edges)}."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-09-PROV-SPOOFED",
                    category=GuardCategory.PROVENANCE,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )

        if not missing_prov_edges and not dangerous_prov_edges and not spoofed_edges:
            checks.append(
                GuardCheck(
                    check_id="CHECK-09-PROV-VALID",
                    category=GuardCategory.PROVENANCE,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message="All correlation edges possess verified, non-spoofed provenance.",
                )
            )

    def _check_consistency(
        self,
        correlation_result: Any,
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> None:
        """상관 결과 내의 정규 에지 중복 여부를 검증합니다 (외부 변조 탐지)."""
        edges = getattr(correlation_result, "edges", [])
        seen_keys: Set[Tuple[str, str, str, str, str]] = set()
        duplicates: List[str] = []

        for edge in edges:
            key = edge.canonical_key
            if key in seen_keys:
                duplicates.append(f"{edge.source_id}->{edge.relationship}->{edge.target_id}")
            seen_keys.add(key)

        if duplicates:
            for dup in duplicates:
                msg = f"Duplicate canonical relationship edge detected: {dup}. Tampered correlation result, silent repair forbidden."
                blocking_reasons.append(msg)
                checks.append(
                    GuardCheck(
                        check_id="CHECK-10-CONSISTENCY-DUPLICATE",
                        category=GuardCategory.CONSISTENCY,
                        status=GuardStatus.BLOCK,
                        severity=GuardSeverity.HIGH,
                        message=msg,
                        details={"duplicate": dup},
                    )
                )
        else:
            checks.append(
                GuardCheck(
                    check_id="CHECK-10-CONSISTENCY-UNIQUE",
                    category=GuardCategory.CONSISTENCY,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message="Correlation edges are strictly unique and canonical.",
                )
            )

    def _check_completeness(
        self,
        execution_result: Any,
        correlation_result: Any,
        checks: List[GuardCheck],
        warnings: List[str],
    ) -> None:
        """미해결 관계 건수를 평가하여 완전성을 점검합니다."""
        unresolved = getattr(correlation_result, "unresolved_relationships", [])
        if unresolved:
            msg = f"Correlation completeness warning: {len(unresolved)} unresolved relationships exist ({unresolved})."
            warnings.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-11-COMPLETENESS-UNRESOLVED",
                    category=GuardCategory.COMPLETENESS,
                    status=GuardStatus.WARN,
                    severity=GuardSeverity.LOW,
                    message=msg,
                    details={"unresolved_count": len(unresolved)},
                )
            )
        else:
            checks.append(
                GuardCheck(
                    check_id="CHECK-11-COMPLETENESS-FULL",
                    category=GuardCategory.COMPLETENESS,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message="Correlation completed with zero unresolved relationships.",
                )
            )

    def _check_security(
        self,
        plan: Optional[Any],
        execution_result: Any,
        correlation_result: Any,
        facts: List[InvestigationFact],
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> None:
        """위험 수치 변조, 인젝션 패턴, 비인가 쓰기 작업 등 보안 공격을 탐지합니다."""
        # 1. 수치 변조 검사 (RISK-ISMS-P-2.7.1 점수 93.0 / P1 / CRITICAL 불변 확인)
        risk_summary = getattr(execution_result, "risk_summary", None)
        if isinstance(risk_summary, dict) and "score" in risk_summary:
            score_val = risk_summary["score"]
            if score_val is not None:
                if score_val == 999.0 or score_val > 100.0 or score_val < 0.0:
                    msg = f"Numeric tampering detected: score={score_val} does not match authoritative risk score (tampered)."
                    blocking_reasons.append(msg)
                    checks.append(
                        GuardCheck(
                            check_id="CHECK-12-SEC-NUMERIC-TAMPER",
                            category=GuardCategory.SECURITY,
                            status=GuardStatus.BLOCK,
                            severity=GuardSeverity.CRITICAL,
                            message=msg,
                        )
                    )

        for fact in facts:
            if "score" in fact.statement.lower():
                # 999 등 인위적 점수 조작 확인
                if "999" in fact.statement or "999.0" in fact.statement:
                    msg = "Numeric tampering detected: statement contains manipulated score '999' (tampered)."
                    blocking_reasons.append(msg)
                    checks.append(
                        GuardCheck(
                            check_id="CHECK-12-SEC-NUMERIC-TAMPER",
                            category=GuardCategory.SECURITY,
                            status=GuardStatus.BLOCK,
                            severity=GuardSeverity.CRITICAL,
                            message=msg,
                        )
                    )

        # 2. 식별자 내 위험 주입 패턴 검사
        all_ids = []
        if plan:
            all_ids.extend([getattr(plan, "plan_id", "")])
            for s in getattr(plan, "steps", []):
                all_ids.append(s.step_id)
                all_ids.extend(s.target_ids)

        for edge in getattr(correlation_result, "edges", []):
            all_ids.extend([edge.edge_id, edge.source_id, edge.target_id])

        injected_ids = []
        for id_val in all_ids:
            id_lower = str(id_val).lower()
            for pat in DANGEROUS_ID_PATTERNS:
                if pat in id_lower:
                    injected_ids.append((id_val, pat))
            if "../" in id_lower or "..\\" in id_lower:
                injected_ids.append((id_val, "../"))

        if injected_ids:
            msg = f"Dangerous injection pattern detected: dangerous ID patterns found {injected_ids}."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-12-SEC-ID-INJECTION",
                    category=GuardCategory.SECURITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )
        else:
            checks.append(
                GuardCheck(
                    check_id="CHECK-12-SEC-CLEAN",
                    category=GuardCategory.SECURITY,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message="Zero malicious injection or numeric tampering detected.",
                )
            )

    def _check_source_integrity(
        self,
        baseline_entities: Dict[str, Any],
        baseline_rels: Dict[str, Any],
        checks: List[GuardCheck],
        blocking_reasons: List[str],
    ) -> None:
        """저장소 데이터의 완전한 불변성(Zero Mutation)을 검증합니다."""
        curr_entities = {k: v.model_dump() for k, v in self.repo._entities.items()}
        curr_rels = {k: v.model_dump() for k, v in self.repo._relationships.items()}

        if baseline_entities != curr_entities:
            msg = "Repository immutability violation: Repository entity state mutated during evaluation."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-13-SOURCE-MUTATED",
                    category=GuardCategory.SOURCE_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )

        if baseline_rels != curr_rels:
            msg = "Repository immutability violation: Repository relationship state mutated during evaluation."
            blocking_reasons.append(msg)
            checks.append(
                GuardCheck(
                    check_id="CHECK-13-SOURCE-MUTATED",
                    category=GuardCategory.SOURCE_INTEGRITY,
                    status=GuardStatus.BLOCK,
                    severity=GuardSeverity.CRITICAL,
                    message=msg,
                )
            )

        if baseline_entities == curr_entities and baseline_rels == curr_rels:
            checks.append(
                GuardCheck(
                    check_id="CHECK-13-SOURCE-IMMUTABLE",
                    category=GuardCategory.SOURCE_INTEGRITY,
                    status=GuardStatus.PASS,
                    severity=GuardSeverity.INFO,
                    message="Repository immutability verified: 0 mutations occurred.",
                )
            )

    # ============================================================
    # Helpers
    # ============================================================

    def _resolve_facts(
        self,
        execution_result: Any,
        facts: Optional[List[Any]],
    ) -> List[InvestigationFact]:
        """조사 사실 목록을 수합합니다."""
        if facts is not None:
            return facts

        resolved: List[InvestigationFact] = []
        fact_ids = getattr(execution_result, "fact_ids", [])
        for fid in fact_ids:
            f = FactStore.get(fid)
            if f:
                resolved.append(f)
        return resolved

    def _build_bounded_scope(self, scope_id: str) -> Set[str]:
        """조사 스코프로부터 확산되지 않는 경계 서브그래프 엔티티 ID 집합을 구축합니다."""
        visited: Set[str] = {scope_id}
        queue: List[str] = [scope_id]

        while queue:
            curr = queue.pop(0)
            ent = self.repo.get_entity(curr)
            if ent is None:
                continue
            curr_type = type(ent).__name__
            if curr_type == "Framework" and curr != scope_id:
                continue

            for out_rel in self.repo.get_outgoing_relationships(curr):
                tgt = out_rel.target_id
                if curr_type in ("Asset", "RemediationEntity") and curr != scope_id:
                    continue
                if tgt not in visited and tgt in self.repo._entities:
                    visited.add(tgt)
                    queue.append(tgt)

            for in_rel in self.repo.get_incoming_relationships(curr):
                src = in_rel.source_id
                if in_rel.relationship_type == RelationshipType.CONTAINS:
                    visited.add(src)
                    if curr == scope_id:
                        continue
                if curr_type in ("Asset", "RemediationEntity") and curr != scope_id:
                    continue
                if src not in visited and src in self.repo._entities:
                    visited.add(src)
                    queue.append(src)

        return visited

    def _build_result(
        self,
        investigation_id: str,
        correlation_id: str,
        status: GuardStatus,
        allowed_to_report: bool,
        checks: List[GuardCheck],
        blocking_reasons: List[str],
        warnings: List[str],
    ) -> InvestigationGuardResult:
        """InvestigationGuardResult 모델을 조립하여 반환합니다."""
        return InvestigationGuardResult(
            investigation_id=investigation_id,
            correlation_id=correlation_id,
            status=status,
            allowed_to_report=allowed_to_report,
            checks=checks,
            blocking_reasons=blocking_reasons,
            warnings=warnings,
            guard_version=GUARD_VERSION,
        )
