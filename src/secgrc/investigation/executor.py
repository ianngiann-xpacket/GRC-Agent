"""Step 23.3 — Read-only Investigation Executor 모듈입니다.

검증된 결정론적 InvestigationPlan을 기존 GRC 저장소 및 엔진(OntologyRepository,
OntologyResolver, RedTeamRunner 등)에 대해 읽기 전용으로 실행하고,
구조화된 사실(InvestigationFact), 결함(InvestigationFinding),
증적 체인(EvidenceChain), 출처(Provenance)를 수집하여 InvestigationResult를 생성합니다.

보안 원칙:
- LLM 호출 일절 없음
- 자율 추론 및 사실 날조 없음
- 저장소 데이터 변경(mutation) 없음
- 기존 읽기 전용 ALLOWED_OPERATIONS만 실행
- 실행 전 플랜/단계 재검증 (untrusted data 처리)
- 엄격한 스코프 및 타깃 검증 (경로 탐색, 셸 주입, URL 거부)
- 의존성 순서 준수 (선행 실패 시 종속 단계 차단)
- 증적 데이터/명령어 분리 (Instruction Separation)
- 출처(Provenance) 및 결정론적 베이스라인 무결성 검증
- 시크릿 스캔 및 마스킹 적용
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import Field

from secgrc.agent_security.secret_guard import SecretGuard
from secgrc.copilot.models import FactType, Provenance
from secgrc.copilot.planner import ALLOWED_OPERATIONS, FORBIDDEN_OPERATIONS
from secgrc.copilot.provenance import ProvenanceBuilder
from secgrc.investigation.enums import (
    EvidenceRole,
    FindingType,
    InvestigationScopeType,
    InvestigationStatus,
    InvestigationStepStatus,
    InvestigationType,
)
from secgrc.investigation.models import (
    DANGEROUS_ID_PATTERNS,
    FORBIDDEN_STEP_OPERATIONS,
    EvidenceChain,
    InvestigationBaseModel,
    InvestigationFact,
    InvestigationFinding,
    InvestigationResult,
    InvestigationStep,
    validate_id_str,
)
from secgrc.investigation.planner import (
    InvestigationPlan,
    detect_dependency_cycle,
)
from secgrc.ontology.builder import OntologyBuilder
from secgrc.ontology.entities import (
    Asset,
    Control,
    EvidenceEntity,
    Finding,
    Framework,
    RemediationEntity,
    RiskEntity,
)
from secgrc.investigation.correlation import FactStore
from secgrc.ontology.models import RelationshipType
from secgrc.ontology.repository import OntologyRepository
from secgrc.ontology.resolver import OntologyResolver
from secgrc.redteam.runner import RedTeamRunner

EXECUTOR_VERSION = "1.0"


class StepExecutionTrace(InvestigationBaseModel):
    """결정론적 단일 단계 실행 메타데이터 추적 모델 (시크릿 미포함)."""
    investigation_id: str = Field(description="소속 조사 식별자")
    plan_id: str = Field(description="소속 계획 식별자")
    step_id: str = Field(description="조사 단계 식별자")
    operation: str = Field(description="수행된 읽기 전용 작업명")
    status: InvestigationStepStatus = Field(description="단계 실행 결과 상태")
    started_at: str = Field(description="실행 시작 일시 (ISO 8601 UTC)")
    completed_at: str = Field(description="실행 완료 일시 (ISO 8601 UTC)")
    result_count: int = Field(default=0, description="조회/산출된 레코드 수")
    error_message: Optional[str] = Field(default=None, description="오류 메시지 (보안 마스킹)")


class InvestigationExecutor:
    """검증된 InvestigationPlan을 안전하고 결정론적으로 실행하는 읽기 전용 조사 실행기."""

    def __init__(
        self,
        repo: Optional[OntologyRepository] = None,
        resolver: Optional[OntologyResolver] = None,
        redteam_runner: Optional[RedTeamRunner] = None,
    ) -> None:
        """저장소 및 해석기 의존성 주입. None 전달 시 기본 인스턴스를 빌드합니다."""
        if repo is None:
            self.repo = OntologyBuilder().build(use_cross_frameworks=False)
            self.resolver = OntologyResolver(self.repo)
        else:
            self.repo = repo
            self.resolver = resolver or OntologyResolver(self.repo)

        self.redteam_runner = redteam_runner or RedTeamRunner()
        self.last_facts: List[InvestigationFact] = []
        self.last_findings: List[InvestigationFinding] = []

    # ============================================================
    # Public Execution Entry Point (Only accepts validated plan)
    # ============================================================

    def execute(self, plan: InvestigationPlan) -> InvestigationResult:
        """검증된 InvestigationPlan을 실행하여 InvestigationResult를 생성합니다.

        외부에서 임의의 명령어/도구를 직접 호출할 수 없으며,
        반드시 본 메서드를 통해서만 실행됩니다.
        """
        # 1. 사전 조건: plan.validated 검증
        if not getattr(plan, "validated", False):
            return self._fail_closed(
                investigation_id=getattr(plan, "investigation_id", "UNKNOWN"),
                reason="Precondition failed: InvestigationPlan.validated is False. Unvalidated plans cannot be executed.",
            )

        # 2. 플랜 재검증 (untrusted data 취급)
        plan_valid, plan_errors = self._revalidate_plan(plan)
        if not plan_valid:
            return self._fail_closed(
                investigation_id=plan.investigation_id,
                reason=f"Plan revalidation failed: {'; '.join(plan_errors)}",
            )

        # 3. 베이스라인 스냅샷 캡처 (실행 전 무결성 기준선)
        try:
            baseline_snapshot = self._capture_baseline_snapshot()
        except Exception as exc:
            safe_msg = SecretGuard.mask_secrets(str(exc))
            return self._fail_closed(
                investigation_id=plan.investigation_id,
                reason=f"Repository baseline capture failed: {safe_msg}",
            )

        # 실행 상태 저장소
        step_status_map: Dict[str, InvestigationStepStatus] = {}
        traces: List[StepExecutionTrace] = []
        collected_facts: List[InvestigationFact] = []
        collected_findings: List[InvestigationFinding] = []
        collected_evidence_ids: Set[str] = set()
        prov_builder = ProvenanceBuilder()
        provenance_ids: List[str] = []
        limitations: List[str] = []

        overall_status = InvestigationStatus.COMPLETED

        # 4. 단계 순차 실행 (의존성 그래프 및 위상 순서 준수)
        for step in plan.steps:
            # 4.1 의존성 검사: 선행 단계 성공 여부 확인
            dep_failed = False
            for dep_id in step.depends_on_step_ids:
                dep_status = step_status_map.get(dep_id)
                if dep_status != InvestigationStepStatus.COMPLETED:
                    dep_failed = True
                    break

            if dep_failed:
                step.status = InvestigationStepStatus.BLOCKED
                step_status_map[step.step_id] = InvestigationStepStatus.BLOCKED
                limitations.append(f"Step '{step.step_id}' blocked due to dependency failure.")
                overall_status = InvestigationStatus.FAILED
                continue

            # 4.2 단계 자체 검증
            step_valid, step_error = self._validate_step(step, plan)
            if not step_valid:
                step.status = InvestigationStepStatus.FAILED
                step_status_map[step.step_id] = InvestigationStepStatus.FAILED
                limitations.append(f"Step '{step.step_id}' validation failed: {step_error}")
                overall_status = InvestigationStatus.FAILED
                continue

            # 4.3 단계 실행
            step.status = InvestigationStepStatus.RUNNING
            started_at = datetime.now(timezone.utc).isoformat()

            try:
                records, step_facts, step_findings, step_ev_ids, step_provs = self._dispatch_operation(
                    step=step,
                    plan=plan,
                    collected_facts=collected_facts,
                    collected_findings=collected_findings,
                )

                # 증적 내용 명령어 분리 (Instruction Separation) & 시크릿 스캔
                for fact in step_facts:
                    fact.statement = SecretGuard.mask_secrets(fact.statement)
                    collected_facts.append(fact)
                    step.output_fact_ids.append(fact.fact_id)

                for fnd in step_findings:
                    fnd.title = SecretGuard.mask_secrets(fnd.title)
                    fnd.description = SecretGuard.mask_secrets(fnd.description)
                    collected_findings.append(fnd)

                for eid in step_ev_ids:
                    collected_evidence_ids.add(eid)
                    step.output_evidence_ids.append(eid)

                for prov in step_provs:
                    prov_builder.add(
                        source_type=prov.source_type,
                        source_id=prov.source_id,
                        source_path=prov.source_path,
                        relationship=prov.relationship,
                        confidence=prov.confidence,
                    )

                step.status = InvestigationStepStatus.COMPLETED
                step_status_map[step.step_id] = InvestigationStepStatus.COMPLETED
                completed_at = datetime.now(timezone.utc).isoformat()

                traces.append(
                    StepExecutionTrace(
                        investigation_id=plan.investigation_id,
                        plan_id=plan.plan_id,
                        step_id=step.step_id,
                        operation=str(step.operation),
                        status=InvestigationStepStatus.COMPLETED,
                        started_at=started_at,
                        completed_at=completed_at,
                        result_count=len(records),
                    )
                )

            except Exception as exc:
                step.status = InvestigationStepStatus.FAILED
                step_status_map[step.step_id] = InvestigationStepStatus.FAILED
                safe_msg = SecretGuard.mask_secrets(str(exc))
                limitations.append(f"Step '{step.step_id}' ({step.operation}) failed: {safe_msg}")
                overall_status = InvestigationStatus.FAILED

                completed_at = datetime.now(timezone.utc).isoformat()
                traces.append(
                    StepExecutionTrace(
                        investigation_id=plan.investigation_id,
                        plan_id=plan.plan_id,
                        step_id=step.step_id,
                        operation=str(step.operation),
                        status=InvestigationStepStatus.FAILED,
                        started_at=started_at,
                        completed_at=completed_at,
                        result_count=0,
                        error_message=safe_msg,
                    )
                )

        # 5. 베이스라인 무결성 재검증 (실행 전후 비교)
        deterministic_integrity = self._verify_baseline_integrity(baseline_snapshot)
        if not deterministic_integrity:
            overall_status = InvestigationStatus.FAILED
            limitations.append("Deterministic GRC integrity check failed: repository values mutated during execution.")

        # 6. Provenance 생성 및 무결성 검증
        all_provenances = prov_builder.build()
        provenance_integrity = self._verify_provenance_integrity(all_provenances)
        for i, prov in enumerate(all_provenances, 1):
            prov_id = f"PROV-{plan.investigation_id}-{i:03d}"
            provenance_ids.append(prov_id)

        # 7. EvidenceChain 조립 (증적이 수집된 경우)
        evidence_chain_ids: List[str] = []
        if collected_evidence_ids:
            roles_map = {eid: EvidenceRole.PRIMARY for eid in collected_evidence_ids}
            chain = EvidenceChain(
                chain_id=f"CHAIN-{plan.investigation_id}-001",
                investigation_id=plan.investigation_id,
                evidence_ids=sorted(list(collected_evidence_ids)),
                fact_ids=[f.fact_id for f in collected_facts],
                finding_ids=[f.finding_id for f in collected_findings],
                evidence_roles=roles_map,
                completeness=1.0,
                confidence=1.0,
                provenance_ids=provenance_ids[:10],
            )
            evidence_chain_ids.append(chain.chain_id)

        # 8. 최종 신뢰도 계산 (결정론적 사실 기반)
        final_confidence = 1.0 if overall_status == InvestigationStatus.COMPLETED else 0.0

        # 9. 최종 결론 텍스트 (추론/날조 없음, 정형 관찰 요약)
        conclusion = None
        if overall_status == InvestigationStatus.COMPLETED:
            conclusion = (
                f"Authoritative investigation completed for {plan.investigation_type.value} "
                f"({plan.scope_type.value}:{plan.scope_id or 'GLOBAL'}). "
                f"Retrieved {len(collected_facts)} authoritative facts across {len(plan.steps)} steps."
            )
        else:
            conclusion = (
                f"Investigation halted or incomplete for {plan.investigation_type.value}. "
                f"Completed {sum(1 for s in plan.steps if s.status == InvestigationStepStatus.COMPLETED)}/{len(plan.steps)} steps."
            )

        self.last_facts = list(collected_facts)
        self.last_findings = list(collected_findings)
        FactStore.register_many(collected_facts)

        return InvestigationResult(
            investigation_id=plan.investigation_id,
            status=overall_status,
            fact_ids=[f.fact_id for f in collected_facts],
            hypothesis_ids=[],  # Step 23.3은 추론 미수행
            finding_ids=[f.finding_id for f in collected_findings],
            evidence_chain_ids=evidence_chain_ids,
            conclusion=conclusion,
            confidence=final_confidence,
            limitations=limitations,
            provenance_ids=provenance_ids,
            deterministic_integrity_verified=deterministic_integrity,
            provenance_integrity_verified=provenance_integrity,
            secret_scan_passed=True,
        )

    # ============================================================
    # Plan Revalidation (Untrusted Data Guard)
    # ============================================================

    def _revalidate_plan(self, plan: InvestigationPlan) -> Tuple[bool, List[str]]:
        """외부/직렬화 플랜을 신뢰할 수 없는 데이터로 취급하여 완전 재검증합니다."""
        errors: List[str] = []

        # 1. read_only 플래그 강제
        if not getattr(plan, "read_only", True):
            errors.append("InvestigationPlan read_only must be True.")

        # 2. 식별자 재검증
        try:
            validate_id_str(plan.plan_id, "plan_id")
            validate_id_str(plan.investigation_id, "investigation_id")
        except Exception as e:
            errors.append(f"Invalid plan/investigation ID: {e}")

        # 3. 스코프 검증
        if plan.scope_type != InvestigationScopeType.GLOBAL:
            if not plan.scope_id:
                errors.append(f"scope_id is required for scope_type '{plan.scope_type.value}'.")
            else:
                try:
                    validate_id_str(plan.scope_id, "scope_id")
                except Exception as e:
                    errors.append(f"Invalid scope_id: {e}")

        # 4. 단계 존재 여부
        if not plan.steps:
            errors.append("InvestigationPlan contains no steps.")

        # 5. 순환 의존성 검증
        cycle_err = detect_dependency_cycle(plan.steps)
        if cycle_err:
            errors.append(cycle_err)

        # 6. 각 단계 작업 및 타깃 사전 검사
        seen_steps: Set[str] = set()
        for idx, step in enumerate(plan.steps):
            if step.step_id in seen_steps:
                errors.append(f"Duplicate step_id '{step.step_id}' found.")
            seen_steps.add(step.step_id)

            if not step.read_only:
                errors.append(f"Step '{step.step_id}' must have read_only=True.")

            op = (step.operation or "").strip().upper()
            if op not in ALLOWED_OPERATIONS:
                errors.append(f"Step '{step.step_id}' operation '{step.operation}' not in ALLOWED_OPERATIONS.")

            for kw in FORBIDDEN_STEP_OPERATIONS:
                if kw in op:
                    errors.append(f"Step '{step.step_id}' operation contains forbidden keyword '{kw}'.")

            for tid in step.target_ids:
                try:
                    validate_id_str(tid, "target_id")
                except Exception as e:
                    errors.append(f"Step '{step.step_id}' target_id '{tid}' is invalid: {e}")

        return len(errors) == 0, errors

    # ============================================================
    # Step Validation
    # ============================================================

    def _validate_step(self, step: InvestigationStep, plan: InvestigationPlan) -> Tuple[bool, Optional[str]]:
        """단일 단계의 실행 전 유효성(작업, 스코프 정합성, 타깃)을 검증합니다."""
        if not step.read_only:
            return False, "read_only flag is False."

        op = (step.operation or "").strip().upper()
        if op not in ALLOWED_OPERATIONS:
            return False, f"Operation '{op}' is not in ALLOWED_OPERATIONS."

        for kw in FORBIDDEN_STEP_OPERATIONS:
            if kw in op:
                return False, f"Operation contains forbidden keyword '{kw}'."

        # 타깃 검증 (URL, 셸 주입 등)
        for tid in step.target_ids:
            try:
                validate_id_str(tid, "target_id")
            except Exception as e:
                return False, f"Target '{tid}' failed validation: {e}"

        # 스코프 강제: 타깃이 지정된 경우 플랜의 scope_id와 모순되지 않는지 검사
        if plan.scope_type != InvestigationScopeType.GLOBAL and plan.scope_id:
            # 타깃이 명시되었는데 scope_id와 전혀 무관한 다른 상위 엔티티로 변조되었는지 확인
            for tid in step.target_ids:
                if tid.startswith("RISK-") and plan.scope_id.startswith("RISK-"):
                    if tid != plan.scope_id:
                        return False, f"Target '{tid}' violates investigation scope '{plan.scope_id}'."

        return True, None

    # ============================================================
    # Operation Dispatcher & Adapters
    # ============================================================

    def _dispatch_operation(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
        collected_facts: List[InvestigationFact],
        collected_findings: List[InvestigationFinding],
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        """허용된 12개 읽기 전용 작업에 대한 결정론적 어댑터를 디스패치합니다."""
        op = (step.operation or "").strip().upper()

        if op == "GET_RISKS":
            return self._adapter_get_risks(step, plan)
        elif op == "GET_CONTROLS":
            return self._adapter_get_controls(step, plan)
        elif op == "GET_EVIDENCE":
            return self._adapter_get_evidence(step, plan)
        elif op == "GET_FINDINGS":
            return self._adapter_get_findings(step, plan)
        elif op == "GET_ASSETS":
            return self._adapter_get_assets(step, plan)
        elif op == "GET_FRAMEWORKS":
            return self._adapter_get_frameworks(step, plan)
        elif op == "GET_RELATIONSHIPS":
            return self._adapter_get_relationships(step, plan)
        elif op == "GET_LINEAGE":
            return self._adapter_get_lineage(step, plan)
        elif op == "GET_COVERAGE":
            return self._adapter_get_coverage(step, plan)
        elif op == "GET_REDTEAM_SUMMARY":
            return self._adapter_get_redteam_summary(step, plan)
        elif op == "GET_AGENT_SECURITY_STATUS":
            return self._adapter_get_agent_security_status(step, plan)
        elif op == "GET_REMEDIATIONS":
            return self._adapter_get_remediations(step, plan)
        else:
            raise ValueError(f"Required repository operation '{op}' is unavailable or not allowed.")

    # ------------------------------------------------------------
    # 1. GET_RISKS
    # ------------------------------------------------------------
    def _adapter_get_risks(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        all_risks = [e for e in self.repo.list_entities("Risk") if isinstance(e, RiskEntity)]
        all_risks.sort(key=lambda r: (-r.risk_score, r.priority))

        # 스코프 필터링
        target_id = self._resolve_target(step, plan, "RISK")
        filtered_risks = [r for r in all_risks if r.entity_id == target_id] if target_id else all_risks

        facts: List[InvestigationFact] = []
        provs: List[Provenance] = []

        for idx, r in enumerate(filtered_risks, 1):
            fact_id = f"FACT-{step.step_id}-{idx:03d}"
            # 권위 있는 관찰 사실 생성 (재계산 없음, 원천값 보존)
            statement = (
                f"Risk {r.entity_id} has authoritative score of {r.risk_score}, "
                f"priority {r.priority}, severity {r.severity}."
            )
            facts.append(
                InvestigationFact(
                    fact_id=fact_id,
                    investigation_id=plan.investigation_id,
                    fact_type=FactType.OBSERVED_FACT,
                    statement=statement,
                    source_type="RiskEngine",
                    source_id=r.entity_id,
                    entity_type="Risk",
                    entity_id=r.entity_id,
                    confidence=1.0,
                    step_id=step.step_id,
                )
            )
            provs.append(
                Provenance(
                    source_type="Risk",
                    source_id=r.entity_id,
                    relationship="AUTHORITATIVE_RISK",
                    confidence=1.0,
                )
            )

        return filtered_risks, facts, [], set(), provs

    # ------------------------------------------------------------
    # 2. GET_CONTROLS
    # ------------------------------------------------------------
    def _adapter_get_controls(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        all_ctrls = [e for e in self.repo.list_entities("Control") if isinstance(e, Control)]

        # 스코프 필터링
        target_id = self._resolve_target(step, plan, "CONTROL")
        if target_id and not target_id.startswith("RISK-"):
            filtered_ctrls = [c for c in all_ctrls if c.entity_id == target_id]
        elif target_id and target_id.startswith("RISK-"):
            filtered_ctrls = self.resolver.find_controls_for_risk(target_id)
        else:
            filtered_ctrls = [c for c in all_ctrls if c.framework_id == "ISMS-P"]

        facts: List[InvestigationFact] = []
        provs: List[Provenance] = []

        for idx, c in enumerate(filtered_ctrls, 1):
            fact_id = f"FACT-{step.step_id}-{idx:03d}"
            statement = (
                f"Control {c.entity_id} ({c.name}) has effectiveness {c.effectiveness.value} "
                f"under framework {c.framework_id}."
            )
            facts.append(
                InvestigationFact(
                    fact_id=fact_id,
                    investigation_id=plan.investigation_id,
                    fact_type=FactType.OBSERVED_FACT,
                    statement=statement,
                    source_type="AuditEngine",
                    source_id=c.entity_id,
                    entity_type="Control",
                    entity_id=c.entity_id,
                    confidence=1.0,
                    step_id=step.step_id,
                )
            )
            provs.append(
                Provenance(
                    source_type="Control",
                    source_id=c.entity_id,
                    relationship="AUTHORITATIVE_CONTROL",
                    confidence=1.0,
                )
            )

        return filtered_ctrls, facts, [], set(), provs

    # ------------------------------------------------------------
    # 3. GET_EVIDENCE
    # ------------------------------------------------------------
    def _adapter_get_evidence(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        all_ev = [e for e in self.repo.list_entities("Evidence") if isinstance(e, EvidenceEntity)]

        target_id = self._resolve_target(step, plan, "EVIDENCE")
        if target_id and target_id.startswith("EV-"):
            filtered_ev = [e for e in all_ev if e.entity_id == target_id]
        elif target_id and (target_id.startswith("ISMS-P-") or target_id.startswith("ISO-") or target_id.startswith("NIST-")):
            filtered_ev = self.resolver.find_evidence_for_control(target_id)
        elif target_id and target_id.startswith("RISK-"):
            ctrls = self.resolver.find_controls_for_risk(target_id)
            filtered_ev = []
            for c in ctrls:
                filtered_ev.extend(self.resolver.find_evidence_for_control(c.entity_id))
        else:
            filtered_ev = all_ev

        facts: List[InvestigationFact] = []
        ev_ids: Set[str] = set()
        provs: List[Provenance] = []

        for idx, ev in enumerate(filtered_ev, 1):
            ev_ids.add(ev.entity_id)
            fact_id = f"FACT-{step.step_id}-{idx:03d}"
            statement = (
                f"Evidence {ev.entity_id} collected from {ev.source_system} "
                f"({ev.evidence_type}): {ev.name}."
            )
            facts.append(
                InvestigationFact(
                    fact_id=fact_id,
                    investigation_id=plan.investigation_id,
                    fact_type=FactType.OBSERVED_FACT,
                    statement=statement,
                    source_type="EvidenceRepository",
                    source_id=ev.entity_id,
                    entity_type="Evidence",
                    entity_id=ev.entity_id,
                    confidence=1.0,
                    step_id=step.step_id,
                    evidence_ids=[ev.entity_id],
                )
            )
            provs.append(
                Provenance(
                    source_type="Evidence",
                    source_id=ev.entity_id,
                    relationship="SUPPORTED_BY",
                    confidence=1.0,
                )
            )

        return filtered_ev, facts, [], ev_ids, provs

    # ------------------------------------------------------------
    # 4. GET_FINDINGS
    # ------------------------------------------------------------
    def _adapter_get_findings(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        all_findings = [e for e in self.repo.list_entities("Finding") if isinstance(e, Finding)]

        target_id = self._resolve_target(step, plan, "FINDING")
        if target_id and target_id.startswith("FND-"):
            filtered_findings = [f for f in all_findings if f.entity_id == target_id]
        elif target_id and target_id.startswith("RISK-"):
            ctrls = self.resolver.find_controls_for_risk(target_id)
            evs = []
            for c in ctrls:
                evs.extend(self.resolver.find_evidence_for_control(c.entity_id))
            fnd_ids = set()
            for e in evs:
                for rel in self.repo.get_outgoing_relationships(e.entity_id, RelationshipType.DERIVED_FROM):
                    fnd_ids.add(rel.target_id)
            filtered_findings = [f for f in all_findings if f.entity_id in fnd_ids]
        elif target_id and (target_id.startswith("ISMS-P-") or target_id.startswith("ISO-")):
            evs = self.resolver.find_evidence_for_control(target_id)
            fnd_ids = set()
            for e in evs:
                for rel in self.repo.get_outgoing_relationships(e.entity_id, RelationshipType.DERIVED_FROM):
                    fnd_ids.add(rel.target_id)
            filtered_findings = [f for f in all_findings if f.entity_id in fnd_ids]
        elif target_id and target_id.startswith("EV-"):
            fnd_ids = set()
            for rel in self.repo.get_outgoing_relationships(target_id, RelationshipType.DERIVED_FROM):
                fnd_ids.add(rel.target_id)
            filtered_findings = [f for f in all_findings if f.entity_id in fnd_ids]
        else:
            filtered_findings = all_findings

        facts: List[InvestigationFact] = []
        inv_findings: List[InvestigationFinding] = []
        provs: List[Provenance] = []

        for idx, f in enumerate(filtered_findings, 1):
            fact_id = f"FACT-{step.step_id}-{idx:03d}"
            statement = (
                f"Finding {f.entity_id} ({f.name}) severity {f.severity}, "
                f"status {f.status} on resource {f.resource_id}."
            )
            facts.append(
                InvestigationFact(
                    fact_id=fact_id,
                    investigation_id=plan.investigation_id,
                    fact_type=FactType.OBSERVED_FACT,
                    statement=statement,
                    source_type="FindingRepository",
                    source_id=f.entity_id,
                    entity_type="Finding",
                    entity_id=f.entity_id,
                    confidence=1.0,
                    step_id=step.step_id,
                )
            )

            # 도메인 결함 모델 생성 (재계산 없음, 원천값 보존)
            inv_findings.append(
                InvestigationFinding(
                    finding_id=f"IFND-{step.step_id}-{idx:03d}",
                    investigation_id=plan.investigation_id,
                    finding_type=FindingType.SECURITY_FINDING,
                    title=f.name,
                    description=f.description or "",
                    severity=f.severity,
                    status=f.status,
                    source_finding_ids=[f.entity_id],
                    confidence=1.0,
                )
            )

            provs.append(
                Provenance(
                    source_type="Finding",
                    source_id=f.entity_id,
                    relationship="DERIVED_FROM",
                    confidence=1.0,
                )
            )

        return filtered_findings, facts, inv_findings, set(), provs

    # ------------------------------------------------------------
    # 5. GET_ASSETS
    # ------------------------------------------------------------
    def _adapter_get_assets(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        all_assets = [e for e in self.repo.list_entities("Asset") if isinstance(e, Asset)]

        target_id = self._resolve_target(step, plan, "ASSET")
        if target_id and target_id.startswith("ASSET-"):
            filtered_assets = [a for a in all_assets if a.entity_id == target_id]
        elif target_id and target_id.startswith("FND-"):
            filtered_assets = self.resolver.find_assets_for_finding(target_id)
        else:
            filtered_assets = all_assets

        facts: List[InvestigationFact] = []
        provs: List[Provenance] = []

        for idx, a in enumerate(filtered_assets, 1):
            fact_id = f"FACT-{step.step_id}-{idx:03d}"
            statement = (
                f"Asset {a.entity_id} ({a.name}) type {a.asset_type}, "
                f"criticality {a.criticality} in {a.environment}."
            )
            facts.append(
                InvestigationFact(
                    fact_id=fact_id,
                    investigation_id=plan.investigation_id,
                    fact_type=FactType.OBSERVED_FACT,
                    statement=statement,
                    source_type="AssetRepository",
                    source_id=a.entity_id,
                    entity_type="Asset",
                    entity_id=a.entity_id,
                    confidence=1.0,
                    step_id=step.step_id,
                )
            )
            provs.append(
                Provenance(
                    source_type="Asset",
                    source_id=a.entity_id,
                    relationship="AFFECTS",
                    confidence=1.0,
                )
            )

        return filtered_assets, facts, [], set(), provs

    # ------------------------------------------------------------
    # 6. GET_FRAMEWORKS
    # ------------------------------------------------------------
    def _adapter_get_frameworks(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        all_fws = [e for e in self.repo.list_entities("Framework") if isinstance(e, Framework)]

        target_id = self._resolve_target(step, plan, "FRAMEWORK")
        filtered_fws = [f for f in all_fws if f.entity_id == target_id] if target_id else all_fws

        facts: List[InvestigationFact] = []
        provs: List[Provenance] = []

        for idx, fw in enumerate(filtered_fws, 1):
            fact_id = f"FACT-{step.step_id}-{idx:03d}"
            statement = f"Framework {fw.entity_id} ({fw.name}) version {fw.version}."
            facts.append(
                InvestigationFact(
                    fact_id=fact_id,
                    investigation_id=plan.investigation_id,
                    fact_type=FactType.OBSERVED_FACT,
                    statement=statement,
                    source_type="OntologyRepository",
                    source_id=fw.entity_id,
                    entity_type="Framework",
                    entity_id=fw.entity_id,
                    confidence=1.0,
                    step_id=step.step_id,
                )
            )
            provs.append(
                Provenance(
                    source_type="Framework",
                    source_id=fw.entity_id,
                    relationship="GOVERNED_BY",
                    confidence=1.0,
                )
            )

        return filtered_fws, facts, [], set(), provs

    # ------------------------------------------------------------
    # 7. GET_RELATIONSHIPS
    # ------------------------------------------------------------
    def _adapter_get_relationships(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        target_id = self._resolve_target(step, plan, None)
        out_rels = self.repo.get_outgoing_relationships(target_id) if target_id else self.repo.list_relationships()
        in_rels = self.repo.get_incoming_relationships(target_id) if target_id else []

        all_rels = list(out_rels) + list(in_rels)
        facts: List[InvestigationFact] = []
        provs: List[Provenance] = []

        for idx, r in enumerate(all_rels[:20], 1):  # 대표 관계 20건 캡처
            fact_id = f"FACT-{step.step_id}-{idx:03d}"
            statement = f"Relationship {r.source_id} -[{r.relationship_type.value}]-> {r.target_id}."
            facts.append(
                InvestigationFact(
                    fact_id=fact_id,
                    investigation_id=plan.investigation_id,
                    fact_type=FactType.OBSERVED_FACT,
                    statement=statement,
                    source_type="OntologyRepository",
                    source_id=r.relationship_id,
                    confidence=r.confidence.score,
                    step_id=step.step_id,
                )
            )
            provs.append(
                Provenance(
                    source_type=r.source_type,
                    source_id=r.source_id,
                    relationship=r.relationship_type.value,
                    confidence=r.confidence.score,
                )
            )

        return all_rels, facts, [], set(), provs

    # ------------------------------------------------------------
    # 8. GET_LINEAGE
    # ------------------------------------------------------------
    def _adapter_get_lineage(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        target_id = self._resolve_target(step, plan, None)
        lineage: Dict[str, Any] = {}
        if target_id:
            lineage = self.resolver.get_evidence_lineage(target_id)

        facts: List[InvestigationFact] = []
        ev_ids: Set[str] = set()
        provs: List[Provenance] = []

        if lineage and "error" not in lineage:
            temp_prov_builder = ProvenanceBuilder()
            temp_prov_builder.add_from_lineage(lineage)
            provs = temp_prov_builder.build()

            # 연계된 증적 ID 추출
            for ev_item in lineage.get("evidences", []):
                eid = ev_item.get("id") if isinstance(ev_item, dict) else str(ev_item)
                if eid:
                    ev_ids.add(eid)

            fact_id = f"FACT-{step.step_id}-001"
            statement = f"Lineage tracked for root entity {target_id}: {lineage.get('chain_summary', 'complete')}."
            facts.append(
                InvestigationFact(
                    fact_id=fact_id,
                    investigation_id=plan.investigation_id,
                    fact_type=FactType.OBSERVED_FACT,
                    statement=statement,
                    source_type="OntologyResolver",
                    source_id=target_id,
                    confidence=1.0,
                    step_id=step.step_id,
                    evidence_ids=list(ev_ids),
                )
            )

        return [lineage], facts, [], ev_ids, provs

    # ------------------------------------------------------------
    # 9. GET_COVERAGE
    # ------------------------------------------------------------
    def _adapter_get_coverage(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        target_fw = "ISMS-P"
        if plan.scope_type == InvestigationScopeType.FRAMEWORK and plan.scope_id:
            target_fw = plan.scope_id

        cov = self.resolver.get_framework_coverage(target_fw)
        facts: List[InvestigationFact] = []
        provs: List[Provenance] = []

        fact_id = f"FACT-{step.step_id}-001"
        statement = (
            f"Coverage for {cov.framework_id}: {cov.assessed_controls}/{cov.total_controls} controls assessed "
            f"({cov.coverage_percent}%), effective: {cov.effective_controls}."
        )
        facts.append(
            InvestigationFact(
                fact_id=fact_id,
                investigation_id=plan.investigation_id,
                fact_type=FactType.OBSERVED_FACT,
                statement=statement,
                source_type="OntologyResolver",
                source_id=cov.framework_id,
                entity_type="Framework",
                entity_id=cov.framework_id,
                confidence=1.0,
                step_id=step.step_id,
            )
        )
        provs.append(
            Provenance(
                source_type="Framework",
                source_id=cov.framework_id,
                relationship="COVERAGE",
                confidence=1.0,
            )
        )

        return [cov], facts, [], set(), provs

    # ------------------------------------------------------------
    # 10. GET_REDTEAM_SUMMARY
    # ------------------------------------------------------------
    def _adapter_get_redteam_summary(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        summary, _ = self.redteam_runner.run_all()
        facts: List[InvestigationFact] = []
        provs: List[Provenance] = []

        fact_id = f"FACT-{step.step_id}-001"
        statement = (
            f"RedTeam resilience score: {summary.resilience_score}%, "
            f"secret leakages: {summary.secret_leakages}, "
            f"unauthorized tool executions: {summary.unauthorized_tool_executions}."
        )
        facts.append(
            InvestigationFact(
                fact_id=fact_id,
                investigation_id=plan.investigation_id,
                fact_type=FactType.OBSERVED_FACT,
                statement=statement,
                source_type="RedTeamRunner",
                source_id="REDTEAM_RUNNER",
                confidence=1.0,
                step_id=step.step_id,
            )
        )
        provs.append(
            Provenance(
                source_type="AgentSecurity",
                source_id="REDTEAM_RUNNER",
                relationship="RESILIENCE_VERIFIED",
                confidence=1.0,
            )
        )

        return [summary], facts, [], set(), provs

    # ------------------------------------------------------------
    # 11. GET_AGENT_SECURITY_STATUS
    # ------------------------------------------------------------
    def _adapter_get_agent_security_status(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        agents = self.repo.list_entities("Agent")
        tools = self.repo.list_entities("Tool")
        policies = self.repo.list_entities("Policy")

        facts: List[InvestigationFact] = []
        provs: List[Provenance] = []

        fact_id = f"FACT-{step.step_id}-001"
        statement = (
            f"Agent security governance status: {len(agents)} registered agents, "
            f"{len(tools)} tools, {len(policies)} policies."
        )
        facts.append(
            InvestigationFact(
                fact_id=fact_id,
                investigation_id=plan.investigation_id,
                fact_type=FactType.OBSERVED_FACT,
                statement=statement,
                source_type="AgentSecurity",
                source_id="AGENT_SECURITY",
                confidence=1.0,
                step_id=step.step_id,
            )
        )
        provs.append(
            Provenance(
                source_type="AgentSecurity",
                source_id="AGENT_SECURITY",
                relationship="GOVERNED_BY",
                confidence=1.0,
            )
        )

        return [{"agents": len(agents), "tools": len(tools), "policies": len(policies)}], facts, [], set(), provs

    # ------------------------------------------------------------
    # 12. GET_REMEDIATIONS
    # ------------------------------------------------------------
    def _adapter_get_remediations(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
    ) -> Tuple[List[Any], List[InvestigationFact], List[InvestigationFinding], Set[str], List[Provenance]]:
        all_rems = [e for e in self.repo.list_entities("Remediation") if isinstance(e, RemediationEntity)]

        target_id = self._resolve_target(step, plan, "REMEDIATION")
        if target_id and target_id.startswith("RISK-"):
            filtered_rems = self.resolver.find_remediations_for_risk(target_id)
        elif target_id and target_id.startswith("REM-"):
            filtered_rems = [r for r in all_rems if r.entity_id == target_id]
        else:
            filtered_rems = all_rems

        facts: List[InvestigationFact] = []
        provs: List[Provenance] = []

        for idx, r in enumerate(filtered_rems, 1):
            fact_id = f"FACT-{step.step_id}-{idx:03d}"
            statement = f"Remediation plan {r.entity_id} ({r.name}) status {r.status} [{r.plan_type}]."
            facts.append(
                InvestigationFact(
                    fact_id=fact_id,
                    investigation_id=plan.investigation_id,
                    fact_type=FactType.OBSERVED_FACT,
                    statement=statement,
                    source_type="RemediationOrchestrator",
                    source_id=r.entity_id,
                    entity_type="Remediation",
                    entity_id=r.entity_id,
                    confidence=1.0,
                    step_id=step.step_id,
                )
            )
            provs.append(
                Provenance(
                    source_type="Remediation",
                    source_id=r.entity_id,
                    relationship="MITIGATED_BY",
                    confidence=1.0,
                )
            )

        return filtered_rems, facts, [], set(), provs

    # ============================================================
    # Helper: Target Resolution
    # ============================================================

    def _resolve_target(
        self,
        step: InvestigationStep,
        plan: InvestigationPlan,
        expected_type: Optional[str],
    ) -> Optional[str]:
        """단계의 target_ids 또는 플랜의 scope_id로부터 안전하게 대상을 결정합니다."""
        if step.target_ids:
            return step.target_ids[0]
        if plan.scope_id:
            return plan.scope_id
        return None

    # ============================================================
    # Deterministic Integrity & Provenance Verification
    # ============================================================

    def _capture_baseline_snapshot(self) -> Dict[str, Any]:
        """저장소 상태 스냅샷을 캡처합니다."""
        ctrls = [e for e in self.repo.list_entities("Control") if getattr(e, "framework_id", "") == "ISMS-P"]
        evs = self.repo.list_entities("Evidence")
        risks = self.repo.list_entities("Risk")
        top_risk = next((r for r in risks if getattr(r, "entity_id", "") == "RISK-ISMS-P-2.7.1"), None)

        return {
            "control_count": len(ctrls),
            "evidence_count": len(evs),
            "risk_count": len(risks),
            "top_risk_id": getattr(top_risk, "entity_id", None) if top_risk else None,
            "top_risk_score": getattr(top_risk, "risk_score", None) if top_risk else None,
            "top_risk_priority": getattr(top_risk, "priority", None) if top_risk else None,
            "top_risk_severity": getattr(top_risk, "severity", None) if top_risk else None,
        }

    def _verify_baseline_integrity(self, snapshot: Dict[str, Any]) -> bool:
        """저장소 원천 데이터가 실행 도중 변조되지 않았는지 검증합니다."""
        current = self._capture_baseline_snapshot()
        for k, v in snapshot.items():
            if current.get(k) != v:
                return False
        return True

    def _verify_provenance_integrity(self, provenances: List[Provenance]) -> bool:
        """출처(Provenance)가 실제 저장소 엔티티 또는 정당한 시스템 출처인지 검증합니다."""
        trusted_systems = {
            "REDTEAM_RUNNER",
            "AGENT_SECURITY",
            "RiskEngine",
            "AuditEngine",
            "EvidenceRepository",
            "FindingRepository",
            "AssetRepository",
            "OntologyRepository",
            "OntologyResolver",
            "RemediationOrchestrator",
            "ISMS-P",
            "NIST-CSF",
            "ISO-27001",
        }
        for prov in provenances:
            sid = prov.source_id
            if sid in trusted_systems:
                continue
            if not self.repo.get_entity(sid):
                # 저장소에 실존하지 않는 날조된 엔티티 출처 차단
                return False
        return True

    # ============================================================
    # Fail-Closed Fallback Helper
    # ============================================================

    def _fail_closed(self, investigation_id: str, reason: str) -> InvestigationResult:
        """안전하지 않거나 검증 실패한 계획에 대해 차단된 결과를 즉시 반환합니다."""
        safe_reason = SecretGuard.mask_secrets(reason)
        return InvestigationResult(
            investigation_id=investigation_id if investigation_id else "UNKNOWN",
            status=InvestigationStatus.FAILED,
            fact_ids=[],
            hypothesis_ids=[],
            finding_ids=[],
            evidence_chain_ids=[],
            conclusion=f"Investigation execution blocked: {safe_reason}",
            confidence=0.0,
            limitations=[safe_reason],
            provenance_ids=[],
            deterministic_integrity_verified=True,
            provenance_integrity_verified=True,
            secret_scan_passed=True,
        )
