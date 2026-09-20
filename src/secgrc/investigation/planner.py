"""결정론적 GRC Investigation Planner 모듈입니다.

사용자의 조사 요청(Investigation)을 수신하여 결정론적 정책 기반의
InvestigationPlan을 생성합니다.

핵심 원칙:
- LLM 호출 없음
- 저장소 조회 없음
- 조치/실행 없음
- 결정론적 정책/템플릿 기반 계획만 수립
- 읽기 전용 ALLOWED_OPERATIONS만 사용
"""

from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from pydantic import Field, field_validator, model_validator

from secgrc.copilot.planner import ALLOWED_OPERATIONS
from secgrc.investigation.enums import (
    InvestigationScopeType,
    InvestigationStatus,
    InvestigationStepStatus,
    InvestigationType,
)
from secgrc.investigation.models import (
    InvestigationBaseModel,
    InvestigationStep,
    Investigation,
    validate_id_str,
    validate_id_list,
    DANGEROUS_ID_PATTERNS,
    FORBIDDEN_STEP_OPERATIONS,
)

# ============================================================
# Planner Version
# ============================================================
PLANNER_VERSION = "1.0"


# ============================================================
# InvestigationPlan Model
# ============================================================

class InvestigationPlan(InvestigationBaseModel):
    """검증된 결정론적 조사 실행 계획 모델.

    조사 요청에 대해 어떤 읽기 전용 작업(InvestigationStep)을 어떤 순서와
    의존성으로 수행할지를 결정론적으로 명시합니다. 실행 자체는 포함하지 않습니다.
    """
    plan_id: str = Field(description="계획 고유 식별자")
    investigation_id: str = Field(description="소속 조사 식별자")
    investigation_type: InvestigationType = Field(description="조사 유형")
    scope_type: InvestigationScopeType = Field(description="조사 범위 유형")
    scope_id: Optional[str] = Field(default=None, description="조사 대상 식별자")
    steps: List[InvestigationStep] = Field(default_factory=list, description="계획된 조사 단계 목록")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="계획 생성 일시 (ISO 8601 UTC)",
    )
    planner_version: str = Field(default=PLANNER_VERSION, description="플래너 버전")

    # Safety
    read_only: bool = Field(default=True, description="읽기 전용 강제 플래그")
    validated: bool = Field(default=False, description="검증 완료 여부")
    validation_errors: List[str] = Field(default_factory=list, description="검증 오류 목록")

    # Metadata
    estimated_steps: int = Field(default=0, description="예상 단계 수")
    required_data_types: List[str] = Field(default_factory=list, description="필요 데이터 유형 목록")

    @field_validator("plan_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("scope_id")
    @classmethod
    def check_scope_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return validate_id_str(v, "scope_id")

    @field_validator("read_only")
    @classmethod
    def check_read_only(cls, v: bool) -> bool:
        if not v:
            raise ValueError("InvestigationPlan must be read-only (read_only=True).")
        return True

    @field_validator("required_data_types")
    @classmethod
    def check_data_types(cls, v: List[str]) -> List[str]:
        return validate_id_list(v, "required_data_types") if v else []


# ============================================================
# Investigation Policies (결정론적 정책/템플릿)
# ============================================================

# 각 InvestigationType별 결정론적 실행 단계 정의
# 형식: (operation_name, step_name, description, depends_on_indices)
# depends_on_indices는 이 리스트 내 0-기반 인덱스 참조

_RISK_ANALYSIS_POLICY: List[Tuple[str, str, str, List[int]]] = [
    ("GET_RISKS", "위험 정보 조회", "대상 위험(Risk)의 상세 평가 정보를 조회합니다.", []),
    ("GET_CONTROLS", "연관 통제 조회", "위험과 연관된 통제항목(Control)을 조회합니다.", [0]),
    ("GET_EVIDENCE", "증적 조회", "통제항목에 연계된 증적(Evidence)을 조회합니다.", [1]),
    ("GET_FINDINGS", "결함 조회", "증적으로부터 도출된 결함(Finding)을 조회합니다.", [2]),
    ("GET_RELATIONSHIPS", "관계 분석", "위험, 통제, 증적, 결함 간 온톨로지 관계를 조회합니다.", [0, 1, 2, 3]),
    ("GET_LINEAGE", "계보 추적", "증적 및 통제의 출처 계보(Lineage)를 추적합니다.", [2, 1]),
]

_CONTROL_INVESTIGATION_POLICY: List[Tuple[str, str, str, List[int]]] = [
    ("GET_CONTROLS", "통제 상세 조회", "대상 통제항목의 유효성 및 메타데이터를 조회합니다.", []),
    ("GET_EVIDENCE", "증적 조회", "통제항목에 연계된 증적을 조회합니다.", [0]),
    ("GET_FINDINGS", "결함 조회", "통제항목 관련 결함을 조회합니다.", [1]),
    ("GET_RELATIONSHIPS", "관계 분석", "통제항목과 다른 엔티티 간 관계를 조회합니다.", [0, 1, 2]),
    ("GET_LINEAGE", "계보 추적", "통제항목과 증적의 출처 계보를 추적합니다.", [1]),
    ("GET_FRAMEWORKS", "프레임워크 매핑 조회", "통제항목의 프레임워크 크로스 매핑을 조회합니다.", [0]),
]

_EVIDENCE_INVESTIGATION_POLICY: List[Tuple[str, str, str, List[int]]] = [
    ("GET_EVIDENCE", "증적 상세 조회", "대상 증적의 상세 정보를 조회합니다.", []),
    ("GET_CONTROLS", "연관 통제 조회", "증적과 연결된 통제항목을 조회합니다.", [0]),
    ("GET_RISKS", "연관 위험 조회", "증적이 영향을 미치는 위험을 조회합니다.", [1]),
    ("GET_FINDINGS", "관련 결함 조회", "증적에서 파생된 결함을 조회합니다.", [0]),
    ("GET_LINEAGE", "계보 추적", "증적의 출처 계보를 추적합니다.", [0]),
    ("GET_RELATIONSHIPS", "관계 분석", "증적과 다른 엔티티 간 관계를 조회합니다.", [0, 1, 2, 3]),
]

_FINDING_INVESTIGATION_POLICY: List[Tuple[str, str, str, List[int]]] = [
    ("GET_FINDINGS", "결함 상세 조회", "대상 결함의 상세 정보를 조회합니다.", []),
    ("GET_EVIDENCE", "근거 증적 조회", "결함을 뒷받침하는 증적을 조회합니다.", [0]),
    ("GET_CONTROLS", "연관 통제 조회", "결함과 연관된 통제항목을 조회합니다.", [1]),
    ("GET_RISKS", "연관 위험 조회", "결함이 기여하는 위험을 조회합니다.", [2]),
    ("GET_ASSETS", "영향 자산 조회", "결함이 영향을 미치는 자산을 조회합니다.", [0]),
    ("GET_RELATIONSHIPS", "관계 분석", "결함과 다른 엔티티 간 관계를 조회합니다.", [0, 1, 2, 3, 4]),
    ("GET_LINEAGE", "계보 추적", "결함과 증적의 출처 계보를 추적합니다.", [1]),
]

_ASSET_INVESTIGATION_POLICY: List[Tuple[str, str, str, List[int]]] = [
    ("GET_ASSETS", "자산 상세 조회", "대상 자산의 상세 정보를 조회합니다.", []),
    ("GET_RISKS", "연관 위험 조회", "자산이 기여하는 위험을 조회합니다.", [0]),
    ("GET_CONTROLS", "보호 통제 조회", "자산을 보호하는 통제항목을 조회합니다.", [0]),
    ("GET_FINDINGS", "관련 결함 조회", "자산에 영향을 미치는 결함을 조회합니다.", [0]),
    ("GET_RELATIONSHIPS", "관계 분석", "자산과 다른 엔티티 간 관계를 조회합니다.", [0, 1, 2, 3]),
]

_FRAMEWORK_INVESTIGATION_POLICY: List[Tuple[str, str, str, List[int]]] = [
    ("GET_FRAMEWORKS", "프레임워크 조회", "대상 프레임워크의 상세 정보를 조회합니다.", []),
    ("GET_CONTROLS", "소속 통제 조회", "프레임워크에 소속된 통제항목 목록을 조회합니다.", [0]),
    ("GET_RELATIONSHIPS", "관계 분석", "프레임워크와 통제 간 관계를 조회합니다.", [0, 1]),
    ("GET_COVERAGE", "커버리지 분석", "프레임워크의 통제 커버리지 통계를 조회합니다.", [1]),
    ("GET_LINEAGE", "계보 추적", "프레임워크 및 통제의 출처 계보를 추적합니다.", [1]),
]

_AGENT_SECURITY_INVESTIGATION_POLICY: List[Tuple[str, str, str, List[int]]] = [
    ("GET_AGENT_SECURITY_STATUS", "에이전트 보안 상태 조회", "AI 에이전트 보안 상태를 조회합니다.", []),
    ("GET_REDTEAM_SUMMARY", "레드팀 요약 조회", "레드팀/퍼플팀 평가 요약을 조회합니다.", [0]),
    ("GET_FINDINGS", "관련 결함 조회", "에이전트 보안 관련 결함을 조회합니다.", [0, 1]),
    ("GET_RELATIONSHIPS", "관계 분석", "에이전트와 다른 엔티티 간 관계를 조회합니다.", [0, 1, 2]),
    ("GET_EVIDENCE", "관련 증적 조회", "에이전트 보안 관련 증적을 조회합니다.", [0, 1]),
]

_INCIDENT_INVESTIGATION_POLICY: List[Tuple[str, str, str, List[int]]] = [
    ("GET_FINDINGS", "인시던트 관련 결함 조회", "인시던트와 연관된 결함을 조회합니다.", []),
    ("GET_EVIDENCE", "관련 증적 조회", "인시던트 관련 증적을 조회합니다.", [0]),
    ("GET_RISKS", "연관 위험 조회", "인시던트와 관련된 위험을 조회합니다.", [0]),
    ("GET_CONTROLS", "관련 통제 조회", "인시던트에 영향받는 통제항목을 조회합니다.", [0, 2]),
    ("GET_RELATIONSHIPS", "관계 분석", "인시던트 관련 엔티티 간 관계를 조회합니다.", [0, 1, 2, 3]),
]

_GENERAL_GRC_POLICY: List[Tuple[str, str, str, List[int]]] = [
    ("GET_RISKS", "위험 현황 조회", "전체 위험 현황을 조회합니다.", []),
    ("GET_CONTROLS", "통제 현황 조회", "전체 통제항목 현황을 조회합니다.", [0]),
    ("GET_EVIDENCE", "증적 현황 조회", "전체 증적 현황을 조회합니다.", [1]),
]

# InvestigationType → Policy 매핑
INVESTIGATION_POLICIES: Dict[InvestigationType, List[Tuple[str, str, str, List[int]]]] = {
    InvestigationType.RISK_ANALYSIS: _RISK_ANALYSIS_POLICY,
    InvestigationType.CONTROL_INVESTIGATION: _CONTROL_INVESTIGATION_POLICY,
    InvestigationType.EVIDENCE_INVESTIGATION: _EVIDENCE_INVESTIGATION_POLICY,
    InvestigationType.INCIDENT_INVESTIGATION: _INCIDENT_INVESTIGATION_POLICY,
    InvestigationType.FINDING_INVESTIGATION: _FINDING_INVESTIGATION_POLICY,
    InvestigationType.ASSET_INVESTIGATION: _ASSET_INVESTIGATION_POLICY,
    InvestigationType.FRAMEWORK_INVESTIGATION: _FRAMEWORK_INVESTIGATION_POLICY,
    InvestigationType.AGENT_SECURITY_INVESTIGATION: _AGENT_SECURITY_INVESTIGATION_POLICY,
    InvestigationType.GENERAL_GRC: _GENERAL_GRC_POLICY,
}

# InvestigationType → 기본 InvestigationScopeType 매핑
TYPE_TO_SCOPE: Dict[InvestigationType, InvestigationScopeType] = {
    InvestigationType.RISK_ANALYSIS: InvestigationScopeType.RISK,
    InvestigationType.CONTROL_INVESTIGATION: InvestigationScopeType.CONTROL,
    InvestigationType.EVIDENCE_INVESTIGATION: InvestigationScopeType.EVIDENCE,
    InvestigationType.INCIDENT_INVESTIGATION: InvestigationScopeType.FINDING,
    InvestigationType.FINDING_INVESTIGATION: InvestigationScopeType.FINDING,
    InvestigationType.ASSET_INVESTIGATION: InvestigationScopeType.ASSET,
    InvestigationType.FRAMEWORK_INVESTIGATION: InvestigationScopeType.FRAMEWORK,
    InvestigationType.AGENT_SECURITY_INVESTIGATION: InvestigationScopeType.AGENT,
    InvestigationType.GENERAL_GRC: InvestigationScopeType.GLOBAL,
}


# ============================================================
# Deterministic Cycle Detection
# ============================================================

def detect_dependency_cycle(steps: List[InvestigationStep]) -> Optional[str]:
    """결정론적 위상정렬(Topological Sort)으로 단계 간 순환 의존성을 탐지합니다.

    Returns:
        None: 순환 없음.
        str: 순환이 감지된 경우 오류 메시지.
    """
    id_to_step: Dict[str, InvestigationStep] = {s.step_id: s for s in steps}
    # 진입 차수 계산
    in_degree: Dict[str, int] = {s.step_id: 0 for s in steps}
    adj: Dict[str, List[str]] = {s.step_id: [] for s in steps}

    for s in steps:
        for dep_id in s.depends_on_step_ids:
            if dep_id not in id_to_step:
                return f"Step '{s.step_id}' depends on non-existent step '{dep_id}'."
            adj[dep_id].append(s.step_id)
            in_degree[s.step_id] += 1

    # Kahn's algorithm
    queue = deque([sid for sid, deg in in_degree.items() if deg == 0])
    visited_count = 0
    while queue:
        node = queue.popleft()
        visited_count += 1
        for neighbor in adj[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    if visited_count < len(steps):
        return "Dependency cycle detected among investigation steps."
    return None


# ============================================================
# InvestigationPlanner
# ============================================================

class InvestigationPlanner:
    """결정론적 GRC 조사 계획 수립기.

    조사 요청(Investigation)을 기반으로 정책 선택, 스코프 검증,
    읽기 전용 작업 배정, 의존성 DAG 구성, 안전성 검증을 수행하여
    InvestigationPlan을 생성합니다.

    Planner는 어떠한 저장소 조회, LLM 호출, 도구 실행도 수행하지 않습니다.
    """

    def __init__(self, version: str = PLANNER_VERSION) -> None:
        self._version = version

    @property
    def version(self) -> str:
        return self._version

    def plan(self, investigation: Investigation) -> InvestigationPlan:
        """Investigation 요청을 검증하고 결정론적 InvestigationPlan을 생성합니다.

        Args:
            investigation: 유효한 Investigation 모델 인스턴스.

        Returns:
            InvestigationPlan: 검증된(validated=True) 또는 실패한(validated=False) 계획.
        """
        plan_id = f"PLAN-{investigation.investigation_id}"
        errors: List[str] = []

        # 1. 스코프 검증
        scope_errors = self._validate_scope(investigation)
        errors.extend(scope_errors)

        # 2. 정책 선택
        policy = INVESTIGATION_POLICIES.get(investigation.investigation_type)
        if policy is None:
            errors.append(
                f"No policy found for investigation type: {investigation.investigation_type.value}"
            )
            return self._build_failed_plan(plan_id, investigation, errors)

        # 3. 단계 생성
        try:
            steps = self._generate_steps(investigation, policy)
        except ValueError as e:
            errors.append(f"Step generation error: {e}")
            return self._build_failed_plan(plan_id, investigation, errors)

        # 4. 의존성 검증
        dep_errors = self._validate_dependencies(steps)
        errors.extend(dep_errors)

        # 5. 작업 안전성 검증
        op_errors = self._validate_operations(steps)
        errors.extend(op_errors)

        # 6. 결과 조립
        required_data_types = sorted(set(s.operation for s in steps if s.operation))
        validated = len(errors) == 0

        return InvestigationPlan(
            plan_id=plan_id,
            investigation_id=investigation.investigation_id,
            investigation_type=investigation.investigation_type,
            scope_type=investigation.scope_type,
            scope_id=investigation.scope_id,
            steps=steps,
            planner_version=self._version,
            read_only=True,
            validated=validated,
            validation_errors=errors,
            estimated_steps=len(steps),
            required_data_types=required_data_types,
        )

    # ----------------------------------------------------------
    # 내부 검증 메서드
    # ----------------------------------------------------------

    def _validate_scope(self, investigation: Investigation) -> List[str]:
        """조사 스코프의 유효성을 검증합니다."""
        errors: List[str] = []
        scope_type = investigation.scope_type
        scope_id = investigation.scope_id

        if scope_type == InvestigationScopeType.GLOBAL:
            # GLOBAL은 scope_id 없어도 허용
            return errors

        # GLOBAL 외에는 scope_id 필수
        if not scope_id or not scope_id.strip():
            errors.append(
                f"scope_id is required for scope_type={scope_type.value}"
            )
            return errors

        # scope_id 안전성 검증
        try:
            validate_id_str(scope_id, "scope_id")
        except ValueError as e:
            errors.append(f"Invalid scope_id: {e}")
            return errors

        return errors

    def _generate_steps(
        self,
        investigation: Investigation,
        policy: List[Tuple[str, str, str, List[int]]],
    ) -> List[InvestigationStep]:
        """결정론적 정책으로부터 InvestigationStep 목록을 생성합니다."""
        steps: List[InvestigationStep] = []
        inv_id = investigation.investigation_id
        scope_id = investigation.scope_id

        # target_ids 결정: scope_id가 있으면 모든 단계의 기본 타깃으로 설정
        base_target = [scope_id] if scope_id else []

        for idx, (op, name, desc, dep_indices) in enumerate(policy):
            seq = idx + 1
            step_id = f"{inv_id}-STEP-{seq:03d}"
            dep_ids = [f"{inv_id}-STEP-{(di + 1):03d}" for di in dep_indices]

            step = InvestigationStep(
                step_id=step_id,
                investigation_id=inv_id,
                sequence=seq,
                name=name,
                description=desc,
                status=InvestigationStepStatus.PENDING,
                operation=op,
                target_ids=list(base_target),
                depends_on_step_ids=dep_ids,
                read_only=True,
            )
            steps.append(step)

        return steps

    def _validate_dependencies(self, steps: List[InvestigationStep]) -> List[str]:
        """단계 간 의존성 그래프(DAG)의 무결성을 결정론적으로 검증합니다."""
        errors: List[str] = []
        step_ids = {s.step_id for s in steps}
        sequences = [s.sequence for s in steps]
        id_to_seq = {s.step_id: s.sequence for s in steps}

        # 고유 step_id 검증
        if len(step_ids) != len(steps):
            errors.append("Duplicate step IDs detected.")

        # 고유 sequence 검증
        if len(set(sequences)) != len(sequences):
            errors.append("Duplicate sequence numbers detected.")

        for s in steps:
            # 자기 의존성 검증
            if s.step_id in s.depends_on_step_ids:
                errors.append(f"Step '{s.step_id}' has self-dependency.")

            # 중복 의존성 검증
            if len(s.depends_on_step_ids) != len(set(s.depends_on_step_ids)):
                errors.append(f"Step '{s.step_id}' has duplicate dependencies.")

            # 존재하지 않는 의존성 검증
            for dep_id in s.depends_on_step_ids:
                if dep_id not in step_ids:
                    errors.append(
                        f"Step '{s.step_id}' depends on non-existent step '{dep_id}'."
                    )

            # 의존 순서 검증: 의존 대상의 sequence < 현재 step의 sequence
            for dep_id in s.depends_on_step_ids:
                if dep_id in id_to_seq and id_to_seq[dep_id] >= s.sequence:
                    errors.append(
                        f"Step '{s.step_id}' (seq={s.sequence}) depends on "
                        f"'{dep_id}' (seq={id_to_seq[dep_id]}) which has equal or later sequence."
                    )

        # 순환 의존성 탐지
        cycle_error = detect_dependency_cycle(steps)
        if cycle_error:
            errors.append(cycle_error)

        return errors

    def _validate_operations(self, steps: List[InvestigationStep]) -> List[str]:
        """모든 단계의 작업이 읽기 전용 허용 목록 내에 있는지 검증합니다."""
        errors: List[str] = []
        for s in steps:
            if s.operation and s.operation not in ALLOWED_OPERATIONS:
                errors.append(
                    f"Step '{s.step_id}' has disallowed operation: '{s.operation}'"
                )
            if not s.read_only:
                errors.append(
                    f"Step '{s.step_id}' has read_only=False, which is forbidden."
                )
        return errors

    def _build_failed_plan(
        self,
        plan_id: str,
        investigation: Investigation,
        errors: List[str],
    ) -> InvestigationPlan:
        """검증 실패 시 빈 단계의 실패 계획을 반환합니다."""
        return InvestigationPlan(
            plan_id=plan_id,
            investigation_id=investigation.investigation_id,
            investigation_type=investigation.investigation_type,
            scope_type=investigation.scope_type,
            scope_id=investigation.scope_id,
            steps=[],
            planner_version=self._version,
            read_only=True,
            validated=False,
            validation_errors=errors,
            estimated_steps=0,
            required_data_types=[],
        )


__all__ = [
    "InvestigationPlan",
    "InvestigationPlanner",
    "PLANNER_VERSION",
    "INVESTIGATION_POLICIES",
    "detect_dependency_cycle",
]
