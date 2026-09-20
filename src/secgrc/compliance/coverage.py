"""Compliance Input Coverage Model & Query API (Step 23.5A).

This module evaluates input data availability against compliance requirements.
Critical principle: Missing Evidence ≠ Control Failure.
Missing input data only reflects input readiness, never an automated audit failure.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from pydantic import Field, field_validator

from secgrc.compliance.frameworks import FrameworkRegistry, default_framework_registry
from secgrc.compliance.input_requirements import (
    ComplianceInputRequirement,
    InputRequirementRegistry,
    default_input_requirement_registry,
)
from secgrc.compliance.models import (
    AutomationLevel,
    CanonicalDataType,
    CanonicalSecurityData,
    ComplianceBaseModel,
    EvidenceState,
    InputCoverageState,
    validate_identifier,
    validate_iso8601_timestamp,
)
from secgrc.compliance.requirements import (
    RequirementRegistry,
    default_requirement_registry,
)


class InputCoverage(ComplianceBaseModel):
    """특정 컴플라이언스 요구사항에 대한 입력 데이터 충족도 평가 결과."""

    framework_id: str = Field(description="소속 프레임워크 식별자")
    framework_version: str = Field(description="소속 프레임워크 버전")
    requirement_id: str = Field(description="대상 요구사항 식별자")
    tenant_id: str = Field(default="default", description="테넌트 식별자")
    required_inputs: List[str] = Field(default_factory=list, description="필요한 입력 항목 식별자 목록")
    available_inputs: List[str] = Field(default_factory=list, description="현재 확보된 입력 항목 식별자 목록")
    missing_inputs: List[str] = Field(default_factory=list, description="미확보된 입력 항목 식별자 목록")
    coverage_state: InputCoverageState = Field(description="입력 데이터 커버리지 상태 (COMPLETE, PARTIAL, MISSING, MANUAL, UNKNOWN)")
    automation_level: AutomationLevel = Field(description="요구사항 대표 자동화 수준")
    evidence_state: EvidenceState = Field(description="증적 연계 상태")
    last_evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="평가 일시 (ISO 8601)",
    )

    @field_validator("framework_id", "framework_version", "requirement_id", "tenant_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("last_evaluated_at")
    @classmethod
    def check_timestamp(cls, v: str, info) -> str:
        return validate_iso8601_timestamp(v, info.field_name)


class InputCoverageEvaluator:
    """결정론적 컴플라이언스 입력 데이터 커버리지 평가기."""

    def __init__(
        self,
        framework_registry: Optional[FrameworkRegistry] = None,
        requirement_registry: Optional[RequirementRegistry] = None,
        input_requirement_registry: Optional[InputRequirementRegistry] = None,
    ) -> None:
        self.frameworks = framework_registry or default_framework_registry
        self.requirements = requirement_registry or default_requirement_registry
        self.input_requirements = input_requirement_registry or default_input_requirement_registry
        self._tenant_data: Dict[str, List[CanonicalSecurityData]] = {}

    def ingest_data(self, data: CanonicalSecurityData) -> None:
        """평가 대상 정규 보안 데이터를 테넌트별로 인메모리 수집합니다."""
        tenant = data.tenant_id
        if tenant not in self._tenant_data:
            self._tenant_data[tenant] = []
        self._tenant_data[tenant].append(data)

    def ingest_data_batch(self, batch: List[CanonicalSecurityData]) -> None:
        """정규 보안 데이터 배치를 수집합니다."""
        for d in batch:
            self.ingest_data(d)

    def clear_data(self, tenant_id: Optional[str] = None) -> None:
        """수집된 평가 데이터를 초기화합니다."""
        if tenant_id:
            self._tenant_data.pop(tenant_id, None)
        else:
            self._tenant_data.clear()

    def evaluate_requirement(
        self,
        requirement_id: str,
        framework_id: str = "ISMS-P",
        version: Optional[str] = None,
        tenant_id: str = "default",
        data_records: Optional[List[CanonicalSecurityData]] = None,
    ) -> InputCoverage:
        """단일 요구사항에 대한 입력 데이터 커버리지를 결정론적으로 평가합니다."""
        fw = self.frameworks.get_framework(framework_id)
        if not fw:
            raise ValueError(f"Unknown framework '{framework_id}'")
        ver = version or fw.default_version

        req = self.requirements.get(requirement_id, framework_id=framework_id, version=ver)
        if not req:
            return InputCoverage(
                framework_id=framework_id,
                framework_version=ver,
                requirement_id=requirement_id,
                tenant_id=tenant_id,
                required_inputs=[],
                available_inputs=[],
                missing_inputs=[],
                coverage_state=InputCoverageState.UNKNOWN,
                automation_level=AutomationLevel.NOT_APPLICABLE,
                evidence_state=EvidenceState.NOT_AVAILABLE,
            )

        # 해당 요구사항의 입력 요구 명세 조회
        in_reqs = self.input_requirements.get_by_requirement(requirement_id, framework_id, ver)
        if not in_reqs:
            return InputCoverage(
                framework_id=framework_id,
                framework_version=ver,
                requirement_id=requirement_id,
                tenant_id=tenant_id,
                required_inputs=[],
                available_inputs=[],
                missing_inputs=[],
                coverage_state=InputCoverageState.UNKNOWN,
                automation_level=AutomationLevel.NOT_APPLICABLE,
                evidence_state=EvidenceState.NOT_AVAILABLE,
            )

        # 가용 데이터 셋
        tenant_records = data_records if data_records is not None else self._tenant_data.get(tenant_id, [])

        # 가용 데이터의 (data_type, source_system) 세트 구성
        available_tuples: Set[str] = {
            f"{d.data_type.value}:{d.source_system.upper()}" for d in tenant_records
        }
        available_data_types: Set[str] = {
            d.data_type.value for d in tenant_records
        }

        required_input_ids: List[str] = []
        available_input_ids: List[str] = []
        missing_input_ids: List[str] = []

        all_manual = True
        has_automatic = False

        for inp in in_reqs:
            required_input_ids.append(inp.input_requirement_id)
            if inp.automation_level != AutomationLevel.MANUAL:
                all_manual = False
            if inp.automation_level == AutomationLevel.AUTOMATIC:
                has_automatic = True

            # 매칭 여부 판정 (data_type 및 source_type 일치 확인)
            match_key = f"{inp.data_type.value}:{inp.source_type.upper()}"
            is_matched = (
                match_key in available_tuples
                or inp.data_type.value in available_data_types
                or (inp.data_type == CanonicalDataType.SECURITY_CONFIGURATION and CanonicalDataType.CONFIGURATION_FINDING.value in available_data_types)
                or (inp.data_type == CanonicalDataType.CONFIGURATION_FINDING and CanonicalDataType.SECURITY_CONFIGURATION.value in available_data_types)
            )

            if is_matched:
                available_input_ids.append(inp.input_requirement_id)
            else:
                missing_input_ids.append(inp.input_requirement_id)

        # 커버리지 상태 결정
        if not missing_input_ids:
            coverage_state = InputCoverageState.COMPLETE
            evidence_state = EvidenceState.AVAILABLE
        elif available_input_ids:
            coverage_state = InputCoverageState.PARTIAL
            evidence_state = EvidenceState.PARTIALLY_AVAILABLE
        else:
            if all_manual:
                coverage_state = InputCoverageState.MANUAL
                evidence_state = EvidenceState.PENDING_REVIEW
            else:
                coverage_state = InputCoverageState.MISSING
                evidence_state = EvidenceState.NOT_AVAILABLE

        # 대표 자동화 수준 결정
        if all_manual:
            rep_auto = AutomationLevel.MANUAL
        elif has_automatic and not missing_input_ids:
            rep_auto = AutomationLevel.AUTOMATIC
        else:
            rep_auto = AutomationLevel.SEMI_AUTOMATIC

        return InputCoverage(
            framework_id=framework_id,
            framework_version=ver,
            requirement_id=requirement_id,
            tenant_id=tenant_id,
            required_inputs=sorted(required_input_ids),
            available_inputs=sorted(available_input_ids),
            missing_inputs=sorted(missing_input_ids),
            coverage_state=coverage_state,
            automation_level=rep_auto,
            evidence_state=evidence_state,
        )

    def evaluate_framework(
        self,
        framework_id: str = "ISMS-P",
        version: Optional[str] = None,
        tenant_id: str = "default",
        data_records: Optional[List[CanonicalSecurityData]] = None,
    ) -> List[InputCoverage]:
        """프레임워크 전체 요구사항에 대한 입력 데이터 커버리지를 평가합니다."""
        fw = self.frameworks.get_framework(framework_id)
        if not fw:
            raise ValueError(f"Unknown framework '{framework_id}'")
        ver = version or fw.default_version
        reqs = self.requirements.list_by_framework(framework_id, ver)

        results = []
        for r in reqs:
            cov = self.evaluate_requirement(
                requirement_id=r.requirement_id,
                framework_id=framework_id,
                version=ver,
                tenant_id=tenant_id,
                data_records=data_records,
            )
            results.append(cov)
        return sorted(results, key=lambda c: c.requirement_id)


# 싱글톤 평가기
default_coverage_evaluator = InputCoverageEvaluator()


# ---------------------------------------------------------------------------
# Public Query APIs (Section 19)
# ---------------------------------------------------------------------------

def get_framework_input_coverage(
    framework_id: str = "ISMS-P",
    version: Optional[str] = None,
    tenant_id: str = "default",
) -> List[InputCoverage]:
    """프레임워크 전체의 입력 데이터 커버리지 결과를 반환합니다."""
    return default_coverage_evaluator.evaluate_framework(
        framework_id=framework_id,
        version=version,
        tenant_id=tenant_id,
    )


def get_requirement_input_coverage(
    requirement_id: str,
    framework_version: Optional[str] = None,
    tenant_id: str = "default",
) -> Optional[InputCoverage]:
    """단일 요구사항의 입력 데이터 커버리지 결과를 반환합니다."""
    # framework_id 추론 (접두사 기준)
    fw_id = "ISMS-P"
    if requirement_id.startswith("GDPR"):
        fw_id = "GDPR"
    elif requirement_id.startswith("ISO"):
        fw_id = "ISO-27001"
    elif requirement_id.startswith("NIST"):
        fw_id = "NIST-CSF"

    return default_coverage_evaluator.evaluate_requirement(
        requirement_id=requirement_id,
        framework_id=fw_id,
        version=framework_version,
        tenant_id=tenant_id,
    )


def get_missing_inputs(
    requirement_id: str,
    framework_version: Optional[str] = None,
    tenant_id: str = "default",
) -> List[str]:
    """특정 요구사항에서 미확보된 입력 항목 식별자 목록을 반환합니다."""
    cov = get_requirement_input_coverage(
        requirement_id=requirement_id,
        framework_version=framework_version,
        tenant_id=tenant_id,
    )
    return cov.missing_inputs if cov else []


def get_supported_data_types() -> List[str]:
    """시스템이 지원하는 모든 정규 데이터 유형 목록을 반환합니다 (결정론적 정렬)."""
    return sorted([dt.value for dt in CanonicalDataType])


def get_supported_sources() -> List[str]:
    """시스템이 지원하는 모든 원천 어댑터 소스 식별자 목록을 반환합니다."""
    return sorted([
        "Firewall",
        "IAM",
        "Nessus",
        "Nmap",
        "PolicyDocument",
        "Prowler",
        "SIEM",
        "WindowsEvent",
    ])


def get_input_requirements(
    requirement_id: str,
    framework_version: Optional[str] = None,
) -> List[ComplianceInputRequirement]:
    """특정 요구사항에 매핑된 입력 요구사항 목록을 반환합니다."""
    fw_id = "ISMS-P"
    if requirement_id.startswith("GDPR"):
        fw_id = "GDPR"
    elif requirement_id.startswith("ISO"):
        fw_id = "ISO-27001"
    elif requirement_id.startswith("NIST"):
        fw_id = "NIST-CSF"

    return default_input_requirement_registry.get_by_requirement(
        requirement_id=requirement_id,
        framework_id=fw_id,
        version=framework_version or "2024-07",
    )
