"""Compliance Evidence Requirement & Assessment Input Models (Step 23.5B).

This module defines deterministic metadata specifying what evidence, data types,
acceptable sources, and sufficiency profiles are needed to assess compliance requirements.
It strictly defines WHAT IS REQUIRED—it does NOT evaluate compliance status (PASS/FAIL).
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import Field, field_validator

from secgrc.compliance.applicability import (
    ApplicabilityProfile,
    EvidenceCondition,
    EvidenceConditionType,
    EvidenceScopeType,
)
from secgrc.compliance.evidence_sets import (
    EvidenceSet,
    EvidenceSetOperator,
)
from secgrc.compliance.freshness import EvidenceFreshness, EvidenceFreshnessType
from secgrc.compliance.models import (
    AutomationLevel,
    CanonicalDataType,
    ComplianceBaseModel,
    validate_identifier,
)
from secgrc.compliance.source_bindings import EvidenceSourceBinding
from secgrc.compliance.temporal import TemporalCoverage, TemporalCoverageType


class EvidenceRole(str, Enum):
    """요구사항 평가에서 증적이 수행하는 결정론적 역할 구분."""
    PRIMARY = "PRIMARY"
    SUPPORTING = "SUPPORTING"
    CONTEXT = "CONTEXT"
    CONTRADICTING = "CONTRADICTING"
    CONDITIONAL = "CONDITIONAL"


class EvidenceSufficiencyProfile(ComplianceBaseModel):
    """증적 충족성 판단을 위한 메타데이터 프로필 (판정 로직 미포함)."""

    minimum_primary: int = Field(default=1, ge=0, description="최소 1차(주) 증적 요구 수")
    minimum_supporting: int = Field(default=0, ge=0, description="최소 보완 증적 요구 수")
    requires_provenance: bool = Field(default=True, description="출처 계보 검증 필수 여부")
    requires_integrity: bool = Field(default=True, description="무결성 해시 검증 필수 여부")
    requires_current_state: bool = Field(default=True, description="최신 시점 상태 반영 필수 여부")
    requires_historical_state: bool = Field(default=False, description="과거 이력 증적 필수 여부")
    requires_human_confirmation: bool = Field(default=False, description="사람의 심사 승인 필수 여부")


class ComplianceDataRequirement(ComplianceBaseModel):
    """컴플라이언스 요구사항 검증에 필요한 표준 데이터 요구 명세."""

    id: str = Field(description="데이터 요구사항 고유 식별자 (예: DTR-ISMS-P-2.7.1-01)")
    framework_id: str = Field(description="소속 프레임워크 식별자")
    framework_version: str = Field(description="소속 프레임워크 버전")
    requirement_id: str = Field(description="대상 요구사항 식별자")
    data_type: str = Field(description="데이터 명칭 구분")
    canonical_data_type: CanonicalDataType = Field(description="표준 정규 데이터 유형")
    required: bool = Field(default=True, description="필수 데이터 여부")
    role: EvidenceRole = Field(default=EvidenceRole.PRIMARY, description="데이터 역할")
    acceptable_sources: List[str] = Field(
        default_factory=list,
        description="허용 원천 시스템/소스 목록 (예: ['AWS_IAM', 'GCP_IAM', 'PROWLER'])",
    )
    minimum_observation_count: int = Field(
        default=1,
        ge=1,
        description="최소 관측 레코드 수",
    )
    freshness_window: Optional[EvidenceFreshness] = Field(
        default=None,
        description="허용 신선도 윈도우",
    )
    temporal_coverage: Optional[TemporalCoverage] = Field(
        default=None,
        description="시간적 커버리지 요건",
    )
    scope: EvidenceScopeType = Field(
        default=EvidenceScopeType.GLOBAL,
        description="데이터 스코프",
    )
    provenance_required: bool = Field(default=True, description="출처 계보 필수 여부")
    integrity_required: bool = Field(default=True, description="무결성 검증 필수 여부")
    description: str = Field(default="", description="데이터 요구사항 설명")
    source_reference: Optional[str] = Field(default=None, description="외부 규정/지침 출처")

    @field_validator("id", "framework_id", "framework_version", "requirement_id", "data_type")
    @classmethod
    def check_data_req_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class ComplianceEvidenceRequirement(ComplianceBaseModel):
    """각 컴플라이언스 요구사항을 평가하기 위해 필요한 증적의 구체적 명세."""

    id: str = Field(description="증적 요구사항 고유 식별자 (예: EV-REQ-ISMS-P-2.7.1-01)")
    framework_id: str = Field(description="소속 프레임워크 식별자")
    framework_version: str = Field(description="소속 프레임워크 버전")
    requirement_id: str = Field(description="대상 요구사항 식별자")
    evidence_id: str = Field(description="증적 항목 식별자 (예: EV-KMS-CONFIG)")
    evidence_type: str = Field(description="증적 항목 분류/유형")
    data_type: CanonicalDataType = Field(description="연계 표준 정규 데이터 유형")
    role: EvidenceRole = Field(default=EvidenceRole.PRIMARY, description="증적 평가 역할")
    mandatory: bool = Field(default=True, description="필수 증적 여부")
    description: str = Field(description="증적 요구사항 상세 설명")
    source_bindings: List[EvidenceSourceBinding] = Field(
        default_factory=list,
        description="허용 소스 및 어댑터 바인딩 목록",
    )
    freshness: Optional[EvidenceFreshness] = Field(
        default=None,
        description="증적 신선도 요건",
    )
    temporal_coverage: Optional[TemporalCoverage] = Field(
        default=None,
        description="시간적 보장 범위 요건",
    )
    automation_level: AutomationLevel = Field(
        description="자동화 수준 (AUTOMATIC, SEMI_AUTOMATIC, MANUAL, NOT_APPLICABLE, UNKNOWN)",
    )
    applicability_condition: Optional[EvidenceCondition] = Field(
        default=None,
        description="증적 요구 적용 조건",
    )
    validation_requirements: List[str] = Field(
        default_factory=list,
        description="증적 무결성 및 적합성 검증 기준 목록",
    )
    provenance_required: bool = Field(default=True, description="출처 계보 증명 필수 여부")
    human_verification_required: bool = Field(
        default=False,
        description="사람의 심사/검토 승인 필수 여부",
    )
    source_reference: Optional[str] = Field(default=None, description="공식 KISA/법령/표준 출처")
    schema_version: str = Field(default="1.0", description="증적 명세 스키마 버전")

    @field_validator(
        "id",
        "framework_id",
        "framework_version",
        "requirement_id",
        "evidence_id",
        "evidence_type",
        "schema_version",
    )
    @classmethod
    def check_evidence_req_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("source_reference")
    @classmethod
    def check_source_ref(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_identifier(v, "source_reference")
        return None


class RequirementAssessmentPrerequisite(ComplianceBaseModel):
    """요구사항 평가 전제조건 및 복합 구성 메타데이터."""

    requirement_id: str = Field(description="대상 요구사항 ID")
    framework_id: str = Field(description="소속 프레임워크 ID")
    framework_version: str = Field(description="프레임워크 버전")
    prerequisite_requirement_ids: List[str] = Field(
        default_factory=list,
        description="선행 필수 통제/요구사항 식별자 목록",
    )
    applicability_profile: Optional[ApplicabilityProfile] = Field(
        default=None,
        description="적용성 프로필",
    )
    sufficiency_profile: Optional[EvidenceSufficiencyProfile] = Field(
        default=None,
        description="증적 충족도 기준 프로필",
    )
    evidence_set: Optional[EvidenceSet] = Field(
        default=None,
        description="복합 증적 세트",
    )
    description: str = Field(default="", description="평가 전제조건 상세 설명")

    @field_validator("requirement_id", "framework_id", "framework_version")
    @classmethod
    def check_prereq_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


# ---------------------------------------------------------------------------
# Evidence Requirement Registry
# ---------------------------------------------------------------------------

class EvidenceRequirementRegistry:
    """컴플라이언스 증적 및 데이터 요구사항 중앙 레지스트리."""

    def __init__(self) -> None:
        self._evidence_requirements: Dict[str, ComplianceEvidenceRequirement] = {}
        self._data_requirements: Dict[str, ComplianceDataRequirement] = {}
        self._evidence_sets: Dict[str, EvidenceSet] = {}
        self._prerequisites: Dict[str, RequirementAssessmentPrerequisite] = {}
        self._initialize_ismsp_2024_evidence()
        self._initialize_ismsp_2019_evidence()
        self._initialize_gdpr_evidence()

    def register_evidence_requirement(self, req: ComplianceEvidenceRequirement) -> None:
        """증적 요구사항을 등록합니다."""
        self._evidence_requirements[req.id] = req

    def register_data_requirement(self, req: ComplianceDataRequirement) -> None:
        """데이터 요구사항을 등록합니다."""
        self._data_requirements[req.id] = req

    def register_evidence_set(self, ev_set: EvidenceSet) -> None:
        """증적 세트를 등록합니다."""
        self._evidence_sets[ev_set.set_id] = ev_set

    def register_prerequisite(self, prereq: RequirementAssessmentPrerequisite) -> None:
        """평가 전제조건을 등록합니다."""
        key = f"{prereq.framework_id}:{prereq.framework_version}:{prereq.requirement_id}"
        self._prerequisites[key] = prereq

    def get_evidence_requirement(self, req_id: str) -> Optional[ComplianceEvidenceRequirement]:
        """고유 ID로 증적 요구사항을 조회합니다."""
        return self._evidence_requirements.get(req_id)

    def get_data_requirement(self, data_req_id: str) -> Optional[ComplianceDataRequirement]:
        """고유 ID로 데이터 요구사항을 조회합니다."""
        return self._data_requirements.get(data_req_id)

    def get_evidence_set(self, set_id: str) -> Optional[EvidenceSet]:
        """고유 ID로 증적 세트를 조회합니다."""
        return self._evidence_sets.get(set_id)

    def get_prerequisite(
        self,
        requirement_id: str,
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
    ) -> Optional[RequirementAssessmentPrerequisite]:
        """요구사항의 평가 전제조건을 조회합니다."""
        key = f"{framework_id}:{framework_version}:{requirement_id}"
        return self._prerequisites.get(key)

    def list_evidence_requirements(
        self,
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
        requirement_id: Optional[str] = None,
    ) -> List[ComplianceEvidenceRequirement]:
        """조건에 맞는 증적 요구사항 목록을 결정론적 순서로 반환합니다."""
        res = [
            r for r in self._evidence_requirements.values()
            if r.framework_id == framework_id and r.framework_version == framework_version
        ]
        if requirement_id is not None:
            res = [r for r in res if r.requirement_id == requirement_id]
        return sorted(res, key=lambda r: r.id)

    def list_data_requirements(
        self,
        framework_id: str = "ISMS-P",
        framework_version: str = "2024-07",
        requirement_id: Optional[str] = None,
    ) -> List[ComplianceDataRequirement]:
        """조건에 맞는 데이터 요구사항 목록을 결정론적 순서로 반환합니다."""
        res = [
            r for r in self._data_requirements.values()
            if r.framework_id == framework_id and r.framework_version == framework_version
        ]
        if requirement_id is not None:
            res = [r for r in res if r.requirement_id == requirement_id]
        return sorted(res, key=lambda r: r.id)

    def _initialize_ismsp_2024_evidence(self) -> None:
        """ISMS-P 2024-07 증적 및 데이터 요구사항 권위 메타데이터 등록."""
        # --- 2.5.2 사용자 인증 (MFA, 패스워드 정책) ---
        ev_252_primary = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-2.5.2-01",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-2.5.2",
            evidence_id="EV-IAM-MFA",
            evidence_type="MFA_CONFIGURATION",
            data_type=CanonicalDataType.MFA_CONFIGURATION,
            role=EvidenceRole.PRIMARY,
            mandatory=True,
            description="정보시스템 및 콘솔 접근 시 다중요소인증(MFA) 활성화 및 강제 설정 증적",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="IAM",
                    canonical_data_type=CanonicalDataType.MFA_CONFIGURATION,
                    source_system="AWS IAM / GCP IAM",
                    adapter_type="IAMPolicyDataAdapter",
                    required=True,
                    priority=1,
                    description="클라우드 및 시스템 콘솔 MFA 구성 상태",
                )
            ],
            freshness=EvidenceFreshness(
                freshness_type=EvidenceFreshnessType.WITHIN_DAYS,
                freshness_value=30,
                unit="days",
                description="최근 30일 이내 수집된 MFA 구성 상태",
            ),
            temporal_coverage=TemporalCoverage(
                temporal_type=TemporalCoverageType.POINT_IN_TIME,
                description="최신 시점의 MFA 강제화 정책 스냅샷",
            ),
            automation_level=AutomationLevel.AUTOMATIC,
            validation_requirements=["MFA_ENABLED_FOR_ADMIN", "NO_EXEMPTION_WITHOUT_APPROVAL"],
            source_reference="KISA-ISMS-P-2024-2.5.2",
        )
        self.register_evidence_requirement(ev_252_primary)

        ev_252_supp = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-2.5.2-02",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-2.5.2",
            evidence_id="EV-AUTH-CONFIG",
            evidence_type="AUTHENTICATION_CONFIGURATION",
            data_type=CanonicalDataType.AUTHENTICATION_CONFIGURATION,
            role=EvidenceRole.SUPPORTING,
            mandatory=False,
            description="비밀번호 복잡도, 변경 주기, 잠금 임계치 설정 구성 증적",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="IAM",
                    canonical_data_type=CanonicalDataType.AUTHENTICATION_CONFIGURATION,
                    source_system="Entra ID / Active Directory",
                    adapter_type="IAMPolicyDataAdapter",
                    required=False,
                    priority=2,
                    description="계정 인증 정책 및 패스워드 정책",
                )
            ],
            automation_level=AutomationLevel.AUTOMATIC,
            source_reference="KISA-ISMS-P-2024-2.5.2",
        )
        self.register_evidence_requirement(ev_252_supp)

        ev_252_cond = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-2.5.2-03",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-2.5.2",
            evidence_id="EV-PAM-RECORD",
            evidence_type="PAM_RECORD",
            data_type=CanonicalDataType.PAM_RECORD,
            role=EvidenceRole.CONDITIONAL,
            mandatory=False,
            description="특권 계정 접근 시 특권접근관리(PAM) 솔루션을 통한 2차 인증 및 세션 기록",
            applicability_condition=EvidenceCondition(
                condition_type=EvidenceConditionType.IF_PRIVILEGED_ACCESS_EXISTS,
                dimension="access",
                parameter="root_admin",
                description="특권 관리자 계정이 존재하는 경우 PAM 2차 인증 증적 필수",
            ),
            automation_level=AutomationLevel.SEMI_AUTOMATIC,
            human_verification_required=True,
            source_reference="KISA-ISMS-P-2024-2.5.2",
        )
        self.register_evidence_requirement(ev_252_cond)

        # 2.5.2 Data Requirements
        self.register_data_requirement(
            ComplianceDataRequirement(
                id="DTR-ISMS-P-2.5.2-01",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.5.2",
                data_type="MFA_CONFIGURATION",
                canonical_data_type=CanonicalDataType.MFA_CONFIGURATION,
                required=True,
                role=EvidenceRole.PRIMARY,
                acceptable_sources=["AWS_IAM", "GCP_IAM", "AZURE_ENTRA", "PROWLER"],
                description="MFA 강제 활성화 상태 데이터",
                source_reference="KISA-ISMS-P-2024-2.5.2",
            )
        )
        self.register_data_requirement(
            ComplianceDataRequirement(
                id="DTR-ISMS-P-2.5.2-02",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.5.2",
                data_type="ACCESS_REVIEW",
                canonical_data_type=CanonicalDataType.ACCESS_REVIEW,
                required=False,
                role=EvidenceRole.SUPPORTING,
                acceptable_sources=["IAM", "GRC_PORTAL"],
                description="정기 계정 권한 및 인증 수단 재검토 이력",
                source_reference="KISA-ISMS-P-2024-2.5.2",
            )
        )

        # 2.5.2 Evidence Set & Prerequisite
        ev_set_252 = EvidenceSet(
            set_id="EV-SET-ISMS-P-2.5.2-01",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-2.5.2",
            operator=EvidenceSetOperator.ALL,
            required_evidence_ids=["EV-REQ-ISMS-P-2.5.2-01"],
            supporting_evidence_ids=["EV-REQ-ISMS-P-2.5.2-02"],
            conditional_evidence_ids=["EV-REQ-ISMS-P-2.5.2-03"],
            description="사용자 인증 통제 검증을 위한 필수 MFA 및 보조 인증 설정 증적 세트",
        )
        self.register_evidence_set(ev_set_252)

        self.register_prerequisite(
            RequirementAssessmentPrerequisite(
                requirement_id="ISMS-P-2.5.2",
                framework_id="ISMS-P",
                framework_version="2024-07",
                prerequisite_requirement_ids=["ISMS-P-2.5.1"],
                applicability_profile=ApplicabilityProfile(
                    jurisdiction="KR",
                    conditions=[
                        EvidenceCondition(
                            condition_type=EvidenceConditionType.ALWAYS,
                            description="모든 정보시스템 사용자 인증에 기본 적용",
                        )
                    ],
                ),
                sufficiency_profile=EvidenceSufficiencyProfile(
                    minimum_primary=1,
                    minimum_supporting=1,
                    requires_provenance=True,
                    requires_integrity=True,
                ),
                evidence_set=ev_set_252,
                description="2.5.1 사용자 식별 요건이 선행 충족되어야 2.5.2 인증 요건 평가 가능",
            )
        )

        # --- 2.6.3 외부망 접근통제 (방화벽, 포트스캔) ---
        ev_263_primary = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-2.6.3-01",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-2.6.3",
            evidence_id="EV-FIREWALL-RULE",
            evidence_type="FIREWALL_RULESET",
            data_type=CanonicalDataType.FIREWALL_RULE,
            role=EvidenceRole.PRIMARY,
            mandatory=True,
            description="외부망 접점 방화벽 인바운드/아웃바운드 정책 및 미사용 포트 차단 룰셋",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="Firewall",
                    canonical_data_type=CanonicalDataType.FIREWALL_RULE,
                    source_system="Palo Alto / Fortinet / iptables",
                    adapter_type="FirewallPolicyDataAdapter",
                    required=True,
                    priority=1,
                    description="경계 방화벽 인바운드 인가 룰셋",
                )
            ],
            freshness=EvidenceFreshness(
                freshness_type=EvidenceFreshnessType.WITHIN_DAYS,
                freshness_value=7,
                unit="days",
                description="최근 7일 이내 추출된 방화벽 룰셋",
            ),
            temporal_coverage=TemporalCoverage(
                temporal_type=TemporalCoverageType.POINT_IN_TIME,
                description="현재 운영 중인 활성 방화벽 구성",
            ),
            automation_level=AutomationLevel.AUTOMATIC,
            validation_requirements=["NO_ANY_ANY_ALLOW", "EXPLICIT_DROP_DEFAULT"],
            source_reference="KISA-ISMS-P-2024-2.6.3",
        )
        self.register_evidence_requirement(ev_263_primary)

        ev_263_supp = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-2.6.3-02",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-2.6.3",
            evidence_id="EV-NMAP-PORT",
            evidence_type="PORT_OBSERVATION",
            data_type=CanonicalDataType.PORT_OBSERVATION,
            role=EvidenceRole.SUPPORTING,
            mandatory=False,
            description="외부 포트 스캐닝 결과를 통한 비인가 포트 개방 여부 검증 데이터",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="Nmap",
                    canonical_data_type=CanonicalDataType.PORT_OBSERVATION,
                    source_system="Nmap Scanner",
                    adapter_type="NmapDataAdapter",
                    required=False,
                    priority=2,
                    description="외부 경계 포트 스캔 결과",
                )
            ],
            automation_level=AutomationLevel.AUTOMATIC,
            source_reference="KISA-ISMS-P-2024-2.6.3",
        )
        self.register_evidence_requirement(ev_263_supp)

        self.register_data_requirement(
            ComplianceDataRequirement(
                id="DTR-ISMS-P-2.6.3-01",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.6.3",
                data_type="FIREWALL_POLICY",
                canonical_data_type=CanonicalDataType.FIREWALL_POLICY,
                required=True,
                role=EvidenceRole.PRIMARY,
                acceptable_sources=["Firewall", "PaloAlto", "Cisco"],
                description="경계 방화벽 접근통제 정책",
                source_reference="KISA-ISMS-P-2024-2.6.3",
            )
        )

        # --- 2.7.1 암호화 적용 (저장 데이터/전송 구간 암호화) ---
        ev_271_primary = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-2.7.1-01",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-2.7.1",
            evidence_id="EV-KMS-ENCRYPTION",
            evidence_type="SECURITY_CONFIGURATION",
            data_type=CanonicalDataType.SECURITY_CONFIGURATION,
            role=EvidenceRole.PRIMARY,
            mandatory=True,
            description="개인정보 저장 데이터베이스 및 스토리지 암호화(CMEK/AES-256) 적용 설정",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="Prowler",
                    canonical_data_type=CanonicalDataType.SECURITY_CONFIGURATION,
                    source_system="Prowler Security Scanner",
                    adapter_type="ProwlerDataAdapter",
                    required=True,
                    priority=1,
                    description="스토리지 및 데이터베이스 암호화 구성 감사",
                )
            ],
            freshness=EvidenceFreshness(
                freshness_type=EvidenceFreshnessType.WITHIN_DAYS,
                freshness_value=14,
                unit="days",
                description="최근 14일 이내 점검된 암호화 설정",
            ),
            automation_level=AutomationLevel.AUTOMATIC,
            validation_requirements=["ALGORITHM_AES256_OR_HIGHER", "CUSTOMER_MANAGED_KEY_VERIFIED"],
            source_reference="KISA-ISMS-P-2024-2.7.1",
        )
        self.register_evidence_requirement(ev_271_primary)

        self.register_data_requirement(
            ComplianceDataRequirement(
                id="DTR-ISMS-P-2.7.1-01",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.7.1",
                data_type="SECURITY_CONFIGURATION",
                canonical_data_type=CanonicalDataType.SECURITY_CONFIGURATION,
                required=True,
                role=EvidenceRole.PRIMARY,
                acceptable_sources=["Prowler", "CloudConfig", "AuditTool"],
                description="저장 및 전송 구간 암호화 구성 데이터",
                source_reference="KISA-ISMS-P-2024-2.7.1",
            )
        )

        # --- 2.11.1 사고 예방 및 모니터링 (SIEM, Nessus) ---
        ev_2111_primary = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-2.11.1-01",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-2.11.1",
            evidence_id="EV-SIEM-ALERT",
            evidence_type="ALERT",
            data_type=CanonicalDataType.ALERT,
            role=EvidenceRole.PRIMARY,
            mandatory=True,
            description="이상 징후 탐지 및 보안 이벤트 통합 모니터링 경보 데이터",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="SIEM",
                    canonical_data_type=CanonicalDataType.ALERT,
                    source_system="Splunk / Wazuh / QRadar",
                    adapter_type="SIEMEventDataAdapter",
                    required=True,
                    priority=1,
                    description="보안 이벤트 및 이상 징후 알림",
                )
            ],
            freshness=EvidenceFreshness(
                freshness_type=EvidenceFreshnessType.WITHIN_HOURS,
                freshness_value=24,
                unit="hours",
                description="실시간 및 최근 24시간 이내 모니터링 로그",
            ),
            temporal_coverage=TemporalCoverage(
                temporal_type=TemporalCoverageType.CONTINUOUS,
                minimum_span_days=180,
                description="최소 6개월 이상의 상시 모니터링 및 탐지 이력",
            ),
            automation_level=AutomationLevel.AUTOMATIC,
            source_reference="KISA-ISMS-P-2024-2.11.1",
        )
        self.register_evidence_requirement(ev_2111_primary)

        ev_2111_supp = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-2.11.1-02",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-2.11.1",
            evidence_id="EV-VULN-SCAN",
            evidence_type="VULNERABILITY_FINDING",
            data_type=CanonicalDataType.VULNERABILITY_FINDING,
            role=EvidenceRole.SUPPORTING,
            mandatory=False,
            description="정기 시스템 및 웹 취약점 진단 보고서 데이터",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="Nessus",
                    canonical_data_type=CanonicalDataType.VULNERABILITY_FINDING,
                    source_system="Tenable Nessus",
                    adapter_type="NessusDataAdapter",
                    required=False,
                    priority=2,
                    description="취약점 점검 결과 목록",
                )
            ],
            automation_level=AutomationLevel.AUTOMATIC,
            source_reference="KISA-ISMS-P-2024-2.11.1",
        )
        self.register_evidence_requirement(ev_2111_supp)

        self.register_data_requirement(
            ComplianceDataRequirement(
                id="DTR-ISMS-P-2.11.1-01",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.11.1",
                data_type="SECURITY_EVENT",
                canonical_data_type=CanonicalDataType.SECURITY_EVENT,
                required=True,
                role=EvidenceRole.PRIMARY,
                acceptable_sources=["SIEM", "Syslog", "EDR"],
                description="보안 이벤트 및 이상행위 탐지 데이터",
                source_reference="KISA-ISMS-P-2024-2.11.1",
            )
        )

        # --- 1.1.1 경영진의 참여 (MANUAL) ---
        ev_111_primary = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-1.1.1-01",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-1.1.1",
            evidence_id="EV-SECURITY-PLAN",
            evidence_type="SECURITY_PLAN",
            data_type=CanonicalDataType.SECURITY_PLAN,
            role=EvidenceRole.PRIMARY,
            mandatory=True,
            description="경영진 서명 또는 전자결재가 완료된 연간 정보보호 계획서",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="PolicyDocument",
                    canonical_data_type=CanonicalDataType.SECURITY_PLAN,
                    source_system="Groupware / EDM",
                    adapter_type="PolicyDocumentDataAdapter",
                    required=True,
                    priority=1,
                    description="경영진 승인 문서",
                )
            ],
            automation_level=AutomationLevel.MANUAL,
            human_verification_required=True,
            source_reference="KISA-ISMS-P-2024-1.1.1",
        )
        self.register_evidence_requirement(ev_111_primary)

        self.register_data_requirement(
            ComplianceDataRequirement(
                id="DTR-ISMS-P-1.1.1-01",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-1.1.1",
                data_type="SECURITY_PLAN",
                canonical_data_type=CanonicalDataType.SECURITY_PLAN,
                required=True,
                role=EvidenceRole.PRIMARY,
                acceptable_sources=["PolicyDocument", "EDM"],
                description="경영진 승인 정보보호 계획서",
                source_reference="KISA-ISMS-P-2024-1.1.1",
            )
        )

        # --- 3.1.1 개인정보 수집 제한 (PRIVACY) ---
        ev_311_primary = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-3.1.1-01",
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id="ISMS-P-3.1.1",
            evidence_id="EV-CONSENT-RECORD",
            evidence_type="CONSENT",
            data_type=CanonicalDataType.CONSENT,
            role=EvidenceRole.PRIMARY,
            mandatory=True,
            description="이용자 개인정보 수집 시 법정 고지 및 동의 획득 이력",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="PolicyDocument",
                    canonical_data_type=CanonicalDataType.CONSENT,
                    source_system="Privacy Management System",
                    adapter_type="PolicyDocumentDataAdapter",
                    required=True,
                    priority=1,
                    description="동의 서식 및 동의 로그",
                )
            ],
            automation_level=AutomationLevel.SEMI_AUTOMATIC,
            human_verification_required=True,
            source_reference="KISA-ISMS-P-2024-3.1.1",
        )
        self.register_evidence_requirement(ev_311_primary)

        self.register_data_requirement(
            ComplianceDataRequirement(
                id="DTR-ISMS-P-3.1.1-01",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-3.1.1",
                data_type="CONSENT",
                canonical_data_type=CanonicalDataType.CONSENT,
                required=True,
                role=EvidenceRole.PRIMARY,
                acceptable_sources=["PrivacyDB", "PolicyDocument"],
                description="이용자 동의 획득 내역 데이터",
                source_reference="KISA-ISMS-P-2024-3.1.1",
            )
        )

    def _initialize_ismsp_2019_evidence(self) -> None:
        """ISMS-P 2019-01 독립 버전 증적 요구사항 등록 (버전 관리 보장)."""
        ev_2019_252 = ComplianceEvidenceRequirement(
            id="EV-REQ-ISMS-P-2019-2.5.2-01",
            framework_id="ISMS-P",
            framework_version="2019-01",
            requirement_id="ISMS-P-2.5.2",
            evidence_id="EV-IAM-MFA-2019",
            evidence_type="MFA_CONFIGURATION",
            data_type=CanonicalDataType.MFA_CONFIGURATION,
            role=EvidenceRole.PRIMARY,
            mandatory=True,
            description="[2019-01 기준] 사용자 인증 및 패스워드 통제 증적",
            source_bindings=[
                EvidenceSourceBinding(
                    source_type="IAM",
                    canonical_data_type=CanonicalDataType.MFA_CONFIGURATION,
                    source_system="Legacy IAM",
                    adapter_type="IAMPolicyDataAdapter",
                    required=True,
                    priority=1,
                    description="레거시 인증 구성",
                )
            ],
            automation_level=AutomationLevel.AUTOMATIC,
            source_reference="KISA-ISMS-P-2019-2.5.2",
        )
        self.register_evidence_requirement(ev_2019_252)

        self.register_data_requirement(
            ComplianceDataRequirement(
                id="DTR-ISMS-P-2019-2.5.2-01",
                framework_id="ISMS-P",
                framework_version="2019-01",
                requirement_id="ISMS-P-2.5.2",
                data_type="MFA_CONFIGURATION",
                canonical_data_type=CanonicalDataType.MFA_CONFIGURATION,
                required=True,
                role=EvidenceRole.PRIMARY,
                acceptable_sources=["IAM", "PROWLER"],
                description="[2019-01 기준] MFA 구성 데이터",
                source_reference="KISA-ISMS-P-2019-2.5.2",
            )
        )

    def _initialize_gdpr_evidence(self) -> None:
        """GDPR 주요 조항(Article 28, 30, 32, 33, 34, 35) 권위 증적 메타데이터 등록."""
        gdpr_reqs = [
            # Article 28: Processor
            (
                "GDPR-Art-28",
                "EV-GDPR-DPA",
                "DPA",
                CanonicalDataType.DPA,
                "Article 28 Data Processing Agreement (DPA) contract binding processor to controller",
                AutomationLevel.MANUAL,
                True,
            ),
            # Article 30: Records of Processing Activities (RoPA)
            (
                "GDPR-Art-30",
                "EV-GDPR-ROPA",
                "PROCESSING_ACTIVITY",
                CanonicalDataType.PROCESSING_ACTIVITY,
                "Article 30 Record of Processing Activities maintained by controller or processor",
                AutomationLevel.SEMI_AUTOMATIC,
                True,
            ),
            # Article 32: Security of Processing (Encryption & Access Control)
            (
                "GDPR-Art-32",
                "EV-GDPR-SEC-MEASURE",
                "SECURITY_CONFIGURATION",
                CanonicalDataType.SECURITY_CONFIGURATION,
                "Article 32 Technical and organisational security measures (encryption, confidentiality, integrity)",
                AutomationLevel.AUTOMATIC,
                False,
            ),
            # Article 33: Breach Notification to Supervisory Authority
            (
                "GDPR-Art-33",
                "EV-GDPR-BREACH-NOTIF",
                "PRIVACY_INCIDENT",
                CanonicalDataType.PRIVACY_INCIDENT,
                "Article 33 Notification of a personal data breach to the supervisory authority within 72 hours",
                AutomationLevel.SEMI_AUTOMATIC,
                True,
            ),
            # Article 34: Communication of Breach to Data Subject
            (
                "GDPR-Art-34",
                "EV-GDPR-BREACH-COMM",
                "PRIVACY_INCIDENT",
                CanonicalDataType.PRIVACY_INCIDENT,
                "Article 34 Direct communication of high-risk personal data breach to affected data subjects",
                AutomationLevel.SEMI_AUTOMATIC,
                True,
            ),
            # Article 35: Data Protection Impact Assessment (DPIA)
            (
                "GDPR-Art-35",
                "EV-GDPR-DPIA",
                "DPIA",
                CanonicalDataType.DPIA,
                "Article 35 Data Protection Impact Assessment document for high-risk processing operations",
                AutomationLevel.MANUAL,
                True,
            ),
        ]

        for req_id, ev_id, ev_type, c_type, desc, auto_lvl, human_req in gdpr_reqs:
            ev_req = ComplianceEvidenceRequirement(
                id=f"EV-REQ-{req_id}-01",
                framework_id="GDPR",
                framework_version="2016-679",
                requirement_id=req_id,
                evidence_id=ev_id,
                evidence_type=ev_type,
                data_type=c_type,
                role=EvidenceRole.PRIMARY,
                mandatory=True,
                description=desc,
                source_bindings=[
                    EvidenceSourceBinding(
                        source_type="PolicyDocument" if auto_lvl == AutomationLevel.MANUAL else "SecuritySource",
                        canonical_data_type=c_type,
                        source_system="GDPR GRC System",
                        adapter_type="PolicyDocumentDataAdapter" if auto_lvl == AutomationLevel.MANUAL else "ProwlerDataAdapter",
                        required=True,
                        priority=1,
                        description=f"GDPR {req_id} compliant source",
                    )
                ],
                automation_level=auto_lvl,
                human_verification_required=human_req,
                source_reference=f"EUR-Lex-GDPR-{req_id}",
            )
            self.register_evidence_requirement(ev_req)

            self.register_data_requirement(
                ComplianceDataRequirement(
                    id=f"DTR-{req_id}-01",
                    framework_id="GDPR",
                    framework_version="2016-679",
                    requirement_id=req_id,
                    data_type=ev_type,
                    canonical_data_type=c_type,
                    required=True,
                    role=EvidenceRole.PRIMARY,
                    acceptable_sources=["GDPR_STORE", "PROWLER", "POLICY_STORE"],
                    description=desc,
                    source_reference=f"EUR-Lex-GDPR-{req_id}",
                )
            )


# 전역 기본 레지스트리 싱글톤
default_evidence_requirement_registry = EvidenceRequirementRegistry()
