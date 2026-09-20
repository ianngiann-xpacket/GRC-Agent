"""Compliance Input Requirement Model & Registry (Step 23.5A).

This module defines the mapping between a compliance Requirement and the specific
enterprise data inputs required to evaluate it, along with automation classifications.
"""

from typing import Dict, List, Optional
from pydantic import Field, field_validator

from secgrc.compliance.models import (
    AutomationLevel,
    CanonicalDataType,
    ComplianceBaseModel,
    validate_identifier,
)


class ComplianceInputRequirement(ComplianceBaseModel):
    """컴플라이언스 요구사항 검증에 필요한 구체적 입력 데이터 항목 명세."""

    input_requirement_id: str = Field(description="입력 요구사항 고유 식별자 (예: INP-REQ-ISMS-P-2.7.1-001)")
    framework_id: str = Field(description="소속 프레임워크 식별자")
    framework_version: str = Field(description="소속 프레임워크 버전")
    requirement_id: str = Field(description="대상 요구사항 식별자 (예: ISMS-P-2.7.1)")
    input_type: str = Field(description="입력 항목 구분명 (예: KMS_CMEK_CONFIGURATION, IAM_POLICY)")
    data_type: CanonicalDataType = Field(description="필요한 표준 정규 데이터 유형")
    source_type: str = Field(description="권장/기대 원천 소스 시스템 유형 (예: Prowler, IAM, Firewall, Nmap, PolicyDocument)")
    mandatory: bool = Field(default=True, description="평가 시 필수 확보 여부")
    assessment_role: str = Field(default="PRIMARY", description="평가 시 역할 (PRIMARY, CORROBORATING, CONTEXTUAL)")
    freshness_requirement: Optional[str] = Field(default="P30D", description="데이터 신선도 요구 주기 (ISO 8601 기간)")
    retention_requirement: Optional[str] = Field(default="P1Y", description="데이터 보존 주기 (ISO 8601 기간)")
    automation_level: AutomationLevel = Field(description="자동화 수준 (AUTOMATIC, SEMI_AUTOMATIC, MANUAL, NOT_APPLICABLE)")
    validation_rule: Optional[str] = Field(default=None, description="데이터 충족/유효성 판단을 위한 결정론적 조건식")
    description: str = Field(description="입력 데이터 상세 설명 및 증빙 취지")
    source_reference: Optional[str] = Field(default=None, description="공식 KISA/감사 기준 출처")

    @field_validator("input_requirement_id", "framework_id", "framework_version", "requirement_id", "input_type", "source_type")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class InputRequirementRegistry:
    """컴플라이언스 입력 요구사항 등록 및 조회 레지스트리."""

    def __init__(self) -> None:
        self._input_requirements: Dict[str, ComplianceInputRequirement] = {}
        self._initialize_ismsp_input_requirements()

    def register(self, input_req: ComplianceInputRequirement) -> None:
        """입력 요구사항을 등록합니다."""
        self._input_requirements[input_req.input_requirement_id] = input_req

    def get(self, input_requirement_id: str) -> Optional[ComplianceInputRequirement]:
        """고유 ID로 입력 요구사항을 조회합니다."""
        return self._input_requirements.get(input_requirement_id)

    def get_by_requirement(
        self,
        requirement_id: str,
        framework_id: str = "ISMS-P",
        version: str = "2024-07",
    ) -> List[ComplianceInputRequirement]:
        """특정 요구사항에 매핑된 모든 입력 요구사항을 반환합니다 (결정론적 정렬)."""
        res = [
            req for req in self._input_requirements.values()
            if req.framework_id == framework_id
            and req.framework_version == version
            and req.requirement_id == requirement_id
        ]
        return sorted(res, key=lambda r: r.input_requirement_id)

    def list_all(self) -> List[ComplianceInputRequirement]:
        """등록된 모든 입력 요구사항 목록을 반환합니다."""
        return sorted(self._input_requirements.values(), key=lambda r: r.input_requirement_id)

    def _initialize_ismsp_input_requirements(self) -> None:
        """ISMS-P 주요 요구사항에 대한 구체적 입력 요구사항 초기화."""

        inputs = [
            # 1.1.1 경영진의 참여 (MANUAL)
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-1.1.1-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-1.1.1",
                input_type="SECURITY_PLAN_DOCUMENT",
                data_type=CanonicalDataType.SECURITY_PLAN,
                source_type="PolicyDocument",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.MANUAL,
                description="최고경영자 결재가 완료된 연간 정보보호 및 개인정보보호 사업 계획서",
                source_reference="KISA-ISMS-P-2024-1.1.1",
            ),
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-1.1.1-002",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-1.1.1",
                input_type="MANAGEMENT_MEETING_MINUTES",
                data_type=CanonicalDataType.POLICY,
                source_type="PolicyDocument",
                mandatory=False,
                assessment_role="CORROBORATING",
                automation_level=AutomationLevel.MANUAL,
                description="경영진 회의록 또는 정보보호위원회 보고 의사록",
                source_reference="KISA-ISMS-P-2024-1.1.1",
            ),

            # 2.5.1 사용자 식별 (SEMI_AUTOMATIC)
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.5.1-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.5.1",
                input_type="IAM_ACCOUNT_INVENTORY",
                data_type=CanonicalDataType.ACCOUNT,
                source_type="IAM",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.AUTOMATIC,
                description="고유 식별자가 부여된 IAM 계정 목록 및 상태",
                source_reference="KISA-ISMS-P-2024-2.5.1",
            ),
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.5.1-002",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.5.1",
                input_type="ACCOUNT_MANAGEMENT_POLICY",
                data_type=CanonicalDataType.POLICY,
                source_type="PolicyDocument",
                mandatory=True,
                assessment_role="CORROBORATING",
                automation_level=AutomationLevel.MANUAL,
                description="계정 발급, 변경, 회수 절차가 명시된 계정 관리 지침",
                source_reference="KISA-ISMS-P-2024-2.5.1",
            ),

            # 2.5.2 사용자 인증 (AUTOMATIC)
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.5.2-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.5.2",
                input_type="MFA_CONFIGURATION",
                data_type=CanonicalDataType.MFA_CONFIGURATION,
                source_type="IAM",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.AUTOMATIC,
                description="관리자 및 사용자 계정의 MFA(다중요소 인증) 활성화 설정",
                source_reference="KISA-ISMS-P-2024-2.5.2",
            ),
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.5.2-002",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.5.2",
                input_type="AUTHENTICATION_AUDIT_LOG",
                data_type=CanonicalDataType.SECURITY_LOG,
                source_type="WindowsEvent",
                mandatory=False,
                assessment_role="CORROBORATING",
                automation_level=AutomationLevel.AUTOMATIC,
                description="사용자 로그온/인증 감사 이벤트 로그 (EventID 4624/4625)",
                source_reference="KISA-ISMS-P-2024-2.5.2",
            ),

            # 2.6.3 외부망 접근통제 (AUTOMATIC)
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.6.3-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.6.3",
                input_type="FIREWALL_RULES_INVENTORY",
                data_type=CanonicalDataType.FIREWALL_RULE,
                source_type="Firewall",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.AUTOMATIC,
                description="인터넷 경계 방화벽 인바운드/아웃바운드 규칙 목록",
                source_reference="KISA-ISMS-P-2024-2.6.3",
            ),
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.6.3-002",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.6.3",
                input_type="PORT_SCAN_OBSERVATION",
                data_type=CanonicalDataType.PORT_OBSERVATION,
                source_type="Nmap",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.AUTOMATIC,
                description="외부 노출 IP 대상 포트 스캔 결과 및 개방 서비스 현황",
                source_reference="KISA-ISMS-P-2024-2.6.3",
            ),
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.6.3-003",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.6.3",
                input_type="CSPM_PUBLIC_ACCESS_FINDING",
                data_type=CanonicalDataType.CONFIGURATION_FINDING,
                source_type="Prowler",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.AUTOMATIC,
                description="퍼블릭 접근 허용 클라우드 보안 구성 결함 진단 결과",
                source_reference="KISA-ISMS-P-2024-2.6.3",
            ),

            # 2.7.1 암호화 적용 (SEMI_AUTOMATIC)
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.7.1-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.7.1",
                input_type="KMS_CMEK_CONFIGURATION",
                data_type=CanonicalDataType.SECURITY_CONFIGURATION,
                source_type="Prowler",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.AUTOMATIC,
                description="클라우드 저장소/DB 암호화(CMEK) 적용 구성 상태",
                source_reference="KISA-ISMS-P-2024-2.7.1",
            ),
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.7.1-002",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.7.1",
                input_type="CRYPTOGRAPHY_POLICY_DOCUMENT",
                data_type=CanonicalDataType.POLICY,
                source_type="PolicyDocument",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.MANUAL,
                description="암호화 대상, 강도, 키 수명주기 관리 지침서",
                source_reference="KISA-ISMS-P-2024-2.7.1",
            ),
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.7.1-003",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.7.1",
                input_type="KEY_MANAGEMENT_IAM_POLICY",
                data_type=CanonicalDataType.IAM_POLICY,
                source_type="IAM",
                mandatory=False,
                assessment_role="CORROBORATING",
                automation_level=AutomationLevel.AUTOMATIC,
                description="KMS 암호키 관리 권한 통제 IAM 정책",
                source_reference="KISA-ISMS-P-2024-2.7.1",
            ),

            # 2.11.1 사고 예방 및 모니터링 (AUTOMATIC)
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.11.1-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.11.1",
                input_type="SIEM_SECURITY_ALERTS",
                data_type=CanonicalDataType.ALERT,
                source_type="SIEM",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.AUTOMATIC,
                description="SIEM 실시간 침해 시도 경보 및 탐지 이벤트",
                source_reference="KISA-ISMS-P-2024-2.11.1",
            ),
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-2.11.1-002",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-2.11.1",
                input_type="VULNERABILITY_SCAN_REPORT",
                data_type=CanonicalDataType.VULNERABILITY_FINDING,
                source_type="Nessus",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.AUTOMATIC,
                description="호스트 및 네트워크 취약점 자동 진단 결과",
                source_reference="KISA-ISMS-P-2024-2.11.1",
            ),

            # 3.1.1 개인정보 수집 제한 (MANUAL)
            ComplianceInputRequirement(
                input_requirement_id="INP-REQ-ISMS-P-3.1.1-001",
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id="ISMS-P-3.1.1",
                input_type="PRIVACY_POLICY_DOCUMENT",
                data_type=CanonicalDataType.POLICY,
                source_type="PolicyDocument",
                mandatory=True,
                assessment_role="PRIMARY",
                automation_level=AutomationLevel.MANUAL,
                description="대외 공개용 개인정보 처리방침 및 동의 서식 문서",
                source_reference="KISA-ISMS-P-2024-3.1.1",
            ),
        ]

        for inp in inputs:
            self.register(inp)


# 기본 싱글톤 입력 요구사항 레지스트리
default_input_requirement_registry = InputRequirementRegistry()
