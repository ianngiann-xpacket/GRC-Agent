"""Compliance Requirement Model & Registry (Step 23.5A).

This module defines the framework-independent Requirement domain model
and houses authoritative requirement sets for ISMS-P, GDPR, and ISO 27001.
"""

from typing import Dict, List, Optional
from pydantic import Field, field_validator

from secgrc.compliance.models import (
    ComplianceBaseModel,
    EnterpriseDomain,
    validate_identifier,
)


class Requirement(ComplianceBaseModel):
    """프레임워크 비종속적 컴플라이언스 요구사항 표준 모델."""

    requirement_id: str = Field(description="요구사항 표준 고유 식별자 (예: ISMS-P-2.7.1, GDPR-Art-32)")
    framework_id: str = Field(description="소속 프레임워크 식별자")
    framework_version: str = Field(description="소속 프레임워크 버전 (예: 2024-07)")
    category_id: str = Field(description="상위 분류/영역 식별자 (예: 1.1, 2.7, 3.1)")
    category_name: str = Field(description="상위 분류/영역 명칭 (예: 암호화 적용, 접근통제)")
    domain: EnterpriseDomain = Field(description="해당 요구사항의 주 엔터프라이즈 도메인")
    name: str = Field(description="요구사항 항목명")
    description: str = Field(description="요구사항 상세 내용 및 법적/기술적 기준")
    guidance: Optional[str] = Field(default=None, description="세부 인증/심사 가이드라인")
    source_reference: Optional[str] = Field(default=None, description="공식 고시/법령 출처 참조")
    mandatory: bool = Field(default=True, description="필수 준수 항목 여부")
    sub_requirements: List[str] = Field(default_factory=list, description="세부 점검 항목 목록")

    @field_validator("requirement_id", "framework_id", "framework_version", "category_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class RequirementRegistry:
    """컴플라이언스 요구사항 등록 및 조회 레지스트리."""

    def __init__(self) -> None:
        self._requirements: Dict[str, Requirement] = {}
        self._initialize_ismsp_2024_requirements()
        self._initialize_ismsp_2019_requirements()
        self._initialize_gdpr_requirements()

    def register(self, requirement: Requirement) -> None:
        """요구사항을 등록합니다 (키: framework_id:framework_version:requirement_id)."""
        key = self._make_key(requirement.framework_id, requirement.framework_version, requirement.requirement_id)
        self._requirements[key] = requirement

    def get(self, requirement_id: str, framework_id: str = "ISMS-P", version: str = "2024-07") -> Optional[Requirement]:
        """특정 프레임워크 및 버전의 요구사항을 조회합니다."""
        key = self._make_key(framework_id, version, requirement_id)
        return self._requirements.get(key)

    def list_by_framework(self, framework_id: str = "ISMS-P", version: str = "2024-07") -> List[Requirement]:
        """특정 프레임워크 버전에 속한 모든 요구사항을 반환합니다 (결정론적 정렬)."""
        res = [
            r for r in self._requirements.values()
            if r.framework_id == framework_id and r.framework_version == version
        ]
        return sorted(res, key=lambda r: r.requirement_id)

    def count(self, framework_id: str = "ISMS-P", version: str = "2024-07") -> int:
        """등록된 요구사항 수를 반환합니다."""
        return len(self.list_by_framework(framework_id, version))

    def _make_key(self, framework_id: str, version: str, requirement_id: str) -> str:
        return f"{framework_id}:{version}:{requirement_id}"

    def _initialize_ismsp_2024_requirements(self) -> None:
        """ISMS-P 2024-07 권위 요구사항 세트 초기화 (1, 2, 3 영역 대표 항목 포함)."""

        reqs = [
            # 1. 관리체계 수립 및 운영
            Requirement(
                requirement_id="ISMS-P-1.1.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="1.1",
                category_name="관리체계 기반 마련",
                domain=EnterpriseDomain.GOVERNANCE,
                name="경영진의 참여",
                description="최고경영자는 정보보호 및 개인정보보호 관리체계의 수립, 운영, 개선 활동에 적극적으로 참여하고 책임을 다하여야 한다.",
                source_reference="KISA-ISMS-P-2024-1.1.1",
                mandatory=True,
                sub_requirements=[
                    "최고경영자의 관리체계 참여 증적 확보",
                    "연간 정보보호 계획 및 예산 승인 문서",
                ],
            ),
            Requirement(
                requirement_id="ISMS-P-1.1.2",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="1.1",
                category_name="관리체계 기반 마련",
                domain=EnterpriseDomain.GOVERNANCE,
                name="최고책임자의 지정",
                description="최고경영자는 정보보호최고책임자(CISO) 및 개인정보보호책임자(CPO)를 관련 법령에 따라 지정하고 공식 임명하여야 한다.",
                source_reference="KISA-ISMS-P-2024-1.1.2",
                mandatory=True,
                sub_requirements=["CISO/CPO 임명 문서", "자격 요건 충족 확인서"],
            ),
            Requirement(
                requirement_id="ISMS-P-1.2.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="1.2",
                category_name="위험 관리",
                domain=EnterpriseDomain.GOVERNANCE,
                name="위험 식별 및 평가",
                description="정보자산 및 개인정보의 위험을 식별하고 주기적으로 위험을 평가하여 조치 계획을 수립하여야 한다.",
                source_reference="KISA-ISMS-P-2024-1.2.1",
                mandatory=True,
                sub_requirements=["위험관리 기준서", "위험평가 보고서"],
            ),
            # 2. 보호대책 요구사항
            Requirement(
                requirement_id="ISMS-P-2.1.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="2.1",
                category_name="정책, 조직, 자산",
                domain=EnterpriseDomain.GOVERNANCE,
                name="보안 정책의 제·개정",
                description="정보보호 및 개인정보보호 정책 및 지침을 제정하고 주기적으로 검토·개정하여야 한다.",
                source_reference="KISA-ISMS-P-2024-2.1.1",
                mandatory=True,
                sub_requirements=["보안 정책서", "보안 지침서", "정책 검토 승인 이력"],
            ),
            Requirement(
                requirement_id="ISMS-P-2.5.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="2.5",
                category_name="인증 및 권한관리",
                domain=EnterpriseDomain.IDENTITY_ACCESS,
                name="사용자 식별",
                description="모든 사용자는 고유하게 식별되어야 하며 안전한 식별 및 인증 메커니즘을 적용하여야 한다.",
                source_reference="KISA-ISMS-P-2024-2.5.1",
                mandatory=True,
                sub_requirements=["고유 식별자 부여 규칙", "계정 정책"],
            ),
            Requirement(
                requirement_id="ISMS-P-2.5.2",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="2.5",
                category_name="인증 및 권한관리",
                domain=EnterpriseDomain.IDENTITY_ACCESS,
                name="사용자 인증",
                description="정보시스템 및 개인정보처리시스템에 접근 시 다중요소 인증(MFA) 등 강력한 인증 메커니즘을 적용하여야 한다.",
                source_reference="KISA-ISMS-P-2024-2.5.2",
                mandatory=True,
                sub_requirements=["MFA 설정 상태", "비밀번호 복잡도 정책"],
            ),
            Requirement(
                requirement_id="ISMS-P-2.6.3",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="2.6",
                category_name="접근통제",
                domain=EnterpriseDomain.NETWORK_SECURITY,
                name="외부망 접근통제",
                description="외부망과 내부망 간의 경계에 방화벽 등 접근통제 시스템을 설치하고 비인가 접근을 차단하여야 한다.",
                source_reference="KISA-ISMS-P-2024-2.6.3",
                mandatory=True,
                sub_requirements=["방화벽 인바운드/아웃바운드 정책", "포트 개방 현황"],
            ),
            Requirement(
                requirement_id="ISMS-P-2.7.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="2.7",
                category_name="암호화 적용",
                domain=EnterpriseDomain.DATA_SECURITY_PRIVACY,
                name="암호화 적용",
                description="개인정보 및 중요정보의 저장 및 전송 시 안전한 암호화 알고리즘을 적용하고 암호키를 안전하게 관리하여야 한다.",
                source_reference="KISA-ISMS-P-2024-2.7.1",
                mandatory=True,
                sub_requirements=[
                    "저장 데이터 암호화(CMEK/AES-256)",
                    "전송 구간 암호화(TLS 1.2 이상)",
                    "암호키 수명주기 관리 정책",
                ],
            ),
            Requirement(
                requirement_id="ISMS-P-2.9.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="2.9",
                category_name="시스템 및 서비스 운영관리",
                domain=EnterpriseDomain.ASSET_CONFIGURATION,
                name="변경관리",
                description="정보시스템 및 네트워크 구성, 애플리케이션의 변경사항을 통제하고 승인 절차를 거쳐 반영하여야 한다.",
                source_reference="KISA-ISMS-P-2024-2.9.1",
                mandatory=True,
                sub_requirements=["변경 요청서", "변경 승인 이력"],
            ),
            Requirement(
                requirement_id="ISMS-P-2.10.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="2.10",
                category_name="시스템 및 서비스 보안관리",
                domain=EnterpriseDomain.SECURITY_OPERATIONS,
                name="보안시스템 운영",
                description="침입탐지시스템, 침입차단시스템 등 보안시스템을 설치·운영하고 최신 보안 정책을 유지하여야 한다.",
                source_reference="KISA-ISMS-P-2024-2.10.1",
                mandatory=True,
                sub_requirements=["보안시스템 룰셋 검토", "보안 이벤트 모니터링"],
            ),
            Requirement(
                requirement_id="ISMS-P-2.11.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="2.11",
                category_name="사고 예방 및 대응",
                domain=EnterpriseDomain.SECURITY_OPERATIONS,
                name="사고 예방 및 모니터링",
                description="보안사고를 예방하기 위하여 내·외부 위협 및 취약점을 모니터링하고 분석하여야 한다.",
                source_reference="KISA-ISMS-P-2024-2.11.1",
                mandatory=True,
                sub_requirements=["SIEM 로그 수집", "취약점 진단 결과"],
            ),
            # 3. 개인정보 처리단계별 요구사항
            Requirement(
                requirement_id="ISMS-P-3.1.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="3.1",
                category_name="개인정보 수집 시 보호조치",
                domain=EnterpriseDomain.DATA_SECURITY_PRIVACY,
                name="개인정보 수집 제한",
                description="개인정보 수집 시 서비스 제공에 필요한 최소한의 개인정보만을 수집하여야 한다.",
                source_reference="KISA-ISMS-P-2024-3.1.1",
                mandatory=True,
                sub_requirements=["수집 항목 최소화 검토", "동의 서식 및 개인정보 처리방침"],
            ),
            Requirement(
                requirement_id="ISMS-P-3.2.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="3.2",
                category_name="개인정보 보유 및 이용 시 보호조치",
                domain=EnterpriseDomain.DATA_SECURITY_PRIVACY,
                name="개인정보 현황 관리",
                description="보유하고 있는 개인정보 파일 및 흐름을 식별하고 개인정보 관리대장을 최신으로 유지하여야 한다.",
                source_reference="KISA-ISMS-P-2024-3.2.1",
                mandatory=True,
                sub_requirements=["개인정보 관리대장", "데이터 흐름도"],
            ),
            Requirement(
                requirement_id="ISMS-P-3.4.1",
                framework_id="ISMS-P",
                framework_version="2024-07",
                category_id="3.4",
                category_name="개인정보 파기 시 보호조치",
                domain=EnterpriseDomain.DATA_SECURITY_PRIVACY,
                name="개인정보의 파기",
                description="보유기간 경과 또는 처리목적 달성 시 지체 없이 복구 불가능한 방법으로 개인정보를 파기하여야 한다.",
                source_reference="KISA-ISMS-P-2024-3.4.1",
                mandatory=True,
                sub_requirements=["파기 절차서", "파기 확인 대장"],
            ),
        ]

        for r in reqs:
            self.register(r)

    def _initialize_ismsp_2019_requirements(self) -> None:
        """ISMS-P 2019-01 과거 버전 요구사항 등록."""
        reqs = [
            Requirement(
                requirement_id="ISMS-P-2.5.2",
                framework_id="ISMS-P",
                framework_version="2019-01",
                category_id="2.5",
                category_name="인증 및 권한관리",
                domain=EnterpriseDomain.IDENTITY_ACCESS,
                name="사용자 인증 (2019)",
                description="[2019-01 기준] 사용자 인증 및 비밀번호 관리 요구사항.",
                source_reference="KISA-ISMS-P-2019-2.5.2",
                mandatory=True,
            ),
        ]
        for r in reqs:
            self.register(r)

    def _initialize_gdpr_requirements(self) -> None:
        """GDPR 2016-679 권위 요구사항 등록."""
        reqs = [
            Requirement(
                requirement_id="GDPR-Art-28",
                framework_id="GDPR",
                framework_version="2016-679",
                category_id="Processor",
                category_name="Data Processor & Processing Agreement",
                domain=EnterpriseDomain.DEVELOPMENT_SUPPLY_CHAIN,
                name="Processor Binding (DPA)",
                description="Processing by a processor shall be governed by a binding contract (DPA).",
                source_reference="EUR-Lex-GDPR-Art-28",
                mandatory=True,
            ),
            Requirement(
                requirement_id="GDPR-Art-30",
                framework_id="GDPR",
                framework_version="2016-679",
                category_id="RoPA",
                category_name="Records of Processing Activities",
                domain=EnterpriseDomain.DATA_SECURITY_PRIVACY,
                name="Records of Processing Activities",
                description="Each controller and processor shall maintain a record of processing activities.",
                source_reference="EUR-Lex-GDPR-Art-30",
                mandatory=True,
            ),
            Requirement(
                requirement_id="GDPR-Art-32",
                framework_id="GDPR",
                framework_version="2016-679",
                category_id="Security",
                category_name="Security of Processing",
                domain=EnterpriseDomain.DATA_SECURITY_PRIVACY,
                name="Security of Processing",
                description="Appropriate technical and organisational measures including encryption and confidentiality.",
                source_reference="EUR-Lex-GDPR-Art-32",
                mandatory=True,
            ),
            Requirement(
                requirement_id="GDPR-Art-33",
                framework_id="GDPR",
                framework_version="2016-679",
                category_id="Breach",
                category_name="Breach Notification",
                domain=EnterpriseDomain.SECURITY_OPERATIONS,
                name="Notification to Supervisory Authority",
                description="Breach notification to supervisory authority within 72 hours.",
                source_reference="EUR-Lex-GDPR-Art-33",
                mandatory=True,
            ),
            Requirement(
                requirement_id="GDPR-Art-34",
                framework_id="GDPR",
                framework_version="2016-679",
                category_id="Breach",
                category_name="Breach Communication",
                domain=EnterpriseDomain.DATA_SECURITY_PRIVACY,
                name="Communication to Data Subject",
                description="Communication of personal data breach to data subjects when high risk.",
                source_reference="EUR-Lex-GDPR-Art-34",
                mandatory=True,
            ),
            Requirement(
                requirement_id="GDPR-Art-35",
                framework_id="GDPR",
                framework_version="2016-679",
                category_id="DPIA",
                category_name="Impact Assessment",
                domain=EnterpriseDomain.DATA_SECURITY_PRIVACY,
                name="Data Protection Impact Assessment",
                description="Assessment of the impact of the envisaged processing operations on protection of personal data.",
                source_reference="EUR-Lex-GDPR-Art-35",
                mandatory=True,
            ),
        ]
        for r in reqs:
            self.register(r)


# 기본 싱글톤 요구사항 레지스트리
default_requirement_registry = RequirementRegistry()
