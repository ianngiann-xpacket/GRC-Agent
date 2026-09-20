"""Compliance Framework & Framework Version Models (Step 23.5A).

This module implements the framework-agnostic compliance abstraction.
No single framework (such as ISMS-P) is hardcoded as a global ceiling;
frameworks and versions are registered with rich metadata and authoritative references.
"""

from typing import Any, Dict, List, Optional
from pydantic import Field, field_validator

from secgrc.compliance.models import (
    ComplianceBaseModel,
    FrameworkStatus,
    validate_identifier,
    validate_iso8601_timestamp,
)


class Framework(ComplianceBaseModel):
    """표준 컴플라이언스 프레임워크 모델 (프레임워크 비종속적 최상위 정의)."""

    framework_id: str = Field(description="프레임워크 고유 식별자 (예: ISMS-P, GDPR, ISO-27001, NIST-CSF)")
    name: str = Field(description="프레임워크 공식 명칭")
    jurisdiction: str = Field(description="관할권/국가 (예: KR, EU, US, GLOBAL)")
    default_version: str = Field(description="기본 권장 버전 식별자 (예: 2024-07)")
    source_authority: str = Field(description="주관/제정 기관 (예: KISA, EDPB, ISO, NIST, CIS)")
    status: FrameworkStatus = Field(default=FrameworkStatus.ACTIVE, description="프레임워크 생명주기 상태")
    description: Optional[str] = Field(default=None, description="프레임워크 상세 설명")

    @field_validator("framework_id", "default_version", "source_authority")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)


class FrameworkVersion(ComplianceBaseModel):
    """특정 시점/개정판 기준의 프레임워크 버전 모델."""

    version_id: str = Field(description="프레임워크 버전 고유 식별자 (예: ISMS-P:2024-07)")
    framework_id: str = Field(description="소속 프레임워크 식별자")
    version: str = Field(description="버전/개정 명칭 (예: 2024-07, 2019-01, 2022, 2.0)")
    effective_from: str = Field(description="적용/시행 일자 (ISO 8601 Date or Timestamp)")
    effective_to: Optional[str] = Field(default=None, description="만료/대체 일자 (선택)")
    source_authority: str = Field(description="해당 버전의 발행/인증 권위 기관")
    source_reference: str = Field(description="공식 고시/지침 출처 문서 URL 또는 식별자")
    total_requirements: int = Field(description="해당 버전에 속한 총 요구사항 수 (동적 산출/공식 고시)")
    status: FrameworkStatus = Field(default=FrameworkStatus.ACTIVE, description="해당 버전의 상태")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="추가 메타데이터 (도메인별 항목 수 등)")

    @field_validator("version_id", "framework_id", "version", "source_authority", "source_reference")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_identifier(v, info.field_name)

    @field_validator("total_requirements")
    @classmethod
    def check_count(cls, v: int) -> int:
        if v < 0:
            raise ValueError("total_requirements cannot be negative")
        return v


class FrameworkRegistry:
    """프레임워크 및 버전의 인메모리 권위 등록소."""

    def __init__(self) -> None:
        self._frameworks: Dict[str, Framework] = {}
        self._versions: Dict[str, FrameworkVersion] = {}
        self._initialize_default_frameworks()

    def register_framework(self, framework: Framework) -> None:
        """새로운 컴플라이언스 프레임워크를 등록합니다."""
        self._frameworks[framework.framework_id] = framework

    def register_version(self, version: FrameworkVersion) -> None:
        """프레임워크 버전을 등록합니다."""
        if version.framework_id not in self._frameworks:
            raise ValueError(f"Framework '{version.framework_id}' must be registered before registering a version.")
        self._versions[version.version_id] = version

    def get_framework(self, framework_id: str) -> Optional[Framework]:
        """프레임워크 정의를 조회합니다."""
        return self._frameworks.get(framework_id)

    def get_version(self, framework_id: str, version: Optional[str] = None) -> Optional[FrameworkVersion]:
        """특정 프레임워크의 지정 버전 또는 기본 버전을 조회합니다."""
        fw = self.get_framework(framework_id)
        if not fw:
            return None
        ver_str = version or fw.default_version
        version_id = f"{framework_id}:{ver_str}"
        return self._versions.get(version_id)

    def list_frameworks(self) -> List[Framework]:
        """등록된 모든 프레임워크 목록을 반환합니다 (결정론적 정렬)."""
        return sorted(self._frameworks.values(), key=lambda f: f.framework_id)

    def list_versions(self, framework_id: Optional[str] = None) -> List[FrameworkVersion]:
        """등록된 프레임워크 버전 목록을 반환합니다."""
        if framework_id:
            return sorted(
                [v for v in self._versions.values() if v.framework_id == framework_id],
                key=lambda v: v.version_id,
            )
        return sorted(self._versions.values(), key=lambda v: v.version_id)

    def _initialize_default_frameworks(self) -> None:
        """글로벌 및 국내 주요 컴플라이언스 프레임워크 메타데이터 초기 등록."""

        # 1. ISMS-P (대한민국 정보보호 및 개인정보보호 관리체계)
        ismsp = Framework(
            framework_id="ISMS-P",
            name="정보보호 및 개인정보보호 관리체계 인증 기준",
            jurisdiction="KR",
            default_version="2024-07",
            source_authority="KISA",
            status=FrameworkStatus.ACTIVE,
            description="과학기술정보통신부 및 개인정보보호위원회 공동고시 기준 ISMS-P 관리체계",
        )
        self.register_framework(ismsp)

        # ISMS-P 최신 개정판 (2024-07: 101개 항목)
        self.register_version(
            FrameworkVersion(
                version_id="ISMS-P:2024-07",
                framework_id="ISMS-P",
                version="2024-07",
                effective_from="2024-07-24T00:00:00Z",
                effective_to=None,
                source_authority="KISA",
                source_reference="KISA-ISMS-P-GUIDE-202407",
                total_requirements=101,
                status=FrameworkStatus.ACTIVE,
                metadata={
                    "breakdown": {
                        "1.관리체계 수립 및 운영": 16,
                        "2.보호대책 요구사항": 64,
                        "3.개인정보 처리단계별 요구사항": 21,
                    },
                    "note": "2024년 7월 고시 개정 반영 (3.5 클라우드 환경 등 21개 통제 정비)",
                },
            )
        )

        # ISMS-P 이전 개정판 (2019-01: 102개 항목 - 버전 변경 감지 및 과거 이력 추적용)
        self.register_version(
            FrameworkVersion(
                version_id="ISMS-P:2019-01",
                framework_id="ISMS-P",
                version="2019-01",
                effective_from="2019-01-01T00:00:00Z",
                effective_to="2024-07-23T23:59:59Z",
                source_authority="KISA",
                source_reference="KISA-ISMS-P-GUIDE-201901",
                total_requirements=102,
                status=FrameworkStatus.SUPERSEDED,
                metadata={
                    "breakdown": {
                        "1.관리체계 수립 및 운영": 16,
                        "2.보호대책 요구사항": 64,
                        "3.개인정보 처리단계별 요구사항": 22,
                    },
                    "note": "구 기준 102개 (16+64+22)",
                },
            )
        )

        # 2. GDPR (EU General Data Protection Regulation)
        gdpr = Framework(
            framework_id="GDPR",
            name="General Data Protection Regulation (Regulation (EU) 2016/679)",
            jurisdiction="EU",
            default_version="2016-679",
            source_authority="EDPB",
            status=FrameworkStatus.ACTIVE,
            description="EU 개인정보보호 규정",
        )
        self.register_framework(gdpr)
        self.register_version(
            FrameworkVersion(
                version_id="GDPR:2016-679",
                framework_id="GDPR",
                version="2016-679",
                effective_from="2018-05-25T00:00:00Z",
                effective_to=None,
                source_authority="EDPB",
                source_reference="EUR-Lex-32016R0679",
                total_requirements=99,
                status=FrameworkStatus.ACTIVE,
                metadata={"articles": 99, "chapters": 11},
            )
        )

        # 3. ISO/IEC 27001
        iso27001 = Framework(
            framework_id="ISO-27001",
            name="ISO/IEC 27001 Information Security Management Systems",
            jurisdiction="GLOBAL",
            default_version="2022",
            source_authority="ISO",
            status=FrameworkStatus.ACTIVE,
            description="국제 표준 정보보안 관리체계",
        )
        self.register_framework(iso27001)
        self.register_version(
            FrameworkVersion(
                version_id="ISO-27001:2022",
                framework_id="ISO-27001",
                version="2022",
                effective_from="2022-10-25T00:00:00Z",
                effective_to=None,
                source_authority="ISO",
                source_reference="ISO-IEC-27001-2022",
                total_requirements=93,
                status=FrameworkStatus.ACTIVE,
                metadata={"themes": {"Organizational": 37, "People": 8, "Physical": 14, "Technological": 34}},
            )
        )

        # 4. NIST Cybersecurity Framework (NIST CSF)
        nist_csf = Framework(
            framework_id="NIST-CSF",
            name="NIST Cybersecurity Framework",
            jurisdiction="US",
            default_version="2.0",
            source_authority="NIST",
            status=FrameworkStatus.ACTIVE,
            description="NIST 사이버보안 프레임워크 2.0 (Govern, Identify, Protect, Detect, Respond, Recover)",
        )
        self.register_framework(nist_csf)
        self.register_version(
            FrameworkVersion(
                version_id="NIST-CSF:2.0",
                framework_id="NIST-CSF",
                version="2.0",
                effective_from="2024-02-26T00:00:00Z",
                effective_to=None,
                source_authority="NIST",
                source_reference="NIST-CSWP-29",
                total_requirements=106,
                status=FrameworkStatus.ACTIVE,
                metadata={"functions": ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]},
            )
        )

        # 5. CIS Critical Security Controls
        cis = Framework(
            framework_id="CIS-CONTROLS",
            name="CIS Critical Security Controls",
            jurisdiction="GLOBAL",
            default_version="v8",
            source_authority="CIS",
            status=FrameworkStatus.ACTIVE,
            description="CIS 18대 주요 보안 통제항목",
        )
        self.register_framework(cis)
        self.register_version(
            FrameworkVersion(
                version_id="CIS-CONTROLS:v8",
                framework_id="CIS-CONTROLS",
                version="v8",
                effective_from="2021-05-18T00:00:00Z",
                effective_to=None,
                source_authority="CIS",
                source_reference="CIS-Controls-v8",
                total_requirements=153,
                status=FrameworkStatus.ACTIVE,
                metadata={"controls": 18, "safeguards": 153},
            )
        )

        # 6. NIST AI RMF
        nist_ai = Framework(
            framework_id="NIST-AI-RMF",
            name="NIST Artificial Intelligence Risk Management Framework",
            jurisdiction="US",
            default_version="1.0",
            source_authority="NIST",
            status=FrameworkStatus.ACTIVE,
            description="NIST AI 위험 관리 프레임워크 1.0 (Govern, Map, Measure, Manage)",
        )
        self.register_framework(nist_ai)
        self.register_version(
            FrameworkVersion(
                version_id="NIST-AI-RMF:1.0",
                framework_id="NIST-AI-RMF",
                version="1.0",
                effective_from="2023-01-26T00:00:00Z",
                effective_to=None,
                source_authority="NIST",
                source_reference="NIST-AI-100-1",
                total_requirements=72,
                status=FrameworkStatus.ACTIVE,
                metadata={"functions": ["GOVERN", "MAP", "MEASURE", "MANAGE"]},
            )
        )


# 전역 기본 싱글톤 레지스트리
default_framework_registry = FrameworkRegistry()
