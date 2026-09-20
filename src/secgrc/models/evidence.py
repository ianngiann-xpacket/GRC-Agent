"""클라우드 보안 감사 증적(Evidence) 데이터 모델 모듈입니다.

Prowler, GCP/AWS API, 수동 업로드 등의 다양한 출처에서 수집된 감사 증적을 표준화합니다.
"""

from enum import Enum
from typing import Any, Dict
from pydantic import BaseModel, Field


class EvidenceStatus(str, Enum):
    """증적 검증 결과 상태"""
    COMPLIANT = "COMPLIANT"                  # 적합 (규정 완벽 준수)
    NON_COMPLIANT = "NON_COMPLIANT"          # 부적합 (결함 / 보안 위험 발견)
    PARTIAL = "PARTIAL"                      # 부분 준수 (일부 리소스 미흡)
    MANUAL_REVIEW = "MANUAL_REVIEW"          # 수동 검토 필요 (사람의 확인 필요)


class Evidence(BaseModel):
    """감사 증적 단일 레코드 모델"""

    evidence_id: str = Field(..., description="증적 고유 식별자 (예: 'EV-GCP-001')")
    control_id: str = Field(..., description="연관된 ISMS-P 통제항목 번호 (예: 'ISMS-P-2.5.2')")
    source: str = Field(..., description="증적 수집 출처 (예: 'PROWLER_GCP', 'GCP_IAM', 'MANUAL_UPLOAD')")
    resource_id: str = Field(default="", description="클라우드 리소스 식별자 (GCP URI, 리소스명 등)")
    collected_at: str = Field(..., description="수집 일시 (ISO-8601 형식: '2026-09-09T10:30:00')")
    status: EvidenceStatus = Field(..., description="컴플라이언스 준수 상태")
    finding: str = Field(..., description="수집된 구체적 감사 발견 사실 (Finding)")
    remediation_hint: str = Field(default="", description="기술적 시정조치 가이드 (Remediation)")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Prowler/GCP 원본 스캔 메타데이터")


class NormalizedEvidence(dict):
    """Prowler 및 클라우드 진단 도구로부터 표준화된 감사 증적(Evidence) 레코드.

    dict를 상속하여 dict 인덱싱(ev['status'])과 속성 접근(ev.status)을 모두 지원하며,
    기존 Evidence 모델로의 변환(to_legacy_evidence) 메서드를 제공합니다.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self

    def to_legacy_evidence(self, control_id: str = "ISMS-P-UNKNOWN") -> Evidence:
        """기존 GRC-Agent 표준 Evidence 모델로 상호 변환합니다."""
        st = str(self.get("status", "")).upper()
        if st == "PASS":
            status_enum = EvidenceStatus.COMPLIANT
        elif st == "FAIL":
            status_enum = EvidenceStatus.NON_COMPLIANT
        elif st in ("MANUAL", "MUTED"):
            status_enum = EvidenceStatus.MANUAL_REVIEW
        else:
            status_enum = EvidenceStatus.PARTIAL

        return Evidence(
            evidence_id=self.get("evidence_id") or "EV-UNKNOWN",
            control_id=control_id,
            source=f"PROWLER_{str(self.get('provider', 'GCP')).upper()}",
            resource_id=self.get("resource_uid") or self.get("resource_name") or "",
            collected_at=self.get("timestamp") or "",
            status=status_enum,
            finding=self.get("description") or self.get("title") or "",
            remediation_hint=self.get("remediation") or "",
            raw_data=self.get("raw") or {},
        )

