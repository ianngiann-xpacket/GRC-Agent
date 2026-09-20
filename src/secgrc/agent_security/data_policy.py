"""데이터 신뢰 경계(Evidence Trust Boundary) 및 데이터 접근 통제 정책 모듈입니다."""

from typing import Dict, List, Optional
from secgrc.agent_security.models import DataTrustLevel


class DataAccessPolicy:
    """에이전트별 데이터 리소스 읽기/쓰기/거부 권한을 정의하고 검증합니다."""

    def __init__(self):
        # 기본 에이전트 데이터 접근 규칙
        self._policies: Dict[str, Dict[str, str]] = {
            "grc-auditor-001": {
                "evidence": "READ",
                "audit_results": "READ",
                "risk_results": "READ",
                "reports": "WRITE",
                "knowledge_base": "READ",
                "production_infrastructure": "DENY",
            },
            "grc-remediation-001": {
                "evidence": "READ",
                "remediation_plans": "READ",
                "production_infrastructure": "WRITE_CONTROLLED",  # Requires explicit approval
            },
        }

    def check_access(self, agent_id: str, resource: str, access_type: str) -> bool:
        """에이전트가 대상 데이터 리소스에 대해 특정 접근(READ, WRITE)을 수행할 수 있는지 검사합니다."""
        agent_rules = self._policies.get(agent_id, {})
        allowed_type = agent_rules.get(resource, "DENY")

        if allowed_type == "DENY":
            return False
        if allowed_type == access_type:
            return True
        if allowed_type == "WRITE_CONTROLLED" and access_type == "WRITE":
            return True
        return False

    @staticmethod
    def classify_data(data_source: str, is_natural_language_field: bool = False) -> DataTrustLevel:
        """데이터 출처 및 필드 유형에 따라 신뢰 경계 수준을 판별합니다.
        
        원칙:
        Prowler의 구조화된 메타데이터(finding_uid, check_id 등)는 TRUSTED_TOOL_OUTPUT이지만,
        description, notes 등 자연어 필드는 UNTRUSTED_DOCUMENT로 분류하여
        지시어가 아닌 데이터로만 취급합니다.
        """
        if is_natural_language_field:
            return DataTrustLevel.UNTRUSTED_DOCUMENT

        lower_src = data_source.lower()
        if "isms_p" in lower_src or "system" in lower_src:
            return DataTrustLevel.TRUSTED_SYSTEM_DATA
        elif "prowler" in lower_src or "tool" in lower_src:
            return DataTrustLevel.TRUSTED_TOOL_OUTPUT
        elif "user" in lower_src:
            return DataTrustLevel.UNTRUSTED_USER_INPUT
        return DataTrustLevel.UNTRUSTED_EXTERNAL_DATA


global_data_policy = DataAccessPolicy()
