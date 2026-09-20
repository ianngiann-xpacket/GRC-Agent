"""AI GRC Copilot 의도(Intent) 정의 및 메타데이터 모듈입니다."""

from enum import Enum
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class IntentCategory(str, Enum):
    """결정론적 의도 카테고리 (19대 유형)"""
    # Risk
    RISK_OVERVIEW = "RISK_OVERVIEW"
    RISK_DETAIL = "RISK_DETAIL"
    RISK_CAUSE = "RISK_CAUSE"
    RISK_TREND = "RISK_TREND"

    # Control
    CONTROL_STATUS = "CONTROL_STATUS"
    CONTROL_DETAIL = "CONTROL_DETAIL"
    CONTROL_GAP = "CONTROL_GAP"
    CONTROL_EFFECTIVENESS = "CONTROL_EFFECTIVENESS"

    # Evidence
    EVIDENCE_LOOKUP = "EVIDENCE_LOOKUP"
    EVIDENCE_LINEAGE = "EVIDENCE_LINEAGE"
    EVIDENCE_GAP = "EVIDENCE_GAP"

    # Remediation
    REMEDIATION_LOOKUP = "REMEDIATION_LOOKUP"

    # Framework
    FRAMEWORK_MAPPING = "FRAMEWORK_MAPPING"
    FRAMEWORK_COVERAGE = "FRAMEWORK_COVERAGE"

    # Asset & Finding
    ASSET_RISK = "ASSET_RISK"
    FINDING_LOOKUP = "FINDING_LOOKUP"

    # Agent Security & Red Team
    AGENT_SECURITY = "AGENT_SECURITY"
    REDTEAM_STATUS = "REDTEAM_STATUS"

    # Unknown
    UNKNOWN = "UNKNOWN"


# 의도별 허용된 읽기 전용 작업 및 필요 데이터 매핑 테이블
INTENT_METADATA: Dict[IntentCategory, Dict[str, Any]] = {
    IntentCategory.RISK_OVERVIEW: {
        "required_data": ["risks", "controls"],
        "allowed_operations": ["GET_RISKS", "GET_CONTROLS", "GET_LINEAGE"],
    },
    IntentCategory.RISK_DETAIL: {
        "required_data": ["risks", "controls", "evidence"],
        "allowed_operations": ["GET_RISKS", "GET_CONTROLS", "GET_LINEAGE"],
    },
    IntentCategory.RISK_CAUSE: {
        "required_data": ["risks", "controls", "evidence", "findings"],
        "allowed_operations": ["GET_RISKS", "GET_CONTROLS", "GET_EVIDENCE", "GET_FINDINGS", "GET_LINEAGE"],
    },
    IntentCategory.RISK_TREND: {
        "required_data": ["continuous_events", "risks"],
        "allowed_operations": ["GET_RISKS", "GET_LINEAGE"],
    },
    IntentCategory.CONTROL_STATUS: {
        "required_data": ["controls", "evidence"],
        "allowed_operations": ["GET_CONTROLS", "GET_EVIDENCE", "GET_LINEAGE"],
    },
    IntentCategory.CONTROL_DETAIL: {
        "required_data": ["controls", "requirements"],
        "allowed_operations": ["GET_CONTROLS", "GET_RELATIONSHIPS"],
    },
    IntentCategory.CONTROL_GAP: {
        "required_data": ["controls", "coverage"],
        "allowed_operations": ["GET_CONTROLS", "GET_COVERAGE"],
    },
    IntentCategory.CONTROL_EFFECTIVENESS: {
        "required_data": ["controls", "coverage"],
        "allowed_operations": ["GET_CONTROLS", "GET_COVERAGE"],
    },
    IntentCategory.EVIDENCE_LOOKUP: {
        "required_data": ["controls", "evidence"],
        "allowed_operations": ["GET_EVIDENCE", "GET_CONTROLS", "GET_LINEAGE"],
    },
    IntentCategory.EVIDENCE_LINEAGE: {
        "required_data": ["evidence", "findings", "assets", "controls", "risks"],
        "allowed_operations": ["GET_LINEAGE", "GET_EVIDENCE", "GET_CONTROLS"],
    },
    IntentCategory.EVIDENCE_GAP: {
        "required_data": ["controls", "evidence"],
        "allowed_operations": ["GET_CONTROLS", "GET_COVERAGE"],
    },
    IntentCategory.REMEDIATION_LOOKUP: {
        "required_data": ["remediations", "risks", "controls"],
        "allowed_operations": ["GET_REMEDIATIONS", "GET_RISKS", "GET_CONTROLS", "GET_LINEAGE"],
    },
    IntentCategory.FRAMEWORK_MAPPING: {
        "required_data": ["controls", "frameworks", "relationships"],
        "allowed_operations": ["GET_CONTROLS", "GET_FRAMEWORKS", "GET_RELATIONSHIPS", "GET_LINEAGE"],
    },
    IntentCategory.FRAMEWORK_COVERAGE: {
        "required_data": ["frameworks", "coverage"],
        "allowed_operations": ["GET_FRAMEWORKS", "GET_COVERAGE", "GET_CONTROLS"],
    },
    IntentCategory.ASSET_RISK: {
        "required_data": ["assets", "findings", "risks"],
        "allowed_operations": ["GET_ASSETS", "GET_FINDINGS", "GET_RISKS"],
    },
    IntentCategory.FINDING_LOOKUP: {
        "required_data": ["findings", "evidence"],
        "allowed_operations": ["GET_FINDINGS", "GET_EVIDENCE"],
    },
    IntentCategory.AGENT_SECURITY: {
        "required_data": ["agent_security", "redteam_summary"],
        "allowed_operations": ["GET_AGENT_SECURITY_STATUS", "GET_REDTEAM_SUMMARY"],
    },
    IntentCategory.REDTEAM_STATUS: {
        "required_data": ["redteam_summary", "agent_security"],
        "allowed_operations": ["GET_REDTEAM_SUMMARY", "GET_AGENT_SECURITY_STATUS"],
    },
    IntentCategory.UNKNOWN: {
        "required_data": [],
        "allowed_operations": [],
    },
}


class IntentResult(BaseModel):
    """의도 분류 및 엔티티 분석 결과"""
    intent: IntentCategory = Field(description="결정론적 의도 카테고리")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="의도 분류 신뢰도")
    entities: Dict[str, Any] = Field(default_factory=dict, description="추출 및 검증된 엔티티 딕셔너리")
    required_data: List[str] = Field(default_factory=list, description="질의 응답에 필요한 데이터 집합")
    allowed_operations: List[str] = Field(default_factory=list, description="허용된 읽기 전용 작업 목록")
