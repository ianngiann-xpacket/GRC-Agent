"""온톨로지 개체(Entity) 정의 모듈입니다.

12종 핵심 보안 개체:
Framework, Control, Requirement, EvidenceEntity, Finding, Asset,
RiskEntity, RemediationEntity, AgentEntity, ToolEntity, PolicyEntity, BaseEntity
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from secgrc.ontology.models import AutomationLevel, ControlEffectiveness


class BaseEntity(BaseModel):
    """온톨로지 기본 개체 모델"""
    entity_id: str = Field(description="고유 개체 식별자")
    entity_type: str = Field(description="개체 유형 식별자")
    name: str = Field(description="개체 명칭")
    description: Optional[str] = Field(default=None, description="개체 상세 설명")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="추가 메타데이터")


class Framework(BaseEntity):
    """보안/컴플라이언스 프레임워크 (예: ISMS-P, NIST CSF, ISO 27001, CIS GCP)"""
    entity_type: str = Field(default="Framework", description="개체 유형")
    version: str = Field(default="1.0", description="프레임워크 버전")
    authority: Optional[str] = Field(default=None, description="발행 기관 (예: KISA, NIST)")


class Control(BaseEntity):
    """보안 통제 항목 (예: ISMS-P-2.7.1, NIST AC-2)"""
    entity_type: str = Field(default="Control", description="개체 유형")
    framework_id: str = Field(description="소속 프레임워크 ID")
    domain: str = Field(default="", description="통제 영역 (예: 보호대책 요구사항)")
    category: str = Field(default="", description="통제 분류 (예: 암호 통제)")
    effectiveness: ControlEffectiveness = Field(
        default=ControlEffectiveness.NOT_ASSESSED,
        description="통제 유효성 판정"
    )
    automation_level: AutomationLevel = Field(
        default=AutomationLevel.PARTIALLY_AUTOMATED,
        description="자동화 평가 수준"
    )
    legal_basis: Optional[str] = Field(default=None, description="관련 법적 근거")


class Requirement(BaseEntity):
    """통제항목 세부 요구사항 (Control -> Requirement)"""
    entity_type: str = Field(default="Requirement", description="개체 유형")
    control_id: str = Field(description="소속 통제항목 ID")
    requirement_order: int = Field(default=1, description="요구사항 순번")
    mandatory: bool = Field(default=True, description="필수 준수 여부")


class EvidenceEntity(BaseEntity):
    """수집된 감사 증적 개체"""
    entity_type: str = Field(default="Evidence", description="개체 유형")
    evidence_type: str = Field(default="configuration", description="증적 유형")
    source_system: str = Field(default="prowler", description="수집 소스 시스템")
    collected_at: Optional[str] = Field(default=None, description="수집 일시")
    checksum: Optional[str] = Field(default=None, description="증적 무결성 체크섬")


class Finding(BaseEntity):
    """보안 진단/감사 결함 개체"""
    entity_type: str = Field(default="Finding", description="개체 유형")
    severity: str = Field(default="MEDIUM", description="심각도 (CRITICAL, HIGH, MEDIUM, LOW)")
    finding_type: str = Field(default="misconfiguration", description="결함 유형")
    status: str = Field(default="OPEN", description="결함 상태 (OPEN, REMEDIATED, SUPPRESSED)")
    source_tool: str = Field(default="prowler", description="발견 도구")
    resource_id: Optional[str] = Field(default=None, description="영향받는 리소스 ID")


class Asset(BaseEntity):
    """대상 자산 (클라우드 리소스, 서비스, 데이터베이스 등)"""
    entity_type: str = Field(default="Asset", description="개체 유형")
    asset_type: str = Field(default="cloud_resource", description="자산 유형")
    criticality: str = Field(default="MEDIUM", description="자산 중요도 (CRITICAL, HIGH, MEDIUM, LOW)")
    owner: Optional[str] = Field(default=None, description="자산 담당자/팀")
    environment: str = Field(default="production", description="운영 환경 (production, staging, dev)")


class RiskEntity(BaseEntity):
    """보안 위험 개체 (결함 및 통제 결여로부터 도출)"""
    entity_type: str = Field(default="Risk", description="개체 유형")
    risk_score: float = Field(default=0.0, description="정량적 위험 점수 (0~100)")
    severity: str = Field(default="MEDIUM", description="위험 등급")
    priority: str = Field(default="P3", description="조치 우선순위 (P1, P2, P3, P4)")
    likelihood: float = Field(default=1.0, description="발생 가능성")
    impact: float = Field(default=1.0, description="영향도")


class RemediationEntity(BaseEntity):
    """조치 계획 및 실행 개체"""
    entity_type: str = Field(default="Remediation", description="개체 유형")
    plan_type: str = Field(default="automated", description="조치 유형 (automated, manual)")
    status: str = Field(default="PENDING", description="조치 상태 (PENDING, APPROVED, EXECUTED, VERIFIED)")
    execution_type: str = Field(default="MOCK", description="실행 방식 (MOCK, SIMULATION)")
    approved_by: Optional[str] = Field(default=None, description="승인자")


class AgentEntity(BaseEntity):
    """GRC 보안 에이전트 개체"""
    entity_type: str = Field(default="Agent", description="개체 유형")
    role: str = Field(default="auditor", description="에이전트 역할 (auditor, redteam, remediator)")
    model: str = Field(default="claude-3-5-sonnet", description="사용 LLM 모델")
    status: str = Field(default="ACTIVE", description="에이전트 상태")


class ToolEntity(BaseEntity):
    """에이전트가 사용하는 도구 개체 (MCP, Adapter 등)"""
    entity_type: str = Field(default="Tool", description="개체 유형")
    tool_type: str = Field(default="mcp", description="도구 유형 (mcp, cli, api)")
    is_destructive: bool = Field(default=False, description="파괴적 작업 여부")


class PolicyEntity(BaseEntity):
    """보안 거버넌스 및 에이전트 가드레일 정책 개체"""
    entity_type: str = Field(default="Policy", description="개체 유형")
    policy_type: str = Field(default="guardrail", description="정책 유형 (guardrail, approval, compliance)")
    enforcement_level: str = Field(default="BLOCK", description="강제 수준 (BLOCK, WARN, AUDIT)")
