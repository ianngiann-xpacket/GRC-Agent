"""AI 에이전트 신원(Agent Identity) 정의 및 기본 프로파일 모듈입니다."""

from typing import Optional
from secgrc.agent_security.models import AgentIdentity, AgentRiskLevel, AgentStatus


def create_agent_identity(
    agent_id: str,
    agent_name: str,
    agent_type: str = "security_grc",
    version: str = "1.0.0",
    model: str = "gemini-2.5-flash",
    prompt_version: str = "1.0.0",
    owner: str = "security_team",
    purpose: str = "ISMS-P Compliance Audit & Risk Analysis",
    risk_level: AgentRiskLevel = AgentRiskLevel.L2,
    allowed_tools: Optional[list] = None,
    data_sources: Optional[list] = None,
    environment: str = "development",
    approval_policy: str = "HIGH_RISK_REQUIRED",
    status: AgentStatus = AgentStatus.ACTIVE,
) -> AgentIdentity:
    """새로운 AgentIdentity 인스턴스를 생성합니다."""
    return AgentIdentity(
        agent_id=agent_id,
        agent_name=agent_name,
        agent_type=agent_type,
        version=version,
        model=model,
        prompt_version=prompt_version,
        owner=owner,
        purpose=purpose,
        risk_level=risk_level,
        allowed_tools=allowed_tools or [],
        data_sources=data_sources or [],
        environment=environment,
        approval_policy=approval_policy,
        status=status,
    )


# 시스템 기본 에이전트 인스턴스: GRC Compliance Auditor (L2 - 분석/평가 전용, Action 금지)
DEFAULT_AUDITOR_AGENT = create_agent_identity(
    agent_id="grc-auditor-001",
    agent_name="GRC Compliance Auditor",
    agent_type="security_grc_auditor",
    version="1.0.0",
    model="gemini-2.5-flash",
    prompt_version="1.0.0",
    owner="security",
    purpose="Automated ISMS-P compliance check and risk scoring",
    risk_level=AgentRiskLevel.L2,
    allowed_tools=[
        "read_evidence",
        "run_audit",
        "calculate_risk",
        "run_ai_audit",
        "create_remediation_plan",
        "generate_report",
    ],
    data_sources=["prowler_gcp_findings", "isms_p_knowledge_base"],
    environment="development",
    approval_policy="HIGH_RISK_REQUIRED",
    status=AgentStatus.ACTIVE,
)

# 별도 인스턴스: GRC Remediation Agent (L4 - 승인 통제형 조치 시뮬레이션 전용)
DEFAULT_REMEDIATION_AGENT = create_agent_identity(
    agent_id="grc-remediation-001",
    agent_name="GRC Remediation Operator",
    agent_type="security_grc_remediation",
    version="1.0.0",
    model="gemini-2.5-flash",
    prompt_version="1.0.0",
    owner="infrastructure_security",
    purpose="Execute approved remediation actions with rollback protection",
    risk_level=AgentRiskLevel.L4,
    allowed_tools=["execute_action"],
    data_sources=["remediation_plans"],
    environment="development",
    approval_policy="ALWAYS_REQUIRE_APPROVAL",
    status=AgentStatus.ACTIVE,
)
