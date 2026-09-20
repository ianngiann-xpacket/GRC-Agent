"""질의 응답용 보안 컨텍스트(CopilotContext) 빌더 모듈입니다."""

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

FORBIDDEN_SECRET_PATTERNS = [
    r"CANARY_SECRET[_\w]*",
    r"AIzaSy[0-9A-Za-z-_]{33}",
    r"ghp_[0-9A-Za-z]{36}",
    r"xoxb-[0-9A-Za-z-_]+",
    r"(?i)password\s*=\s*['\"][^'\"]+['\"]",
]


def sanitize_text(text: str) -> str:
    """텍스트 내 민감 시크릿 및 카나리 토큰 마스킹"""
    if not isinstance(text, str):
        return text
    sanitized = text
    for pattern in FORBIDDEN_SECRET_PATTERNS:
        sanitized = re.sub(pattern, "[MASKED_SECRET]", sanitized)
    return sanitized


def sanitize_data(obj: Any) -> Any:
    """딕셔너리, 리스트 등 중첩 데이터 내 민감 정보 재귀적 마스킹"""
    if isinstance(obj, str):
        return sanitize_text(obj)
    elif isinstance(obj, dict):
        return {k: sanitize_data(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_data(item) for item in obj]
    return obj


class CopilotContext(BaseModel):
    """검증된 읽기 전용 보안 데이터 컨텍스트 번들"""
    control: Optional[Dict[str, Any]] = Field(default=None, description="대상 통제항목 정보")
    controls: List[Dict[str, Any]] = Field(default_factory=list, description="복수 통제항목 목록")
    risk: Optional[Dict[str, Any]] = Field(default=None, description="대상 위험 평가 정보")
    risks: List[Dict[str, Any]] = Field(default_factory=list, description="위험 평가 목록")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="증적 목록")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="결함 목록")
    assets: List[Dict[str, Any]] = Field(default_factory=list, description="영향받는 자산 목록")
    remediations: List[Dict[str, Any]] = Field(default_factory=list, description="시정조치 계획 목록")
    relationships: List[Dict[str, Any]] = Field(default_factory=list, description="온톨로지 간선 관계")
    framework_mapping: List[Dict[str, Any]] = Field(default_factory=list, description="타 프레임워크 매핑 정보")
    coverage: Optional[Dict[str, Any]] = Field(default=None, description="프레임워크 평가 커버리지")
    agent_security: Optional[Dict[str, Any]] = Field(default=None, description="에이전트 보안 및 Red Team 요약")
    continuous_events: List[Dict[str, Any]] = Field(default_factory=list, description="최근 변경 및 위험 변동")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="추가 컨텍스트 메타데이터")

    def sanitize(self) -> "CopilotContext":
        """컨텍스트 내 모든 민감 정보를 마스킹한 정제된 객체를 반환합니다."""
        dumped = self.model_dump()
        clean = sanitize_data(dumped)
        return CopilotContext(**clean)

    def to_summary_text(self, max_length: int = 4000) -> str:
        """LLM 프롬프트에 주입할 간결하고 정제된 마크다운 텍스트 요약 생성"""
        clean = self.sanitize()
        lines: List[str] = []

        if clean.risk:
            lines.append(f"### [Top Risk] {clean.risk.get('risk_id')} - {clean.risk.get('name')}")
            lines.append(f"- Score: {clean.risk.get('risk_score')}, Priority: {clean.risk.get('priority')}, Severity: {clean.risk.get('severity')}")
            if clean.risk.get("description"):
                lines.append(f"- Description: {clean.risk.get('description')}")

        if clean.risks and not clean.risk:
            lines.append(f"### [Risks Overview] (Total: {len(clean.risks)})")
            for r in clean.risks[:5]:
                lines.append(f"- {r.get('risk_id')}: Score {r.get('risk_score')} ({r.get('priority')}) [{r.get('severity')}] - {r.get('name')}")

        if clean.control:
            lines.append(f"### [Control] {clean.control.get('entity_id')} - {clean.control.get('name')}")
            lines.append(f"- Effectiveness: {clean.control.get('effectiveness')}, Automation: {clean.control.get('automation_level')}")
            if clean.control.get("description"):
                lines.append(f"- Requirement: {clean.control.get('description')}")

        if clean.controls and not clean.control:
            lines.append(f"### [Controls] (Count: {len(clean.controls)})")
            for c in clean.controls[:10]:
                lines.append(f"- {c.get('entity_id')}: {c.get('name')} [Effectiveness: {c.get('effectiveness')}]")

        if clean.evidence:
            lines.append(f"### [Supporting Evidence] (Count: {len(clean.evidence)})")
            for ev in clean.evidence[:5]:
                lines.append(f"- {ev.get('entity_id')}: {ev.get('name')}")

        if clean.remediations:
            lines.append(f"### [Planned Remediations] (Count: {len(clean.remediations)})")
            for rem in clean.remediations[:5]:
                lines.append(f"- {rem.get('entity_id')}: {rem.get('name')} [Status: {rem.get('status')}]")

        if clean.framework_mapping:
            lines.append(f"### [Cross-Framework Mappings]")
            for fm in clean.framework_mapping[:6]:
                lines.append(f"- Mapped to {fm.get('target_control_id')} (Confidence: {fm.get('confidence')}) - {fm.get('rationale', '')}")

        if clean.coverage:
            lines.append(f"### [Framework Coverage]")
            lines.append(f"- Framework: {clean.coverage.get('framework_id')}")
            lines.append(f"- Total: {clean.coverage.get('total_controls')}, Assessed: {clean.coverage.get('assessed_controls')} ({clean.coverage.get('coverage_percent')}%)")
            lines.append(f"- Effective: {clean.coverage.get('effective_controls')}, Partial: {clean.coverage.get('partially_effective_controls')}, Ineffective: {clean.coverage.get('ineffective_controls')}, Not Assessed: {clean.coverage.get('not_assessed_controls')}")

        if clean.agent_security:
            lines.append(f"### [Agent Security & Red Team]")
            lines.append(f"- Resilience Score: {clean.agent_security.get('resilience_score')}")
            lines.append(f"- Total Scenarios: {clean.agent_security.get('total_scenarios')}, Blocked: {clean.agent_security.get('blocked_attacks')}")
            lines.append(f"- Leaked Secrets: {clean.agent_security.get('secret_leakages')}, Unauthorized Tools: {clean.agent_security.get('unauthorized_tool_executions')}")

        text = "\n".join(lines)
        return text[:max_length]
