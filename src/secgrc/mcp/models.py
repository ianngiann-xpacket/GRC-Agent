"""Model Context Protocol (MCP) 기반 보안 도구 연동 계층의 데이터 모델입니다."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from secgrc.agent_security.models import AgentRiskLevel, PolicyDecision, ToolType


class MCPTransportType(str, Enum):
    """MCP 통신 트랜스포트 종류"""
    IN_PROCESS = "in_process"
    STDIO = "stdio"
    SSE = "sse"
    DOCKER = "docker"


class MCPToolStatus(str, Enum):
    """도구 등록 상태"""
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"


class MCPToolMetadata(BaseModel):
    """MCP 보안 도구 메타데이터 모델"""
    tool_id: str = Field(description="도구 식별자 (예: prowler.get_findings, gcp.list_firewalls)")
    name: str = Field(description="사람이 읽기 쉬운 도구명")
    description: str = Field(description="도구 상세 설명")
    tool_type: ToolType = Field(default=ToolType.READ, description="READ, ANALYZE, PLAN, ACTION")
    risk_level: AgentRiskLevel = Field(default=AgentRiskLevel.L1, description="L0~L5 권한 등급")
    requires_approval: bool = Field(default=False, description="휴먼 승인 필요 여부")
    production_change: bool = Field(default=False, description="프로덕션 변경/수정 여부")
    allowed_agents: List[str] = Field(default_factory=list, description="실행 인가된 에이전트 ID 목록")
    status: MCPToolStatus = Field(default=MCPToolStatus.ACTIVE, description="도구 상태")
    parameters_schema: Dict[str, Any] = Field(default_factory=dict, description="JSON Schema 형태의 인자 정의")
    timeout_seconds: int = Field(default=30, description="실행 타임아웃(초)")
    rate_limit_per_session: int = Field(default=20, description="세션당 최대 호출 가능 횟수")


class MCPRequest(BaseModel):
    """MCP 도구 호출 요청 명세"""
    request_id: str = Field(description="요청 고유 식별자")
    agent_id: str = Field(description="호출을 시도하는 에이전트 식별자")
    tool_id: str = Field(description="호출 대상 도구 ID")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="도구 전달 인자")
    session_id: Optional[str] = Field(default="default-session", description="세션 식별자")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="요청 생성 시각")


class MCPToolResult(BaseModel):
    """MCP 도구 실행 최종 결과"""
    success: bool = Field(default=True, description="성공 여부")
    tool_id: str = Field(description="실행된 도구 ID")
    data: Any = Field(default=None, description="결과 데이터 페이로드")
    is_data_only: bool = Field(default=True, description="결과가 순수 데이터(DATA_ONLY)인지 보장 여부")
    items_count: int = Field(default=0, description="반환 아이템 수")
    truncated: bool = Field(default=False, description="사이즈 초과로 결과가 절삭되었는지 여부")
    error: Optional[str] = Field(default=None, description="오류 메시지 (실패 시)")
    decision: PolicyDecision = Field(default=PolicyDecision.ALLOW, description="정책 결정 상태")
    execution_time_ms: float = Field(default=0.0, description="실행 소요 시간(ms)")


class MCPResponse(BaseModel):
    """MCP 서버 응답 객체"""
    request_id: str = Field(description="연관된 요청 ID")
    tool_id: str = Field(description="대상 도구 ID")
    result: Optional[MCPToolResult] = Field(default=None, description="도구 실행 결과")
    status_code: int = Field(default=200, description="응답 상태 코드")
    error_message: Optional[str] = Field(default=None, description="에러 내용")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="응답 시각")
