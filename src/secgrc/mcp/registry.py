"""MCP 보안 도구 등록소(MCP Tool Registry) 모듈입니다."""

from typing import Callable, Dict, List, Optional
from secgrc.agent_security.models import AgentRiskLevel, ToolType
from secgrc.mcp.models import MCPToolMetadata, MCPToolStatus


class MCPToolRegistry:
    """MCP 보안 도구의 등록, 조회 및 인가 대상 에이전트 목록을 관리합니다."""

    def __init__(self):
        self._tools: Dict[str, MCPToolMetadata] = {}
        self._handlers: Dict[str, Callable] = {}
        self._initialize_default_tools()

    def _initialize_default_tools(self):
        """기본 보안 도구들을 등록합니다."""
        # 1. Prowler 진단 수집 도구
        self.register_tool(
            MCPToolMetadata(
                tool_id="prowler.get_findings",
                name="Prowler Findings Collector",
                description="Prowler 보안 진단 CSV 파일에서 컴플라이언스 및 보안 평가 증적을 로드하고 필터링합니다.",
                tool_type=ToolType.READ,
                risk_level=AgentRiskLevel.L1,
                requires_approval=False,
                production_change=False,
                allowed_agents=["grc-auditor-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "evidence_path": {"type": "string", "description": "진단 결과 CSV 경로"},
                        "status_filter": {"type": "string", "description": "PASS/FAIL 필터링"},
                        "severity_filter": {"type": "string", "description": "심각도 필터링"},
                    },
                },
                timeout_seconds=30,
            )
        )

        # 2. GCP Read-Only 도구들
        self.register_tool(
            MCPToolMetadata(
                tool_id="gcp.list_firewalls",
                name="GCP Firewall Rules Lister",
                description="GCP VPC 방화벽 규칙 목록을 조회합니다 (읽기 전용).",
                tool_type=ToolType.READ,
                risk_level=AgentRiskLevel.L1,
                requires_approval=False,
                production_change=False,
                allowed_agents=["grc-auditor-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "project_id": {"type": "string", "description": "GCP 프로젝트 ID"},
                    },
                },
                timeout_seconds=30,
            )
        )
        self.register_tool(
            MCPToolMetadata(
                tool_id="gcp.list_iam_bindings",
                name="GCP IAM Policy Lister",
                description="GCP IAM 역할 및 권한 바인딩 목록을 조회합니다 (읽기 전용).",
                tool_type=ToolType.READ,
                risk_level=AgentRiskLevel.L1,
                requires_approval=False,
                production_change=False,
                allowed_agents=["grc-auditor-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "project_id": {"type": "string", "description": "GCP 프로젝트 ID"},
                    },
                },
                timeout_seconds=30,
            )
        )
        self.register_tool(
            MCPToolMetadata(
                tool_id="gcp.list_storage_buckets",
                name="GCP Cloud Storage Bucket Lister",
                description="GCP Cloud Storage 버킷 목록 및 접근 정책을 조회합니다 (읽기 전용).",
                tool_type=ToolType.READ,
                risk_level=AgentRiskLevel.L1,
                requires_approval=False,
                production_change=False,
                allowed_agents=["grc-auditor-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "project_id": {"type": "string", "description": "GCP 프로젝트 ID"},
                    },
                },
                timeout_seconds=30,
            )
        )
        self.register_tool(
            MCPToolMetadata(
                tool_id="gcp.list_logging_config",
                name="GCP Cloud Logging Config Lister",
                description="GCP Cloud Logging 싱크 및 보관 설정을 조회합니다 (읽기 전용).",
                tool_type=ToolType.READ,
                risk_level=AgentRiskLevel.L1,
                requires_approval=False,
                production_change=False,
                allowed_agents=["grc-auditor-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "project_id": {"type": "string", "description": "GCP 프로젝트 ID"},
                    },
                },
                timeout_seconds=30,
            )
        )

        # 3. Evidence 도구들
        self.register_tool(
            MCPToolMetadata(
                tool_id="evidence.load",
                name="Evidence Loader",
                description="증적 소스로부터 정규화된 Evidence 목록을 메모리에 로드합니다.",
                tool_type=ToolType.READ,
                risk_level=AgentRiskLevel.L1,
                requires_approval=False,
                production_change=False,
                allowed_agents=["grc-auditor-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "source_path": {"type": "string", "description": "증적 데이터 경로"},
                    },
                },
                timeout_seconds=30,
            )
        )
        self.register_tool(
            MCPToolMetadata(
                tool_id="evidence.search",
                name="Evidence Search",
                description="통제항목 번호, 자원명, 서비스명 등으로 증적을 검색합니다.",
                tool_type=ToolType.READ,
                risk_level=AgentRiskLevel.L1,
                requires_approval=False,
                production_change=False,
                allowed_agents=["grc-auditor-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "검색 키워드"},
                        "service": {"type": "string", "description": "서비스명 필터"},
                    },
                },
                timeout_seconds=30,
            )
        )
        self.register_tool(
            MCPToolMetadata(
                tool_id="evidence.get",
                name="Evidence Detail Getter",
                description="단일 증적 ID에 대한 전체 정규화 객체를 조회합니다.",
                tool_type=ToolType.READ,
                risk_level=AgentRiskLevel.L1,
                requires_approval=False,
                production_change=False,
                allowed_agents=["grc-auditor-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "evidence_id": {"type": "string", "description": "증적 고유 ID"},
                    },
                    "required": ["evidence_id"],
                },
                timeout_seconds=30,
            )
        )

        # 4. Mutation / High Risk Action 도구 (Human Approval & Remediation 전용)
        self.register_tool(
            MCPToolMetadata(
                tool_id="gcp.modify_firewall",
                name="GCP Firewall Modifier",
                description="GCP VPC 방화벽 규칙을 수정하거나 위험 포트를 차단합니다 (프로덕션 변경).",
                tool_type=ToolType.ACTION,
                risk_level=AgentRiskLevel.L4,
                requires_approval=True,
                production_change=True,
                allowed_agents=["grc-remediation-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "rule_name": {"type": "string"},
                        "action": {"type": "string"},
                    },
                    "required": ["rule_name", "action"],
                },
                timeout_seconds=60,
            )
        )
        self.register_tool(
            MCPToolMetadata(
                tool_id="gcp.delete_resource",
                name="GCP Resource Deleter",
                description="GCP 취약 리소스를 삭제합니다 (프로덕션 파괴적 변경).",
                tool_type=ToolType.ACTION,
                risk_level=AgentRiskLevel.L4,
                requires_approval=True,
                production_change=True,
                allowed_agents=["grc-remediation-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "resource_id": {"type": "string"},
                    },
                    "required": ["resource_id"],
                },
                timeout_seconds=60,
            )
        )
        self.register_tool(
            MCPToolMetadata(
                tool_id="gcp.change_iam",
                name="GCP IAM Binding Modifier",
                description="GCP IAM 바인딩 정책을 변경하거나 관리자 권한을 회수합니다 (프로덕션 변경).",
                tool_type=ToolType.ACTION,
                risk_level=AgentRiskLevel.L4,
                requires_approval=True,
                production_change=True,
                allowed_agents=["grc-remediation-001"],
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "binding": {"type": "string"},
                        "member": {"type": "string"},
                    },
                    "required": ["binding", "member"],
                },
                timeout_seconds=60,
            )
        )

    def register_tool(self, metadata: MCPToolMetadata, handler: Optional[Callable] = None) -> MCPToolMetadata:
        """새로운 도구 메타데이터 및 실행 핸들러를 등록합니다."""
        self._tools[metadata.tool_id] = metadata
        if handler:
            self._handlers[metadata.tool_id] = handler
        return metadata

    def register_handler(self, tool_id: str, handler: Callable):
        """기존 등록된 도구에 실행 핸들러를 바인딩합니다."""
        if tool_id not in self._tools:
            raise KeyError(f"Tool {tool_id} not registered in MCPToolRegistry.")
        self._handlers[tool_id] = handler

    def get_tool(self, tool_id: str) -> Optional[MCPToolMetadata]:
        """도구 메타데이터를 반환합니다."""
        return self._tools.get(tool_id)

    def get_handler(self, tool_id: str) -> Optional[Callable]:
        """도구 실행 핸들러를 반환합니다."""
        return self._handlers.get(tool_id)

    def list_tools(self, agent_id: Optional[str] = None) -> List[MCPToolMetadata]:
        """등록된 도구 목록을 반환합니다. agent_id 제공 시 해당 에이전트에게 인가된 도구만 필터링합니다."""
        if not agent_id:
            return list(self._tools.values())
        return [t for t in self._tools.values() if agent_id in t.allowed_agents]

    def is_authorized(self, agent_id: str, tool_id: str) -> bool:
        """에이전트가 특정 도구를 실행할 권한이 있는지 검사합니다."""
        tool = self.get_tool(tool_id)
        if not tool or tool.status != MCPToolStatus.ACTIVE:
            return False
        return agent_id in tool.allowed_agents
