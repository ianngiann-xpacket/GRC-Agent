"""AI 조사 작업(Task) 모델 및 검증 모듈 (Section 50, 51)."""

from datetime import datetime, timezone
from typing import List, Optional
from pydantic import Field, field_validator

from secgrc.ai.models import (
    AIBaseModel,
    AIInvestigationTaskType,
    ReasoningType,
    validate_id_str,
    validate_id_list,
)

# 엄격히 금지된 자율/변경 작업 키워드
FORBIDDEN_TASK_KEYWORDS = [
    "DECIDE_COMPLIANCE",
    "CHANGE_RISK",
    "EXECUTE_REMEDIATION",
    "RUN_TOOL",
    "MODIFY_CONTROL",
    "UPDATE_RISK",
    "OVERRIDE_ASSESSMENT",
    "INVOKE_SHELL",
    "EXECUTE_COMMAND",
    "MUTATE_REPOSITORY",
]


class AIInvestigationTask(AIBaseModel):
    """AI 조사 작업 명세 모델 (Section 51).
    
    LLM에게 부여되는 단일 추론 작업의 목적, 범위, 인가된 엔티티 및 요구 출력 형식을 정의합니다.
    자율적 조치나 권한 변경 작업은 원천 차단됩니다.
    """
    task_id: str = Field(description="작업 고유 식별자")
    investigation_id: str = Field(description="소속 조사 식별자")
    task_type: AIInvestigationTaskType = Field(description="인가된 작업 유형 (Section 50)")
    objective: str = Field(description="작업 목표 및 지시 내용")
    scope: str = Field(description="조사 스코프 (예: 'CLOUD_INFRA', 'IAM_POLICIES')")
    required_output_type: ReasoningType = Field(default=ReasoningType.HYPOTHESIS, description="요구되는 추론 출력 유형")
    allowed_data_types: List[str] = Field(default_factory=lambda: ["FACT", "EVIDENCE", "ASSESSMENT"], description="인가된 데이터 유형")
    allowed_entity_ids: List[str] = Field(default_factory=list, description="인가된 엔티티 ID 목록")
    human_review_required: bool = Field(default=False, description="인간 검토 필수 여부")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="작업 생성 일시 (ISO-8601)",
    )

    @field_validator("task_id", "investigation_id")
    @classmethod
    def check_ids(cls, v: str, info) -> str:
        return validate_id_str(v, info.field_name)

    @field_validator("allowed_entity_ids")
    @classmethod
    def check_entities_list(cls, v: List[str], info) -> List[str]:
        return validate_id_list(v, info.field_name)

    @field_validator("objective")
    @classmethod
    def check_objective_safety(cls, v: str) -> str:
        v_upper = v.upper()
        for kw in FORBIDDEN_TASK_KEYWORDS:
            if kw in v_upper:
                raise ValueError(f"AI investigation task objective contains forbidden operation keyword: '{kw}'")
        return v
