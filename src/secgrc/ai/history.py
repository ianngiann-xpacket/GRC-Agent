"""AI 추론 불변 이력 저장소(History Store) 모듈 (Section 38, 75)."""

from datetime import datetime, timezone
import copy
from typing import Any, Dict, List, Optional
from pydantic import Field

from secgrc.ai.guard import AIInvestigationGuardResult
from secgrc.ai.models import AIBaseModel, AIReasoningResult, validate_id_str


class AIReasoningRecord(AIBaseModel):
    """추가 전용(Append-only) 불변 AI 추론 이력 레코드 (Section 38)"""
    record_id: str = Field(description="이력 레코드 고유 식별자")
    request_id: str = Field(description="요청 식별자")
    response_id: str = Field(description="응답 식별자")
    investigation_id: str = Field(description="연관 조사 식별자")
    provider_id: str = Field(description="프로바이더 식별자")
    model_id: str = Field(description="모델 식별자")
    prompt_template_id: str = Field(description="프롬프트 템플릿 ID")
    prompt_template_version: str = Field(description="프롬프트 템플릿 버전")
    context_hash: str = Field(description="컨텍스트 해시")
    output_hash: str = Field(description="원시 출력 해시")
    guard_result: AIInvestigationGuardResult = Field(description="가드 검증 결과")
    reasoning_result: Optional[AIReasoningResult] = Field(default=None, description="파싱된 최종 추론 객체")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="기록 일시 (ISO-8601)",
    )

    @property
    def is_blocked(self) -> bool:
        return self.guard_result.is_blocked


class AIReasoningHistoryStore:
    """불변, 추가 전용(Append-only) AI 추론 이력 저장소 (Section 38, 75).
    
    모든 LLM 추론 기록은 덮어쓰기나 수정이 영구적으로 차단됩니다.
    """

    def __init__(self):
        self._records: Dict[str, AIReasoningRecord] = {}
        self._investigation_index: Dict[str, List[str]] = {}

    def append_record(self, record: AIReasoningRecord) -> None:
        """새로운 추론 레코드를 불변 저장소에 추가합니다. 덮어쓰기 시 ValueError 발생."""
        if record.record_id in self._records:
            raise ValueError(f"Cannot overwrite existing AI reasoning record: '{record.record_id}'. Store is append-only.")

        stored = copy.deepcopy(record)
        self._records[record.record_id] = stored

        inv_id = record.investigation_id
        if inv_id not in self._investigation_index:
            self._investigation_index[inv_id] = []
        self._investigation_index[inv_id].append(record.record_id)

    def get_record(self, record_id: str) -> Optional[AIReasoningRecord]:
        """기록 식별자로 추론 레코드를 조회합니다."""
        val = self._records.get(record_id)
        return copy.deepcopy(val) if val else None

    def list_records(
        self,
        investigation_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AIReasoningRecord]:
        """추론 레코드 목록을 반환합니다."""
        if investigation_id:
            rec_ids = self._investigation_index.get(investigation_id, [])
            records = [self._records[rid] for rid in rec_ids if rid in self._records]
        else:
            records = list(self._records.values())

        # 최신순 정렬
        sorted_records = sorted(records, key=lambda r: r.created_at, reverse=True)
        return [copy.deepcopy(r) for r in sorted_records[:limit]]

    def count(self) -> int:
        """저장된 총 레코드 수를 반환합니다."""
        return len(self._records)

    def clear_for_tests(self) -> None:
        """테스트 간 격리를 위한 초기화 헬퍼."""
        self._records.clear()
        self._investigation_index.clear()


default_ai_history_store = AIReasoningHistoryStore()
