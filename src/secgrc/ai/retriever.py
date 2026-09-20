"""AI 조사 컨텍스트 검색기(Retriever) 모듈 (Section 48, 49)."""

from typing import Any, Dict, List, Optional
from secgrc.ai.context import AIInvestigationContext, AIContextBuilder


class AIInvestigationRetriever:
    """결정론적, 읽기 전용, 스코프 한정 조사 데이터 검색기 (Section 48, 49).
    
    임의의 벡터 검색이나 비결정론적 검색을 배제하고, 권위 있는 저장소 및 조사 결과로부터
    출처(Provenance)와 식별자가 명확한 구조화된 데이터만을 조회합니다.
    """

    def __init__(self, context_builder: Optional[AIContextBuilder] = None):
        self.context_builder = context_builder or AIContextBuilder()

    def retrieve_context(
        self,
        investigation_id: str,
        scope: str,
        allowed_entity_ids: List[str],
        facts_source: Optional[List[Dict[str, Any]]] = None,
        evidence_source: Optional[List[Dict[str, Any]]] = None,
        relationships_source: Optional[List[Dict[str, Any]]] = None,
        assessments_source: Optional[List[Dict[str, Any]]] = None,
        changes_source: Optional[List[Dict[str, Any]]] = None,
    ) -> AIInvestigationContext:
        """지정된 조사 식별자 및 스코프에 맞는 정제된 컨텍스트를 검색 및 구성합니다."""
        # 1. 전달된 원천 데이터가 없는 경우 빈 리스트로 초기화
        facts = facts_source or []
        evidence = evidence_source or []
        relationships = relationships_source or []
        assessments = assessments_source or []
        changes = changes_source or []

        # 2. 컨텍스트 빌더를 통한 무해화 및 스코프 제약 필터링 적용
        return self.context_builder.build_context(
            investigation_id=investigation_id,
            scope=scope,
            allowed_entity_ids=allowed_entity_ids,
            facts=facts,
            evidence=evidence,
            relationships=relationships,
            assessments=assessments,
            changes=changes,
        )
