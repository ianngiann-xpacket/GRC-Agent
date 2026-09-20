"""AI GRC Copilot 최상위 통합 서비스(CopilotService) 모듈입니다."""

import uuid
from typing import Any, Dict, List, Optional, Union

from secgrc.copilot.answer import CopilotAnswerGenerator
from secgrc.copilot.classifier import CopilotIntentClassifier
from secgrc.copilot.executor import CopilotQueryExecutor
from secgrc.copilot.guard import CopilotGuard
from secgrc.copilot.intents import INTENT_METADATA, IntentCategory
from secgrc.copilot.models import CopilotAnswer, CopilotQuery, UserRole
from secgrc.copilot.planner import CopilotQueryPlanner
from secgrc.ontology.builder import OntologyBuilder
from secgrc.ontology.repository import OntologyRepository
from secgrc.ontology.resolver import OntologyResolver


class CopilotService:
    """자연어 보안 질의의 수신, 의도 분류, 계획 수립, 결정론적 실행 및 답변 조율 서비스"""

    def __init__(
        self,
        repo: Optional[OntologyRepository] = None,
        resolver: Optional[OntologyResolver] = None,
    ) -> None:
        self.repo = repo or OntologyBuilder().build()
        self.resolver = resolver or OntologyResolver(self.repo)

        self.classifier = CopilotIntentClassifier(self.repo)
        self.planner = CopilotQueryPlanner()
        self.executor = CopilotQueryExecutor(self.repo, self.resolver)
        self.guard = CopilotGuard(self.repo)
        self.generator = CopilotAnswerGenerator(self.repo, self.guard)

    def ask(
        self,
        question: str,
        user_role: Union[str, UserRole] = UserRole.ANALYST,
        language: str = "ko",
    ) -> CopilotAnswer:
        """자연어 질의를 수신하여 최종 CopilotAnswer를 생성합니다."""
        if isinstance(user_role, str):
            user_role = UserRole.from_str(user_role)

        query = CopilotQuery(
            query_id=f"QRY-{uuid.uuid4().hex[:8]}",
            question=question,
            language=language,
            user_role=user_role,
        )

        # 1. 의도 분류 및 엔티티 추출
        intent_res = self.classifier.classify(question)

        # 2. 질의 계획 수립 (읽기 전용 가드레일 강제)
        plan = self.planner.create_plan(intent_res)

        # 3. 결정론적 데이터 및 온톨로지 조회
        context, provenance = self.executor.execute(plan)

        # 4. 검증된 답변 생성
        answer = self.generator.generate(query, intent_res, context, provenance)

        return answer

    def get_supported_intents(self) -> List[Dict[str, Any]]:
        """지원 가능한 의도 카테고리 목록을 반환합니다."""
        intents_list = []
        for cat, meta in INTENT_METADATA.items():
            intents_list.append(
                {
                    "intent": cat.value,
                    "required_data": meta["required_data"],
                    "allowed_operations": meta["allowed_operations"],
                }
            )
        return intents_list

    def get_health(self) -> Dict[str, Any]:
        """Copilot 서비스의 헬스체크 및 역량 상태를 반환합니다."""
        summary = self.repo.get_summary()
        return {
            "status": "HEALTHY",
            "read_only": True,
            "entities_count": summary.get("total_entities", 0),
            "relationships_count": summary.get("total_relationships", 0),
            "supported_intents_count": len(INTENT_METADATA),
            "guardrail_status": "ACTIVE",
        }
