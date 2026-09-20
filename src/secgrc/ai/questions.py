"""AI 추가 조사 질문 검증 및 관리 모듈 (Section 15, 16)."""

from typing import List, Tuple
from secgrc.ai.models import CREDENTIAL_PATTERNS, InvestigationQuestion


class QuestionValidator:
    """LLM이 제안한 질문의 보안성 및 자격증명 추출 시도를 엄격히 검증합니다 (Section 16)."""

    @classmethod
    def validate_question(cls, question: InvestigationQuestion) -> Tuple[bool, str]:
        """질문이 패스워드, 비밀키, 토큰 등을 요구하는지 검사합니다."""
        text_lower = question.question.lower()
        reason_lower = question.reason.lower()

        for pat in CREDENTIAL_PATTERNS:
            if pat in text_lower or pat in reason_lower:
                return False, f"Question requests credentials or secret tokens: '{pat}'"

        return True, "Valid question"

    @classmethod
    def filter_safe_questions(cls, questions: List[InvestigationQuestion]) -> List[InvestigationQuestion]:
        """안전한 질문만을 선별하여 반환합니다."""
        safe = []
        for q in questions:
            is_valid, _ = cls.validate_question(q)
            if is_valid:
                safe.append(q)
        return safe
