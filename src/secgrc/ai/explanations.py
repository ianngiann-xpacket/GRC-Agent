"""AI 보안 설명 및 불확실성 보존 모듈 (Section 17, 18)."""

from typing import List, Optional
from secgrc.ai.models import AIExplanation, validate_id_str


class ExplanationBuilder:
    """원천 데이터를 일절 변경하지 않으면서도 불확실성을 구조적으로 보존하는 AI 설명 생성기."""

    @staticmethod
    def build_explanation(
        explanation_id: str,
        target_type: str,
        target_id: str,
        summary: str,
        reasoning_points: List[str],
        supporting_refs: List[str],
        uncertainty_points: Optional[List[str]] = None,
    ) -> AIExplanation:
        """결정론적 원천 데이터와 분리된 비권위적 설명을 생성합니다."""
        uncertainties = uncertainty_points or []
        # 불확실성 항목이 명시되지 않은 경우, 기본적으로 증적 한계점을 보존
        if not uncertainties:
            uncertainties.append("Direct definitive causation cannot be concluded without additional forensic verification.")

        return AIExplanation(
            explanation_id=validate_id_str(explanation_id, "explanation_id"),
            target_type=target_type,
            target_id=validate_id_str(target_id, "target_id"),
            summary=summary,
            reasoning_points=reasoning_points,
            supporting_refs=supporting_refs,
            uncertainty_points=uncertainties,
            created_by="LLM",
        )
