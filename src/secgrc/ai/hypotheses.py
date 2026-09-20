"""AI 가설 검증 및 결정론적 지지 수준 산출 모듈 (Section 13, 35, 36)."""

from typing import Any, Dict, List, Optional
from secgrc.ai.context import AIInvestigationContext
from secgrc.ai.models import (
    HypothesisStatus,
    HypothesisSupport,
    InvestigationHypothesisAI,
)


class HypothesisValidator:
    """LLM이 제안한 가설을 결정론적 사실 및 증적과 대조하여 지지 수준을 평가하는 검증기 (Section 35, 36).
    
    주의: 이 검증기는 결정론적 증적 일치도를 평가할 뿐, 가설을 권위 있는 사실(Fact)로 승격시키거나
    인간 승인 없이 상태를 완료(SUPPORTED)로 임의 변경하지 않습니다.
    """

    @classmethod
    def evaluate_support(
        cls,
        hypothesis: InvestigationHypothesisAI,
        context: AIInvestigationContext,
    ) -> HypothesisSupport:
        """컨텍스트 내 검증된 사실 및 증적과 대조하여 지지 수준을 결정론적으로 계산합니다."""
        known_facts = {f.get("fact_id") for f in context.facts if isinstance(f, dict) and f.get("fact_id")}
        known_evidence = {e.get("evidence_id") for e in context.evidence if isinstance(e, dict) and e.get("evidence_id")}

        # 1. 반박 사실 존재 여부 검사
        contradicting_matches = set(hypothesis.contradicting_fact_ids) & known_facts
        if contradicting_matches:
            return HypothesisSupport.CONTRADICTED

        # 2. 지지 사실 및 증적 일치 수 검사
        supporting_fact_matches = set(hypothesis.supporting_fact_ids) & known_facts
        supporting_ev_matches = set(hypothesis.supporting_evidence_ids) & known_evidence

        if len(supporting_fact_matches) >= 2:
            return HypothesisSupport.STRONG_SUPPORT
        elif len(supporting_fact_matches) == 1:
            return HypothesisSupport.PARTIAL_SUPPORT
        elif len(supporting_ev_matches) >= 1:
            return HypothesisSupport.WEAK_SUPPORT
        else:
            return HypothesisSupport.NO_SUPPORT

    @classmethod
    def validate_and_annotate(
        cls,
        hypothesis: InvestigationHypothesisAI,
        context: AIInvestigationContext,
    ) -> InvestigationHypothesisAI:
        """가설을 검증하고 지지 수준(support_level) 메타데이터를 부여하여 반환합니다."""
        support_level = cls.evaluate_support(hypothesis, context)
        # 불변성을 유지하면서 support_level 필드 주입
        data = hypothesis.model_dump()
        data["support_level"] = support_level
        # 상태는 반드시 PROPOSED 유지 (LLM이나 검증기가 자율 승격 금지)
        data["status"] = HypothesisStatus.PROPOSED
        return InvestigationHypothesisAI.model_validate(data)
