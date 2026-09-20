"""ISMS-P 지식 검색(Knowledge Retriever) 모듈입니다.

자연어 질의 또는 점검 텍스트로부터 가장 관련성이 높은 ISMS-P 통제항목을 검색합니다.
"""

from typing import List, Optional, Tuple
from secgrc.knowledge.isms_p import ISMS_P_CONTROLS, ISMSPControl


class KnowledgeRetriever:
    """ISMS-P 통제항목 검색기 (Lexical / Keyword Retriever)"""

    def __init__(self, controls: Optional[List[ISMSPControl]] = None):
        self.controls = controls if controls is not None else ISMS_P_CONTROLS

    def retrieve(self, query: str) -> Optional[Tuple[ISMSPControl, int]]:
        """
        주어진 질의(query)와 가장 관련성이 높은 ISMS-P 통제항목을 검색하여 반환합니다.

        Returns:
            (가장 일치하는 ISMSPControl 객체, 매칭 점수) 또는 일치 항목이 없으면 None
        """
        query_lower = query.lower()
        best_control: Optional[ISMSPControl] = None
        highest_score = 0

        for control in self.controls:
            score = 0

            # 1. 정의된 핵심 키워드 매칭 (가장 높은 가중치: 3점)
            for kw in control.keywords:
                if kw.lower() in query_lower:
                    score += 3

            # 2. 통제항목명 매칭 (가중치: 2점)
            for word in control.name.split():
                if word.lower() in query_lower:
                    score += 2

            # 3. 요구사항 본문 매칭 (가중치: 1점)
            for word in control.requirements.split():
                if len(word) > 1 and word.lower() in query_lower:
                    score += 1

            if score > highest_score:
                highest_score = score
                best_control = control

        if highest_score > 0 and best_control is not None:
            return best_control, highest_score

        return None
