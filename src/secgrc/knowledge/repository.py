"""ISMS-P 통제항목 및 프레임워크 크로스 매핑 지식 저장소 모듈입니다."""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from secgrc.models.control import Control
from secgrc.models.mapping import FrameworkMapping


class ControlRepository:
    """보안 컴플라이언스 통제항목 및 프레임워크 매핑 저장소"""

    def __init__(self, data_dir: Path = None):
        if data_dir is None:
            # 프로젝트 루트의 data 디렉터리 탐색
            data_dir = (
                Path(__file__).resolve().parent.parent.parent.parent
                / "data"
            )
        self.controls_path = data_dir / "controls" / "isms_p.json"
        self.mappings_path = data_dir / "frameworks" / "mapping_isms_p.json"

        self._controls: List[Control] = self._load_controls()
        self._mappings: Dict[str, FrameworkMapping] = self._load_mappings()

    def _load_controls(self) -> List[Control]:
        """JSON 데이터셋에서 Control Pydantic 모델 목록을 로드합니다."""
        if not self.controls_path.exists():
            return []

        with open(self.controls_path, "r", encoding="utf-8") as f:
            raw_list = json.load(f)

        return [Control(**item) for item in raw_list]

    def _load_mappings(self) -> Dict[str, FrameworkMapping]:
        """JSON 데이터셋에서 FrameworkMapping 맵(control_id -> Mapping)을 로드합니다."""
        if not self.mappings_path.exists():
            return {}

        with open(self.mappings_path, "r", encoding="utf-8") as f:
            raw_list = json.load(f)

        mapping_dict = {}
        for item in raw_list:
            mapping = FrameworkMapping(**item)
            mapping_dict[mapping.control_id] = mapping
        return mapping_dict

    @property
    def controls(self) -> List[Control]:
        """전체 통제항목 목록 반환"""
        return self._controls

    def get_mapping(self, control_id: str) -> Optional[FrameworkMapping]:
        """특정 통제항목 번호(예: 'ISMS-P-2.5.2')에 매핑된 글로벌 프레임워크 정보를 조회합니다."""
        return self._mappings.get(control_id)

    def search(self, query: str, top_k: int = 3) -> List[Tuple[Control, Optional[FrameworkMapping], int]]:
        """
        질의(query)를 바탕으로 통제항목 및 매핑 프레임워크를 검색하여 반환합니다.

        Returns:
            List of (Control, Optional[FrameworkMapping], match_score)
        """
        query_lower = query.lower()
        query_terms = query_lower.split()
        scored_results: List[Tuple[Control, Optional[FrameworkMapping], int]] = []

        for ctrl in self._controls:
            score = 0
            mapping = self.get_mapping(ctrl.control_id)

            # 검색 대상 텍스트 결합 (통제항목 + 매핑 정보)
            mapping_text = ""
            if mapping:
                mapping_text = f"{' '.join(mapping.iso27001)} {' '.join(mapping.nist_csf)} {' '.join(mapping.cis_controls)} {mapping.rationale}".lower()

            searchable_text = f"{ctrl.control_id} {ctrl.title} {ctrl.domain} {ctrl.requirement} {' '.join(ctrl.keywords)} {' '.join(ctrl.evidence)} {mapping_text}".lower()

            # 1. 키워드 정확 일치 (가중치: 5점)
            for kw in ctrl.keywords:
                if kw.lower() in query_lower:
                    score += 5

            # 2. 통제 ID 또는 제목 정확 매칭 (가중치: 4점)
            if ctrl.control_id.lower() in query_lower:
                score += 8
            for term in query_terms:
                if term in ctrl.title.lower():
                    score += 3
                elif term in searchable_text:
                    score += 1

            if score > 0:
                scored_results.append((ctrl, mapping, score))

        # 점수 내림차순 정렬 후 상위 top_k개 반환
        scored_results.sort(key=lambda x: x[2], reverse=True)
        return scored_results[:top_k]
