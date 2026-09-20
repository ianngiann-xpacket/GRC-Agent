"""감사 증적(Evidence) 데이터 저장소 및 조회 모듈입니다."""

import json
from pathlib import Path
from typing import Dict, List, Any
from secgrc.models.evidence import Evidence, EvidenceStatus


class EvidenceRepository:
    """클라우드 및 수동 감사 증적 관리 저장소"""

    def __init__(self, evidence_dir: Path = None):
        if evidence_dir is None:
            # 프로젝트 루트의 data/evidence 탐색
            evidence_dir = (
                Path(__file__).resolve().parent.parent.parent.parent
                / "data"
                / "evidence"
            )
        self.evidence_dir = evidence_dir
        self._evidence_list: List[Evidence] = self._load_all_evidence()

    def _load_all_evidence(self) -> List[Evidence]:
        """data/evidence 폴더 내의 모든 JSON 증적 파일들을 병합 로드합니다."""
        if not self.evidence_dir.exists():
            return []

        evidence_items: List[Evidence] = []
        for json_file in self.evidence_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        evidence_items.append(Evidence(**item))
            except Exception as e:
                print(f"[경고] 증적 파일 {json_file.name} 로드 실패: {e}")

        return evidence_items

    @property
    def all_evidence(self) -> List[Evidence]:
        """전체 증적 목록 반환"""
        return self._evidence_list

    def get_by_control(self, control_id: str) -> List[Evidence]:
        """특정 통제항목 번호(예: 'ISMS-P-2.5.2')와 연관된 모든 증적 목록을 조회합니다."""
        target_id = control_id.strip().upper()
        return [ev for ev in self._evidence_list if ev.control_id.upper() == target_id]

    def get_summary(self) -> Dict[str, Any]:
        """전체 증적 준수 현황 요약 통계를 반환합니다."""
        total = len(self._evidence_list)
        if total == 0:
            return {
                "total": 0,
                "compliant": 0,
                "non_compliant": 0,
                "partial": 0,
                "score_percent": 0.0,
            }

        compliant = sum(1 for e in self._evidence_list if e.status == EvidenceStatus.COMPLIANT)
        non_compliant = sum(1 for e in self._evidence_list if e.status == EvidenceStatus.NON_COMPLIANT)
        partial = sum(1 for e in self._evidence_list if e.status == EvidenceStatus.PARTIAL)

        # 준수율 계산 (적합: 1.0점, 부분준수: 0.5점)
        score = ((compliant * 1.0) + (partial * 0.5)) / total * 100

        return {
            "total": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
            "score_percent": round(score, 1),
        }
