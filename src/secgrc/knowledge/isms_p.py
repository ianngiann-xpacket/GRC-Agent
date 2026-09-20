"""KISA ISMS-P 인증기준 지식 베이스(Knowledge Base) 데이터 모듈입니다.

src/secgrc/data/isms_p_controls.json 파일에서 최신 통제항목 데이터를 로드합니다.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class ISMSPControl:
    """ISMS-P 통제항목 데이터 모델"""
    control_id: str             # 통제항목 번호 (예: '2.7.1', '3.2.1')
    category: str               # 영역 분류 (예: '3. 개인정보 처리단계별 요구사항 > 3.2 개인정보 보유 및 파기')
    name: str                   # 통제항목 이름
    requirements: str           # 핵심 요구사항
    checkpoints: List[str]      # 주요 점검/확인 사항
    flaw_examples: List[str]    # 대표적 결함 사례 (부적합 사례)
    keywords: List[str] = field(default_factory=list)  # 검색 가중치 키워드


def load_controls_from_json() -> List[ISMSPControl]:
    """JSON 데이터 파일에서 ISMS-P 통제항목 목록을 로드합니다."""
    json_path = Path(__file__).resolve().parent.parent / "data" / "isms_p_controls.json"

    if not json_path.exists():
        # 파일이 없을 경우 기본 최소 항목 반환
        return []

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    controls = []
    for item in data:
        controls.append(
            ISMSPControl(
                control_id=item["control_id"],
                category=item["category"],
                name=item["name"],
                requirements=item["requirements"],
                checkpoints=item.get("checkpoints", []),
                flaw_examples=item.get("flaw_examples", []),
                keywords=item.get("keywords", []),
            )
        )
    return controls


# 전체 ISMS-P 통제항목 지식 베이스 로드
ISMS_P_CONTROLS: List[ISMSPControl] = load_controls_from_json()
