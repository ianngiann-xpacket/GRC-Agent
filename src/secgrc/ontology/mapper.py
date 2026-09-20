"""프레임워크 간 통제항목 교차 매핑(Cross-Framework Mapping) 모듈입니다."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from secgrc.ontology.confidence import MappingConfidence, MappingType
from secgrc.ontology.entities import Control, Framework
from secgrc.ontology.models import RelationshipType
from secgrc.ontology.relationships import Relationship
from secgrc.ontology.repository import OntologyRepository

FRAMEWORK_METADATA = {
    "ISO-27001": {"name": "ISO/IEC 27001:2022", "authority": "ISO/IEC", "version": "2022"},
    "NIST-CSF": {"name": "NIST Cybersecurity Framework", "authority": "NIST", "version": "2.0"},
    "CIS-Controls": {"name": "CIS Critical Security Controls", "authority": "Center for Internet Security", "version": "v8"},
    "NIST-AI-RMF": {"name": "NIST Artificial Intelligence Risk Management Framework", "authority": "NIST", "version": "1.0"},
}


class CrossFrameworkMapper:
    """프레임워크 간 결정론적 매핑 및 그래프 관계 생성기"""

    def __init__(self, mapping_path: Optional[str] = None) -> None:
        if mapping_path is None:
            mapping_path = str(Path(__file__).resolve().parent.parent.parent.parent / "data" / "frameworks" / "mapping_isms_p.json")
        self.mapping_path = Path(mapping_path)
        self.mappings: List[Dict[str, Any]] = self._load_mappings()

    def _load_mappings(self) -> List[Dict[str, Any]]:
        if not self.mapping_path.exists():
            return []
        with open(self.mapping_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def populate_cross_frameworks(self, repo: OntologyRepository) -> None:
        """타 프레임워크 개체와 통제항목 및 매핑 관계를 온톨로지 저장소에 등록합니다."""
        # 1. 대상 프레임워크 등록
        for fw_id, meta in FRAMEWORK_METADATA.items():
            if not repo.get_entity(fw_id):
                repo.add_entity(
                    Framework(
                        entity_id=fw_id,
                        name=meta["name"],
                        authority=meta["authority"],
                        version=meta["version"],
                        description=f"{meta['name']} Framework"
                    )
                )

        # 2. 매핑 항목 순회 및 대상 Control 생성 + MAPS_TO 관계 생성
        for item in self.mappings:
            source_ctrl_id = item["control_id"]
            rationale = item.get("rationale", "")

            # 매핑 타깃 매핑 테이블: json 키 -> 프레임워크 ID
            targets = [
                ("iso27001", "ISO-27001"),
                ("nist_csf", "NIST-CSF"),
                ("cis_controls", "CIS-Controls"),
                ("nist_ai_rmf", "NIST-AI-RMF"),
            ]

            for key, fw_id in targets:
                for target_ctrl_raw in item.get(key, []):
                    # 타깃 컨트롤 ID 정규화 (예: "A.5.1" 추출 또는 앞부분 분리)
                    target_ctrl_id = f"{fw_id}:{target_ctrl_raw.split()[0]}"
                    if not repo.get_entity(target_ctrl_id):
                        repo.add_entity(
                            Control(
                                entity_id=target_ctrl_id,
                                framework_id=fw_id,
                                name=target_ctrl_raw,
                                description=f"{fw_id} Control: {target_ctrl_raw}",
                                metadata={"raw_definition": target_ctrl_raw}
                            )
                        )
                        # Framework -> Control CONTAINS 관계
                        repo.add_relationship(
                            Relationship(
                                relationship_id=f"rel_contains_{fw_id}_{target_ctrl_id}",
                                source_type="Framework",
                                source_id=fw_id,
                                relationship_type=RelationshipType.CONTAINS,
                                target_type="Control",
                                target_id=target_ctrl_id,
                                confidence=MappingConfidence(
                                    score=1.0,
                                    mapping_type=MappingType.EXPLICIT,
                                    source="framework_definition"
                                )
                            )
                        )

                    # ISMS-P Control -> Target Control MAPS_TO 관계 생성
                    rel_id = f"rel_maps_{source_ctrl_id}_{target_ctrl_id}"
                    if not repo.get_relationship(rel_id):
                        repo.add_relationship(
                            Relationship(
                                relationship_id=rel_id,
                                source_type="Control",
                                source_id=source_ctrl_id,
                                relationship_type=RelationshipType.MAPS_TO,
                                target_type="Control",
                                target_id=target_ctrl_id,
                                confidence=MappingConfidence(
                                    score=1.0,
                                    mapping_type=MappingType.EXPLICIT,
                                    rationale=rationale,
                                    source="mapping_isms_p.json"
                                ),
                                source="deterministic_mapping",
                                metadata={"target_framework": fw_id}
                            )
                        )
