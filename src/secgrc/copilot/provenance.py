"""증적 출처 및 근거 추적(Provenance) 모듈입니다."""

from typing import Any, Dict, List, Optional
from secgrc.copilot.models import Provenance


class ProvenanceBuilder:
    """답변에 포함될 증적/통제/위험 출처 체인 구성기"""

    def __init__(self) -> None:
        self._items: List[Provenance] = []
        self._seen_ids: set = set()

    def add(
        self,
        source_type: str,
        source_id: str,
        source_path: str = "",
        relationship: str = "",
        confidence: float = 1.0,
    ) -> "ProvenanceBuilder":
        """단일 근거 항목을 추가합니다 (중복 방지)."""
        key = (source_type, source_id, relationship)
        if key in self._seen_ids:
            return self
        self._seen_ids.add(key)
        self._items.append(
            Provenance(
                source_type=source_type,
                source_id=source_id,
                source_path=source_path,
                relationship=relationship,
                confidence=round(float(confidence), 2),
            )
        )
        return self

    def add_from_lineage(self, lineage: Dict[str, Any]) -> "ProvenanceBuilder":
        """OntologyResolver의 lineage 결과로부터 출처 체인을 자동 추출하여 추가합니다."""
        if not lineage or "error" in lineage:
            return self

        # Root Entity
        if "root_entity" in lineage:
            root = lineage["root_entity"]
            self.add(
                source_type=root.get("type", "Entity"),
                source_id=root.get("id", ""),
                relationship="ROOT",
                confidence=1.0,
            )

        # Controls
        if "control_id" in lineage:
            self.add(
                source_type="Control",
                source_id=lineage["control_id"],
                relationship="TARGET_CONTROL",
                confidence=1.0,
            )
        for c in lineage.get("controls", []):
            self.add(
                source_type="Control",
                source_id=c.get("control_id", ""),
                relationship="MAPS_TO",
                confidence=1.0,
            )

        # Evidences
        for ev in lineage.get("evidences", []):
            eid = ev.get("id") if isinstance(ev, dict) else str(ev)
            self.add(
                source_type="Evidence",
                source_id=eid,
                relationship="SUPPORTED_BY",
                confidence=1.0,
            )

        # Risks
        if "risk_id" in lineage:
            self.add(
                source_type="Risk",
                source_id=lineage["risk_id"],
                relationship="TARGET_RISK",
                confidence=1.0,
            )
        for r in lineage.get("risks", []):
            rid = r.get("risk_id") if isinstance(r, dict) else str(r)
            self.add(
                source_type="Risk",
                source_id=rid,
                relationship="CREATES_RISK",
                confidence=1.0,
            )

        # Findings
        for f in lineage.get("findings", []):
            fid = f.get("finding_id") if isinstance(f, dict) else str(f)
            self.add(
                source_type="Finding",
                source_id=fid,
                relationship="DERIVED_FROM",
                confidence=1.0,
            )

        # Remediations
        for rem in lineage.get("remediations", []):
            rem_id = rem.get("remediation_id") if isinstance(rem, dict) else str(rem)
            self.add(
                source_type="Remediation",
                source_id=rem_id,
                relationship="MITIGATED_BY",
                confidence=1.0,
            )

        return self

    def build(self) -> List[Provenance]:
        """조립된 Provenance 리스트를 반환합니다."""
        return list(self._items)
