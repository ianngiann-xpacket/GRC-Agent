"""Prowler Evidence를 ISMS-P 통제항목에 연결하는 결정론적 매퍼(EvidenceMapper) 모듈입니다.

4단계 우선순위 전략:
  Priority 1: 글로벌 표준(ISO 27001, NIST, CIS) 크로스 매핑 (mapping_isms_p.json)
  Priority 2: Prowler 컴플라이언스 메타데이터(COMPLIANCE) 내 ISMS-P 명시
  Priority 3: GRC-Agent 지식 베이스 키워드 및 보안 점검(Check ID) 패턴 매핑
  Priority 4: 매핑 불가 항목 처리 (NO_EVIDENCE / 미매핑)
"""

import re
from typing import Any, Dict, List, Optional, Set

from secgrc.knowledge.repository import ControlRepository
from secgrc.models.evidence import NormalizedEvidence


class EvidenceMapper:
    """Prowler 증적 객체를 ISMS-P 통제항목에 매핑하는 엔진."""

    # 보안 점검 ID 및 카테고리에 대한 결정론적 휴리스틱 패턴
    CHECK_ID_HEURISTICS: Dict[str, str] = {
        "storage_bucket_public_access": "ISMS-P-2.7.1",
        "kms_cmek_encryption_enabled": "ISMS-P-2.7.1",
        "bigquery_dataset_encrypted_with_cmek": "ISMS-P-2.7.1",
        "compute_firewall_ssh_public": "ISMS-P-2.6.3",
        "compute_firewall_rdp_public": "ISMS-P-2.6.3",
        "compute_default_network_exist": "ISMS-P-2.6.3",
        "iam_service_account_key_rotation": "ISMS-P-2.5.2",
        "iam_mfa_enabled": "ISMS-P-2.5.2",
        "iam_sa_no_admin_privileges": "ISMS-P-2.5.3",
        "logging_bucket_retention": "ISMS-P-2.9.2",
        "logging_audit_logs_data_access": "ISMS-P-2.9.2",
        "vpc_subnet_flow_logs_enabled": "ISMS-P-2.9.2",
        "resilience_disaster_recovery_plan": "ISMS-P-2.8.1",
    }

    def __init__(self, repo: Optional[ControlRepository] = None):
        """매퍼 초기화 및 지식 저장소 연동."""
        self.repo = repo if repo is not None else ControlRepository()
        self.valid_control_ids: Set[str] = {c.control_id for c in self.repo.controls}

    def _normalize_control_id(self, raw_id: str) -> Optional[str]:
        """통제번호 문자열을 'ISMS-P-X.X.X' 표준 형식으로 변환합니다."""
        cleaned = raw_id.strip()
        if not cleaned:
            return None

        # '2.5.2' -> 'ISMS-P-2.5.2'
        m = re.search(r"([123]\.[0-9]+\.[0-9]+)", cleaned)
        if m:
            candidate = f"ISMS-P-{m.group(1)}"
            if candidate in self.valid_control_ids:
                return candidate

        upper_id = cleaned.upper()
        if upper_id in self.valid_control_ids:
            return upper_id

        return None

    def _match_priority_1_cross_framework(self, evidence: NormalizedEvidence) -> List[str]:
        """Priority 1: mapping_isms_p.json의 글로벌 표준(ISO/NIST/CIS) 매핑 확인."""
        matched: List[str] = []
        comp = evidence.get("compliance")
        if not comp:
            return matched

        # 1. 딕셔너리 구조에서 CIS, ISO, NIST 엔트리 정밀 검사
        if isinstance(comp, dict):
            for k, v in comp.items():
                k_low = str(k).lower()
                vals = [str(x).strip().lower() for x in (v if isinstance(v, list) else [v])]

                # CIS 컨트롤 매칭 (예: Prowler의 CIS 항목이 mapping_isms_p.json의 CIS 번호와 일치하는지)
                if "cis" in k_low:
                    for ctrl in self.repo.controls:
                        mapping = self.repo.get_mapping(ctrl.control_id)
                        if not mapping:
                            continue
                        for cis in mapping.cis_controls:
                            m = re.search(r"cis\s+([0-9]+\.[0-9]+)", cis.lower())
                            if m and m.group(1) in vals:
                                if ctrl.control_id not in matched:
                                    matched.append(ctrl.control_id)

                # ISO 27001 조항 매칭
                if "iso" in k_low:
                    for ctrl in self.repo.controls:
                        mapping = self.repo.get_mapping(ctrl.control_id)
                        if not mapping:
                            continue
                        for iso in mapping.iso27001:
                            iso_code = iso.split()[0].lower()
                            if any(iso_code == val or iso_code in val for val in vals):
                                if ctrl.control_id not in matched:
                                    matched.append(ctrl.control_id)

        # 2. 문자열 형태의 프레임워크 명시 검사
        elif isinstance(comp, str):
            comp_lower = comp.lower()
            for ctrl in self.repo.controls:
                mapping = self.repo.get_mapping(ctrl.control_id)
                if not mapping:
                    continue
                for cis in mapping.cis_controls:
                    m = re.search(r"cis\s+([0-9]+\.[0-9]+)", cis.lower())
                    if m and re.search(r"\bcis[ -_]?" + re.escape(m.group(1)) + r"\b", comp_lower):
                        if ctrl.control_id not in matched:
                            matched.append(ctrl.control_id)

        return matched

    def _match_priority_2_explicit_isms_p(self, evidence: NormalizedEvidence) -> List[str]:
        """Priority 2: Prowler COMPLIANCE 메타데이터에서 직접 명시된 ISMS-P 번호 추출."""
        matched: List[str] = []
        comp = evidence.get("compliance")
        if not comp:
            return matched

        # 1. 딕셔너리 구조인 경우 (예: {"ISMS-P": ["2.5.2"]})
        if isinstance(comp, dict):
            for k, v in comp.items():
                k_lower = str(k).lower()
                if "isms" in k_lower:
                    items = v if isinstance(v, list) else [v]
                    for item in items:
                        cid = self._normalize_control_id(str(item))
                        if cid and cid not in matched:
                            matched.append(cid)

        # 2. 문자열 형태인 경우 (예: "ISMS-P: 2.9.2")
        elif isinstance(comp, str) and "isms" in comp.lower():
            cid = self._normalize_control_id(comp)
            if cid and cid not in matched:
                matched.append(cid)

        return matched

    def _match_priority_3_knowledge_and_heuristics(self, evidence: NormalizedEvidence) -> List[str]:
        """Priority 3: Check ID 패턴 및 통제항목 키워드 매칭."""
        check_id = evidence.get("check_id", "")
        if check_id in self.CHECK_ID_HEURISTICS:
            target_id = self.CHECK_ID_HEURISTICS[check_id]
            if target_id in self.valid_control_ids:
                return [target_id]

        # 지식 저장소 키워드 검색
        query = f"{evidence.get('title', '')} {' '.join(evidence.get('categories', []))} {evidence.get('description', '')}"
        results = self.repo.search(query, top_k=1)
        if results and results[0][2] >= 5:  # 신뢰도 임계값
            return [results[0][0].control_id]

        return []

    def map_evidence(self, evidence: NormalizedEvidence) -> List[str]:
        """단일 증적을 4단계 우선순위에 따라 1개 이상의 ISMS-P 통제항목에 매핑합니다.

        Args:
            evidence: 정규화된 Prowler 증적

        Returns:
            List[str]: 매핑된 통제번호 목록 (매핑 실패 시 빈 리스트)
        """
        # Priority 1: 크로스 프레임워크(ISO/CIS) 매핑
        p1 = self._match_priority_1_cross_framework(evidence)
        if p1:
            return p1

        # Priority 2: Prowler 메타데이터 직접 ISMS-P 명시
        p2 = self._match_priority_2_explicit_isms_p(evidence)
        if p2:
            return p2

        # Priority 3: Check ID 및 지식 베이스 키워드 휴리스틱
        p3 = self._match_priority_3_knowledge_and_heuristics(evidence)
        if p3:
            return p3

        # Priority 4: 미매핑 (NO_EVIDENCE 대상)
        return []

    def group_by_control(
        self, evidence_list: List[NormalizedEvidence]
    ) -> Dict[str, List[NormalizedEvidence]]:
        """전체 통제항목(10개)을 기준으로 매핑된 증적들을 그룹핑합니다.

        증적이 없는 통제항목도 빈 리스트([])로 키를 유지하여 NO_EVIDENCE 판정을 보장합니다.

        Args:
            evidence_list: Prowler 증적 목록

        Returns:
            Dict[str, List[NormalizedEvidence]]: {통제ID: [증적목록]}
        """
        grouped: Dict[str, List[NormalizedEvidence]] = {
            ctrl.control_id: [] for ctrl in self.repo.controls
        }

        for ev in evidence_list:
            mapped_controls = self.map_evidence(ev)
            for cid in mapped_controls:
                if cid in grouped:
                    grouped[cid].append(ev)

        return grouped
