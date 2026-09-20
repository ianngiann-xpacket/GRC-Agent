"""Closed-loop 증적 비교(Evidence Diff Engine) 모듈입니다."""

from typing import Any, Dict, List, Optional, Tuple
from secgrc.closed_loop.models import EvidenceDiffResult
from secgrc.models.evidence import NormalizedEvidence


class EvidenceDiffEngine:
    """조치 전후의 증적 목록을 비교 분석하여 상태 변화 및 개선 사항을 산출하는 엔진입니다."""

    @staticmethod
    def _extract_key(item: Any) -> str:
        """증적 항목으로부터 고유 비교 키(finding_uid 또는 resource_id+check_id)를 추출합니다."""
        if isinstance(item, dict):
            f_uid = item.get("finding_uid") or item.get("evidence_id")
            if f_uid:
                return str(f_uid)
            r_id = item.get("resource_uid") or item.get("resource_name") or item.get("resource_id", "")
            c_id = item.get("check_id") or item.get("control_id", "")
            return f"{r_id}::{c_id}"
        return str(getattr(item, "evidence_id", getattr(item, "finding_id", "unknown")))

    @classmethod
    def compare(
        cls,
        before_evidence: List[NormalizedEvidence],
        after_evidence: List[NormalizedEvidence],
    ) -> List[EvidenceDiffResult]:
        """조치 전 증적 목록과 조치 후 증적 목록을 1:1로 매핑하여 Diff 목록을 생성합니다."""
        after_map: Dict[str, Any] = {}
        for ev in after_evidence:
            key = cls._extract_key(ev)
            after_map[key] = ev

        diff_results: List[EvidenceDiffResult] = []

        for b_ev in before_evidence:
            key = cls._extract_key(b_ev)
            a_ev = after_map.get(key)

            b_stat = str(b_ev.get("status", "")).upper()
            b_sev = str(b_ev.get("severity", "")).upper()
            r_id = str(b_ev.get("resource_uid") or b_ev.get("resource_name") or b_ev.get("resource_id", ""))
            c_id = str(b_ev.get("control_id") or "")

            if a_ev is not None:
                a_stat = str(a_ev.get("status", "")).upper()
                a_sev = str(a_ev.get("severity", "")).upper()
            else:
                # 조치 후 스캔에서 누락/제거된 경우
                a_stat = "NOT_FOUND"
                a_sev = "UNKNOWN"

            changed = (b_stat != a_stat) or (b_sev != a_sev)

            # change_type 결정
            if b_stat in ("FAIL", "NON_COMPLIANT", "PARTIAL") and a_stat in ("PASS", "COMPLIANT"):
                c_type = "RESOLVED"
            elif b_stat in ("PASS", "COMPLIANT") and a_stat in ("FAIL", "NON_COMPLIANT", "PARTIAL"):
                c_type = "DEGRADED"
            elif b_stat == a_stat and b_stat in ("FAIL", "NON_COMPLIANT", "PARTIAL"):
                c_type = "UNRESOLVED"
            else:
                c_type = "UNCHANGED"

            diff_results.append(
                EvidenceDiffResult(
                    finding_id=key,
                    resource_id=r_id,
                    control_id=c_id,
                    before_status=b_stat,
                    after_status=a_stat,
                    severity_before=b_sev,
                    severity_after=a_sev,
                    changed=changed,
                    change_type=c_type,
                )
            )

        return diff_results

    @classmethod
    def get_summary(cls, diffs: List[EvidenceDiffResult]) -> Dict[str, int]:
        """비교 결과에 대한 통계 요약을 생성합니다."""
        summary = {
            "total": len(diffs),
            "resolved": 0,
            "unresolved": 0,
            "degraded": 0,
            "unchanged": 0,
        }
        for d in diffs:
            if d.change_type == "RESOLVED":
                summary["resolved"] += 1
            elif d.change_type == "UNRESOLVED":
                summary["unresolved"] += 1
            elif d.change_type == "DEGRADED":
                summary["degraded"] += 1
            else:
                summary["unchanged"] += 1
        return summary
