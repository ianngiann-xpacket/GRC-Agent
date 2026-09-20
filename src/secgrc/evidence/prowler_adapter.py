"""Prowler v5.x CSV 출력 결과를 GRC-Agent 표준 증적(Evidence) 객체로 변환하는 어댑터 모듈입니다.

Prowler가 생성한 CSV(세미콜론 ';' 구분자)를 파싱하여,
상태(STATUS), 심각도(SEVERITY), 컴플라이언스(COMPLIANCE), 카테고리(CATEGORIES)를 정규화하고
모든 원본 데이터를 보존한 표준 NormalizedEvidence 객체를 생성합니다.
"""

import ast
import csv
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from secgrc.models.evidence import NormalizedEvidence

logger = logging.getLogger(__name__)


class ProwlerEvidenceAdapter:
    """Prowler 보안 진단 결과(CSV)를 GRC-Agent 표준 규격으로 변환하는 어댑터."""

    def __init__(self, delimiter: str = ";"):
        """어댑터 초기화.
        
        Args:
            delimiter: Prowler CSV 구분자 (기본값: ';')
        """
        self.delimiter = delimiter

    def load_csv(self, path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Prowler CSV 파일을 읽어 원본 행(row) 딕셔너리 리스트를 반환합니다.

        Args:
            path: CSV 파일 경로

        Returns:
            List[Dict[str, Any]]: 원본 CSV row 리스트
        """
        csv_path = Path(path)
        if not csv_path.exists():
            raise FileNotFoundError(f"Prowler CSV 파일을 찾을 수 없습니다: {csv_path}")

        rows: List[Dict[str, Any]] = []
        with open(csv_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f, delimiter=self.delimiter)
            for line_no, row in enumerate(reader, start=2):
                if not row or not any(row.values()):
                    continue
                # DictReader에서 헤더 수와 불일치하여 None 키가 생성된 경우 안전하게 정리
                clean_row: Dict[str, Any] = {}
                for k, v in row.items():
                    if k is not None:
                        clean_row[k.strip()] = v if v is not None else ""
                rows.append(clean_row)

        return rows

    def normalize_status(self, status_raw: Any, muted_raw: Any = "") -> str:
        """Prowler STATUS 및 MUTED 값을 표준 상태 문자열로 정규화합니다.

        표준 상태: PASS, FAIL, MANUAL, MUTED, UNKNOWN

        Args:
            status_raw: 원본 STATUS 값
            muted_raw: 원본 MUTED 값

        Returns:
            str: 표준화된 상태 문자열
        """
        muted_str = str(muted_raw).strip().lower() if muted_raw else ""
        if muted_str in ("true", "muted", "yes"):
            return "MUTED"

        if not status_raw:
            return "UNKNOWN"

        s = str(status_raw).strip().upper()
        if s == "MUTED":
            return "MUTED"
        if s in ("PASS", "PASSED", "COMPLIANT", "OK"):
            return "PASS"
        if s in ("FAIL", "FAILED", "NON_COMPLIANT", "KO"):
            return "FAIL"
        if s in ("MANUAL", "MANUAL_REVIEW", "WARNING"):
            return "MANUAL"

        return s

    def normalize_severity(self, severity_raw: Any) -> str:
        """Prowler SEVERITY 값을 소문자 표준 문자열로 정규화합니다.

        표준 심각도: critical, high, medium, low, informational, unknown

        Args:
            severity_raw: 원본 SEVERITY 값

        Returns:
            str: 표준화된 심각도 문자열
        """
        if not severity_raw:
            return "unknown"

        s = str(severity_raw).strip().lower()
        if s in ("critical", "crit"):
            return "critical"
        if s in ("high",):
            return "high"
        if s in ("medium", "med"):
            return "medium"
        if s in ("low",):
            return "low"
        if s in ("informational", "info", "informative"):
            return "informational"
        if s in ("unknown", "none", ""):
            return "unknown"

        return s

    def parse_compliance(self, compliance_raw: Any) -> Optional[Any]:
        """COMPLIANCE 필드를 JSON/dict 구조로 파싱합니다. 파싱 실패 시 원본 문자열을 보존합니다.

        Args:
            compliance_raw: 원본 COMPLIANCE 값

        Returns:
            Optional[Union[dict, list, str]]: 파싱된 구조 또는 원본 문자열, 빈 값이면 None
        """
        if compliance_raw is None:
            return None

        if isinstance(compliance_raw, (dict, list)):
            return compliance_raw

        text = str(compliance_raw).strip()
        if not text:
            return None

        # 1. 표준 JSON 파싱 시도
        try:
            return json.loads(text)
        except Exception:
            pass

        # 2. Python dict 형태(단일 따옴표 등) 파싱 시도
        if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
            try:
                return ast.literal_eval(text)
            except Exception:
                pass

        # 3. 파싱 불가능한 텍스트는 원본 문자열 그대로 보존
        return text

    def parse_categories(self, categories_raw: Any) -> List[str]:
        """CATEGORIES 필드를 문자열 리스트로 정규화합니다.

        Args:
            categories_raw: 원본 CATEGORIES 값

        Returns:
            List[str]: 정규화된 카테고리 목록
        """
        if not categories_raw:
            return []

        if isinstance(categories_raw, list):
            return [str(c).strip() for c in categories_raw if str(c).strip()]

        text = str(categories_raw).strip()
        if not text:
            return []

        # JSON 리스트 형태 시도
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return [str(c).strip() for c in parsed if str(c).strip()]
            except Exception:
                pass

        # 쉼표(,) 또는 파이프(|) 구분자 분리
        delimiter = "," if "," in text else ("|" if "|" in text else None)
        if delimiter:
            parts = text.split(delimiter)
        else:
            parts = [text]

        return [p.strip() for p in parts if p.strip()]

    def normalize_row(self, row: Dict[str, Any]) -> NormalizedEvidence:
        """Prowler CSV의 한 행을 표준 NormalizedEvidence 객체로 변환합니다.

        모든 원본 데이터는 'raw' 필드에 그대로 보존됩니다.

        Args:
            row: CSV 한 행 딕셔너리

        Returns:
            NormalizedEvidence: 표준화된 감사 증적 객체
        """
        finding_uid = str(row.get("FINDING_UID", "")).strip()
        check_id = str(row.get("CHECK_ID", "")).strip()
        provider = str(row.get("PROVIDER", "")).strip().lower() or "gcp"

        # 고유 evidence_id 결정
        if finding_uid:
            evidence_id = f"EV-{finding_uid}" if not finding_uid.startswith("EV-") else finding_uid
        elif check_id:
            res_name = str(row.get("RESOURCE_NAME", "") or row.get("RESOURCE_UID", "")).strip()
            evidence_id = f"EV-PROWLER-{check_id}-{res_name}" if res_name else f"EV-PROWLER-{check_id}"
        else:
            evidence_id = "EV-PROWLER-UNKNOWN"

        account_email_raw = str(row.get("ACCOUNT_EMAIL", "")).strip()
        account_email = account_email_raw if account_email_raw else None

        remediation_url_raw = str(row.get("REMEDIATION_RECOMMENDATION_URL", "")).strip()
        remediation_url = remediation_url_raw if remediation_url_raw else None

        remediation_text = (
            str(row.get("REMEDIATION_RECOMMENDATION_TEXT", "")).strip()
            or str(row.get("REMEDIATION_CODE_CLI", "")).strip()
            or str(row.get("REMEDIATION_CODE_TERRAFORM", "")).strip()
            or ""
        )

        status_norm = self.normalize_status(
            row.get("STATUS", ""),
            row.get("MUTED", "")
        )
        severity_norm = self.normalize_severity(row.get("SEVERITY", ""))
        compliance_norm = self.parse_compliance(row.get("COMPLIANCE"))
        categories_norm = self.parse_categories(row.get("CATEGORIES"))

        return NormalizedEvidence(
            evidence_id=evidence_id,
            source="prowler",
            provider=provider,
            account_id=str(row.get("ACCOUNT_UID", "")).strip(),
            account_email=account_email,
            timestamp=str(row.get("TIMESTAMP", "")).strip(),
            finding_uid=finding_uid,
            check_id=check_id,
            title=str(row.get("CHECK_TITLE", "")).strip(),
            status=status_norm,
            severity=severity_norm,
            resource_type=str(row.get("RESOURCE_TYPE", "")).strip(),
            resource_uid=str(row.get("RESOURCE_UID", "")).strip(),
            resource_name=str(row.get("RESOURCE_NAME", "")).strip(),
            region=str(row.get("REGION", "")).strip(),
            description=str(row.get("DESCRIPTION", "")).strip(),
            risk=str(row.get("RISK", "")).strip(),
            remediation=remediation_text,
            remediation_url=remediation_url,
            compliance=compliance_norm,
            categories=categories_norm,
            prowler_version=str(row.get("PROWLER_VERSION", "")).strip(),
            raw=dict(row),
        )

    def load_findings(self, path: Union[str, Path]) -> List[NormalizedEvidence]:
        """CSV 파일을 로드하고 모든 행을 NormalizedEvidence 리스트로 변환합니다.

        Args:
            path: CSV 파일 경로

        Returns:
            List[NormalizedEvidence]: 변환된 증적 리스트
        """
        raw_rows = self.load_csv(path)
        findings: List[NormalizedEvidence] = []
        for row in raw_rows:
            try:
                findings.append(self.normalize_row(row))
            except Exception as e:
                logger.warning(f"행 정규화 실패 (행 무시): {e}, row={row}")
        return findings

    def summary(self, findings: List[NormalizedEvidence]) -> Dict[str, Any]:
        """정규화된 증적 리스트로부터 집계 요약 통계를 생성합니다.

        Args:
            findings: 정규화된 증적 목록

        Returns:
            Dict[str, Any]: 집계 통계 딕셔너리
        """
        provider = findings[0].get("provider", "gcp") if findings else "gcp"

        stats: Dict[str, Any] = {
            "source": "prowler",
            "provider": provider,
            "findings": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "unknown_severity": 0,
            "pass": 0,
            "fail": 0,
            "manual": 0,
            "muted": 0,
            "unknown_status": 0,
        }

        for f in findings:
            sev = str(f.get("severity", "unknown")).lower()
            if sev == "critical":
                stats["critical"] += 1
            elif sev == "high":
                stats["high"] += 1
            elif sev == "medium":
                stats["medium"] += 1
            elif sev == "low":
                stats["low"] += 1
            elif sev == "informational":
                stats["informational"] += 1
            else:
                stats["unknown_severity"] += 1

            st = str(f.get("status", "UNKNOWN")).upper()
            if st == "PASS":
                stats["pass"] += 1
            elif st == "FAIL":
                stats["fail"] += 1
            elif st == "MANUAL":
                stats["manual"] += 1
            elif st == "MUTED":
                stats["muted"] += 1
            else:
                stats["unknown_status"] += 1

        return stats
