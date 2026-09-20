"""Base Security Data Adapter Contract & Parser Security (Step 23.5A).

This module defines the extensible SecurityDataAdapter protocol and
the BaseSecurityDataAdapter class providing parser hardening, size/depth limits,
hash calculation, and deterministic provenance generation.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from secgrc.compliance.models import (
    CanonicalDataType,
    CanonicalSecurityData,
    ClassificationLevel,
    ProvenanceRecord,
)

# 보안 제한 상수
MAX_PAYLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_COLLECTION_SIZE = 50_000
MAX_NESTING_DEPTH = 10


@runtime_checkable
class SecurityDataAdapter(Protocol):
    """모든 보안 데이터 어댑터가 구현해야 하는 불변 프로토콜."""

    source_type: str
    schema_version: str

    def detect(self, payload: Any) -> bool:
        """입력 페이로드가 해당 어댑터의 지원 형식인지 감지합니다."""
        ...

    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        """원천 페이로드를 원시 레코드 딕셔너리 목록으로 파싱합니다."""
        ...

    def normalize(
        self,
        records: List[Dict[str, Any]],
        tenant_id: str = "default",
        scope: str = "GLOBAL",
    ) -> List[CanonicalSecurityData]:
        """파싱된 레코드를 표준 정규 CanonicalSecurityData 목록으로 변환합니다."""
        ...

    def validate(self, records: List[CanonicalSecurityData]) -> bool:
        """변환된 정규 레코드 목록의 무결성과 필수 속성을 검증합니다."""
        ...


class BaseSecurityDataAdapter(ABC):
    """어댑터 공통 보안 점검 및 정규화 헬퍼 기반 클래스."""

    source_type: str = "BASE"
    schema_version: str = "1.0"

    def check_payload_safety(self, payload: Any) -> None:
        """파서 보안 검증: 크기, 중첩 깊이, 원시 바이트 제한 점검."""
        if payload is None:
            raise ValueError("Payload cannot be None")

        if isinstance(payload, (str, bytes)):
            byte_len = len(payload.encode("utf-8") if isinstance(payload, str) else payload)
            if byte_len > MAX_PAYLOAD_BYTES:
                raise ValueError(f"Payload size {byte_len} exceeds maximum allowed {MAX_PAYLOAD_BYTES} bytes")
        elif isinstance(payload, (list, dict)):
            # 컬렉션 크기 및 중첩 깊이 검사
            self._check_depth_and_size(payload, depth=1)

    def _check_depth_and_size(self, node: Any, depth: int) -> None:
        if depth > MAX_NESTING_DEPTH:
            raise ValueError(f"Payload nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH}")

        if isinstance(node, list):
            if len(node) > MAX_COLLECTION_SIZE:
                raise ValueError(f"Collection size {len(node)} exceeds maximum allowed {MAX_COLLECTION_SIZE}")
            for item in node:
                if isinstance(item, (dict, list)):
                    self._check_depth_and_size(item, depth + 1)
        elif isinstance(node, dict):
            if len(node) > MAX_COLLECTION_SIZE:
                raise ValueError(f"Dictionary keys {len(node)} exceeds maximum allowed {MAX_COLLECTION_SIZE}")
            for v in node.values():
                if isinstance(v, (dict, list)):
                    self._check_depth_and_size(v, depth + 1)

    def compute_hash(self, data: Any) -> str:
        """재현 가능한 SHA-256 무결성 해시를 계산합니다."""
        if isinstance(data, (dict, list)):
            dumped = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        elif isinstance(data, str):
            dumped = data.encode("utf-8")
        elif isinstance(data, bytes):
            dumped = data
        else:
            dumped = str(data).encode("utf-8")
        return hashlib.sha256(dumped).hexdigest()

    def safe_timestamp(self, ts_val: Any) -> str:
        """임의의 날짜/시간 입력을 ISO 8601 UTC 표준 포맷으로 변환합니다."""
        if not ts_val:
            return datetime.now(timezone.utc).isoformat()
        if isinstance(ts_val, datetime):
            if ts_val.tzinfo is None:
                return ts_val.replace(tzinfo=timezone.utc).isoformat()
            return ts_val.isoformat()
        if isinstance(ts_val, str):
            ts_str = ts_val.strip()
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                return dt.isoformat()
            except Exception:
                return datetime.now(timezone.utc).isoformat()
        return datetime.now(timezone.utc).isoformat()

    @abstractmethod
    def detect(self, payload: Any) -> bool:
        pass

    @abstractmethod
    def parse(self, payload: Any) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def normalize(
        self,
        records: List[Dict[str, Any]],
        tenant_id: str = "default",
        scope: str = "GLOBAL",
    ) -> List[CanonicalSecurityData]:
        pass

    def validate(self, records: List[CanonicalSecurityData]) -> bool:
        """기본 정규 레코드 검증: record_id, data_type, provenance 유효성."""
        for r in records:
            if not r.record_id or not r.provenance or not r.data_type:
                return False
        return True
