"""Append-Only Change Ledger with Deduplication and Ordering (Step 25).

Maintains an immutable, append-only history of canonical change events,
guaranteeing idempotency and preventing out-of-order state regression.
"""

from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from secgrc.continuous.models import ChangeEvent


class ChangeLedger:
    """엔터프라이즈 정규 데이터 변경 원장 (Append-only)."""

    def __init__(self) -> None:
        self._entries: List[ChangeEvent] = []
        self._by_id: Dict[str, ChangeEvent] = {}
        self._idempotency_keys: Set[Tuple[str, str, str, str, str, str, str]] = set()
        # entity_id -> latest observed_at timestamp
        self._latest_observed: Dict[str, str] = {}

    def _make_idempotency_key(self, change: ChangeEvent) -> Tuple[str, str, str, str, str, str, str]:
        """결정론적 멱등성 키를 생성합니다 (Section 11)."""
        return (
            change.tenant_id,
            change.source_system,
            change.source_record_id,
            change.entity_id,
            change.previous_hash,
            change.new_hash,
            str(change.change_type.value),
        )

    def append(self, change: ChangeEvent) -> bool:
        """새로운 변경 이벤트를 원장에 추가합니다.
        
        이미 존재하는 멱등성 키인 경우 추가하지 않고 False를 반환합니다 (멱등성 보장).
        순서가 뒤바뀐 구버전 이벤트도 이력에는 기록하되, 최신 권위 상태를 후퇴시키지 않습니다 (Section 12).
        """
        if not isinstance(change, ChangeEvent):
            raise TypeError("Expected ChangeEvent instance")

        # Duplicate ID check
        if change.change_id in self._by_id:
            return False

        key = self._make_idempotency_key(change)
        if key in self._idempotency_keys:
            return False

        # Check out-of-order status
        is_out_of_order = False
        latest_time = self._latest_observed.get(change.entity_id)
        if latest_time and change.observed_at < latest_time:
            is_out_of_order = True
        else:
            self._latest_observed[change.entity_id] = change.observed_at

        # Record event in append-only storage
        stored = deepcopy(change)
        if is_out_of_order:
            # Mark provenance that this is recorded as an out-of-order historical event
            prov = dict(stored.provenance)
            prov["out_of_order"] = True
            stored = stored.model_copy(update={"provenance": prov})

        self._entries.append(stored)
        self._by_id[stored.change_id] = stored
        self._idempotency_keys.add(key)
        return True

    def get(self, change_id: str, tenant_id: Optional[str] = None) -> Optional[ChangeEvent]:
        """ID로 변경 이벤트를 조회합니다 (딥카피 반환)."""
        c = self._by_id.get(change_id)
        if c is None:
            return None
        if tenant_id and c.tenant_id != tenant_id:
            return None
        return deepcopy(c)

    def list(self, tenant_id: Optional[str] = None, limit: int = 100) -> List[ChangeEvent]:
        """전체 변경 이벤트를 시간순으로 조회합니다."""
        res = [
            deepcopy(c)
            for c in self._entries
            if tenant_id is None or c.tenant_id == tenant_id
        ]
        return res[:limit]

    def find_by_entity(self, entity_id: str, tenant_id: Optional[str] = None) -> List[ChangeEvent]:
        """특정 엔티티의 모든 변경 이벤트를 조회합니다."""
        return [
            deepcopy(c)
            for c in self._entries
            if c.entity_id == entity_id and (tenant_id is None or c.tenant_id == tenant_id)
        ]

    def find_by_source(self, source_system: str, tenant_id: Optional[str] = None) -> List[ChangeEvent]:
        """특정 소스 시스템의 변경 이벤트를 조회합니다."""
        return [
            deepcopy(c)
            for c in self._entries
            if c.source_system == source_system and (tenant_id is None or c.tenant_id == tenant_id)
        ]

    def find_by_time_range(
        self,
        start_time: str,
        end_time: str,
        tenant_id: Optional[str] = None,
    ) -> List[ChangeEvent]:
        """시간 범위 내의 변경 이벤트를 조회합니다."""
        return [
            deepcopy(c)
            for c in self._entries
            if start_time <= c.occurred_at <= end_time and (tenant_id is None or c.tenant_id == tenant_id)
        ]

    def count(self, tenant_id: Optional[str] = None) -> int:
        """기록된 총 변경 수를 반환합니다."""
        if tenant_id is None:
            return len(self._entries)
        return sum(1 for c in self._entries if c.tenant_id == tenant_id)

    def record_change(self, change: ChangeEvent) -> Tuple[ChangeEvent, bool]:
        """record_change helper returning (stored_or_existing, was_appended)."""
        was_added = self.append(change)
        stored = self.get(change.change_id)
        return (stored or change, was_added)

    def get_change(self, change_id: str, tenant_id: Optional[str] = None) -> Optional[ChangeEvent]:
        """get의 명시적 별칭."""
        return self.get(change_id, tenant_id)

    def list_changes(self, tenant_id: Optional[str] = None, limit: int = 100) -> List[ChangeEvent]:
        """list의 명시적 별칭."""
        return self.list(tenant_id, limit)

    def list_by_tenant(self, tenant_id: str) -> List[ChangeEvent]:
        """테넌트별 변경 목록 조회."""
        return self.list(tenant_id=tenant_id)

    def get_latest_observed_time(self, entity_or_tenant_id: str) -> Optional[str]:
        """특정 엔티티의 최신 관측 일시 조회."""
        return self._latest_observed.get(entity_or_tenant_id)

    def clear(self) -> None:
        """테스트 격리용 원장 초기화."""
        self._entries.clear()
        self._by_id.clear()
        self._idempotency_keys.clear()
        self._latest_observed.clear()


default_change_ledger = ChangeLedger()
