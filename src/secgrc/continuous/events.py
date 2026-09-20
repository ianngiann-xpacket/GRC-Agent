"""Continuous GRC 이벤트 소스 추상화 및 Mock 이벤트 소스, 중복 제거(Deduplication) 모듈입니다."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from secgrc.continuous.models import ChangeType


class EventSource(ABC):
    """이벤트 소스 추상 기반 클래스 (Event Source Interface)"""

    @abstractmethod
    def poll(self) -> List[Dict[str, Any]]:
        """소스(GCP Audit Logs, Cloud Logging, GitHub 등)로부터 새로운 변경 이벤트를 폴링합니다."""
        pass


class MockEventSource(EventSource):
    """실제 클라우드 연결 없이 변경 이벤트를 시뮬레이션 및 큐잉하는 Mock 이벤트 소스입니다."""

    def __init__(self):
        self._queue: List[Dict[str, Any]] = []
        self._seed_default_events()

    def _seed_default_events(self):
        """기본 시뮬레이션용 변경 이벤트 세팅"""
        self.emit(
            event_id="EVT-GCP-FW-001",
            source="gcp",
            event_type="FIREWALL_CHANGED",
            resource_type="firewall_rule",
            resource_id="firewall-rule-001",
            change_type=ChangeType.UPDATE,
            actor="admin@company.com",
            metadata={
                "action": "allow_ingress",
                "source_ranges": ["0.0.0.0/0"],
                "ports": ["22"],
                "public_access": True,
            },
        )
        self.emit(
            event_id="EVT-GCP-IAM-002",
            source="gcp",
            event_type="IAM_CHANGED",
            resource_type="service_account",
            resource_id="ci-deployer-sa",
            change_type=ChangeType.PERMISSION_CHANGE,
            actor="security-admin@company.com",
            metadata={
                "role_added": "roles/owner",
                "allUsers": True,
            },
        )
        self.emit(
            event_id="EVT-GCP-GCS-003",
            source="gcp",
            event_type="STORAGE_POLICY_CHANGED",
            resource_type="bucket",
            resource_id="customer-data-bucket",
            change_type=ChangeType.POLICY_CHANGE,
            actor="operator@company.com",
            metadata={
                "uniform_bucket_level_access": False,
                "public_access": True,
            },
        )

    def emit(
        self,
        event_id: str,
        source: str,
        event_type: str,
        resource_type: str,
        resource_id: str,
        change_type: ChangeType = ChangeType.UPDATE,
        actor: str = "service-account",
        environment: str = "production",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """테스트 및 시뮬레이션을 위해 새로운 이벤트를 큐에 직접 주입합니다."""
        event_data = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "event_type": event_type,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "change_type": change_type.value if hasattr(change_type, "value") else str(change_type),
            "actor": actor,
            "environment": environment,
            "metadata": metadata or {},
        }
        self._queue.append(event_data)

    def poll(self) -> List[Dict[str, Any]]:
        """큐에 누적된 이벤트를 모두 꺼내어 반환합니다."""
        events = list(self._queue)
        self._queue.clear()
        return events


class EventDeduplicator:
    """이벤트 중복 평가 방지를 위한 식별자 기반 Deduplication 엔진입니다."""

    def __init__(self):
        self._processed_event_ids: Set[str] = set()

    def is_duplicate(self, event_id: str) -> bool:
        """이벤트가 이미 처리되었는지 검사합니다."""
        return event_id in self._processed_event_ids

    def mark_processed(self, event_id: str):
        """이벤트를 처리 완료 상태로 등록합니다."""
        self._processed_event_ids.add(event_id)

    def process_event(self, event: Dict[str, Any]) -> str:
        """이벤트를 확인하여 이미 처리된 경우 ALREADY_PROCESSED를, 신규인 경우 PROCEED를 반환합니다."""
        e_id = event.get("event_id", "")
        if not e_id or self.is_duplicate(e_id):
            return "ALREADY_PROCESSED"
        self.mark_processed(e_id)
        return "PROCEED"
