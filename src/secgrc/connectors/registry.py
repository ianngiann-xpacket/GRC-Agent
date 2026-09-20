"""Phase 33-A: Production Connector Architecture - Connector Registry (Section 35 & 36).

Manages connector registration, lifecycle state transitions, and validation:
- register() -> Blocks duplicate connector_id
- unregister()
- get()
- list()
- enable() / disable()
- transition_status()
- validate_registration()
"""

import threading
from typing import Dict, List, Optional

from secgrc.connectors.base import BaseConnector
from secgrc.connectors.models import (
    ConnectorDefinition,
    ConnectorHealth,
    ConnectorStatus,
)


class ConnectorRegistry:
    """Thread-safe deterministic registry for external security connectors."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._connectors: Dict[str, BaseConnector] = {}
        self._statuses: Dict[str, ConnectorStatus] = {}

    def register(self, connector: BaseConnector) -> None:
        """Registers a connector instance. Blocks duplicate connector_id."""
        with self._lock:
            cid = connector.connector_id
            if cid in self._connectors:
                raise ValueError(f"DUPLICATE_CONNECTOR: Connector '{cid}' is already registered.")

            self.validate_registration(connector.definition)
            self._connectors[cid] = connector
            initial_status = ConnectorStatus.READY if connector.definition.enabled else ConnectorStatus.DISABLED
            self._statuses[cid] = initial_status

    def unregister(self, connector_id: str) -> bool:
        """Unregisters a connector."""
        with self._lock:
            if connector_id in self._connectors:
                conn = self._connectors.pop(connector_id)
                self._statuses.pop(connector_id, None)
                try:
                    conn.close()
                except Exception:
                    pass
                return True
            return False

    def get(self, connector_id: str) -> Optional[BaseConnector]:
        """Retrieves a connector by ID."""
        with self._lock:
            return self._connectors.get(connector_id)

    def list(self) -> List[ConnectorDefinition]:
        """Lists definitions of all registered connectors sorted by ID."""
        with self._lock:
            return [
                conn.describe()
                for cid, conn in sorted(self._connectors.items(), key=lambda item: item[0])
            ]

    def get_status(self, connector_id: str) -> ConnectorStatus:
        """Retrieves current operational status of a connector."""
        with self._lock:
            if connector_id not in self._statuses:
                raise KeyError(f"Connector '{connector_id}' not found in registry.")
            return self._statuses[connector_id]

    def transition_status(self, connector_id: str, new_status: ConnectorStatus) -> None:
        """Transitions connector operational lifecycle status."""
        with self._lock:
            if connector_id not in self._statuses:
                raise KeyError(f"Connector '{connector_id}' not found.")
            current = self._statuses[connector_id]

            # Allowed transitions
            # REGISTERED -> READY
            # READY <-> RUNNING
            # RUNNING -> DEGRADED / FAILED / READY
            # Any -> DISABLED
            # DISABLED -> READY
            if current == ConnectorStatus.DISABLED and new_status != ConnectorStatus.READY:
                raise ValueError(f"Disabled connector '{connector_id}' must transition to READY before {new_status.value}")

            self._statuses[connector_id] = new_status

    def enable(self, connector_id: str) -> None:
        """Enables a disabled connector."""
        with self._lock:
            self.transition_status(connector_id, ConnectorStatus.READY)

    def disable(self, connector_id: str) -> None:
        """Disables an active connector."""
        with self._lock:
            self.transition_status(connector_id, ConnectorStatus.DISABLED)

    def validate_registration(self, definition: ConnectorDefinition) -> bool:
        """Validates static definition integrity and security rules."""
        if not definition.connector_id or not definition.connector_id.strip():
            raise ValueError("connector_id cannot be empty")
        if not definition.name or not definition.name.strip():
            raise ValueError("Connector name cannot be empty")
        if not definition.supported_canonical_types:
            raise ValueError(f"Connector '{definition.connector_id}' must support at least one CanonicalDataType")
        if not definition.metadata_hash:
            raise ValueError("Connector metadata_hash is missing")
        return True

    def clear(self) -> None:
        """Clears all registered connectors."""
        with self._lock:
            for conn in self._connectors.values():
                try:
                    conn.close()
                except Exception:
                    pass
            self._connectors.clear()
            self._statuses.clear()
