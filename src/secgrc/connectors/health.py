"""Phase 33-A: Production Connector Architecture - Health & Audit Monitor (Section 28 & 38).

Tracks:
1. ConnectorHealth:
   - Operational metadata (status, latency, records processed, failures)
   - health_hash excludes wall-clock
   - NEVER treats health as a compliance score
2. ConnectorAuditLogger:
   - Records every collection pass into immutable ConnectorAuditRecord
   - Strictly prohibits logging secrets
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional

from secgrc.connectors.models import (
    ConnectorAuditRecord,
    ConnectorHealth,
    ConnectorStatus,
    compute_canonical_hash,
)
from secgrc.connectors.validator import SecretScanner


class ConnectorHealthMonitor:
    """Maintains operational telemetry and health states for registered connectors."""

    def __init__(self) -> None:
        self._health_records: Dict[str, ConnectorHealth] = {}

    def get_health(self, connector_id: str, status: ConnectorStatus) -> ConnectorHealth:
        """Retrieves or initializes operational health metadata."""
        if connector_id not in self._health_records:
            self._health_records[connector_id] = ConnectorHealth(
                connector_id=connector_id,
                status=status,
                records_processed=0,
                records_rejected=0,
                latency_ms=0.0,
            )
        return self._health_records[connector_id]

    def record_run_success(
        self,
        connector_id: str,
        processed_count: int,
        rejected_count: int,
        latency_ms: float,
        timestamp: Optional[str] = None,
    ) -> ConnectorHealth:
        """Updates health stats following a successful collection run."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        current = self.get_health(connector_id, ConnectorStatus.READY)
        updated = ConnectorHealth(
            connector_id=connector_id,
            status=ConnectorStatus.READY if rejected_count == 0 else ConnectorStatus.DEGRADED,
            last_successful_collection=ts,
            last_failure=current.last_failure,
            records_processed=current.records_processed + processed_count,
            records_rejected=current.records_rejected + rejected_count,
            latency_ms=latency_ms,
            checkpoint_state="ACTIVE",
        )
        self._health_records[connector_id] = updated
        return updated

    def record_run_failure(
        self,
        connector_id: str,
        error_message: str,
        latency_ms: float,
        timestamp: Optional[str] = None,
    ) -> ConnectorHealth:
        """Updates health stats following a run error."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        current = self.get_health(connector_id, ConnectorStatus.FAILED)
        updated = ConnectorHealth(
            connector_id=connector_id,
            status=ConnectorStatus.FAILED,
            last_successful_collection=current.last_successful_collection,
            last_failure=ts,
            records_processed=current.records_processed,
            records_rejected=current.records_rejected + 1,
            latency_ms=latency_ms,
            checkpoint_state="ERROR",
        )
        self._health_records[connector_id] = updated
        return updated


class ConnectorAuditLogger:
    """Creates immutable, sanitized audit records for connector runs."""

    def __init__(self) -> None:
        self._audit_log: List[ConnectorAuditRecord] = []

    def log_operation(
        self,
        audit_id: str,
        connector_id: str,
        operation: str,
        organization_id: str,
        started_at: str,
        completed_at: str,
        record_count: int,
        success_count: int,
        failure_count: int,
        error_categories: List[str],
        provenance: Optional[Dict[str, Any]] = None,
    ) -> ConnectorAuditRecord:
        """Records a new audit log entry without persisting secrets."""
        # Sanitize provenance to ensure zero secret leakage
        clean_prov = SecretScanner.sanitize_secrets(provenance or {})

        record = ConnectorAuditRecord(
            audit_id=audit_id,
            connector_id=connector_id,
            operation=operation,
            organization_id=organization_id,
            started_at=started_at,
            completed_at=completed_at,
            record_count=record_count,
            success_count=success_count,
            failure_count=failure_count,
            error_categories=error_categories,
            provenance=clean_prov,
        )
        self._audit_log.append(record)
        return record

    def list_records(self, connector_id: Optional[str] = None) -> List[ConnectorAuditRecord]:
        """Returns recorded audit records, optionally filtered by connector_id."""
        if connector_id:
            return [r for r in self._audit_log if r.connector_id == connector_id]
        return list(self._audit_log)
