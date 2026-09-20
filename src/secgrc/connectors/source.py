"""Phase 33-A: Production Connector Architecture - Source Ingestion & Batches (Section 9 & 10).

Handles:
- RawSourceRecord construction & validation
- ConnectorCollectionBatch tracking with deterministic semantic hash
- Idempotency key derivation from stable source attributes (no wall-clock timestamps)
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional

from secgrc.connectors.models import (
    ConnectorCollectionBatch,
    RawSourceRecord,
    compute_canonical_hash,
    compute_idempotency_key,
)


class ConnectorSourceHandler:
    """Manages raw source record ingestion and batch lifecycle."""

    @staticmethod
    def create_raw_record(
        connector_id: str,
        source_system: str,
        source_record_id: str,
        source_type: str,
        organization_ref: str,
        source_event_time: str,
        payload: Dict[str, Any],
        source_version: str = "1.0",
        source_locator: str = "",
        collection_batch_id: str = "",
        raw_provenance: Optional[Dict[str, Any]] = None,
        collected_at: Optional[str] = None,
    ) -> RawSourceRecord:
        """Constructs an immutable RawSourceRecord."""
        record_id = f"RAW-{connector_id}-{source_record_id}"
        ts_collected = collected_at or datetime.now(timezone.utc).isoformat()

        prov = dict(raw_provenance or {})
        prov["connector_id"] = connector_id
        prov["source_system"] = source_system
        prov["source_record_id"] = source_record_id
        prov["idempotency_key"] = compute_idempotency_key(
            connector_id=connector_id,
            source_system=source_system,
            source_record_id=source_record_id,
            source_event_time=source_event_time,
        )

        return RawSourceRecord(
            record_id=record_id,
            connector_id=connector_id,
            source_system=source_system,
            source_type=source_type,
            source_version=source_version,
            organization_ref=organization_ref,
            collected_at=ts_collected,
            source_event_time=source_event_time,
            payload=payload,
            source_locator=source_locator,
            collection_batch_id=collection_batch_id,
            raw_provenance=prov,
        )

    @staticmethod
    def start_batch(
        batch_id: str,
        connector_id: str,
        organization_id: str,
        cursor: Optional[str] = None,
        started_at: Optional[str] = None,
    ) -> ConnectorCollectionBatch:
        """Initializes a new collection batch."""
        ts_start = started_at or datetime.now(timezone.utc).isoformat()
        return ConnectorCollectionBatch(
            batch_id=batch_id,
            connector_id=connector_id,
            organization_id=organization_id,
            started_at=ts_start,
            cursor=cursor,
            status="RUNNING",
        )

    @staticmethod
    def complete_batch(
        batch: ConnectorCollectionBatch,
        record_count: int,
        success_count: int,
        failure_count: int,
        cursor: Optional[str] = None,
        continuation_token: Optional[str] = None,
        completed_at: Optional[str] = None,
    ) -> ConnectorCollectionBatch:
        """Closes and seals a collection batch with semantic batch_hash."""
        ts_end = completed_at or datetime.now(timezone.utc).isoformat()
        status = "COMPLETED" if failure_count == 0 else "PARTIAL_FAILURE"
        return ConnectorCollectionBatch(
            batch_id=batch.batch_id,
            connector_id=batch.connector_id,
            organization_id=batch.organization_id,
            started_at=batch.started_at,
            completed_at=ts_end,
            record_count=record_count,
            success_count=success_count,
            failure_count=failure_count,
            cursor=cursor or batch.cursor,
            continuation_token=continuation_token,
            status=status,
        )
