"""Phase 33-B: Prowler Raw Output Ingestor.

Parses structured Prowler JSON and JSON-OCSF outputs and produces
immutable RawSourceRecord instances with deterministic payload hashes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from secgrc.connectors.errors import ConnectorError, ConnectorErrorCode
from secgrc.connectors.models import RawSourceRecord, compute_canonical_hash
from secgrc.connectors.source import ConnectorSourceHandler


class ProwlerRawIngestor:
    """Ingests raw JSON/JSON-OCSF Prowler scan results."""

    MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
    MAX_RECORDS = 50000

    @classmethod
    def load_raw_findings(cls, file_path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Reads file, validates JSON, and returns raw finding dictionaries and SHA-256 hash."""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"Prowler raw output file not found: {file_path}")

        file_size = p.stat().st_size
        if file_size > cls.MAX_FILE_SIZE_BYTES:
            raise ConnectorError(
                ConnectorErrorCode.RESOURCE_LIMIT,
                f"Prowler output file size {file_size} exceeds limit of {cls.MAX_FILE_SIZE_BYTES} bytes.",
            )

        content = p.read_text(encoding="utf-8").strip()
        if not content:
            return [], compute_canonical_hash({})

        raw_output_hash = compute_canonical_hash(content)

        findings: List[Dict[str, Any]] = []
        try:
            # First try standard JSON array or object
            parsed = json.loads(content)
            if isinstance(parsed, list):
                findings = parsed
            elif isinstance(parsed, dict):
                # Check if it has a findings wrapper
                if "findings" in parsed and isinstance(parsed["findings"], list):
                    findings = parsed["findings"]
                else:
                    findings = [parsed]
        except json.JSONDecodeError:
            # Try JSON Lines (one JSON object per line)
            lines = content.splitlines()
            for idx, line in enumerate(lines):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    record = json.loads(line_str)
                    if isinstance(record, dict):
                        findings.append(record)
                except json.JSONDecodeError as err:
                    raise ConnectorError(
                        ConnectorErrorCode.SOURCE_SCHEMA_CHANGED,
                        f"Malformed JSON in Prowler output at line {idx + 1}: {err}",
                    )

        if len(findings) > cls.MAX_RECORDS:
            raise ConnectorError(
                ConnectorErrorCode.RESOURCE_LIMIT,
                f"Prowler finding count {len(findings)} exceeds limit of {cls.MAX_RECORDS} records.",
            )

        return findings, raw_output_hash

    @classmethod
    def ingest_to_raw_records(
        cls,
        findings: List[Dict[str, Any]],
        connector_id: str,
        organization_ref: str,
        prowler_version: str = "4.3.0",
        source_locator: str = "",
        collection_batch_id: str = "",
    ) -> List[RawSourceRecord]:
        """Converts raw Prowler findings into immutable RawSourceRecord objects."""
        raw_records: List[RawSourceRecord] = []

        for idx, finding in enumerate(findings):
            # Extract stable source identifiers across Prowler v3/v4/v5 schemas
            # v5는 OCSF 형식: metadata.event_code / cloud.account.uid / resources[0] 등
            ocsf_resources = finding.get("resources") or []
            ocsf_res0 = ocsf_resources[0] if ocsf_resources and isinstance(ocsf_resources[0], dict) else {}
            check_id = (
                finding.get("CheckID")
                or finding.get("check_id")
                or finding.get("metadata", {}).get("CheckID")
                or finding.get("metadata", {}).get("event_code")
                or (finding.get("finding_info", {}).get("analytic") or {}).get("uid")
                or f"UNKNOWN-CHECK-{idx}"
            )
            resource_id = (
                finding.get("ResourceID")
                or finding.get("resource_id")
                or finding.get("resource_arn")
                or finding.get("ResourceId")
                or (ocsf_res0.get("data", {}).get("metadata") or {}).get("id")
                or ocsf_res0.get("uid")
                or ocsf_res0.get("name")
                or f"RESOURCE-{idx}"
            )
            project_id = (
                finding.get("Project")
                or finding.get("project_id")
                or finding.get("account_id")
                or finding.get("AccountId")
                or (finding.get("cloud", {}).get("account") or {}).get("uid")
                or organization_ref
            )
            event_time = (
                finding.get("Timestamp")
                or finding.get("timestamp")
                or finding.get("time_dt")
                or (finding.get("finding_info") or {}).get("created_time_dt")
                or finding.get("time")
                or "2026-09-13T00:00:00Z"
            )

            source_record_id = f"{project_id}:{check_id}:{resource_id}"

            raw_record = ConnectorSourceHandler.create_raw_record(
                connector_id=connector_id,
                source_system="Prowler",
                source_record_id=source_record_id,
                source_type="Prowler-GCP",
                source_version=prowler_version,
                organization_ref=organization_ref,
                source_event_time=str(event_time),
                payload=finding,
                source_locator=source_locator,
                collection_batch_id=collection_batch_id,
            )
            raw_records.append(raw_record)

        return raw_records
