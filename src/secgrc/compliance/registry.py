"""Adapter Schema Registry (Step 23.5A).

This module manages the registration, lookup, and structure validation
of data adapter schemas for the 8 canonical security data sources.
"""

from typing import Any, Dict, List, Optional

from secgrc.compliance.schemas import (
    FIREWALL_SCHEMA,
    IAM_SCHEMA,
    NESSUS_SCHEMA,
    NMAP_SCHEMA,
    POLICY_DOCUMENT_SCHEMA,
    PROWLER_SCHEMA,
    SIEM_SCHEMA,
    WINDOWS_EVENT_SCHEMA,
    AdapterSchema,
)


class SchemaRegistry:
    """원천 데이터 어댑터 스키마 레지스트리."""

    def __init__(self) -> None:
        self._schemas: Dict[str, AdapterSchema] = {}
        self._initialize_default_schemas()

    def register(self, schema: AdapterSchema) -> None:
        """어댑터 스키마를 등록합니다."""
        key = self._make_key(schema.source_type, schema.schema_version)
        self._schemas[key] = schema

    def get(self, source_type: str, schema_version: str = "1.0") -> Optional[AdapterSchema]:
        """소스 유형 및 버전으로 어댑터 스키마를 조회합니다."""
        key = self._make_key(source_type, schema_version)
        return self._schemas.get(key)

    def list_schemas(self) -> List[AdapterSchema]:
        """등록된 모든 어댑터 스키마 목록을 반환합니다 (결정론적 정렬)."""
        return sorted(self._schemas.values(), key=lambda s: (s.source_type, s.schema_version))

    def validate_record_structure(
        self,
        source_type: str,
        record: Dict[str, Any],
        schema_version: str = "1.0",
    ) -> bool:
        """레코드가 해당 어댑터 스키마의 필수 필드를 모두 포함하는지 검증합니다."""
        schema = self.get(source_type, schema_version)
        if not schema:
            return False
        return all(field in record and record[field] is not None for field in schema.required_fields)

    def _make_key(self, source_type: str, schema_version: str) -> str:
        return f"{source_type.upper()}:{schema_version}"

    def _initialize_default_schemas(self) -> None:
        """8대 표준 어댑터 스키마 등록."""
        self.register(PROWLER_SCHEMA)
        self.register(NMAP_SCHEMA)
        self.register(NESSUS_SCHEMA)
        self.register(IAM_SCHEMA)
        self.register(FIREWALL_SCHEMA)
        self.register(SIEM_SCHEMA)
        self.register(WINDOWS_EVENT_SCHEMA)
        self.register(POLICY_DOCUMENT_SCHEMA)


# 기본 싱글톤 스키마 레지스트리
default_schema_registry = SchemaRegistry()
