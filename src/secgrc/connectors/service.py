"""Phase 33-A: Production Connector Architecture - Connector Service Facade.

Central service coordinating connectors, registries, health, audits, and contract testing.
Provides singleton accessor: get_connector_service().
"""

from typing import Any, Dict, List, Optional

from secgrc.compliance.models import CanonicalDataType
from secgrc.connectors.adapters.mock_contract import ContractMockAdapter
from secgrc.connectors.base import BaseConnector
from secgrc.connectors.contracts import ConnectorContractTestHarness
from secgrc.connectors.health import ConnectorAuditLogger, ConnectorHealthMonitor
from secgrc.connectors.models import (
    ConnectorDefinition,
    ConnectorHealth,
    ConnectorReadiness,
    ConnectorStatus,
    RawSourceRecord,
)
from secgrc.connectors.registry import ConnectorRegistry
from secgrc.connectors.source import ConnectorSourceHandler
from secgrc.connectors.validator import ConnectorValidator


class ConnectorService:
    """Central facade for the GRC-Agent production connector architecture."""

    def __init__(self) -> None:
        self.registry = ConnectorRegistry()
        self.validator = ConnectorValidator()
        self.health_monitor = ConnectorHealthMonitor()
        self.audit_logger = ConnectorAuditLogger()
        self.harness = ConnectorContractTestHarness()

        # Auto-register default reference mock connector
        default_mock = ContractMockAdapter()
        self.registry.register(default_mock)

    def register_connector(self, connector: BaseConnector) -> ConnectorDefinition:
        """Registers a connector into the registry."""
        self.registry.register(connector)
        return connector.describe()

    def unregister_connector(self, connector_id: str) -> bool:
        """Unregisters a connector."""
        return self.registry.unregister(connector_id)

    def get_connector(self, connector_id: str) -> Optional[BaseConnector]:
        """Retrieves connector instance by ID."""
        return self.registry.get(connector_id)

    def list_connectors(self) -> List[ConnectorDefinition]:
        """Lists all registered connector definitions."""
        return self.registry.list()

    def get_status(self, connector_id: str) -> ConnectorStatus:
        """Retrieves connector status."""
        return self.registry.get_status(connector_id)

    def get_health(self, connector_id: str) -> ConnectorHealth:
        """Retrieves connector health."""
        conn = self.get_connector(connector_id)
        if not conn:
            raise KeyError(f"Connector '{connector_id}' not found.")
        status = self.get_status(connector_id)
        return self.health_monitor.get_health(connector_id, status)

    def get_capabilities(self, connector_id: str) -> List[str]:
        """Retrieves connector capabilities."""
        conn = self.get_connector(connector_id)
        if not conn:
            raise KeyError(f"Connector '{connector_id}' not found.")
        return conn.capabilities()

    def validate_connector(self, connector_id: str) -> bool:
        """Validates connector registration and integrity."""
        conn = self.get_connector(connector_id)
        if not conn:
            raise KeyError(f"Connector '{connector_id}' not found.")
        return self.registry.validate_registration(conn.definition)

    def test_contract(
        self,
        connector_id: str,
        fixtures: Optional[List[RawSourceRecord]] = None,
        target_type: Optional[CanonicalDataType] = None,
    ) -> Dict[str, Any]:
        """Runs contract test suite against a connector."""
        conn = self.get_connector(connector_id)
        if not conn:
            raise KeyError(f"Connector '{connector_id}' not found.")

        # If no fixtures provided, generate a canonical contract fixture
        test_fixtures = fixtures
        if not test_fixtures:
            rec = ConnectorSourceHandler.create_raw_record(
                connector_id=connector_id,
                source_system="TestSource",
                source_record_id="REC-001",
                source_type="OBSERVATION",
                organization_ref="ORG-SYN-001",
                source_event_time="2026-09-13T00:00:00Z",
                payload={"check_id": "CHK-01", "status": "PASS", "resource": "res-01"},
            )
            test_fixtures = [rec]

        eff_type = target_type or conn.definition.supported_canonical_types[0]
        test_res = self.harness.run_contract_test(
            connector=conn,
            fixtures=test_fixtures,
            target_canonical_type=eff_type,
            organization_id="ORG-SYN-001",
        )

        # Record audit trail
        self.audit_logger.log_operation(
            audit_id=f"AUD-{connector_id}-CONTRACT",
            connector_id=connector_id,
            operation="test_contract",
            organization_id="ORG-SYN-001",
            started_at="2026-09-13T00:00:00Z",
            completed_at="2026-09-13T00:00:01Z",
            record_count=len(test_fixtures),
            success_count=1 if test_res["passed"] else 0,
            failure_count=0 if test_res["passed"] else 1,
            error_categories=test_res.get("errors", []),
        )

        return test_res

    def get_readiness(self, connector_id: str) -> ConnectorReadiness:
        """Retrieves production readiness report for connector."""
        conn = self.get_connector(connector_id)
        if not conn:
            raise KeyError(f"Connector '{connector_id}' not found.")
        contract_res = self.test_contract(connector_id)
        return self.harness.assess_readiness(conn, contract_res["passed"])

    def get_errors(self, connector_id: str) -> List[Dict[str, Any]]:
        """Retrieves recent errors for a connector."""
        records = self.audit_logger.list_records(connector_id)
        error_list = []
        for r in records:
            if r.failure_count > 0:
                error_list.append({
                    "audit_id": r.audit_id,
                    "operation": r.operation,
                    "error_categories": r.error_categories,
                    "timestamp": r.completed_at,
                })
        return error_list


# Singleton instance
_connector_service_instance: Optional[ConnectorService] = None


def get_connector_service() -> ConnectorService:
    """Returns singleton ConnectorService."""
    global _connector_service_instance
    if _connector_service_instance is None:
        _connector_service_instance = ConnectorService()
    return _connector_service_instance


def reset_connector_service() -> None:
    """Resets singleton ConnectorService."""
    global _connector_service_instance
    if _connector_service_instance:
        _connector_service_instance.registry.clear()
    _connector_service_instance = None
