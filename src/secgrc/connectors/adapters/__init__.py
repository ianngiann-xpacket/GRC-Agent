"""Phase 33-A: Connector Adapters Package.

Contains contract adapters and mocks for testing the connector architecture.
Product-specific adapters (Prowler, Wiz, Entra, Splunk) will be implemented in future phases.
"""

from secgrc.connectors.adapters.mock_contract import ContractMockAdapter

__all__ = ["ContractMockAdapter"]
