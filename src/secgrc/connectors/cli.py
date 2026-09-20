"""Phase 33-A: Production Connector Architecture - CLI Handler (Section 39).

Commands:
    secgrc connector list
    secgrc connector show <connector_id>
    secgrc connector validate <connector_id>
    secgrc connector health <connector_id>
    secgrc connector capabilities <connector_id>
    secgrc connector test-contract <connector_id>
"""

import argparse
import json
import sys
from typing import Any, List

from secgrc.connectors.service import get_connector_service


def _json_out(obj: Any) -> int:
    """Outputs JSON string to stdout and returns status code 0."""
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
    return 0


def handle_connector_cli(args_list: List[str]) -> int:
    """Dispatches connector CLI subcommands."""
    if args_list and args_list[0] == "prowler-gcp":
        from secgrc.connectors.prowler.cli import run_prowler_gcp_cli
        return run_prowler_gcp_cli(args_list[1:])

    parser = argparse.ArgumentParser(prog="secgrc connector", description="Production Connector Architecture CLI")
    subparsers = parser.add_subparsers(dest="subcommand", help="Connector subcommand")

    if not args_list:
        parser.print_help()
        return 0

    # list
    subparsers.add_parser("list", help="List registered connectors")

    # show
    show_p = subparsers.add_parser("show", help="Show connector definition")
    show_p.add_argument("connector_id", help="Connector ID")

    # validate
    val_p = subparsers.add_parser("validate", help="Validate connector registration")
    val_p.add_argument("connector_id", help="Connector ID")

    # health
    hlth_p = subparsers.add_parser("health", help="Check connector health")
    hlth_p.add_argument("connector_id", help="Connector ID")

    # capabilities
    cap_p = subparsers.add_parser("capabilities", help="Inspect connector capabilities")
    cap_p.add_argument("connector_id", help="Connector ID")

    # test-contract
    tst_p = subparsers.add_parser("test-contract", help="Run contract tests against connector")
    tst_p.add_argument("connector_id", help="Connector ID")

    if not args_list:
        parser.print_help()
        return 0

    parsed = parser.parse_args(args_list)
    service = get_connector_service()

    try:
        if parsed.subcommand == "list":
            connectors = service.list_connectors()
            return _json_out({
                "count": len(connectors),
                "connectors": [c.model_dump() for c in connectors],
            })

        cid = getattr(parsed, "connector_id", None)
        if not cid:
            parser.print_help()
            return 1

        if parsed.subcommand == "show":
            conn = service.get_connector(cid)
            if not conn:
                print(f"Error: Connector '{cid}' not found", file=sys.stderr)
                return 1
            return _json_out({
                "definition": conn.describe().model_dump(),
                "status": service.get_status(cid).value,
            })

        if parsed.subcommand == "validate":
            is_valid = service.validate_connector(cid)
            return _json_out({
                "connector_id": cid,
                "is_valid": is_valid,
                "status": "VALID" if is_valid else "INVALID",
            })

        if parsed.subcommand == "health":
            health_record = service.get_health(cid)
            return _json_out(health_record.model_dump())

        if parsed.subcommand == "capabilities":
            caps = service.get_capabilities(cid)
            return _json_out({
                "connector_id": cid,
                "capabilities_count": len(caps),
                "capabilities": caps,
            })

        if parsed.subcommand == "test-contract":
            contract_res = service.test_contract(cid)
            return _json_out(contract_res)

        parser.print_help()
        return 0

    except Exception as ex:
        print(f"Error: {ex}", file=sys.stderr)
        return 1
