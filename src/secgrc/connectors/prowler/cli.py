"""Phase 33-B: Prowler GCP Connector CLI Dispatcher.

Handles:
secgrc connector prowler-gcp [validate|plan|run|import|normalize|validate-run|report|replay]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from secgrc.connectors.prowler.models import (
    ExecutionMode,
    GcpCredentialReference,
    ProwlerGcpTarget,
    ProwlerRuntimeConfig,
)
from secgrc.connectors.prowler.service import get_prowler_service


def build_prowler_gcp_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secgrc connector prowler-gcp",
        description="Prowler GCP Production Connector CLI",
    )
    sub = parser.add_subparsers(dest="prowler_action", help="Prowler GCP Action")

    # validate
    p_val = sub.add_parser("validate", help="Validate runtime & auth configuration")
    p_val.add_argument("--image", default="ghcr.io/prowler-cloud/prowler:4.3.0")
    p_val.add_argument("--version", default="4.3.0")

    # plan
    p_plan = sub.add_parser("plan", help="Display execution plan without scanning")
    p_plan.add_argument("--project", default="gcp-prod-kr-001", help="Target GCP project ID")
    p_plan.add_argument("--org", default="ORG-REAL-001", help="Organization ID")

    # run
    p_run = sub.add_parser("run", help="Run Prowler GCP scan")
    p_run.add_argument("--project", required=True, help="Target GCP project ID")
    p_run.add_argument("--org", default="ORG-REAL-001", help="Organization ID")
    p_run.add_argument("--fixture", help="Optional fixture file for mock/test execution")
    p_run.add_argument("--mock", action="store_true", help="Simulate container execution")
    p_run.add_argument("--image", default="toniblyx/prowler:5.42.0", help="Prowler Docker image")
    p_run.add_argument("--version", default="5.42.0", help="Prowler version")

    # import
    p_imp = sub.add_parser("import", help="Import raw Prowler JSON file")
    p_imp.add_argument("--file", required=True, help="Raw Prowler JSON file path")
    p_imp.add_argument("--project", default="gcp-prod-kr-001")
    p_imp.add_argument("--org", default="ORG-REAL-001")

    # normalize
    p_norm = sub.add_parser("normalize", help="Normalize existing run")
    p_norm.add_argument("--run", required=True, help="Run ID")

    # validate-run
    p_vr = sub.add_parser("validate-run", help="Validate run artifacts and hashes")
    p_vr.add_argument("--run", required=True, help="Run ID")

    # report
    p_rep = sub.add_parser("report", help="Generate inspection report for run")
    p_rep.add_argument("--run", required=True, help="Run ID")

    # replay
    p_rep2 = sub.add_parser("replay", help="Replay normalization from raw file without GCP call")
    p_rep2.add_argument("--file", required=True, help="Raw Prowler JSON file path")
    p_rep2.add_argument("--project", default="gcp-prod-kr-001")
    p_rep2.add_argument("--org", default="ORG-REAL-001")

    # upload-gcs
    p_up = sub.add_parser("upload-gcs", help="Upload run artifacts to GCS bucket")
    p_up.add_argument("--bucket", required=True, help="Target GCS bucket name (e.g. grc-prowler-reports-...)")
    p_up.add_argument("--run", default=None, help="Run ID to upload (default: all runs)")

    return parser


def run_prowler_gcp_cli(args: Optional[List[str]] = None) -> int:
    parser = build_prowler_gcp_parser()
    parsed = parser.parse_args(args)
    service = get_prowler_service()

    if not parsed.prowler_action:
        parser.print_help()
        return 1

    try:
        config = ProwlerRuntimeConfig()

        if parsed.prowler_action == "validate":
            target = ProwlerGcpTarget(
                organization_id="ORG-REAL-001",
                tenant_id="ORG-REAL-001",
                gcp_project_ids=["gcp-prod-kr-001"],
                credential_ref=GcpCredentialReference(credential_ref_id="cred-adc", auth_mode="ADC"),
            )
            res = service.dry_run(config, target)
            print(json.dumps(res, indent=2))
            return 0

        elif parsed.prowler_action == "plan":
            target = ProwlerGcpTarget(
                organization_id=parsed.org,
                tenant_id=parsed.org,
                gcp_project_ids=[parsed.project],
                credential_ref=GcpCredentialReference(credential_ref_id="cred-adc", auth_mode="ADC"),
            )
            res = service.plan_run(config, target)
            print(json.dumps(res, indent=2))
            return 0

        elif parsed.prowler_action == "run":
            config = ProwlerRuntimeConfig(
                image=parsed.image or "toniblyx/prowler:5.42.0",
                version=parsed.version or "5.42.0",
            )
            target = ProwlerGcpTarget(
                organization_id=parsed.org,
                tenant_id=parsed.org,
                gcp_project_ids=[parsed.project],
                credential_ref=GcpCredentialReference(credential_ref_id="cred-adc", auth_mode="ADC"),
            )
            run = service.execute_scan(
                config=config,
                target=target,
                mock_docker=parsed.mock or bool(parsed.fixture),
                mock_output_fixture=parsed.fixture,
            )
            print(json.dumps(run.model_dump(), indent=2, default=str))

            raw_dir = Path("data/prowler/raw") / run.run_id
            html_reports = list(raw_dir.rglob("*.html"))
            if html_reports:
                print(f"\n[HTML Report Available] File: {html_reports[0]}")
            return 0

        elif parsed.prowler_action == "import" or parsed.prowler_action == "replay":
            target = ProwlerGcpTarget(
                organization_id=parsed.org,
                tenant_id=parsed.org,
                gcp_project_ids=[parsed.project],
                credential_ref=GcpCredentialReference(credential_ref_id="cred-adc", auth_mode="ADC"),
            )
            run = service.replay(raw_file_path=parsed.file, target=target)
            print(json.dumps(run.model_dump(), indent=2, default=str))
            return 0

        elif parsed.prowler_action == "report":
            rep = service.get_run_report(parsed.run)
            print(json.dumps(rep, indent=2, default=str))
            return 0

        elif parsed.prowler_action == "validate-run":
            run = service.get_run(parsed.run)
            if not run:
                print(f"Error: Run '{parsed.run}' not found.", file=sys.stderr)
                return 1
            manifest = service.get_manifest(parsed.run)
            result = {
                "run_id": run.run_id,
                "status": run.status,
                "valid": manifest is not None and len(manifest.manifest_hash) == 64,
                "manifest_hash": manifest.manifest_hash if manifest else "",
                "raw_output_hash": run.raw_output_hash,
            }
            print(json.dumps(result, indent=2))
            return 0

        elif parsed.prowler_action == "upload-gcs":
            uploaded = service.upload_to_gcs(
                bucket_name=parsed.bucket,
                run_id=getattr(parsed, "run", None),
            )
            print(json.dumps({
                "bucket": parsed.bucket,
                "uploaded_count": len(uploaded),
                "files": uploaded,
            }, indent=2))
            return 0

        elif parsed.prowler_action == "normalize":
            run = service.get_run(parsed.run)
            if not run:
                print(f"Error: Run '{parsed.run}' not found.", file=sys.stderr)
                return 1
            records = service.get_canonical_records(parsed.run)
            print(json.dumps({"run_id": run.run_id, "normalized_count": len(records)}, indent=2))
            return 0

    except Exception as ex:
        print(f"Error executing prowler-gcp command: {ex}", file=sys.stderr)
        return 1

    return 0
