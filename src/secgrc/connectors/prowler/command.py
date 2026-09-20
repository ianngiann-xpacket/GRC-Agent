"""Phase 33-B: Deterministic Prowler GCP Command Construction.

Constructs validated subprocess argument arrays for Prowler execution.
Enforces:
- Pure read-only execution (strictly blocks remediation / write options)
- Rejection of shell metacharacters and arbitrary shell strings
- Explicit project scoping (--project-id)
- Subprocess argument array generation without shell=True
"""

from __future__ import annotations

import re
from typing import List, Optional
from pydantic import BaseModel, ConfigDict

from secgrc.connectors.models import compute_canonical_hash
from secgrc.connectors.prowler.models import ProwlerGcpTarget, ProwlerRuntimeConfig

DANGEROUS_SHELL_CHARS = re.compile(r"[;`|&$><\n\r]")
FORBIDDEN_FLAGS = (
    "--remediation", "--remediate", "--fix", "--auto-fix",
    "--mutate", "--delete", "--update", "--create", "--write"
)


class ProwlerCommandSpec(BaseModel):
    """Validated specification of an executable Prowler command."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    args: List[str]
    command_hash: str
    target_projects: List[str]
    output_format: str
    output_dir: str


class ProwlerCommandBuilder:
    """Builds deterministic, safe CLI argument lists for Prowler GCP."""

    @staticmethod
    def build_command(
        config: ProwlerRuntimeConfig,
        target: ProwlerGcpTarget,
        output_dir: str,
        output_filename: str = "results",
        services: Optional[List[str]] = None,
        checks: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
    ) -> ProwlerCommandSpec:
        """Constructs a validated argument array for Prowler container execution."""
        # 1. Validate target projects exist
        if not target.gcp_project_ids:
            raise ValueError("Target must specify at least one GCP project ID. Implicit scanning forbidden.")

        # 2. Check for dangerous characters in all inputs
        all_inputs = list(target.gcp_project_ids) + [output_dir, output_filename]
        if services:
            all_inputs.extend(services)
        if checks:
            all_inputs.extend(checks)
        if severities:
            all_inputs.extend(severities)

        for inp in all_inputs:
            if DANGEROUS_SHELL_CHARS.search(inp):
                raise ValueError(f"Dangerous shell character detected in input '{inp}'. Command execution blocked.")
            for f in FORBIDDEN_FLAGS:
                if f in inp.lower():
                    raise ValueError(f"Forbidden write/remediation flag '{f}' detected. Operation blocked.")

        # 3. Build argument list starting with 'prowler gcp'
        # Inside container, prowler is the entrypoint or command
        args = ["prowler", "gcp"]

        # Add projects
        args.append("--project-ids")
        args.extend(sorted(target.gcp_project_ids))

        # Output format (Prowler v5 uses json-ocsf/html, v4 uses json/html)
        is_v5 = config.version.startswith("5") or "5." in config.image
        out_fmt = config.output_format.lower()
        if is_v5:
            format_name = "json-ocsf" if out_fmt in ("json", "json-ocsf") else out_fmt
            args.extend(["-M", format_name, "html"])
        else:
            if out_fmt == "json-ocsf":
                args.extend(["-M", "json-ocsf", "html"])
            else:
                args.extend(["-M", "json", "html"])

        # Output directory & filename
        args.extend(["-o", output_dir, "--output-filename", output_filename])

        # Optional filters
        if services:
            args.append("--services")
            args.extend(sorted(services))
        if checks:
            args.append("--checks")
            args.extend(sorted(checks))
        if severities:
            args.append("--severities")
            args.extend(sorted(severities))

        # Non-interactive / quiet flags
        args.append("--no-banner")

        command_hash = compute_canonical_hash(args)

        return ProwlerCommandSpec(
            args=args,
            command_hash=command_hash,
            target_projects=sorted(target.gcp_project_ids),
            output_format=out_fmt,
            output_dir=output_dir,
        )
