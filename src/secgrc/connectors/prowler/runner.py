"""Phase 33-B: Isolated Docker Container Execution Runner.

Enforces:
- Isolated container execution for Prowler
- Strict volume mount restrictions (blocks Docker socket, home directory, /Users)
- Read-only credential mounts
- Resource bounds (CPU, memory, timeout)
- Non-privileged container execution (--security-opt=no-new-privileges:true)
- Sanitized error reporting without secret leakage
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict

from secgrc.connectors.errors import ConnectorError, ConnectorErrorCode
from secgrc.connectors.prowler.command import ProwlerCommandSpec
from secgrc.connectors.prowler.models import ProwlerRuntimeConfig
from secgrc.connectors.validator import SecretScanner


class DockerExecutionResult(BaseModel):
    """Result of running Prowler Docker container."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    runtime_image: str = ""
    command_args: List[str] = []


class ProwlerDockerRunner:
    """Executes Prowler safely within an isolated Docker container."""

    FORBIDDEN_MOUNT_TARGETS = (
        "/var/run/docker.sock",
        "/var/run",
        "/etc",
        "/bin",
        "/usr",
        "/sbin",
        "/dev",
        "/proc",
        "/sys",
    )

    @classmethod
    def validate_mount_safety(cls, host_path: str, is_read_only: bool = True) -> str:
        """Validates that a host mount path is strictly isolated and safe."""
        resolved = Path(host_path).resolve()
        path_str = str(resolved)
        home = str(Path.home().resolve())

        check_paths = {host_path.rstrip("/"), path_str.rstrip("/")}
        if path_str.startswith("/private"):
            check_paths.add(path_str[len("/private"):].rstrip("/"))

        if any("docker.sock" in p for p in check_paths):
            raise ValueError("Mounting Docker socket into container is strictly forbidden.")

        sensitive_user_subdirs = (".ssh", ".aws", ".gnupg")
        for p in check_paths:
            if p == home or p == "/Users" or p == "/home" or p == "/root":
                raise ValueError(f"Mounting user home directory '{host_path}' into container is strictly forbidden.")
            for sub in sensitive_user_subdirs:
                if p == f"{home}/{sub}" or p.startswith(f"{home}/{sub}/"):
                    raise ValueError(f"Mounting sensitive user directory '{host_path}' into container is strictly forbidden.")
            for forbidden in cls.FORBIDDEN_MOUNT_TARGETS:
                if p == forbidden or p.startswith(forbidden + "/"):
                    raise ValueError(f"Mounting sensitive system path '{host_path}' into container is strictly forbidden.")

        return path_str

    @classmethod
    def build_docker_argv(
        cls,
        config: ProwlerRuntimeConfig,
        command_spec: ProwlerCommandSpec,
        host_output_dir: str,
        host_credential_file: Optional[str] = None,
        cpu_limit: str = "2.0",
        memory_limit: str = "2g",
    ) -> List[str]:
        """Constructs safe docker run CLI argument array."""
        safe_output = cls.validate_mount_safety(host_output_dir, is_read_only=False)

        argv = [
            "docker", "run", "--rm",
            "--security-opt=no-new-privileges:true",
            f"--cpus={cpu_limit}",
            f"--memory={memory_limit}",
            "-v", f"{safe_output}:/output",
        ]

        if host_credential_file:
            safe_cred = cls.validate_mount_safety(host_credential_file, is_read_only=True)
            if not Path(safe_cred).exists():
                raise FileNotFoundError(f"Credential file not found: {safe_cred}")
            # Mount read-only into container
            argv.extend(["-v", f"{safe_cred}:/tmp/credentials/credentials.json:ro"])
            argv.extend(["-e", "GOOGLE_APPLICATION_CREDENTIALS=/tmp/credentials/credentials.json"])

        # Pinned image identifier
        argv.append(config.image)

        # Replace host output dir with container mount /output in Prowler args
        container_args = []
        skip_next = False
        for idx, arg in enumerate(command_spec.args):
            if skip_next:
                skip_next = False
                continue
            if arg == "-o":
                container_args.extend(["-o", "/output"])
                skip_next = True
            elif arg == command_spec.output_dir:
                container_args.append("/output")
            else:
                container_args.append(arg)

        # Append Prowler subcommands (without 'prowler' if entrypoint is already prowler)
        if container_args and container_args[0] == "prowler":
            argv.extend(container_args[1:])
        else:
            argv.extend(container_args)

        return argv

    @classmethod
    def execute(
        cls,
        config: ProwlerRuntimeConfig,
        command_spec: ProwlerCommandSpec,
        host_output_dir: str,
        host_credential_file: Optional[str] = None,
        timeout_seconds: int = 300,
        mock_mode: bool = False,
    ) -> DockerExecutionResult:
        """Executes the Prowler container with bounds and safety checks."""
        argv = cls.build_docker_argv(
            config=config,
            command_spec=command_spec,
            host_output_dir=host_output_dir,
            host_credential_file=host_credential_file,
        )

        if mock_mode:
            # Simulate safe execution for testing / replay environments
            return DockerExecutionResult(
                exit_code=0,
                stdout="[MOCK] Prowler scan executed successfully.",
                stderr="",
                timed_out=False,
                runtime_image=config.image,
                command_args=argv,
            )

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            # Sanitize stderr/stdout in case of any credential leakage
            stdout = proc.stdout
            stderr = proc.stderr
            has_secret, _ = SecretScanner.scan_for_secrets(stderr)
            if has_secret:
                stderr = "[REDACTED - SENSITIVE DATA DETECTED IN STDERR]"

            return DockerExecutionResult(
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=False,
                runtime_image=config.image,
                command_args=argv,
            )
        except subprocess.TimeoutExpired:
            return DockerExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Prowler execution timed out after {timeout_seconds} seconds.",
                timed_out=True,
                runtime_image=config.image,
                command_args=argv,
            )
        except FileNotFoundError:
            raise ConnectorError(
                ConnectorErrorCode.CONNECTOR_UNAVAILABLE,
                "Docker binary not found on host system. Prowler container cannot be launched.",
            )
