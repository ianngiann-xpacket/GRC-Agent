"""Cloud Run Job 기반 Prowler 실행 러너 — GCP 배포 환경용.

Cloud Run 서비스는 컨테이너-in-컨테이너가 불가하므로, 별도 Cloud Run Job
(deploy/prowler-job 이미지)을 실행하고 결과를 GCS에서 회수한다.

흐름:
  1) jobs:run API로 실행 — PROWLER_RUN_ID/PROWLER_ARGS/GCS_BUCKET env 주입
  2) executions.get 폴링으로 완료 대기
  3) gs://<bucket>/runs/<run_id>/ 의 산출물을 host_output_dir로 다운로드
  4) _result.json의 exit_code/stderr를 DockerExecutionResult로 반환

필요한 환경변수 (PROWLER_EXECUTION_MODE=cloudrun 일 때):
  PROWLER_JOB_NAME     Cloud Run Job 이름
  PROWLER_JOB_REGION   Job 리전 (예: asia-northeast3)
  PROWLER_JOB_PROJECT  Job이 속한 GCP 프로젝트 (기본: GOOGLE_CLOUD_PROJECT/ADC 프로젝트)
  PROWLER_GCS_BUCKET   산출물 버킷
인증: google.auth.default() — Cloud Run 서비스계정 (키 파일 불필요)
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
from pathlib import Path
from typing import List, Optional

import requests
from google.auth import default as google_auth_default
from google.auth.transport.requests import AuthorizedSession

from secgrc.connectors.prowler.command import ProwlerCommandSpec
from secgrc.connectors.prowler.models import ProwlerRuntimeConfig
from secgrc.connectors.prowler.runner import DockerExecutionResult
from secgrc.connectors.validator import SecretScanner

GCS_API = "https://storage.googleapis.com/storage/v1"
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class ProwlerCloudRunJobRunner:
    """Cloud Run Job으로 Prowler를 실행하고 GCS에서 산출물을 회수한다."""

    @staticmethod
    def _env(name: str, required: bool = True) -> str:
        v = os.environ.get(name, "").strip()
        if required and not v:
            raise RuntimeError(f"{name} 환경변수가 설정되지 않았습니다 — Cloud Run Job 실행 불가")
        return v

    @classmethod
    def configured(cls) -> bool:
        return bool(
            os.environ.get("PROWLER_EXECUTION_MODE", "").lower() == "cloudrun"
            and os.environ.get("PROWLER_JOB_NAME")
            and os.environ.get("PROWLER_JOB_REGION")
            and os.environ.get("PROWLER_GCS_BUCKET")
        )

    @classmethod
    def _session(cls) -> AuthorizedSession:
        creds, _ = google_auth_default(scopes=SCOPES)
        return AuthorizedSession(creds)

    @classmethod
    def _submit(cls, session: AuthorizedSession, args: List[str],
                run_id: str, bucket: str) -> str:
        region = cls._env("PROWLER_JOB_REGION")
        project = cls._env("PROWLER_JOB_PROJECT", required=False) \
            or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        job = cls._env("PROWLER_JOB_NAME")
        if not project:
            raise RuntimeError(
                "PROWLER_JOB_PROJECT/GOOGLE_CLOUD_PROJECT 미설정 — Job 프로젝트를 알 수 없습니다")
        url = (f"https://{region}-run.googleapis.com/apis/run.googleapis.com/v1/"
               f"namespaces/{project}/jobs/{job}:run")
        body = {"overrides": {"containerOverrides": [{"env": [
            {"name": "PROWLER_RUN_ID", "value": run_id},
            {"name": "PROWLER_ARGS", "value": json.dumps(args)},
            {"name": "GCS_BUCKET", "value": bucket},
        ]}]}}
        resp = session.post(url, json=body, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"Cloud Run Job 실행 요청 실패 ({resp.status_code}): {resp.text[:400]}")
        return resp.json()["name"]  # namespaces/{p}/executions/{exec}

    @classmethod
    def _wait(cls, session: AuthorizedSession, exec_name: str,
              timeout_seconds: int) -> dict:
        region = cls._env("PROWLER_JOB_REGION")
        url = (f"https://{region}-run.googleapis.com/apis/run.googleapis.com/v1/"
               f"{exec_name}")
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            resp = session.get(url, timeout=30)
            if resp.status_code != 200:
                raise RuntimeError(f"실행 상태 조회 실패 ({resp.status_code}): {resp.text[:300]}")
            conds = (resp.json().get("status") or {}).get("conditions") or []
            for c in conds:
                if c.get("type") == "Completed" and c.get("status") == "True":
                    return resp.json()
                if c.get("status") == "True" and c.get("type") in (
                        "Failed", "RetryableFailure"):
                    return resp.json()
            time.sleep(8)
        raise TimeoutError(f"Cloud Run Job 실행이 {timeout_seconds}초 내 완료되지 않았습니다")

    @classmethod
    def _fetch_outputs(cls, session: AuthorizedSession, run_id: str,
                       bucket: str, dest_dir: str) -> dict:
        prefix = f"runs/{run_id}/"
        url = (f"{GCS_API}/b/{bucket}/o?prefix={urllib.parse.quote(prefix, safe='')}"
               "&fields=items(name)")
        resp = session.get(url, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"GCS 목록 조회 실패 ({resp.status_code}): {resp.text[:300]}")
        names = [i["name"] for i in resp.json().get("items", [])]
        result_meta: dict = {}
        for name in names:
            obj = urllib.parse.quote(name, safe="")
            dl = session.get(f"{GCS_API}/b/{bucket}/o/{obj}?alt=media", timeout=120)
            if dl.status_code != 200:
                continue
            fname = name.rsplit("/", 1)[-1]
            if fname == "_result.json":
                result_meta = json.loads(dl.content.decode("utf-8", "replace"))
            elif fname:
                Path(dest_dir, fname).write_bytes(dl.content)
        return result_meta

    @classmethod
    def execute(
        cls,
        config: ProwlerRuntimeConfig,
        command_spec: ProwlerCommandSpec,
        run_id: str,
        host_output_dir: str,
        timeout_seconds: int = 1800,
    ) -> DockerExecutionResult:
        """Cloud Run Job 실행 → GCS 산출물 회수 → DockerExecutionResult 반환."""
        bucket = cls._env("PROWLER_GCS_BUCKET")
        args = list(command_spec.args)
        if args and args[0] == "prowler":
            args = args[1:]

        session = cls._session()
        exec_name = cls._submit(session, args, run_id, bucket)
        try:
            exec_doc = cls._wait(session, exec_name, timeout_seconds)
        except TimeoutError as e:
            return DockerExecutionResult(
                exit_code=124, stdout="", stderr=str(e), timed_out=True,
                runtime_image=config.image,
                command_args=["cloud-run-job", exec_name],
            )

        fail_msg = ""
        for c in (exec_doc.get("status") or {}).get("conditions") or []:
            if c.get("status") == "True" and c.get("type") != "Completed":
                fail_msg = c.get("message") or c.get("reason") or c.get("type", "")

        meta = cls._fetch_outputs(session, run_id, bucket, host_output_dir)
        if not meta:
            detail = f"Job 실행됐으나 GCS 산출물 없음 (gs://{bucket}/runs/{run_id}/)"
            if fail_msg:
                detail = f"{detail} — 실행 실패: {fail_msg[:300]}"
            return DockerExecutionResult(
                exit_code=125, stdout="", stderr=detail,
                timed_out=False, runtime_image=config.image,
                command_args=["cloud-run-job", exec_name],
            )

        stderr = meta.get("stderr_tail", "")
        has_secret, _ = SecretScanner.scan_for_secrets(stderr)
        if has_secret:
            stderr = "[REDACTED - SENSITIVE DATA DETECTED IN STDERR]"

        return DockerExecutionResult(
            exit_code=int(meta.get("exit_code", 1)),
            stdout=meta.get("stdout_tail", ""),
            stderr=stderr,
            timed_out=False,
            runtime_image=config.image,
            command_args=["cloud-run-job", exec_name],
        )
