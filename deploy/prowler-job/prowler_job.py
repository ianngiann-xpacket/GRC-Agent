"""Cloud Run Job 워커 — Prowler 스캔 실행 후 결과를 GCS로 업로드.

표준 라이브러리만 사용 (prowler 이미지에 추가 pip 의존성 없음).
인증은 Cloud Run 메타데이터 서버의 서비스계정 토큰 — 키 파일 없음.

환경변수:
  PROWLER_RUN_ID   (필수) run-XXXXXXXXXXXX — GCS 업로드 경로 runs/<id>/
  PROWLER_ARGS     (필수) JSON 배열 — 웹 서비스가 검증한 prowler CLI 인자
                   (예: ["gcp","--project-ids","p1","-M","json","-F","results"])
  GCS_BUCKET       (필수) 결과 업로드 버킷
결과:
  gs://<bucket>/runs/<run_id>/ 아래에 prowler 산출물 + _result.json
  _result.json = {exit_code, stdout_tail, stderr_tail, finished_at}
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

META_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/"
    "instance/service-accounts/default/token"
)
OUT_DIR = Path("/tmp/prowler-out")
FORBIDDEN_ARG_CHARS = re.compile(r"[;&|`$<>\\\n\r]")
OUTPUT_FLAGS = ("-o", "--output-directory", "--output-dir")
MAX_TAIL = 8000


def _fail(msg: str) -> None:
    print(f"[prowler-job] FATAL: {msg}", file=sys.stderr)
    sys.exit(2)


def _access_token() -> str:
    req = urllib.request.Request(
        META_TOKEN_URL, headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())["access_token"]


def _sanitize_args(raw_args: list) -> list:
    """출력 경로 플래그는 Job이 소유한 경로로 고정하고 쉘 메타문자를 거부."""
    args = []
    skip_next = False
    for a in raw_args:
        if skip_next:
            skip_next = False
            continue
        if a in OUTPUT_FLAGS:
            skip_next = True
            continue
        if a.startswith("--output-directory=") or a.startswith("--output-dir="):
            continue
        if FORBIDDEN_ARG_CHARS.search(str(a)):
            _fail(f"forbidden character in prowler arg: {a!r}")
        args.append(str(a))
    if not args or args[0] != "gcp":
        _fail("prowler args must start with 'gcp'")
    return args + ["-o", str(OUT_DIR)]


def _upload(bucket: str, run_id: str, path: Path, token: str) -> None:
    name = f"runs/{run_id}/{path.name}"
    url = ("https://storage.googleapis.com/upload/storage/v1/b/"
           f"{bucket}/o?uploadType=media&name={urllib.parse.quote(name, safe='')}")
    req = urllib.request.Request(
        url, data=path.read_bytes(), method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        resp.read()


def main() -> int:
    run_id = os.environ.get("PROWLER_RUN_ID", "")
    bucket = os.environ.get("GCS_BUCKET", "")
    raw_args = os.environ.get("PROWLER_ARGS", "")
    if not re.fullmatch(r"run-[A-Za-z0-9_-]{4,60}", run_id):
        _fail(f"invalid PROWLER_RUN_ID: {run_id!r}")
    if not bucket:
        _fail("GCS_BUCKET env is required")
    try:
        args = _sanitize_args(json.loads(raw_args))
    except (json.JSONDecodeError, TypeError):
        _fail("PROWLER_ARGS must be a JSON array of strings")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[prowler-job] run={run_id} bucket={bucket}")
    print(f"[prowler-job] argv: prowler {' '.join(args)}")

    proc = subprocess.run(
        ["prowler", *args], capture_output=True, text=True, check=False)
    exit_code = proc.returncode
    print(proc.stdout[-MAX_TAIL:])
    print(proc.stderr[-MAX_TAIL:], file=sys.stderr)

    token = _access_token()
    files = sorted(p for p in OUT_DIR.rglob("*") if p.is_file())
    for f in files:
        _upload(bucket, run_id, f, token)
        print(f"[prowler-job] uploaded {f.name}")

    result = {
        "exit_code": exit_code,
        "stdout_tail": proc.stdout[-MAX_TAIL:],
        "stderr_tail": proc.stderr[-MAX_TAIL:],
        "files": [f.name for f in files],
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    tmp = OUT_DIR / "_result.json"
    tmp.write_text(json.dumps(result), encoding="utf-8")
    _upload(bucket, run_id, tmp, token)
    print(f"[prowler-job] done exit={exit_code} files={len(files)}")
    return 0  # 실제 스캔 결과는 _result.json으로 전달 — Job 자체는 업로드 성공이면 0


if __name__ == "__main__":
    sys.exit(main())
