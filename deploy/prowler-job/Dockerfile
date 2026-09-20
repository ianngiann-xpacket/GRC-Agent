# Cloud Run Job용 Prowler 워커 이미지.
# 웹 서비스의 ProwlerRuntimeConfig.image와 동일 digest로 고정 — 실행 환경 일치 보장.
FROM prowlercloud/prowler@sha256:863beb094d8e526ffbbf8286d6f2a526db9455e173e1e99c2ea2802c637c7805

COPY prowler_job.py /app/prowler_job.py

# prowler 이미지는 python:3.12 계열 — 표준 라이브러리만 사용, 추가 의존성 없음.
# entrypoint를 덮어써서 GCS 업로드 래퍼가 prowler CLI를 대신 호출한다.
ENTRYPOINT ["python", "/app/prowler_job.py"]
