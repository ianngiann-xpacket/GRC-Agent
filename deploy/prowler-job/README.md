# Cloud Run Prowler 스캔 배포 가이드

GRC Agent를 Cloud Run에서 운용할 때 라이브 Prowler 스캔을 가능하게 하는 구성입니다.
Cloud Run 서비스는 컨테이너-in-컨테이너를 실행할 수 없으므로, 웹 서비스가
**Cloud Run Job**을 트리거하고 결과를 **GCS 버킷**에서 회수합니다.

```
[GRC Agent 웹 서비스]                [Cloud Run Job: prowler-scan]
 jobs:run API (SA 인증)  ────────→   prowler gcp 읽기전용 스캔
        ↑                                   │
        └──── gs://<bucket>/runs/<id>/ ←── 결과 JSON + _result.json
              ↓ 정규화 → 원장 → 보고서
```

## Cloud Shell 배포 절차

```bash
# 0) 변수 설정
PROJECT=$(gcloud config get-value project)   # GRC Agent 배포 프로젝트
REGION=asia-northeast3                        # 배포 리전
TARGET_PROJECT=<스캔 대상 GCP 프로젝트 ID>     # prowler가 진단할 프로젝트
BUCKET=${PROJECT}-prowler-artifacts

# 1) 소스 최신화
git clone https://github.com/ianngiann-xpacket/GRC-Agent.git 2>/dev/null || true
cd GRC-Agent && git fetch && git reset --hard origin/main

# 2) 웹 서비스 배포 (기존 절차)
gcloud run deploy grc-agent --source . --region $REGION --allow-unauthenticated

# 3) 결과 버킷 생성
gcloud storage buckets create gs://$BUCKET --location=$REGION \
  --uniform-bucket-level-access

# 4) Job용 서비스계정 (스캔 대상 읽기 + 버킷 쓰기)
gcloud iam service-accounts create prowler-scan-sa \
  --display-name "Prowler scan worker"
SA=prowler-scan-sa@${PROJECT}.iam.gserviceaccount.com

# 스캔 대상 프로젝트에 읽기 권한 (Prowler 요구 최소 권한)
gcloud projects add-iam-policy-binding $TARGET_PROJECT \
  --member=serviceAccount:$SA --role=roles/viewer
gcloud projects add-iam-policy-binding $TARGET_PROJECT \
  --member=serviceAccount:$SA --role=roles/iam.securityReviewer

# 결과 버킷 쓰기 권한
gcloud storage buckets add-iam-policy-binding gs://$BUCKET \
  --member=serviceAccount:$SA --role=roles/storage.objectAdmin

# 5) Job 이미지 빌드 + Job 생성
gcloud builds submit --tag gcr.io/$PROJECT/prowler-job deploy/prowler-job

gcloud run jobs create prowler-scan \
  --image gcr.io/$PROJECT/prowler-job \
  --region $REGION \
  --service-account $SA \
  --cpu 2 --memory 2Gi --task-timeout 30m --max-retries 0

# 6) 웹 서비스 SA에 권한 부여
WEB_SA=$(gcloud run services describe grc-agent --region $REGION \
  --format='value(spec.template.spec.serviceAccountName)')
WEB_SA=${WEB_SA:-${PROJECT}@appspot.gserviceaccount.com}

gcloud run jobs add-iam-policy-binding prowler-scan --region $REGION \
  --member=serviceAccount:$WEB_SA --role=roles/run.invoker
gcloud storage buckets add-iam-policy-binding gs://$BUCKET \
  --member=serviceAccount:$WEB_SA --role=roles/storage.objectViewer

# 7) 웹 서비스에 실행 모드 설정
gcloud run services update grc-agent --region $REGION --set-env-vars \
  PROWLER_EXECUTION_MODE=cloudrun,\
PROWLER_JOB_NAME=prowler-scan,\
PROWLER_JOB_REGION=$REGION,\
PROWLER_JOB_PROJECT=$PROJECT,\
PROWLER_GCS_BUCKET=$BUCKET
```

## 동작 확인

`/collection` → Prowler 패널 배지가 `실행 방식: Cloud Run Job` + `라이브 스캔: 실행 가능`으로
표시되면 준비 완료. 프로젝트 ID + 서비스(예: `iam`) 입력 → 스캔 실행.

## 보안 구조

- 웹 서비스는 Job을 *트리거*만 하고 스캔 자격증명을 보유하지 않음
- Job SA는 스캔 대상에 `viewer`+`securityReviewer`(읽기 전용)만 보유
- PROWLER_ARGS는 웹 측 `ProwlerCommandBuilder` 검증 + Job 측 쉘 메타문자 재검증
- 결과 경로는 `runs/<run_id>/`로 격리 — run_id 형식 서버 검증
