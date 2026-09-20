# GRC Agent — 개발 워크플로우

## 표준 변경 절차 (사용자 지정 순서)

1. **맥북에서 코드 수정** — 로컬 저장소 `/Users/taesunhwang/GRC Agent`
2. **로컬호스트 확인** — 로컬 서버에서 웹화면으로 직접 검증
   - 실행: `PYTHONPATH=src GRC_WEB_AUTH=disabled python3 -m secgrc web-cert --host 127.0.0.1 --port 8001`
   - 기존 프로세스가 포트를 점유하면 PID 확인 후 종료하고 재기동
3. **원격 commit (GitHub)** — 로컬 `main` 커밋 후 스냅샷 클론에 반영
   - 로컬: `git add -A && git commit`
   - 스냅샷: `/tmp/grc-remote` (HTTPS clone, v2 배포용 히스토리 — 해시가 로컬과 다름)
   - `git -C /tmp/grc-remote fetch origin && git -C /tmp/grc-remote reset --hard origin/main`
   - 변경 파일만 복사 → 동일 메시지로 커밋 → `git -C /tmp/grc-remote push origin main`
   - 원격 트리는 `data/`, `tools/`, `run_ui.sh`를 제외한 배포 산출물
4. **Cloud Shell을 통한 배포** — 사용자가 Cloud Shell에서 직접 실행
   ```bash
   cd ~/GRC-Agent/GRC-Agent
   git fetch origin && git reset --hard origin/main
   gcloud run deploy grc-agent --source . --region asia-northeast3 \
     --allow-unauthenticated \
     --set-env-vars "GRC_WEB_AUTH=required,GRC_WEB_USERNAME=admin" \
     --set-secrets "GRC_WEB_PASSWORD=web-password:latest,GEMINI_API_KEY=gemini-key:latest" \
     --memory 1Gi --cpu 1 --max-instances 2
   ```

> 맥북에는 gcloud CLI가 없음 — 배포는 항상 Cloud Shell 경유. 로컬에서 배포하지 않는다.

## 검증 명령

- 테스트: `PYTHONPATH=src python3 -m unittest tests.test_assurance_api -v` (15개)
- JS 문법: `node --check src/secgrc/web/static/certification/*.js`
- Python AST: `python3 -c "import ast; ast.parse(open('파일').read())"`

## 제품 구조

- 활성 제품: ISMS-P 인증심사 콘솔 (v2) — `templates_certification/` + `certification_routes.py`
- 컨텍스트 파라미터 `audit`/`date`는 모든 내부 내비게이션에서 `AS.url()`로 보존
- 업로드 API: `control_id`=쿼리 파라미터, 파일명=`X-File-Name` 헤더, `X-Evidence-Upload: 1` 필수
