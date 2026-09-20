# ISMS-P Dynamic Audit Assurance UI — Implementation Note

## 1. 현재 프론트엔드 아키텍처

| 항목 | 현황 |
|------|------|
| 프레임워크 | FastAPI + Jinja2 서버 렌더링 (React/Vue 등 SPA 없음, 빌드 파이프라인 없음) |
| v1 콘솔 | `secgrc.web.app` (포트 8000) — 광범위 GRC 콘솔, `routes.py` + `templates/` |
| v2 콘솔 | `secgrc.web.certification_app` (포트 8001) — 인증심사 전용, `certification_routes.py` + `templates_certification/` |
| 인증 | `secgrc.web.auth` — `GRC_WEB_AUTH=auto|required|disabled`, 로컬호스트 auto 면제 |
| 보안 | SecurityHeadersMiddleware (CSP), AuthMiddleware, 민감정보 마스킹 |
| 테스트 | pytest 미설치 → `unittest` + `httpx` 기반 FastAPI `TestClient` 사용 |

## 2. 재사용 대상

### 백엔드 엔진 (source of truth — 변경 금지)
- `control_engine.engine.ControlEngine` — 통제 정의 (16개 로드, `isms_p_controls.json`)
- `evidence.ledger.EvidenceLedger` — 불변 증적 원장, 해시체인
- `reconciliation.engine.ReconciliationEngine` — 정책↔설정/요구↔증적/범위↔자산 대사
- `audit_workspace.workspace.AuditWorkspace` — 심사 세션, 표본 요청
- `audit_findings.manager.AuditFindingsManager` — 결함 생명주기 (12개 필드, 6가지 조치)
- `gap_analysis.engine.GapAnalysisEngine` — GAP/준비도 평가
- `certification.workflow.CertificationAuditWorkflow` — 심사 단계/유형/등급
- `certification_view._seed_demo_data()` — 기존 데모 시드 재사용

### v2에서 새로 만드는 것
- `secgrc.web.assurance_data` — **typed mock/service 계층**. 프론트가 소비하는 유일한 인터페이스.
  실제 엔진 데이터 + 결정론적 합성 데이터(타임라인 스냅샷, 리플레이 시나리오, 활동 스트림, 어시스턴트)를 하나의 계약으로 제공. 모든 합성 데이터에 `demo: true` 표기.
- `static/certification/` — vanilla JS 모듈 (빌드 도구 없이 `<script src>` 로드)

## 3. 신규 API 계약 (UI 전용, `/api/audit/...`)

| Endpoint | 용도 | 근거 |
|----------|------|------|
| `GET /api/audit/context` | 현재 심사 컨텍스트(ID/유형/등급/D-day) | workflow |
| `GET /api/audit/kpis` | KPI 5종 | gap+ledger+findings |
| `GET /api/audit/landscape` | 도메인→통제 트리 + 상태 집계 | control_engine + 합성 상태 |
| `GET /api/audit/controls/{id}` | 통제 상세 + 증적 체인 | control+ledger+recon+findings |
| `GET /api/audit/gaps` | GAP 목록/필터 | gap+recon |
| `GET /api/audit/findings` | 지적사항+생명주기 | findings_manager |
| `GET /api/audit/population` | 범위/모집단 지표 | 합성(demo) |
| `GET /api/audit/trend` | 시계열 차트 데이터 | 합성(demo) |
| `GET /api/audit/snapshots` | Time Machine 스냅샷 목록 | 합성(demo) |
| `GET /api/audit/snapshot?date=` | 특정 시점 상태 | 합성(demo) |
| `GET /api/audit/activity` | 활동 스트림 (폴링) | 합성(demo) |
| `GET /api/audit/replay` | 리플레이 시나리오 스텝 | 합성(demo) |
| `POST /api/audit/assistant` | 어시스턴트 메시지 | 결정론적(demo) |

합성 데이터는 전부 `demo: true` 필드로 구분. 프론트는 절대 PASS/FAIL/점수를 자체 산출하지 않고 API 응답만 렌더링.

## 4. 파일 계획

### 신규
- `src/secgrc/web/assurance_data.py` — 데이터 서비스 계층
- `src/secgrc/web/static/certification/app.css` — 다크 네이비 사이드바 등 스타일
- `src/secgrc/web/static/certification/app.js` — 공통(state, fetch, activity poll)
- `src/secgrc/web/static/certification/landscape.js` — 통제 랜드스케이프 SVG
- `src/secgrc/web/static/certification/timemachine.js` — 타임머신 슬라이더
- `src/secgrc/web/static/certification/replay.js` — 리플레이 플레이어
- `src/secgrc/web/static/certification/assistant.js` — AI 어시스턴트
- `src/secgrc/web/static/certification/chart.js` — SVG 라인 차트
- `src/secgrc/web/templates_certification/control_center.html` — `/audit` 메인
- `templates_certification/control_detail.html`, `replay.html`, `collection.html`, `intake.html`, `connections.html`, `reports.html`, `history.html`, `criteria.html`, `users.html`, `settings.html`
- `tests/test_assurance_api.py` — API 계약/페이지 렌더링 unittest

### 수정
- `src/secgrc/web/certification_routes.py` — 신규 라우트/JSON API 추가
- `src/secgrc/web/certification_app.py` — StaticFiles 마운트
- `templates_certification/base.html` — 사이드바 내비 + 컨텍스트 카드로 전면 재작성
- `templates_certification/dashboard.html`, `controls.html`, `evidence.html`, `reconciliation.html`, `audit.html`, `findings.html`, `gap.html` — 신규 IA로 재편

### 의도적으로 미수정
- `routes.py`, `app.py`, `templates/` (v1 보존)
- `auth.py`, 엔진 모듈 전부 (source of truth)
- `repository.py`, `certification_view.py` (기존 시드 재사용)

## 5. 구현 결과 (완료)

| Phase | 산출물 | 상태 |
|-------|--------|------|
| 1 셸 | 다크 네이비 사이드바 + 감사 컨텍스트 카드(D-day·유형·선택자) | ✅ |
| 2 KPI+Landscape | 클릭 가능 KPI 5종 + 101개 통제 3단 트리(도메인 확장/상태 필터) | ✅ |
| 3 Control Detail | 9노드 증적 체인(Requirement→Verification) 노드별 드릴다운 | ✅ |
| 4 GAP+Findings | 유형별 집계 + 12필드 결함 카드 + 생명주기 스텝퍼 | ✅ |
| 5 Activity | 폴링 기반 실시간 스트림 (demo feed) | ✅ |
| 6 Time Machine | 90/60/30/오늘 스냅샷, 통제 상태 변화 표시 | ✅ |
| 7 Replay | 퇴직자 계정 시나리오 8단계, 재생/탐색/증적 점프 | ✅ |
| 8 Assistant | 결정론적 advisory 응답 + 링크 액션 | ✅ |
| 9 반응형/a11y | 1180px 사이드 접힘, focus-visible, aria-label | ✅ |
| 10 테스트 | `tests/test_assurance_api.py` 15건 unittest 통과 | ✅ |

## 6. 실행

```bash
# v2 인증심사 전용 콘솔 (8001)
PYTHONPATH=src python3 -m secgrc web-cert --port 8001
# v1 기존 콘솔 (8000) — 변경 없음
PYTHONPATH=src python3 -m secgrc web --port 8000
```

## 7. 남은 과제 (향후 백엔드 구현 필요)

- 스냅샷/리플레이/활동 스트림/어시스턴트는 현재 `demo:true` 결정론적 mock —
  실제 구현 시 증적 원장 타임스탬프 기반 시점 재구성, 이벤트 소싱 스트림,
  LLM 어댑터(advisory 유지)로 `/api/audit/*` 계약만 교체
- 통제 정의 로드 16/101 — 나머지 85개 `isms_p_controls.json` 확충 필요
- 표본 요청의 실제 제출/검증 플로우는 엔진 API 존재, UI 연동은 추후
