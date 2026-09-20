# GRC Agent — ISMS-P Certification Audit Console (v2)

ISMS-P 인증심사 준비·대응·유지를 지원하는 감사 보증(Audit Assurance) 워크스페이스.
정적 GRC 대시보드가 아닌, 증적 중심의 동적 심사 대응 환경을 제공합니다.

## 실행

```bash
pip install -e .
GEMINI_API_KEY=...   # .env에 설정 (AI 심사지원 LLM — 미설정 시 규칙 기반 폴백)
PYTHONPATH=src python3 -m secgrc web-cert --port 8001
# → http://127.0.0.1:8001/audit
```

## 주요 기능

- **Audit Control Center** — 준비도 KPI, 통제 랜드스케이드(101개 통제), Audit Time Machine
- **Control Detail** — Requirement→Policy→Config→Population→Evidence→Finding 9노드 증적 체인
- **Evidence Intake** — 실제 파일 업로드(확장자·매직바이트·민감정보 차단), 내용 기반 통제 자동 추천
- **AI 심사지원 채팅** — 증적 ID(REC-/DOC-)·파일명 참조 해석, 본문 접지 LLM 응답(advisory)
- **GAP / Findings** — 정합성 엔진, 지적사항 생명주기, Audit Replay(심사원 질의 시뮬레이션)

## 아키텍처 원칙

- 결정론적 엔진이 판정 권위 — UI·AI는 렌더링/advisory만
- 합성 데이터는 `demo:true` + 배지로 구분
- 증적은 SHA-256 해시체인 WORM 원장에 기록

## 문서

- `docs/ui/` — UX 설계·구현 노트
- `docs/security/` — 취약점 레지스터·AI 컴포넌트 플로우(레드팀 학습 자료)
- `docs/development/` — 마스터 개발 가이드라인

## 테스트

```bash
PYTHONPATH=src python3 -m unittest tests.test_assurance_api
```
