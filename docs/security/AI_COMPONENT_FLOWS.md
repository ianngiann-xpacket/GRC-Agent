# GRC Agent — LLM · Tool Calling · RAG · MCP 구현 상세 Flow

> **목적**: 레드티밍 학습용. 이 저장소의 AI 관련 구성요소(LLM 연동, 에이전트
> 도구 호출, 검색/컨텍스트 주입, MCP 파이프라인, 가드레일)의 실제 구현 flow와
> 각 단계의 **공격 표면/신뢰 경계**를 정리한다.
> **기준 코드**: `src/secgrc/` — 모든 경로는 실제 파일 기준.

---

## 0. 구성요소 존재 여부 요약

| 기능 | 구현 | 위치 | 실제 LLM 호출 |
|------|:---:|------|:---:|
| LLM 연동 | ✅ | `secgrc/llm.py`, `secgrc/ai/`, `secgrc/synthlab/llm_provider.py` | Gemini (google-genai) |
| Tool Calling | ✅ | `secgrc/agent/` (LangGraph + allowlist) | 노드 내부 `execute_safely` |
| RAG | ⚠️ 부분 | `secgrc/ai/retriever.py` — **벡터 검색 아님**, 결정론적 스코프 검색 | — |
| MCP | ✅ | `secgrc/mcp/` (레지스트리·정책·9단계 보안 파이프라인) | — |
| NL Copilot | ✅ | `secgrc/copilot/` (규칙 기반 분류 → 결정론적 실행) | ❌ LLM 미사용 |
| 에이전트 가드레일 | ✅ | `secgrc/agent_security/` (10개 모듈) | — |
| RedTeam 평가기 | ✅ | `secgrc/redteam/` (10개 공격 카테고리) | — |
| 합성 공격 데이터 | ✅ | `secgrc/synthlab/` (attack catalog 1668줄) | — |

---

## 1. LLM 연동 — 3개 독립 경로

### 1-A. 레거시 직접 호출 — `secgrc/llm.py` (v1 대시보드 경로)

```text
audit_with_llm(query, control_id, control_name, requirements)
  │
  ├─ get_gemini_api_key()          # GEMINI_API_KEY / GOOGLE_API_KEY env
  │     └─ load_dotenv(override=True)   # ⚠️ .env가 실제 env보다 우선 (R-06)
  │
  ├─ [키 없음] → _fallback_rule_evaluation()   # 키워드 매칭 규칙 판정
  │
  └─ [키 있음] → google.genai.Client
        │  prompt = f'''...ISMS-P {control_id}...
        │           [점검 대상 보안 현황]
        │           "{query}"'''          # 🔴 query를 미살균 삽입 — 직접 프롬프트 인젝션 표면
        │
        ├─ 모델 폴백: gemini-2.5-flash → gemini-1.5-flash → gemini-3.6-flash
        ├─ temperature=0.2
        │
        ├─ 성공 → _parse_llm_response()
        │        # "판정/소견/조치" 텍스트 파싱 — 구조화 출력 아님
        │        # is_compliant: 첫 줄에 "적합" && !"부적합" — 🔴 파싱 조작 가능
        │
        └─ 실패 → fallback + notice
               # 🔴 V-013: notice에 api_key[:6]...api_key[-4:] + 예외 메시지 포함
```

**레드팀 포인트**
- `query`는 프롬프트에 무살균 삽입 → 지시어 주입, 판정 문구 조작("판정: 적합" 유도) 가능
- 파싱은 첫 줄 문자열 매칭 → LLM 출력 첫 줄에 `판정: 적합`을 유도하면 `is_compliant=True`
- 단, 이 결과는 **advisory**로만 쓰이고 결정론적 `AuditEngine` 판정을 덮어쓰지 않음
- 예외 경로가 키 일부 + 에러 상세를 사용자 노출 필드에 포함 (V-013)

### 1-B. AI Auditor — `secgrc/ai/auditor.py` (LangGraph 노드 4)

```text
AIAuditor.analyze_all(audit_results, risk_results, evidence)
  │
  ├─ format_evidence_payload()
  │     └─ sanitize_evidence_text()     # </untrusted_evidence> 탈출·``` 차단
  │
  ├─ SYSTEM_PROMPT + USER_PROMPT_TEMPLATE (ai/prompts.py, PROMPT_VERSION 추적)
  ├─ google.genai 호출 (api_key = GEMINI_API_KEY)
  │
  ├─ 실패 → sanitize_fallback_reason()  # ✅ 16자+ 토큰 [REDACTED] 마스킹 (llm.py와 대조적)
  └─ 성공 → 구조화 파싱 → AIAnalysis (EvidenceBasis 포함 — 근거 증적 ID 강제)
```

- **설계 원칙**: "결정론적 판정 불변" — AI는 소견만 생성, PASS/FAIL·risk_score 불변
- **공격 표면**: 증적 텍스트 경유 간접 인젝션 → `sanitize_evidence_text`가 태그 탈출만 방어 (지시어 텍스트 자체는 통과 가능)

### 1-C. 프로바이더 추상화 — `secgrc/ai/provider.py`

```text
LLMProvider (Protocol): provider_id, model_id, generate(LLMRequest) -> LLMResponse

MockLLMProvider — 결정론적 오프라인 추론 + 적대적 테스트 주입:
  set_adversarial_flags(
    inject_tool_call          # LLM이 tool_call JSON 출력 → 가드 검증
    inject_secret_request     # "AWS root password 요청" 질문 주입
    inject_fact_claim         # 근거 없는 FACT 사칭
    inject_risk_override      # risk_score_override: 98 시도
    inject_compliance_override# compliance_status_override: FAIL 시도
  )
```

- LLMResponse는 `raw_output_hash`(SHA-256) 보유 — 응답 무결성 추적
- **레드팀 학습**: 이 플래그들은 guard 검증 테스트용 — 프로덕션 LLM의 이상 출력을 시뮬레이션

---

## 2. Tool Calling — LangGraph 워크플로우 (`secgrc/agent/`)

### 2-A. 그래프 구조 (`agent/graph.py`)

```text
START → load_evidence → audit_controls → calculate_risk → ai_audit
      → create_remediation_plan → [risk_based_router]
              ├─ CRITICAL/HIGH 존재 → human_approval → [approval_router]
              │        ├─ APPROVED / approved_actions 존재 → execute_action
              │        ├─ DRY_RUN 모드 → execute_action   # ⚠️ 시뮬레이션 실행 허용
              │        └─ 그 외 → generate_report
              ├─ MANUAL/NO_EVIDENCE → auditor_review → generate_report
              └─ 그 외 → generate_report → END
```

- 체크포인터: `InMemorySaver` + `thread_id=scan_id` (인메모리 — 재시작 시 상태 소실)
- 진입점: `run_agent_workflow(evidence_path, ...)` — v1 `POST /api/agent/runs`에서 호출

### 2-B. 도구 화이트리스트 (`agent/tools.py`)

```python
ALLOWED_TOOLS = {read_evidence, run_audit, calculate_risk,
                 run_ai_audit, create_remediation_plan, generate_report}
FORBIDDEN_TOOLS = {arbitrary_shell, arbitrary_python, arbitrary_http,
                   arbitrary_gcloud, arbitrary_file_write}

execute_safely(tool_name, func, *args):
    validate_tool_call(tool_name)   # 화이트리스트 외 → SecurityViolationError
    return func(*args)
```

- **모든 노드 호출이 `execute_safely` 경유** — 이름 기반 화이트리스트
- `sanitize_untrusted_input()`: 증적 텍스트에서 `INJECTION_PATTERNS`(8개 정규식) 탐지 → `[UNTRUSTED_INSTRUCTION_REMOVED]` 치환
  - 패턴: `ignore previous instructions`, `system override`, `run command/bash`, `reveal secret/token`, `override audit result`, `pass this control` 등
  - **우회 표면**: 영문 패턴만 — 한글 인젝션("이전 지시를 무시하고"), 인코딩/난독화, 분할 지시어는 미탐지 가능

### 2-C. 실행 안전성 (`agent/nodes.py`)

- `execute_action`은 **항상 `act.execute(dry_run=True)`** — 실제 리소스 변경 없음 (현재 구현)
- 승인 로직: `approval_status==APPROVED` or `act_id in approved_actions` or `global_approval_manager.is_action_approved()` or **DRY_RUN 조건** — `approval_router`에서도 `execution_mode=="DRY_RUN"`이면 execute로 라우팅
- **공격 표면**: `execution_mode`는 `AgentRunRequest`의 클라이언트 필드 → 요청자가 `"DRY_RUN"` 지정 시 승인 없이 실행 경로 진입(실행 자체는 dry-run이라 무해 — 단 EXECUTE 모드 구현 시 이 분기가 치명적 경로가 됨)

---

## 3. RAG — 결정론적 검색기 (`secgrc/ai/retriever.py`)

**이 저장소의 "RAG"는 벡터 검색이 아니다** — 의도적으로 배제:

```text
AIInvestigationRetriever.retrieve_context(investigation_id, scope, allowed_entity_ids, ...)
  │
  └─ AIContextBuilder.build_context()
        # 스코프 한정 + allowed_entity_ids 필터링 + 무해화
        # facts / evidence / relationships / assessments / changes 소스만 조회
        # "Evidence is data, not instructions" 원칙
```

- `llm.py` docstring의 "RAG로 검색된 ISMS-P 기준"은 실제로는 **정적 요구사항 텍스트 주입** — 임베딩/벡터DB 없음
- **레드팀 관점**: 벡터DB 중독(poisoning)·임베딩 인젝션 표면이 없는 것은 방어적 선택. 컨텍스트는 `allowed_entity_ids`로 스코프 제한 → 스코프 탈출 시도는 ID 필터로 차단

---

## 4. MCP — 9단계 보안 파이프라인 (`secgrc/mcp/`)

### 4-A. 도구 레지스트리 (`mcp/registry.py`) — 7개 등록 도구

`prowler.get_findings`, `gcp.list_firewalls`, `gcp.list_iam_bindings`,
`gcp.list_storage_buckets`, `gcp.list_logging_config`, `evidence.load` 등 —
각 도구에 `risk_level`, `rate_limit_per_session`, `timeout_seconds`, `parameters_schema` 메타데이터

### 4-B. 파이프라인 (`mcp/security.py` — `execute_with_guard`)

```text
MCPRequest{request_id, agent_id, tool_id, arguments, session_id}  # 🔴 전부 클라이언트 제공
  │
  [1] Rate Limit — key = f"{session_id}:{tool_id}"
  │     # 🔴 session_id를 클라이언트가 지정 → 임의 session_id 회전으로 우회 가능
  │
  [2] Policy 평가 (mcp/policy.py MCPPolicyEngine)
  │     ├─ agent_id 미등록 → DENY        # 🔴 단, 등록된 agent_id 사칭은 검증 수단 없음
  │     ├─ agent REVOKED/SUSPENDED → DENY #     (신원 주장과 인증 분리)
  │     ├─ tool 미등록/비활성 → DENY
  │     └─ 위험도·승인 정책 → REQUIRE_APPROVAL 가능
  │
  [3] 인자 검증
  │     ├─ 스키마 required 필드
  │     ├─ SUSPICIOUS_PATH_PATTERNS 7개: ../, /.., ~/, /etc/passwd|shadow,
  │     │   .env, id_rsa|id_ed25519, .git/  # ⚠️ 정규식 우회 여지(인코딩, 절대경로 변종)
  │     └─ InputGuard.detect_injection → confidence ≥ 0.85만 차단
  │          # 🔴 confidence < 0.85 인젝션은 통과 — 임계값 우회 표면
  │
  [4] 핸들러 실행 + 경과시간 측정 (timeout_seconds — 사후 측정, 선제 중단 아님)
  [5] 결과 절삭 — list > 500 items / (크기 상수 1MB 정의됨)
  [6] SecretGuard.redact() — 출력 시크릿 마스킹 → DATA_ONLY 보장
  [7] SecurityAuditLogger — 모든 결정(ALLOW/DENY/TIMEOUT/EXCEPTION) 감사 로그
  │
  └─ MCPToolResult{success, data(redacted), is_data_only, items_count, truncated}
```

### 4-C. 신뢰 경계 (레드팀 핵심)

| 경계 | 검증 수단 | 약점 |
|------|----------|------|
| `agent_id` | 레지스트리 존재 여부 | 신원 인증 없음 — 등록 ID 알면 사칭 가능 |
| `session_id` | 없음 | 임의 값으로 rate-limit 우회 |
| `arguments` | 스키마 + 정규식 + 인젝션 탐지 | 0.85 임계값, 패턴 우회 |
| 도구 출력 | SecretGuard + 절삭 | 1MB 미만 내 인코딩된 시크릿 패턴 외 변종 |

---

## 5. 에이전트 가드레일 스택 (`secgrc/agent_security/`)

```text
InputGuard        — detect_injection(): 49개 정규식 패턴, confidence·category·risk 반환
OutputGuard       — validate_ai_finding(): AI 출력이 권위 판정(상태/점수/증적ID)과
                    불일치하면 violations 반환 → 결정론적 값으로 덮어씀
SecretGuard       — mask_secrets()/redact(): 카나리·키 패턴 마스킹
ToolExecutionGuard— 도구 실행 전 정책 평가
ExcessiveAgencyGuard (risk_policy) — CRITICAL/프로덕션 변경 시 승인 강제
AgentRegistry     — 에이전트 신원·상태(ACTIVE/REVOKED/SUSPENDED)
DataAccessPolicy  — 외부 전송/데이터 접근 정책
SecurityAuditLogger— 전 결정의 불변 감사 로그
```

**설계 원칙(문서화됨)**: "Evidence is data, not instructions" / 결정론적 엔진이 절대 권위 / AI 출력은 advisory

---

## 6. Copilot — 자연어 인터페이스 (`secgrc/copilot/`) — LLM 미사용

```text
CopilotService.ask(question, user_role, language)
  │
  [1] classifier.classify(question)        # 규칙 기반 의도 분류 + 엔티티 추출
  │     # IntentCategory 16종: RISK_*, CONTROL_*, EVIDENCE_*,
  │     #   REMEDIATION_LOOKUP, FRAMEWORK_*, ASSET_RISK,
  │     #   FINDING_LOOKUP, AGENT_SECURITY, REDTEAM_STATUS, UNKNOWN
  │
  [2] planner.create_plan(intent_res)      # QueryPlan — 읽기 전용 가드레일 강제
  │
  [3] executor.execute(plan)               # OntologyRepository/Resolver 결정론적 조회
  │     # _execute_get_risks/_controls/_lineage/_evidence/_remediations/...
  │
  [4] generator.generate(...)              # CopilotGuard.verify_and_guard()
        │                                 #   + verify_provenance() (출처 검증)
        └─ CopilotAnswer (프로비넌스 첨부)
```

- **특징**: LLM을 거치지 않는 완전 결정론적 NL 파이프라인 → 프롬프트 인젝션 표면 자체가 없음
- **공격 표면**: 의도 오분류(엔티티 추출 조작), 프로비넌스 검증 우회, role 기반 필터링 검증 필요

---

## 7. 기존 RedTeam 평가기 (`secgrc/redteam/`)

```text
RedTeamEvaluator.evaluate_scenario(RedTeamScenario)
  │
  ├─ PROMPT_INJECTION   → InputGuard.detect_injection
  ├─ TOOL_ABUSE         → path traversal 검사 / PolicyEngine 평가
  ├─ DATA_EXFILTRATION  → 외부 URL·인젝션 탐지
  ├─ SECRET_LEAKAGE     → SecretGuard 카나리(CANARY_SECRET_001) 마스킹 검증
  ├─ EXCESSIVE_AGENCY   → CRITICAL/HIGH·비-dry_run 시 승인 강제 확인
  ├─ POLICY_BYPASS      → 위조 헤더(RootAdmin/fake_token)·override 액션 차단
  ├─ OUTPUT_MANIPULATION→ OutputGuard — AI 주장 상태/점수 vs 권위 값 대조
  ├─ TRUST_BOUNDARY     → EventNormalizer 살균 검증 (DATA_ONLY_NEUTRALIZED)
  ├─ APPROVAL_BYPASS    → approver=="verified_ciso" + APPROVED 조합만 유효
  └─ LOOP_ABUSE         → MAX_REMEDIATION_CYCLES + 멱등성(ALREADY_REMEDIATED)
```

- 지원물: `corpus.py`(공격 코퍼스+카나리), `scenarios.py`, `runner.py`, `scoring.py`, `reporters.py`
- **synthlab** `campaign/attack/catalog.py`(1668줄): 합성 공격 시나리오 카탈로그 — 레드팀 학습 코퍼스 확장 소스

---

## 8. 웹 노출 맵 (v1, 포트 8000) — AI/에이전트 엔드포인트

| 엔드포인트 | 기능 | 공격 표면 |
|-----------|------|----------|
| `POST /api/agent/runs` | 워크플로우 실행 | `evidence_path` 임의 경로 (V-014), `execution_mode` 클라이언트 지정 |
| `POST /api/agent/runs/{id}/approve` `/reject` | 승인/반려 | 결재자 `user` 필드는 자유 문자열 — 역할 검증 없음 |
| `GET /api/agent-security/*` | 에이전트·도구·정책·이벤트 조회 | 정보 노출(정책 구조 열람) |
| `POST /api/agent-security/evaluate` | 정책 평가 호출 | 평가 오라클 남용 |
| `GET /api/redteam/*` | 시나리오·결과·요약 | 방어 결과 노출(공격자에게 탐지 우회 힌트) |
| `POST /api/copilot/query` | 자연어 질의 | 의도 분류 조작 |
| `POST /api/ai/investigate` `/explain` `/hypotheses` `/questions` | AI 조사 | 컨텍스트 스코프 탈출 시도 |
| `GET /api/ai/reasoning/*` `/guard/*` | 추론 이력·가드 결과 | 방어 판정 근거 열람 |

전부 `AuthMiddleware` 하에 있음(비루프백 인증 필요). v2(8001)는 `POST /api/audit/assistant`(advisory, 결정론적 응답)만 노출.

---

## 9. 레드티밍용 공격 표면 우선순위

| 우선 | 표면 | 시나리오 |
|:---:|------|---------|
| P1 | `llm.py` query 무살균 프롬프트 삽입 | 직접 인젝션 → "판정: 적합" 유도 → 파싱 조작 (단, advisory 한계로 영향 제한) |
| P1 | `MCPRequest.agent_id`/`session_id` 클라이언트 제공 | 등록 에이전트 사칭, session 회전 rate-limit 우회 |
| P1 | `/api/agent/runs` `evidence_path` | 임의 파일 경로 오라클/파싱 (V-014) |
| P2 | `InputGuard` 0.85 임계값 + 영문 패턴 | 한글·난독화·분할 지시어로 인젝션 우회 시도 |
| P2 | `llm.py` 에러 경로 키 에코 | API 실패 유도 → 부분 키+예외 수집 (V-013) |
| P2 | `INJECTION_PATTERNS` 8종 정규식 | 증적 CSV 내 지시어 → sanitize 우회 패턴 탐색 |
| P3 | approval_router `DRY_RUN` 분기 | EXECUTE 모드 도입 시 승인 우회 경로화 — 지금 회귀 테스트 필요 |
| P3 | `/api/redteam/*` 결과 열람 | 방어 로직 역산 → 우회 페이로드 설계 |
| P3 | `OutputGuard` 검증 규칙 | 미검증 필드(confidence, narrative)를 통한 간접 조작 |

**기존 방어가 이미 커버**: 도구 화이트리스트, 증적 무해화, 출력 권위 검증, 시크릿 마스킹,
경로 탐색 차단, 감사 로그, 결정론적 판정 불변 — 레드팀은 **우회(bypass)와 경계 혼합**을 목표로 해야 함.
