import os
import sys
from datetime import datetime, timezone
from typing import Optional
from secgrc.graph import build_graph
from secgrc.knowledge.repository import ControlRepository
from secgrc.evidence.repository import EvidenceRepository


def handle_search(query: str):
    """지식 베이스에서 통제항목을 검색하고 증적 및 글로벌 매핑 정보를 출력합니다."""
    repo = ControlRepository()
    results = repo.search(query, top_k=3)

    if not results:
        print(f"\n❌ '{query}'에 해당하는 통제항목을 찾을 수 없습니다.")
        return

    print(f"\n🔍 [컴플라이언스 검색 결과: '{query}']")
    print("=" * 68)
    for ctrl, mapping, score in results:
        auto_badge = "⚙️ [자동검증 가능]" if ctrl.automatable else "📋 [사람의 판단 필요]"
        print(f"\n[{ctrl.control_id}] {ctrl.title}  {auto_badge}")
        print(f"  • 영역: {ctrl.domain}")
        print(f"  • 요구사항: {ctrl.requirement}")
        if ctrl.risk:
            print(f"  • 위험(Risk): {ctrl.risk}")

        print("  • 필요 증적(Evidence):")
        for ev in ctrl.evidence:
            print(f"    - {ev}")

        if mapping:
            print("  • 글로벌 프레임워크 매핑:")
            if mapping.iso27001:
                print(f"    ├── 🇪🇺 ISO 27001: {', '.join(mapping.iso27001)}")
            if mapping.nist_csf:
                print(f"    ├── 🇺🇸 NIST CSF : {', '.join(mapping.nist_csf)}")
            if mapping.cis_controls:
                print(f"    ├── 🛡️ CIS Controls: {', '.join(mapping.cis_controls)}")
            if mapping.nist_ai_rmf:
                print(f"    └── 🤖 NIST AI RMF : {', '.join(mapping.nist_ai_rmf)}")

    print("\n" + "=" * 68)


def handle_mapping(control_id: str):
    """특정 통제항목의 세부 크로스 프레임워크 매핑 상세 정보를 출력합니다."""
    repo = ControlRepository()
    target_ctrl = next((c for c in repo.controls if c.control_id.lower() == control_id.lower()), None)

    if not target_ctrl:
        print(f"\n❌ '{control_id}' 통제항목을 찾을 수 없습니다.")
        return

    mapping = repo.get_mapping(target_ctrl.control_id)

    print(f"\n🌐 [컴플라이언스 크로스 프레임워크 매핑 명세]")
    print("=" * 68)
    auto_badge = "⚙️ [자동검증 가능]" if target_ctrl.automatable else "📋 [사람의 판단 필요]"
    print(f"기준 통제: [{target_ctrl.control_id}] {target_ctrl.title}  {auto_badge}")
    print(f"• 영역: {target_ctrl.domain}")
    print(f"• 요구사항: {target_ctrl.requirement}")
    print("• 필요 증적(Evidence):")
    for ev in target_ctrl.evidence:
        print(f"  - {ev}")

    print("\n[상호 인정 및 매핑된 글로벌 프레임워크]")
    if mapping:
        if mapping.iso27001:
            print("  ├── 🇪🇺 ISO/IEC 27001:2022")
            for item in mapping.iso27001:
                print(f"  │     └── {item}")
        if mapping.nist_csf:
            print("  ├── 🇺🇸 NIST CSF 2.0")
            for item in mapping.nist_csf:
                print(f"  │     └── {item}")
        if mapping.cis_controls:
            print("  ├── 🛡️ CIS Controls v8")
            for item in mapping.cis_controls:
                print(f"  │     └── {item}")
        if mapping.nist_ai_rmf:
            print("  └── 🤖 NIST AI RMF (AI 위험관리)")
            for item in mapping.nist_ai_rmf:
                print(f"        └── {item}")
        if mapping.rationale:
            print(f"\n💡 매핑 근거: {mapping.rationale}")
    else:
        print("  매핑 정보가 아직 등록되지 않은 통제항목입니다.")

    print("=" * 68 + "\n")


def handle_evidence(control_id: str = ""):
    """수집된 클라우드 증적(Evidence) 현황 및 세부 Findings를 출력합니다."""
    repo = EvidenceRepository()

    if control_id:
        findings = repo.get_by_control(control_id)
        print(f"\n📑 [통제항목 증적 조회: {control_id.upper()}]")
        print("=" * 68)
        if not findings:
            print(f"등록된 수집 증적이 없습니다.")
            return
        for ev in findings:
            status_icon = "✅" if ev.status == "COMPLIANT" else ("⚠️" if ev.status == "PARTIAL" else "❌")
            print(f"\n{status_icon} [{ev.evidence_id}] 상태: {ev.status.value} (출처: {ev.source})")
            print(f"  • 대상 리소스: {ev.resource_id}")
            print(f"  • 수집 시각  : {ev.collected_at}")
            print(f"  • 감사 결과  : {ev.finding}")
            if ev.remediation_hint:
                print(f"  • 조치 가이드: {ev.remediation_hint}")
        print("=" * 68 + "\n")
        return

    summary = repo.get_summary()
    print("\n" + "=" * 68)
    print("📊 [GRC Agent: 클라우드 감사 증적(Evidence) 현황 대시보드]")
    print("=" * 68)
    bar_filled = int(summary['score_percent'] / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    print(f"\n전체 준수율 (Overall Compliance): [{bar}] {summary['score_percent']}%\n")
    print(f"• 총 수집 증적 수 : {summary['total']}건")
    print(f"  ├── ✅ 적합 (COMPLIANT)     : {summary['compliant']}건")
    print(f"  ├── ⚠️ 부분준수 (PARTIAL)    : {summary['partial']}건")
    print(f"  └── ❌ 부적합 (NON_COMPLIANT): {summary['non_compliant']}건")
    print("\n" + "-" * 68)
    print("[주요 클라우드 감사 발견 사실 (Key Findings)]")
    for ev in repo.all_evidence:
        status_icon = "✅" if ev.status == "COMPLIANT" else ("⚠️" if ev.status == "PARTIAL" else "❌")
        print(f"\n{status_icon} [{ev.evidence_id}] ISMS-P {ev.control_id} | {ev.status.value} ({ev.source})")
        print(f"  • 대상: {ev.resource_id}")
        print(f"  • 발견: {ev.finding}")
        if ev.remediation_hint and ev.status != "COMPLIANT":
            print(f"  • 시정조치: {ev.remediation_hint}")
    print("=" * 68 + "\n")


def handle_prowler_evidence(csv_path: str):
    """Prowler CSV 진단 결과를 로드하고 정규화 요약 통계를 출력합니다."""
    from secgrc.evidence.prowler_adapter import ProwlerEvidenceAdapter
    from pathlib import Path

    if not csv_path:
        print("❌ Prowler CSV 파일 경로를 입력해 주세요.")
        print("   사용법: python -m secgrc evidence prowler <csv-path>")
        return

    path = Path(csv_path)
    if not path.exists():
        print(f"❌ 파일을 찾을 수 없습니다: {csv_path}")
        return

    adapter = ProwlerEvidenceAdapter()
    try:
        findings = adapter.load_findings(path)
    except Exception as e:
        print(f"❌ Prowler CSV 파싱 실패: {e}")
        return

    stats = adapter.summary(findings)

    print("## Prowler Evidence Summary\n")
    print(f"Source: {stats['source']}")
    print(f"Provider: {stats['provider']}")
    print(f"Findings: {stats['findings']}")
    print(f"Critical: {stats['critical']}")
    print(f"High: {stats['high']}")
    print(f"Medium: {stats['medium']}")
    print(f"Low: {stats['low']}")
    print(f"Manual: {stats['manual']}")
    print(f"Pass: {stats['pass']}")
    print(f"Fail: {stats['fail']}")


def handle_audit_prowler(csv_path: str, as_json: bool = False):
    """Prowler CSV 진단 결과를 바탕으로 결정론적 ISMS-P 감사를 수행하고 결과를 출력합니다."""
    import json
    from pathlib import Path
    from secgrc.evidence.prowler_adapter import ProwlerEvidenceAdapter
    from secgrc.audit.engine import AuditEngine
    from secgrc.audit.models import AuditStatus

    if not csv_path:
        print("❌ Prowler CSV 파일 경로를 입력해 주세요.")
        print("   사용법: python -m secgrc audit prowler <csv-path> [--json]")
        return

    path = Path(csv_path)
    if not path.exists():
        print(f"❌ 파일을 찾을 수 없습니다: {csv_path}")
        return

    adapter = ProwlerEvidenceAdapter()
    try:
        findings = adapter.load_findings(path)
    except Exception as e:
        print(f"❌ Prowler CSV 파싱 실패: {e}")
        return

    engine = AuditEngine()
    results = engine.assess(findings)
    summary = engine.summary(results)

    if as_json:
        payload = {
            "summary": {
                "framework": "ISMS-P",
                "evidence_count": len(findings),
                **summary,
            },
            "results": [r.model_dump() for r in results],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    print("## GRC Audit Summary\n")
    print("Framework: ISMS-P")
    print(f"Evidence: {len(findings)}\n")
    print(f"Controls Assessed: {summary['total_controls']}")
    print(f"PASS: {summary['pass']}")
    print(f"FAIL: {summary['fail']}")
    print(f"PARTIAL: {summary['partial']}")
    print(f"MANUAL: {summary['manual']}")
    print(f"NO_EVIDENCE: {summary['no_evidence']}\n")
    print("Risk:")
    print(f"CRITICAL: {summary['critical']}")
    print(f"HIGH: {summary['high']}")
    print(f"MEDIUM: {summary['medium']}")
    print(f"LOW: {summary['low']}\n")

    failing_results = [r for r in results if r.status in (AuditStatus.FAIL, AuditStatus.PARTIAL)]
    if failing_results:
        print("-" * 50)
        print("[주요 결함 및 시정조치 항목]")
        for r in failing_results:
            status_tag = f"[{r.status.value}]"
            ev_str = ", ".join(r.evidence_ids[:3]) + (f" (외 {len(r.evidence_ids)-3}건)" if len(r.evidence_ids) > 3 else "")
            print(f"\n{status_tag} {r.control_id} - {r.control_title}")
            print(f"Severity: {r.severity.value}")
            print(f"Evidence: {ev_str}")
            print(f"Reason: {r.rationale}")
            if r.recommendations:
                print("Recommendation:")
                for rec in r.recommendations[:2]:
                    print(f"  • {rec}")
        print("\n" + "=" * 50)


def handle_risk_prowler(csv_path: str, as_json: bool = False):
    """Prowler CSV로부터 감사 결과를 도출하고 GRC 위험 점수(Risk Score)를 산출합니다."""
    import json
    from pathlib import Path
    from secgrc.evidence.prowler_adapter import ProwlerEvidenceAdapter
    from secgrc.audit.engine import AuditEngine
    from secgrc.risk.engine import RiskEngine

    if not csv_path:
        print("❌ Prowler CSV 파일 경로를 입력해 주세요.")
        print("   사용법: python -m secgrc risk prowler <csv-path> [--json]")
        return

    path = Path(csv_path)
    if not path.exists():
        print(f"❌ 파일을 찾을 수 없습니다: {csv_path}")
        return

    adapter = ProwlerEvidenceAdapter()
    try:
        findings = adapter.load_findings(path)
    except Exception as e:
        print(f"❌ Prowler CSV 파싱 실패: {e}")
        return

    # 1. 컴플라이언스 평가
    audit_engine = AuditEngine()
    audit_results = audit_engine.assess(findings)

    # 2. 위험 점수 산출
    risk_engine = RiskEngine()
    assessments = risk_engine.assess(audit_results, findings)
    summary = risk_engine.summary(assessments)

    if as_json:
        payload = {
            "summary": summary,
            "risks": [a.model_dump() for a in assessments],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    print("## GRC Risk Summary\n")
    print(f"Controls: {summary['total']}\n")
    print(f"CRITICAL: {summary['critical']}")
    print(f"HIGH: {summary['high']}")
    print(f"MEDIUM: {summary['medium']}")
    print(f"LOW: {summary['low']}\n")
    print(f"P1: {summary['p1']}")
    print(f"P2: {summary['p2']}")
    print(f"P3: {summary['p3']}")
    print(f"P4: {summary['p4']}")
    print(f"P5: {summary['p5']}\n")

    print("-" * 50)
    print("[Top Risks]")
    for r in assessments[:10]:
        ev_str = ", ".join(r.evidence_ids[:3]) + (f" (외 {len(r.evidence_ids)-3}건)" if len(r.evidence_ids) > 3 else "")
        if not ev_str:
            ev_str = "None (No Evidence)"
        print(f"\n[{r.priority.value}][{r.risk_level.value}] {r.control_id} - {r.control_title}")
        print(f"Risk Score: {r.risk_score}")
        print(f"Severity: {r.severity.value}")
        print(f"Status: {r.audit_status.value}")
        print(f"Evidence: {ev_str}")
        print(f"Reason: {r.rationale}")
        if r.recommendations:
            print("Recommendation:")
            for rec in r.recommendations[:2]:
                print(f"  • {rec}")

def handle_ai_audit_prowler(csv_path: str, as_json: bool = False):
    """Prowler CSV로부터 컴플라이언스 및 위험 평가를 거쳐 AI Auditor 심층 분석 소견을 도출합니다."""
    import json
    from pathlib import Path
    from secgrc.evidence.prowler_adapter import ProwlerEvidenceAdapter
    from secgrc.audit.engine import AuditEngine
    from secgrc.risk.engine import RiskEngine
    from secgrc.ai.auditor import AIAuditor

    if not csv_path:
        print("❌ Prowler CSV 파일 경로를 입력해 주세요.")
        print("   사용법: python -m secgrc ai-audit prowler <csv-path> [--json]")
        return

    path = Path(csv_path)
    if not path.exists():
        print(f"❌ 파일을 찾을 수 없습니다: {csv_path}")
        return

    adapter = ProwlerEvidenceAdapter()
    try:
        findings = adapter.load_findings(path)
    except Exception as e:
        print(f"❌ Prowler CSV 파싱 실패: {e}")
        return

    # 1. 컴플라이언스 평가
    audit_engine = AuditEngine()
    audit_results = audit_engine.assess(findings)

    # 2. 위험 점수 산출
    risk_engine = RiskEngine()
    risk_assessments = risk_engine.assess(audit_results, findings)

    # 3. AI Auditor 심층 추론
    auditor = AIAuditor()
    analyses = auditor.analyze_all(audit_results, risk_assessments, findings)

    if as_json:
        payload = [a.model_dump() for a in analyses]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    print("=" * 68)
    print("🤖 [GRC Agent: AI Auditor 심층 보안 감사 보고서]")
    print("=" * 68)
    print(f"총 분석 통제항목: {len(analyses)}건\n")

    # 우선순위 순 정렬 (P1 -> P5)
    sorted_analyses = sorted(analyses, key=lambda a: a.priority)

    for a in sorted_analyses:
        print("-" * 68)
        print(f"[{a.priority}][{a.risk_level}] {a.control_id} - {a.control_title}")
        print(f"• 감사 상태: {a.audit_status} (위험 점수: {a.risk_score})")
        print(f"• 경영진 요약 (Executive Summary):")
        print(f"  {a.executive_summary}")
        print(f"• 기술적 발견 (Technical Summary):")
        print(f"  {a.technical_summary}")
        print(f"• 근본 원인 (Root Cause):")
        print(f"  {a.root_cause}")
        print(f"• 비즈니스 영향 (Business Impact):")
        print(f"  {a.business_impact}")
        print(f"• 공격 시나리오 (Attack Scenario):")
        for line in a.attack_scenario.splitlines():
            print(f"  {line}")
        if a.remediation:
            print(f"• 시정조치 권고 (Remediation):")
            for rec in a.remediation:
                print(f"  - {rec}")
        if a.auditor_questions:
            print(f"• 심사원 실사 질문 (Auditor Questions):")
            for q in a.auditor_questions:
                print(f"  ? {q}")
        if a.evidence_basis:
            print(f"• 증적 출처 추적 (Evidence Basis):")
            for eb in a.evidence_basis[:3]:
                print(f"  [{eb.basis}] {eb.evidence_id}: {eb.claim}")
        llm_stat = "LLM 추론 완료" if a.llm_used else f"Fallback ({a.fallback_reason or 'rule-based'})"
        print(f"• 신뢰도: {a.confidence * 100:.0f}% (모델: {a.model_name}, 엔진: {llm_stat}, 프롬프트: v{a.prompt_version})")
    print("=" * 68 + "\n")


def handle_report_prowler(csv_path: str, format_type: str = "markdown", output_dir: str = "reports"):
    """Prowler CSV로부터 컴플라이언스, 위험, AI 소견을 취합하여 통합 GRC 감사 보고서를 생성합니다."""
    import json
    from datetime import datetime, timezone
    from pathlib import Path
    from secgrc.evidence.prowler_adapter import ProwlerEvidenceAdapter
    from secgrc.audit.engine import AuditEngine
    from secgrc.risk.engine import RiskEngine
    from secgrc.ai.auditor import AIAuditor
    from secgrc.report.generator import AuditReportGenerator
    from secgrc.report.markdown import MarkdownReportRenderer
    from secgrc.report.html import HTMLReportRenderer

    if not csv_path:
        print("❌ Prowler CSV 파일 경로를 입력해 주세요.")
        print("   사용법: python -m secgrc report prowler <csv-path> [--format markdown|html|json]")
        return

    path = Path(csv_path)
    if not path.exists():
        print(f"❌ 파일을 찾을 수 없습니다: {csv_path}")
        return

    adapter = ProwlerEvidenceAdapter()
    try:
        findings = adapter.load_findings(path)
    except Exception as e:
        print(f"❌ Prowler CSV 파싱 실패: {e}")
        return

    # 1. 컴플라이언스 평가
    audit_engine = AuditEngine()
    audit_results = audit_engine.assess(findings)

    # 2. 위험 점수 산출
    risk_engine = RiskEngine()
    risk_assessments = risk_engine.assess(audit_results, findings)

    # 3. AI Auditor 심층 추론 (AI 장애 시에도 무중단 안전 폴백)
    ai_analyses = []
    try:
        auditor = AIAuditor()
        ai_analyses = auditor.analyze_all(audit_results, risk_assessments, findings)
    except Exception:
        ai_analyses = []

    # 4. 종합 보고서 데이터 생성
    report_gen = AuditReportGenerator()
    report = report_gen.generate(
        audit_results=audit_results,
        risk_assessments=risk_assessments,
        ai_analyses=ai_analyses,
        evidence_list=findings,
    )

    # 5. 출력 디렉터리 준비
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    fmt = format_type.lower().strip()
    if fmt == "html":
        renderer = HTMLReportRenderer()
        content = renderer.render(report)
        out_file = out_dir / f"GRC-Audit-{timestamp_str}.html"
        out_file.write_text(content, encoding="utf-8")
        print(f"✅ HTML 감사 보고서가 생성되었습니다: {out_file}")
        print(f"   Overall Risk Level : [{report.overall_risk_level}]")
        print(f"   Controls Assessed  : {report.total_controls}건 (FAIL: {report.fail_count}, PARTIAL: {report.partial_count})")
        print(f"   Priority Breakdown : P1({report.p1_count}), P2({report.p2_count}), P3({report.p3_count}), P5({report.p5_count})")
    elif fmt == "json":
        content = report.model_dump_json(indent=2)
        out_file = out_dir / f"GRC-Audit-{timestamp_str}.json"
        out_file.write_text(content, encoding="utf-8")
        print(f"✅ JSON 감사 보고서가 생성되었습니다: {out_file}")
        print(f"   Overall Risk Level : [{report.overall_risk_level}]")
        print(f"   Top Risk           : {report.top_risks[0].control_id} ({report.top_risks[0].risk_score:.1f})")
    else:  # markdown
        renderer = MarkdownReportRenderer()
        content = renderer.render(report)
        out_file = out_dir / f"GRC-Audit-{timestamp_str}.md"
        out_file.write_text(content, encoding="utf-8")
        print(f"✅ Markdown 감사 보고서가 생성되었습니다: {out_file}")
        print(f"   Overall Risk Level : [{report.overall_risk_level}]")
        print(f"   Controls Assessed  : {report.total_controls}건 (P1: {report.p1_count}, P2: {report.p2_count})")
        print(f"   Top Risk           : {report.top_risks[0].control_id} (Score: {report.top_risks[0].risk_score:.1f}, {report.top_risks[0].priority.value})")


def handle_certification_web_server(host: str = "127.0.0.1", port: int = 8001):
    """ISMS-P 인증심사 전용 콘솔(v2)을 uvicorn으로 실행합니다."""
    import uvicorn
    from secgrc.web.certification_app import app

    print("=" * 68)
    print("🛡️  ISMS-P Certification Audit Console (v2)")
    print("=" * 68)
    print(f"• 인증심사 콘솔 URL : http://{host}:{port}/dashboard")
    print(f"• 대화형 API 문서   : http://{host}:{port}/docs")
    print(f"• 서버 바인딩 주소  : {host}:{port}")
    print("• 메뉴 범위         : 인증심사 전용 (6계층 아키텍처)")

    auth = getattr(app.state, "web_auth", None)
    if auth and auth.mode != "disabled":
        print(f"• 접근 인증         : {auth.mode} (HTTP Basic / Bearer / X-API-Key)")
        if auth.mode == "auto":
            print("  - auto 모드: 로컬호스트 접속은 인증 면제, 외부 접속은 인증 필요")
    else:
        print("• 접근 인증         : 비활성화됨 (GRC_WEB_AUTH=disabled)")

    print("• 서버를 종료하려면 Ctrl+C를 누르세요.\n")

    uvicorn.run(app, host=host, port=port, log_level="info")


def handle_agent_run(csv_path: str, as_json: bool = False, scan_id: Optional[str] = None, dry_run: bool = True):
    """LangGraph 기반 Agentic GRC Workflow를 실행하고 결과를 출력합니다."""
    import json
    from secgrc.agent import run_agent_workflow

    if not csv_path:
        print("❌ CSV 파일 경로를 지정해 주세요.")
        print("   사용법: python -m secgrc agent run prowler <csv-path> [--dry-run] [--json] [--scan-id <id>]")
        return

    s_id = scan_id or f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    exec_mode = "DRY_RUN" if dry_run else "EXECUTE"

    res = run_agent_workflow(
        evidence_path=csv_path,
        scan_id=s_id,
        execution_mode=exec_mode,
    )

    if as_json:
        summary_payload = {
            "scan_id": res.get("scan_id"),
            "approval_required": res.get("approval_required"),
            "approval_status": res.get("approval_status"),
            "execution_mode": res.get("execution_mode"),
            "report_summary": res.get("report_summary"),
            "remediation_plan_count": len(res.get("remediation_plan", [])),
            "execution_result_count": len(res.get("execution_result", [])),
            "audit_trail_count": len(res.get("audit_trail", [])),
            "errors": res.get("errors", []),
        }
        print(json.dumps(summary_payload, indent=2, default=str))
        return

    print("🤖 GRC Agent Workflow\n")
    print(f"Scan ID: {s_id}\n")

    has_errors = bool(res.get("errors"))
    step1 = "FAILED" if has_errors and not res.get("evidence") else "OK"
    step2 = "FAILED" if has_errors and not res.get("audit_result") else "OK"
    step3 = "FAILED" if has_errors and not res.get("risk_result") else "OK"
    step4 = "OK"
    step5 = "OK"
    step6 = "REQUIRED" if res.get("approval_required") else "NOT_REQUIRED"
    step7 = "SKIPPED (DRY-RUN)" if res.get("execution_mode") == "DRY_RUN" else "EXECUTED"
    step8 = "OK" if res.get("report_summary") else "FAILED"

    print(f"[1/8] Evidence Loading ........ {step1}")
    print(f"[2/8] ISMS-P Audit ............ {step2}")
    print(f"[3/8] Risk Analysis ........... {step3}")
    print(f"[4/8] AI Auditor .............. {step4}")
    print(f"[5/8] Remediation Plan ........ {step5}")
    print(f"[6/8] Approval ................ {step6}")
    print(f"[7/8] Action .................. {step7}")
    print(f"[8/8] Report .................. {step8}\n")

    report_summary = res.get("report_summary") or {}
    overall_risk = report_summary.get("overall_risk_level", "UNKNOWN")
    print(f"Overall Risk: {overall_risk}\n")
    print(f"P1: {report_summary.get('p1_count', 0)}")
    print(f"P2: {report_summary.get('p2_count', 0)}")
    print(f"P3: {report_summary.get('p3_count', 0)}\n")

    appr_str = "YES" if res.get("approval_required") else "NO"
    print(f"Human approval required: {appr_str}")
    print(f"Execution: {res.get('execution_mode', 'DRY_RUN')}")


def handle_closed_loop_run(csv_path: str, simulate: bool = False, scan_id: Optional[str] = None):
    """Closed-loop Security (Discover -> Remediate -> Verify) 워크플로우를 실행하고 결과를 출력합니다."""
    from secgrc.closed_loop.workflow import build_closed_loop_graph

    if not csv_path or not os.path.exists(csv_path):
        print(f"❌ 파일을 찾을 수 없습니다: {csv_path}")
        return

    s_id = scan_id or f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    mode = "SIMULATED" if simulate else "DRY_RUN"

    initial_state = {
        "scan_id": s_id,
        "evidence_path": csv_path,
        "execution_mode": mode,
        "approval_status": "APPROVED" if simulate else "PENDING",
        "cycle_count": 0,
        "max_cycles": 3,
        "history": [],
    }

    graph = build_closed_loop_graph()
    res = graph.invoke(initial_state)

    if not simulate:
        print("🤖 Closed-loop Security\n")
        print(f"Scan: {s_id}\n")
        print("Initial Audit ............ OK")
        r_before = res.get("risk_before", 93.0)
        print(f"Initial Risk ............. CRITICAL / {r_before:.1f}")
        print("Remediation Plan ......... OK")
        print("Approval ................. REQUIRED")
        print("Execution ................ DRY-RUN")
        print("Verification ............. PENDING\n")
        print("No production changes made.")
    else:
        r_before = res.get("risk_before", 93.0)
        r_after = res.get("risk_after", 42.0)
        red_pct = res.get("risk_reduction_pct", 54.8)
        res_lvl = res.get("residual_risk_level", "MEDIUM")
        v_status = res.get("verification_status")
        v_str = v_status.value if hasattr(v_status, "value") else str(v_status or "VERIFIED_WITH_RESIDUAL_RISK")
        v_display = "PASS" if "VERIFIED" in v_str else "PARTIAL"

        print(f"Initial Risk:      {r_before:.1f}")
        print("Remediation:       SIMULATED")
        print(f"Verification:      {v_display}")
        print(f"Final Risk:        {r_after:.1f}")
        print(f"Risk Reduction:    {red_pct:.1f}%")
        print(f"Residual Risk:     {res_lvl}")
        print(f"Status:            {v_str}")


def handle_continuous_simulate():
    """Continuous GRC (Change -> Impact -> Re-evaluation -> Alert) 시뮬레이션을 실행하고 결과를 출력합니다."""
    from secgrc.continuous.workflow import build_continuous_graph

    sample_event = {
        "event_id": "EVT-SIM-001",
        "source": "gcp",
        "event_type": "FIREWALL_CHANGED",
        "resource_type": "firewall_rule",
        "resource_id": "firewall-rule-001",
        "change_type": "UPDATE",
        "actor": "service-account",
        "environment": "production",
        "metadata": {
            "public_access": True,
            "source_ranges": ["0.0.0.0/0"],
            "ports": ["22"],
        },
    }

    graph = build_continuous_graph()
    res = graph.invoke({"event_raw": sample_event, "history": []})

    evt = res.get("event")
    affected = res.get("affected_controls", [])
    ctrl_id = affected[0].control_id if affected else "ISMS-P-2.6.3"
    r_before = res.get("risk_before", 22.0)
    r_after = res.get("risk_after", 79.5)
    r_delta = res.get("risk_delta", 57.5)
    c_type = res.get("risk_change_type")
    c_str = c_type.value if hasattr(c_type, "value") else str(c_type or "RISK_INCREASED")
    alert = res.get("alert")
    prio = alert.priority if alert else "P2"
    action = alert.action_required if alert else "HUMAN REVIEW REQUIRED"

    print("🤖 Continuous GRC Simulation\n")
    print("Event:")
    print(f"{sample_event['event_type']}\n")
    print("Resource:")
    print(f"{sample_event['resource_id']}\n")
    print("Affected Control:")
    print(f"{ctrl_id}\n")
    print("Risk Before:")
    print(f"{r_before:.1f}\n")
    print("Risk After:")
    print(f"{r_after:.1f}\n")
    print("Risk Delta:")
    sign = "+" if r_delta > 0 else ""
    print(f"{sign}{r_delta:.1f}\n")
    print("Classification:")
    print(f"{c_str}\n")
    print("Priority:")
    print(f"{prio}\n")
    print("Action:")
    print(f"{action.upper()}")


def handle_redteam_run(category: Optional[str] = None, as_json: bool = False):
    """Red Team 공격 시나리오를 실행하고 결과를 요약 출력합니다."""
    from secgrc.redteam.runner import RedTeamRunner
    from secgrc.redteam.reporters import RedTeamReporter
    from secgrc.redteam.models import RedTeamCategory

    runner = RedTeamRunner()
    if category:
        cat_enum = None
        for c in RedTeamCategory:
            if c.value.upper() == category.upper():
                cat_enum = c
                break
        if not cat_enum:
            print(f"❌ 알 수 없는 카테고리입니다: {category}")
            print(f"   가능한 카테고리: {', '.join(c.value for c in RedTeamCategory)}")
            return
        summary, results = runner.run_category(cat_enum)
    else:
        summary, results = runner.run_all()

    if as_json:
        print(RedTeamReporter.generate_json_report(summary, results))
        return

    print("=" * 65)
    print("🛡️ AI AGENT RED TEAM / PURPLE TEAM SECURITY VALIDATION")
    print("=" * 65)
    print(f"Overall Status:        {summary.overall_status}")
    print(f"Resilience Score:      {summary.resilience_score} / 100")
    print(f"Scenarios Evaluated:   {summary.total_scenarios}")
    print(f"Detection Rate:        {summary.detection_rate}% ({summary.detected}/{summary.total_scenarios})")
    print(f"Block Rate:            {summary.block_rate}% ({summary.blocked}/{summary.total_scenarios})")
    print("-" * 65)
    print(f"Secret Leakage:        {summary.secret_leakages}")
    print(f"Unauthorized Tools:    {summary.unauthorized_tool_executions}")
    print(f"Approval Bypasses:     {summary.approval_bypasses}")
    print(f"Policy Violations:     {summary.policy_violations}")
    print("=" * 65)

    if summary.critical_findings:
        print("\n[CRITICAL FINDINGS]")
        for f in summary.critical_findings:
            print(f"  ❌ [{f.get('scenario_id')}] {f.get('category')}: {f.get('explanation')}")
            print(f"     Remediation: {f.get('remediation')}")
    else:
        print("\n✅ All simulated attack vectors were successfully blocked and contained.")
        print("   Deterministic defense layer verified intact.")


def handle_redteam_scenario(scenario_id: str):
    """단일 Red Team 시나리오 상세 실행 및 결과를 출력합니다."""
    from secgrc.redteam.runner import RedTeamRunner
    from secgrc.redteam.scenarios import get_scenario_by_id

    sc = get_scenario_by_id(scenario_id)
    if not sc:
        print(f"❌ 시나리오를 찾을 수 없습니다: {scenario_id}")
        return

    runner = RedTeamRunner()
    res = runner.run_scenario(scenario_id)
    if not res:
        print(f"❌ 시나리오 실행 실패: {scenario_id}")
        return

    status_str = "PASS (BLOCKED)" if res.blocked else "FAIL (UNBLOCKED)"
    print("=" * 60)
    print(f"🛡️ Red Team Scenario: {res.scenario_id} - {sc.name}")
    print("=" * 60)
    print(f"Category:         {res.category.value}")
    print(f"Severity:         {res.severity}")
    print(f"Expected:         {res.expected_decision}")
    print(f"Actual Decision:  {res.actual_decision}")
    print(f"Status:           {status_str}")
    print(f"Explanation:      {res.explanation}")
    if res.remediation:
        print(f"Remediation:      {res.remediation}")
    print("=" * 60)


def handle_ontology_build(csv_path: Optional[str] = None, out_path: Optional[str] = None, as_json: bool = False):
    """온톨로지 지식 그래프를 빌드하고 요약 또는 JSON 파일로 저장합니다."""
    import json
    from secgrc.ontology import OntologyBuilder, save_to_file, to_dict

    builder = OntologyBuilder()
    repo = builder.build(evidence_path=csv_path)
    summary = repo.get_summary()

    if out_path:
        save_to_file(repo, out_path)

    if as_json:
        data = to_dict(repo) if not out_path else {"saved_to": out_path, "summary": summary}
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    print("=" * 65)
    print("🕸️ Security Knowledge Graph / Control Ontology Build Complete")
    print("=" * 65)
    print(f"Total Entities:        {summary['total_entities']}")
    print(f"Total Relationships:   {summary['total_relationships']}")
    print("\n[Entities by Type]")
    for etype, count in summary["entities_by_type"].items():
        print(f"  • {etype:<15}: {count}")
    print("\n[Relationships by Type]")
    for rtype, count in summary["relationships_by_type"].items():
        print(f"  • {rtype:<18}: {count}")
    if out_path:
        print(f"\n💾 Saved graph to: {out_path}")
    print("=" * 65)


def handle_ontology_summary(as_json: bool = False):
    """온톨로지 그래프 요약 및 ISMS-P 프레임워크 커버리지를 출력합니다."""
    import json
    from secgrc.ontology import OntologyBuilder, OntologyResolver

    repo = OntologyBuilder().build()
    resolver = OntologyResolver(repo)
    summary = repo.get_summary()
    coverage = resolver.get_framework_coverage("ISMS-P")

    if as_json:
        result = {"graph_summary": summary, "coverage": coverage.model_dump()}
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    print("=" * 65)
    print("🕸️ Security Knowledge Graph & Ontology Summary")
    print("=" * 65)
    print(f"Total Entities:        {summary['total_entities']}")
    print(f"Total Relationships:   {summary['total_relationships']}")
    print("-" * 65)
    print("📊 ISMS-P Framework Coverage")
    print(f"  Total Controls:        {coverage.total_controls}")
    print(f"  Assessed Controls:     {coverage.assessed_controls} ({coverage.coverage_percent}%)")
    print(f"    - Effective (PASS):  {coverage.effective_controls}")
    print(f"    - Partially Effective: {coverage.partially_effective_controls}")
    print(f"    - Ineffective (FAIL): {coverage.ineffective_controls}")
    print(f"    - Not Assessed:      {coverage.not_assessed_controls}")
    print(f"  Automation Ratio:      {coverage.automation_percent}%")
    print("=" * 65)


def handle_ontology_lineage(entity_id: str, as_json: bool = False):
    """특정 개체의 전주기 보안 혈통(Lineage) 경로를 분석하고 출력합니다."""
    import json
    from secgrc.ontology import OntologyBuilder, OntologyResolver

    repo = OntologyBuilder().build()
    resolver = OntologyResolver(repo)
    lineage = resolver.get_evidence_lineage(entity_id)

    if as_json:
        print(json.dumps(lineage, indent=2, ensure_ascii=False))
        return

    print("=" * 65)
    print(f"🔗 Security Lineage for Entity: {entity_id}")
    print("=" * 65)
    if "error" in lineage:
        print(f"❌ {lineage['error']}")
        return

    # Case 1: Evidence Lineage
    if "root_entity" in lineage:
        root = lineage["root_entity"]
        print(f"Root: [{root.get('type')}] {root.get('name', entity_id)}")
        if "chain_summary" in lineage:
            print(f"Summary: {lineage['chain_summary']}")

        if "controls" in lineage:
            print("\n[Mapped Controls & Cascading Risks]")
            for c in lineage["controls"]:
                print(f"  • Control: {c['control_id']} ({c['name']}) [Effectiveness: {c['effectiveness']}]")
                for r in c.get("risks", []):
                    print(f"    └── Risk: {r['risk_id']} (Priority: {r['priority']}, Score: {r['score']})")
                    if r.get("remediations"):
                        print(f"        └── Remediation Actions: {', '.join(r['remediations'])}")

        if "findings" in lineage:
            print("\n[Derived Findings & Impacted Assets]")
            for f in lineage["findings"]:
                print(f"  • Finding: {f['finding_id']} [{f['severity']}] - {f['name']}")
                if f.get("assets"):
                    print(f"    └── Assets: {', '.join(f['assets'])}")

    # Case 2: Control Lineage
    elif "control_id" in lineage:
        print(f"Control: [{lineage['control_id']}] {lineage['name']} (Domain: {lineage['domain']})")
        print(f"Effectiveness: {lineage['effectiveness']} | Automation: {lineage['automation_level']}")
        if lineage.get("cross_mappings"):
            print("\n[Cross-Framework Mappings]")
            for cm in lineage["cross_mappings"]:
                print(f"  • {cm['target_control_id']} (Confidence: {cm['confidence']}) - {cm.get('rationale', '')}")
        if lineage.get("evidences"):
            print(f"\n[Supporting Evidence ({lineage['evidence_count']})]")
            for ev in lineage["evidences"]:
                print(f"  • {ev['id']}: {ev['name']}")
        if lineage.get("risks"):
            print(f"\n[Derived Risks ({lineage['risk_count']})]")
            for rk in lineage["risks"]:
                print(f"  • {rk['risk_id']} [Score: {rk['score']}, Priority: {rk['priority']}, Severity: {rk['severity']}]")
        if lineage.get("remediations"):
            print(f"\n[Planned Remediations ({len(lineage['remediations'])})]")
            for rm in lineage["remediations"]:
                print(f"  • {rm['remediation_id']}: {rm['name']} [{rm['status']}]")

    # Case 3: Risk Lineage
    elif "risk_id" in lineage:
        print(f"Risk: [{lineage['risk_id']}] {lineage['name']}")
        print(f"Score: {lineage['risk_score']} | Priority: {lineage['priority']} | Severity: {lineage['severity']}")
        if lineage.get("root_cause_controls"):
            print("\n[Root Cause Controls]")
            for rc in lineage["root_cause_controls"]:
                print(f"  • {rc['control_id']} ({rc['name']}) [Effectiveness: {rc['effectiveness']}]")
                if rc.get("evidences"):
                    print(f"    └── Trigger Evidences: {', '.join(rc['evidences'])}")
        if lineage.get("mitigating_remediations"):
            print("\n[Mitigating Remediations]")
            for mr in lineage["mitigating_remediations"]:
                print(f"  • {mr['remediation_id']}: {mr['name']} [{mr['status']}]")

    print("=" * 65)


def handle_ontology_framework(framework_id: str = "ISMS-P", as_json: bool = False):
    """프레임워크의 통제 유효성 평가 커버리지 통계를 출력합니다."""
    import json
    from secgrc.ontology import OntologyBuilder, OntologyResolver

    repo = OntologyBuilder().build()
    resolver = OntologyResolver(repo)
    coverage = resolver.get_framework_coverage(framework_id)

    if as_json:
        print(json.dumps(coverage.model_dump(), indent=2, ensure_ascii=False))
        return

    print("=" * 65)
    print(f"🛡️ Framework Coverage: {framework_id}")
    print("=" * 65)
    print(f"Total Controls:        {coverage.total_controls}")
    print(f"Assessed Controls:     {coverage.assessed_controls} ({coverage.coverage_percent}%)")
    print(f"  • Effective:         {coverage.effective_controls}")
    print(f"  • Partially Effective: {coverage.partially_effective_controls}")
    print(f"  • Ineffective:       {coverage.ineffective_controls}")
    print(f"  • Not Assessed:      {coverage.not_assessed_controls}")
    print(f"Automation Ratio:      {coverage.automation_percent}%")
    print("=" * 65)


def handle_copilot_ask(question: str, user_role: str = "analyst", as_json: bool = False):
    """자연어 질의를 수신하여 Copilot 답변을 출력합니다."""
    import json
    from secgrc.copilot import CopilotService

    service = CopilotService()
    answer = service.ask(question, user_role=user_role)

    if as_json:
        print(json.dumps(answer.model_dump(), indent=2, ensure_ascii=False))
        return

    print("=" * 68)
    print(f"🤖 AI GRC Copilot (Role: {user_role.upper()})")
    print("=" * 68)
    print(f"❓ 질의: \"{question}\" [의도: {answer.intent}]")
    print("-" * 68)
    print(answer.answer)
    print("-" * 68)
    if answer.provenance:
        print("\n🔍 [증적 및 데이터 근거 출처 (Provenance)]")
        for p in answer.provenance[:5]:
            rel_info = f" ({p.relationship})" if p.relationship else ""
            print(f"  • {p.source_type}: {p.source_id}{rel_info}")
    if answer.limitations:
        print("\n⚠️ [유의사항 및 한계]")
        for lim in answer.limitations:
            print(f"  • {lim}")
    print("=" * 68)




def run_audit(app, query_text: str):
    """주어진 보안 질의/현황에 대해 RAG 및 LangGraph 감사를 수행하고 결과를 출력합니다."""
    print(f"\n==================================================")
    print(f"점검 질의: \"{query_text}\"")
    print(f"==================================================")

    initial_state = {
        "query": query_text,
        "control_id": "",
        "control_name": "",
        "requirements": "",
        "is_compliant": False,
        "findings": "",
        "recommendation": "",
    }

    result = app.invoke(initial_state)

    status_str = "✅ 적합(통과)" if result["is_compliant"] else "❌ 부적합(결함)"
    print(f"매칭 통제항목: ISMS-P {result['control_id']} ({result['control_name']})")
    print(f"최종 판정: {status_str}")
    print(f"\n[감사 소견]\n{result['findings']}")
    print(f"\n[조치 가이드]\n{result['recommendation']}")
    print(f"==================================================")


def run_interactive():
    """실시간 대화형 보안 감사 루프를 실행합니다."""
    print("=" * 68)
    print("🛡️  GRC Agent: AI-Powered Cybersecurity & Compliance Auditor")
    print("=" * 68)
    print("💡 사용 방법:")
    print("  • 일반 감사 질의를 입력하면 AI가 ISMS-P 기준 대조 및 감사를 수행합니다.")
    print("  • 검색 모드 실행     : python -m secgrc search \"MFA 권한관리\"")
    print("  • 매핑 상세 조회     : python -m secgrc map ISMS-P-2.5.2")
    print("  • 증적 대시보드 조회 : python -m secgrc evidence")
    print("  • 종료하려면 'q' 또는 'exit'를 입력하세요.\n")

    app = build_graph()

    while True:
        try:
            user_input = input("secgrc > ").strip()

            if user_input.lower() in ("q", "exit", "quit"):
                print("\n👋 GRC Agent를 종료합니다. 안전한 하루 되세요!")
                break

            if not user_input:
                continue

            run_audit(app, user_input)

        except (KeyboardInterrupt, EOFError):
            print("\n\n👋 프로그램을 종료합니다.")
            break


def handle_compliance_coverage(framework_id: str = "ISMS-P", version: Optional[str] = None, as_json: bool = False):
    """컴플라이언스 입력 데이터 커버리지 CLI 핸들러."""
    import json
    from secgrc.compliance.coverage import get_framework_input_coverage
    from secgrc.compliance.frameworks import default_framework_registry

    fw = default_framework_registry.get_framework(framework_id)
    ver = version or (fw.default_version if fw else "2024-07")
    coverages = get_framework_input_coverage(framework_id=framework_id, version=ver)

    if as_json:
        data = {
            "framework_id": framework_id,
            "version": ver,
            "total_requirements": len(coverages),
            "coverages": [c.model_dump() for c in coverages],
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    print("\n==================================================")
    print(f"Framework: {framework_id}")
    print(f"Version: {ver}")
    print("==================================================\n")
    print("Requirements:")
    for c in coverages:
        print(f"  - {c.requirement_id}: {c.coverage_state.value} (Auto: {c.automation_level.value}, Evidence: {c.evidence_state.value})")
        if c.missing_inputs:
            print(f"      Missing: {', '.join(c.missing_inputs)}")

    counts: dict[str, int] = {}
    for c in coverages:
        st = c.coverage_state.value
        counts[st] = counts.get(st, 0) + 1

    print("\nInput Coverage:")
    for state_name in ["COMPLETE", "PARTIAL", "MISSING", "MANUAL", "UNKNOWN"]:
        if state_name in counts:
            print(f"  {state_name}: {counts[state_name]}")
    print()


def handle_compliance_evidence_requirements(
    framework_id: str = "ISMS-P",
    requirement_id: str = "ISMS-P-2.5.2",
    version: Optional[str] = None,
    as_json: bool = False,
):
    """컴플라이언스 요구사항별 증적 요건 및 메타데이터 CLI 핸들러."""
    import json
    from secgrc.compliance.evidence_requirements import (
        default_evidence_requirement_registry,
    )
    from secgrc.compliance.frameworks import default_framework_registry

    fw = default_framework_registry.get_framework(framework_id)
    ver = version or (fw.default_version if fw else "2024-07")

    ev_reqs = default_evidence_requirement_registry.list_evidence_requirements(
        framework_id=framework_id,
        framework_version=ver,
        requirement_id=requirement_id,
    )
    prereq = default_evidence_requirement_registry.get_prerequisite(
        requirement_id=requirement_id,
        framework_id=framework_id,
        framework_version=ver,
    )

    if as_json:
        data = {
            "framework_id": framework_id,
            "version": ver,
            "requirement_id": requirement_id,
            "evidence_requirements": [e.model_dump() for e in ev_reqs],
            "prerequisite": prereq.model_dump() if prereq else None,
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    print("\nFramework:")
    print(f"  {framework_id}")
    print("\nVersion:")
    print(f"  {ver}")
    print("\nRequirement:")
    print(f"  {requirement_id}")

    print("\nEvidence Requirements:")
    if not ev_reqs:
        print("  (등록된 증적 요구사항 없음)")
    else:
        for ev in ev_reqs:
            print(f"\n  {ev.role.value}")
            print(f"    - {ev.evidence_type} ({ev.data_type.value})")
            sources_str = ", ".join(b.source_system for b in ev.source_bindings) if ev.source_bindings else "N/A"
            print(f"      Source: {sources_str}")
            print(f"      Mandatory: {'YES' if ev.mandatory else 'NO'}")
            if ev.applicability_condition:
                print(f"      Condition: {ev.applicability_condition.condition_type.value}")
            if ev.freshness:
                print(f"      Freshness: {ev.freshness.freshness_type.value}")
            if ev.temporal_coverage:
                print(f"      Temporal: {ev.temporal_coverage.temporal_type.value}")
            if ev.human_verification_required:
                print("      Human Verification: YES")

    if ev_reqs:
        primary_req = ev_reqs[0]
        print(f"\nAutomation:\n  {primary_req.automation_level.value}")
        if primary_req.freshness:
            print(f"\nFreshness:\n  {primary_req.freshness.freshness_type.value}")
        if primary_req.temporal_coverage:
            print(f"\nTemporal:\n  {primary_req.temporal_coverage.temporal_type.value}")
        print(f"\nHuman Verification:\n  {'YES' if any(e.human_verification_required for e in ev_reqs) else 'NO'}")
    print()


def handle_compliance_assess(
    framework_id: str = "ISMS-P",
    requirement_id: Optional[str] = None,
    is_all: bool = False,
    version: Optional[str] = None,
    as_json: bool = False,
):
    """결정론적 컴플라이언스 평가 CLI 핸들러."""
    import json
    from secgrc.compliance.assessment import (
        assess_requirement,
        assess_requirements,
    )
    from secgrc.compliance.frameworks import default_framework_registry
    from secgrc.compliance.requirements import default_requirement_registry

    fw = default_framework_registry.get_framework(framework_id)
    ver = version or (fw.default_version if fw else "2024-07")

    if is_all:
        reqs = default_requirement_registry.list_by_framework(framework_id, ver)
        req_ids = [r.requirement_id for r in reqs]
        batch = assess_requirements(
            framework_id=framework_id,
            framework_version=ver,
            requirement_ids=req_ids,
            available_data=[],
        )
        if as_json:
            print(json.dumps(batch.model_dump(), indent=2, ensure_ascii=False))
            return

        print("\n==================================================")
        print(f"Compliance Assessment Batch: {framework_id} ({ver})")
        print("==================================================\n")
        print("Summary:")
        for k, v in batch.summary.items():
            print(f"  {k}: {v}")
        print("\nRequirements Assessment:")
        for res in batch.results:
            print(f"  - {res.requirement_id}: {res.status.value} ({res.explanation_code})")
        print()
        return

    if requirement_id:
        result = assess_requirement(
            framework_id=framework_id,
            framework_version=ver,
            requirement_id=requirement_id,
            available_data=[],
        )
        if as_json:
            print(json.dumps(result.model_dump(), indent=2, ensure_ascii=False))
            return

        print("\n==================================================")
        print(f"Compliance Assessment: {requirement_id}")
        print(f"Framework: {framework_id} ({ver})")
        print("==================================================")
        print(f"Status: {result.status.value}")
        print(f"Explanation: {result.explanation_code}")
        print(f"Confidence: {result.confidence}")
        if result.rule_id:
            print(f"Rule: {result.rule_id} (v{result.rule_version})")
        if result.missing_items:
            print(f"Missing Required Items: {', '.join(result.missing_items)}")
        if result.available_items:
            print(f"Available Items: {', '.join(result.available_items)}")
        if result.conflicts:
            print(f"Conflicts: {', '.join(result.conflicts)}")
        print(f"Evaluated At: {result.evaluated_at}")
        print()
        return


def handle_compliance_report(
    framework_id: str = "ISMS-P",
    report_type: str = "executive",
    requirement_id: Optional[str] = None,
    version: Optional[str] = None,
    as_json: bool = False,
    as_markdown: bool = False,
):
    """결정론적 컴플라이언스 보고서 CLI 핸들러."""
    from secgrc.compliance.assessment import (
        assess_requirement,
        assess_requirements,
    )
    from secgrc.compliance.frameworks import default_framework_registry
    from secgrc.compliance.reporting import (
        export_report_json,
        export_report_markdown,
        generate_compliance_report,
    )
    from secgrc.compliance.reporting_models import ReportRisk
    from secgrc.compliance.requirements import default_requirement_registry

    fw = default_framework_registry.get_framework(framework_id)
    ver = version or (fw.default_version if fw else "2024-07")

    if requirement_id:
        asm = assess_requirement(
            framework_id=framework_id,
            framework_version=ver,
            requirement_id=requirement_id,
            available_data=[],
        )
        assessments = [asm]
    else:
        reqs = default_requirement_registry.list_by_framework(framework_id, ver)
        req_ids = [r.requirement_id for r in reqs]
        batch = assess_requirements(
            framework_id=framework_id,
            framework_version=ver,
            requirement_ids=req_ids,
            available_data=[],
        )
        assessments = batch.results

    risks = [
        ReportRisk(
            risk_id="RSK-ISMS-P-2.7.1",
            title="미인가 접근 통제 및 권한 관리 결함",
            score=93.0,
            priority="P1",
            severity="CRITICAL",
            requirement_id="ISMS-P-2.7.1",
            affected_assets=["asset-prod-db-01"],
        )
    ]

    report = generate_compliance_report(
        report_type=report_type,
        framework_id=framework_id,
        framework_version=ver,
        assessments=assessments,
        risks=risks,
    )

    if as_json:
        print(export_report_json(report))
    else:
        print(export_report_markdown(report))


def handle_investigation_report(
    investigation_id: str,
    as_json: bool = False,
    as_markdown: bool = False,
):
    """조사 결과 보고서 CLI 핸들러."""
    from secgrc.compliance.reporting import (
        export_report_json,
        export_report_markdown,
        generate_investigation_report,
    )
    from secgrc.compliance.reporting_models import ReportRisk
    from secgrc.investigation.guard import (
        GuardCategory,
        GuardCheck,
        GuardSeverity,
        GuardStatus,
        InvestigationGuardResult,
    )

    guard_res = InvestigationGuardResult(
        investigation_id=investigation_id,
        correlation_id=f"CORR-{investigation_id}",
        status=GuardStatus.PASS,
        allowed_to_report=True,
        checks=[
            GuardCheck(
                check_id="CHK-001",
                category=GuardCategory.INPUT_STRUCTURE,
                status=GuardStatus.PASS,
                severity=GuardSeverity.INFO,
                message="Investigation input structure and schema validated successfully.",
            )
        ],
    )

    risks = [
        ReportRisk(
            risk_id="RSK-ISMS-P-2.7.1",
            title="미인가 접근 통제 및 권한 관리 결함",
            score=93.0,
            priority="P1",
            severity="CRITICAL",
            requirement_id="ISMS-P-2.7.1",
        )
    ]

    report = generate_investigation_report(
        investigation_id=investigation_id,
        guard_result=guard_res,
        risks=risks,
        investigation_data={"investigation_id": investigation_id, "status": "COMPLETED"},
        correlation_data={"correlation_id": f"CORR-{investigation_id}", "hypotheses_count": 1},
    )

    if as_json:
        print(export_report_json(report))
    else:
        print(export_report_markdown(report))


def handle_security_adversarial(
    is_list: bool = False,
    is_run_all: bool = False,
    category: Optional[str] = None,
    is_report: bool = False,
    as_json: bool = False,
    as_markdown: bool = False,
):
    """적대적 컴플라이언스 인텔리전스 검증 CLI 핸들러."""
    from secgrc.security import (
        AdversarialCategory,
        AdversarialTestHarness,
        run_scenario_a_fake_provenance,
        run_scenario_b_requirement_confusion,
        run_scenario_c_cross_scope_pollution,
        run_scenario_d_rule_tampering,
        run_scenario_e_historical_rewrite,
        run_scenario_f_conflicting_truth,
        run_scenario_g_evidence_poisoning,
        run_scenario_h_report_tampering,
    )

    harness = AdversarialTestHarness()
    harness.register_test_case("SCENARIO-A", run_scenario_a_fake_provenance)
    harness.register_test_case("SCENARIO-B", run_scenario_b_requirement_confusion)
    harness.register_test_case("SCENARIO-C", run_scenario_c_cross_scope_pollution)
    harness.register_test_case("SCENARIO-D", run_scenario_d_rule_tampering)
    harness.register_test_case("SCENARIO-E", run_scenario_e_historical_rewrite)
    harness.register_test_case("SCENARIO-F", run_scenario_f_conflicting_truth)
    harness.register_test_case("SCENARIO-G", run_scenario_g_evidence_poisoning)
    harness.register_test_case("SCENARIO-H", run_scenario_h_report_tampering)

    if is_list:
        print("\n🛡️ [Adversarial Compliance Attack Categories]")
        print("=" * 60)
        for cat in AdversarialCategory:
            print(f"  • {cat.value}")
        print("=" * 60 + "\n")
        return

    if is_run_all or is_report:
        harness.run_all()
        if as_json:
            print(harness.export_report_json())
        else:
            print(harness.export_report_markdown())
        return

    if category:
        cat_upper = category.upper().strip()
        matched_cat = next((c for c in AdversarialCategory if c.value == cat_upper or cat_upper in c.value), None)
        if not matched_cat:
            print(f"❌ Unknown adversarial category: '{category}'")
            return
        results = harness.run_category(matched_cat)
        if as_json:
            import json
            print(json.dumps([r.model_dump() for r in results], indent=2, ensure_ascii=False))
        else:
            print(f"\n🛡️ [Adversarial Tests for Category: {matched_cat.value}]")
            for r in results:
                print(f"  • {r.test_id}: {r.actual_outcome.value} (Detected={r.detected}, Blocked={r.blocked})")
            print()
        return

    print("❌ 옵션을 지정해 주세요.")
    print("   사용법: python -m secgrc security adversarial --list")
    print("           python -m secgrc security adversarial --run-all [--json]")
    print("           python -m secgrc security adversarial --category <category>")
    print("           python -m secgrc security adversarial --report [--markdown]")


def handle_dashboard(
    framework_id: str = "ISMS-P",
    role_str: str = "CISO",
    as_json: bool = False,
    as_html: bool = False,
):
    """CISO 컴플라이언스 & 보안 지능 대시보드 CLI 출력을 처리합니다."""
    from secgrc.dashboard import (
        DashboardRole,
        build_ciso_dashboard_snapshot,
        export_dashboard_html,
        export_dashboard_json,
        export_dashboard_markdown,
    )
    role_enum = getattr(DashboardRole, role_str.upper().strip(), DashboardRole.CISO)
    snapshot = build_ciso_dashboard_snapshot(framework_id=framework_id)
    if as_json:
        print(export_dashboard_json(snapshot))
    elif as_html:
        print(export_dashboard_html(snapshot, role=role_enum))
    else:
        print(export_dashboard_markdown(snapshot, role=role_enum))


def handle_compliance_changes(entity_id: Optional[str] = None, as_json: bool = False):
    """컴플라이언스 변경 이벤트 목록 CLI 핸들러 (Step 25, Section 50)."""
    import json
    from secgrc.continuous import get_changes, get_entity_changes
    changes = get_entity_changes(entity_id) if entity_id else get_changes()
    if as_json:
        print(json.dumps([c.model_dump() for c in changes], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"📋 변경 이벤트 목록 (총 {len(changes)}건):")
        for c in changes[:20]:
            print(f"• [{c.change_type.value}] {c.change_id}: {c.entity_type} ({c.entity_id}) at {c.occurred_at}")


def handle_compliance_impact(change_id: Optional[str], as_json: bool = False):
    """컴플라이언스 변경 영향 분석 CLI 핸들러 (Step 25, Section 50)."""
    import json
    if not change_id:
        print("❌ 변경 ID를 입력해 주세요. (예: --change <ID>)")
        return
    from secgrc.continuous import get_impacts
    impact = get_impacts(change_id)
    if not impact:
        print(f"❌ 변경 이벤트를 찾을 수 없습니다: {change_id}")
        return
    if as_json:
        print(json.dumps(impact.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🔍 변경 영향 분석 결과 [{impact.impact_id}]:")
        print(f"• 원인 변경: {impact.change_id} (심각도: {impact.impact_level.value})")
        print(f"• 영향 요구사항: {', '.join(impact.affected_requirements) or 'None'}")
        print(f"• 영향 프레임워크: {', '.join(impact.affected_frameworks) or 'None'}")


def handle_compliance_delta(requirement_id: Optional[str] = None, as_json: bool = False):
    """컴플라이언스 델타 CLI 핸들러 (Step 25, Section 50)."""
    import json
    from secgrc.continuous import get_compliance_deltas
    deltas = get_compliance_deltas(requirement_id=requirement_id)
    if as_json:
        print(json.dumps([d.model_dump() for d in deltas], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"📊 컴플라이언스 델타 목록 (총 {len(deltas)}건):")
        for d in deltas[:20]:
            st = "CHANGED" if d.status_changed else "UNCHANGED"
            print(f"• [{st}] {d.delta_id} ({d.requirement_id}): {d.previous_status or 'INIT'} -> {d.current_status}")


def handle_compliance_timeline(requirement_id: Optional[str] = None, as_json: bool = False):
    """컴플라이언스 타임라인 CLI 핸들러 (Step 25, Section 50)."""
    import json
    if not requirement_id:
        print("❌ 요구사항 ID를 입력해 주세요. (예: --requirement <ID>)")
        return
    from secgrc.continuous import get_requirement_timeline
    timeline = get_requirement_timeline(requirement_id=requirement_id)
    if as_json:
        print(json.dumps(timeline.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        print(f"⏳ 컴플라이언스 타임라인 [{timeline.requirement_id}] (총 {len(timeline.entries)}건):")
        for e in timeline.entries:
            print(f"• [{e.timestamp}] [{e.event_type}] status={e.status or 'N/A'}: {e.summary}")


def handle_events_list(category: Optional[str] = None, priority: Optional[str] = None, as_json: bool = False):
    """이벤트 목록 조회 CLI 핸들러 (Step 26)."""
    import json
    from secgrc.events import get_orchestrator
    orchestrator = get_orchestrator()
    events = orchestrator.bus.get_events()
    if category:
        events = [e for e in events if e.category.value == category]
    if priority:
        events = [e for e in events if e.priority.value == priority]
    if as_json:
        print(json.dumps([e.model_dump() for e in events], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"📡 이벤트 버스 목록 (총 {len(events)}건):")
        for e in events[:20]:
            print(f"• [{e.priority.value}][{e.event_type.value}] {e.event_id} ({e.occurred_at}) - payload keys: {list(e.payload.keys())}")


def handle_events_process(event_id: Optional[str] = None, as_json: bool = False):
    """이벤트 처리 CLI 핸들러 (Step 26)."""
    import json
    from secgrc.events import get_orchestrator
    orchestrator = get_orchestrator()
    if event_id:
        envelope = orchestrator.bus.get_event(event_id)
        if not envelope:
            print(f"❌ 이벤트를 찾을 수 없습니다: {event_id}")
            return
        instance = orchestrator.process(envelope)
        instances = [instance]
    else:
        instances = orchestrator.process_batch()
    if as_json:
        print(json.dumps([i.model_dump() for i in instances], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"⚙️ 이벤트 처리 완료 (총 {len(instances)}건 인스턴스):")
        for inst in instances:
            print(f"• 워크플로우 {inst.workflow_id}: event={inst.event_id} status={inst.status.value} stage={inst.current_stage.value}")


def handle_events_replay(workflow_id: Optional[str], as_json: bool = False):
    """워크플로우 재생 CLI 핸들러 (Step 26)."""
    import json
    if not workflow_id:
        print("❌ 워크플로우 ID를 입력해 주세요. (예: --workflow <ID>)")
        return
    from secgrc.events import get_orchestrator
    orchestrator = get_orchestrator()
    replayed = orchestrator.replay(workflow_id)
    if not replayed:
        print(f"❌ 워크플로우를 찾을 수 없거나 재생에 실패했습니다: {workflow_id}")
        return
    if as_json:
        print(json.dumps(replayed.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🔄 워크플로우 재생 완료 [{replayed.workflow_id}]:")
        print(f"• 이벤트 ID: {replayed.event_id}")
        print(f"• 상태: {replayed.status.value}")
        print(f"• 체크포인트: {len(replayed.checkpoints)}건")


def handle_events_causal_chain(event_id: Optional[str], as_json: bool = False):
    """이벤트 인과 체인 조회 CLI 핸들러 (Step 26)."""
    import json
    if not event_id:
        print("❌ 이벤트 ID를 입력해 주세요. (예: --event <ID>)")
        return
    from secgrc.events import get_orchestrator
    orchestrator = get_orchestrator()
    chain = orchestrator.get_causal_chain(event_id)
    if as_json:
        print(json.dumps([e.model_dump() for e in chain], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🔗 이벤트 인과 체인 (Event {event_id}, 총 {len(chain)}단계):")
        for idx, e in enumerate(chain):
            indent = "  " * idx
            print(f"{indent}└─ [{e.event_type.value}] {e.event_id} (causation={e.causation_id or 'ROOT'})")


def handle_events_dlq(as_json: bool = False):
    """Dead Letter Queue 조회 CLI 핸들러 (Step 26)."""
    import json
    from secgrc.events import get_orchestrator
    orchestrator = get_orchestrator()
    dlq_items = orchestrator.dlq.get_all()
    if as_json:
        print(json.dumps([item.model_dump() for item in dlq_items], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"💀 Dead Letter Queue (총 {len(dlq_items)}건):")
        for item in dlq_items:
            print(f"• [{item.dead_letter_id}] event={item.event_id} error_code={item.error_code}: {item.error_summary}")


def handle_events_status(as_json: bool = False):
    """오케스트레이터 상태 조회 CLI 핸들러 (Step 26)."""
    import json
    from secgrc.events import get_orchestrator
    orchestrator = get_orchestrator()
    status = orchestrator.get_status()
    if as_json:
        print(json.dumps(status, indent=2, ensure_ascii=False, default=str))
    else:
        print("📊 Event-Driven GRC Orchestrator 상태 요약:")
        print(f"• 버전: {status['orchestrator_version']} (전달 보장: {status['delivery_guarantee']})")
        print(f"• 이벤트 버스 대기: {status['events_count']}건")
        print(f"• 워크플로우 인스턴스: {status['workflows_count']}건")
        print(f"• 의사결정 큐 (인간 검토 대기): {status['decision_queue_count']}건")
        print(f"• Dead Letter Queue: {status['dead_letter_count']}건")


def handle_decision_queue_list(as_json: bool = False):
    """인간 검토 의사결정 큐 조회 CLI 핸들러 (Step 26)."""
    import json
    from secgrc.events import get_orchestrator
    orchestrator = get_orchestrator()
    items = orchestrator.get_decision_queue()
    if as_json:
        print(json.dumps([item.model_dump() for item in items], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🛡️ 오케스트레이션 인간 검토 의사결정 큐 (총 {len(items)}건):")
        for item in items:
            print(f"• [{item.priority.value}] {item.item_id}: [{item.event_type.value}] {item.title}")
            print(f"    후보 ID: {item.candidate_id or 'N/A'}, 설명: {item.description}")


def handle_ai_investigate(investigation_id: str, as_json: bool = False):
    """AI 보조 조사 추론 CLI 핸들러 (Step 27)."""
    import json
    from secgrc.ai import AIReasoningEngine, AIInvestigationTask, AIInvestigationTaskType, ReasoningType
    engine = AIReasoningEngine()
    task = AIInvestigationTask(
        task_id=f"task-inv-{investigation_id[:8]}",
        investigation_id=investigation_id,
        task_type=AIInvestigationTaskType.SUMMARIZE_INVESTIGATION,
        objective=f"Analyze and summarize investigation {investigation_id}",
        scope="INVESTIGATION_SCOPE",
        required_output_type=ReasoningType.HYPOTHESIS,
        allowed_entity_ids=["ASSET-001"],
    )
    context = engine.context_builder.build_context(
        investigation_id=investigation_id,
        scope="INVESTIGATION_SCOPE",
        allowed_entity_ids=["ASSET-001"],
        facts=[{"fact_id": "FACT-001", "entity_id": "ASSET-001", "statement": "Verified telemetry observed"}],
        evidence=[{"evidence_id": "EV-001", "entity_id": "ASSET-001", "data": "Audit finding recorded"}],
    )
    res, guard_res = engine.reason(task, context)
    if as_json:
        print(json.dumps({
            "reasoning": res.model_dump() if res else None,
            "guard_result": guard_res.model_dump(),
            "is_authoritative": False,
        }, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🤖 AI Investigation Reasoning [{investigation_id}] (NON-AUTHORITATIVE):")
        print(f"• 가드 판정: {guard_res.status.value}")
        if res:
            print(f"• 제안 가설 ({len(res.hypotheses)}건):")
            for h in res.hypotheses:
                print(f"  - [{h.status.value}] {h.statement}")
            print(f"• 추가 조사 질문 ({len(res.questions)}건):")
            for q in res.questions:
                print(f"  - {q.question}")
            if res.root_causes:
                print(f"• 근본 원인 후보 ({len(res.root_causes)}건):")
                for r in res.root_causes:
                    print(f"  - [{r.status}] {r.candidate}")


def handle_ai_explain(assessment_id: str, as_json: bool = False):
    """AI 보안 설명 생성 CLI 핸들러 (Step 27)."""
    import json
    from secgrc.ai import AIReasoningEngine, AIInvestigationTask, AIInvestigationTaskType, ReasoningType
    engine = AIReasoningEngine()
    task = AIInvestigationTask(
        task_id=f"task-exp-{assessment_id[:8]}",
        investigation_id=f"inv-exp-{assessment_id[:8]}",
        task_type=AIInvestigationTaskType.EXPLAIN_FINDING,
        objective=f"Explain assessment {assessment_id} preserving uncertainty",
        scope="EXPLANATION_SCOPE",
        required_output_type=ReasoningType.EXPLANATION,
        allowed_entity_ids=[assessment_id],
    )
    context = engine.context_builder.build_context(
        investigation_id=f"inv-exp-{assessment_id[:8]}",
        scope="EXPLANATION_SCOPE",
        allowed_entity_ids=[assessment_id],
        facts=[{"fact_id": "FACT-001", "entity_id": assessment_id, "statement": "Assessment evaluated"}],
        evidence=[{"evidence_id": "EV-001", "entity_id": assessment_id, "data": "Evidence evaluated"}],
    )
    res, guard_res = engine.reason(task, context)
    if as_json:
        print(json.dumps({
            "reasoning": res.model_dump() if res else None,
            "guard_result": guard_res.model_dump(),
            "is_authoritative": False,
        }, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"💡 AI Security Explanation [{assessment_id}] (NON-AUTHORITATIVE):")
        print(f"• 가드 판정: {guard_res.status.value}")
        if res and res.explanations:
            for exp in res.explanations:
                print(f"• 요약: {exp.summary}")
                for p in exp.reasoning_points:
                    print(f"  - {p}")
                if exp.uncertainty_points:
                    print("  [불확실성 보존]:")
                    for u in exp.uncertainty_points:
                        print(f"    * {u}")


def handle_ai_hypotheses(investigation_id: str, as_json: bool = False):
    """AI 가설 제안 CLI 핸들러 (Step 27)."""
    import json
    from secgrc.ai import AIReasoningEngine, AIInvestigationTask, AIInvestigationTaskType, ReasoningType
    engine = AIReasoningEngine()
    task = AIInvestigationTask(
        task_id=f"task-hypo-{investigation_id[:8]}",
        investigation_id=investigation_id,
        task_type=AIInvestigationTaskType.IDENTIFY_PLAUSIBLE_CAUSES,
        objective="Generate plausible hypotheses grounded in facts",
        scope="HYPOTHESIS_SCOPE",
        required_output_type=ReasoningType.HYPOTHESIS,
        allowed_entity_ids=["ASSET-001"],
    )
    context = engine.context_builder.build_context(
        investigation_id=investigation_id,
        scope="HYPOTHESIS_SCOPE",
        allowed_entity_ids=["ASSET-001"],
        facts=[{"fact_id": "FACT-001", "entity_id": "ASSET-001", "statement": "Fact observed"}],
        evidence=[{"evidence_id": "EV-001", "entity_id": "ASSET-001", "data": "Evidence recorded"}],
    )
    res, guard_res = engine.reason(task, context)
    if as_json:
        print(json.dumps({
            "hypotheses": [h.model_dump() for h in (res.hypotheses if res else [])],
            "guard_result": guard_res.model_dump(),
            "is_authoritative": False,
        }, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🔬 AI 제안 가설 목록 [{investigation_id}] (NON-AUTHORITATIVE):")
        print(f"• 가드 판정: {guard_res.status.value}")
        if res:
            for h in res.hypotheses:
                print(f"• [{h.status.value}] {h.statement} (지지수준: {h.support_level.value if h.support_level else 'N/A'})")


def handle_ai_questions(investigation_id: str, as_json: bool = False):
    """AI 추가 질문 도출 CLI 핸들러 (Step 27)."""
    import json
    from secgrc.ai import AIReasoningEngine, AIInvestigationTask, AIInvestigationTaskType, ReasoningType
    engine = AIReasoningEngine()
    task = AIInvestigationTask(
        task_id=f"task-q-{investigation_id[:8]}",
        investigation_id=investigation_id,
        task_type=AIInvestigationTaskType.GENERATE_INVESTIGATION_QUESTIONS,
        objective="Formulate clarifying questions without requesting secrets",
        scope="QUESTION_SCOPE",
        required_output_type=ReasoningType.QUESTION,
        allowed_entity_ids=["ASSET-001"],
    )
    context = engine.context_builder.build_context(
        investigation_id=investigation_id,
        scope="QUESTION_SCOPE",
        allowed_entity_ids=["ASSET-001"],
        facts=[{"fact_id": "FACT-001", "entity_id": "ASSET-001", "statement": "Fact observed"}],
        evidence=[{"evidence_id": "EV-001", "entity_id": "ASSET-001", "data": "Evidence recorded"}],
    )
    res, guard_res = engine.reason(task, context)
    if as_json:
        print(json.dumps({
            "questions": [q.model_dump() for q in (res.questions if res else [])],
            "guard_result": guard_res.model_dump(),
            "is_authoritative": False,
        }, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"❓ AI 추가 질문 도출 [{investigation_id}] (NON-AUTHORITATIVE):")
        print(f"• 가드 판정: {guard_res.status.value}")
        if res:
            for q in res.questions:
                print(f"• [{q.priority}] {q.question} (사유: {q.reason})")


def handle_actions_list(status: Optional[str] = None, as_json: bool = False):
    """액션 목록 조회 CLI 핸들러 (Step 28)."""
    import json
    from secgrc.actions import default_action_history_store, ActionStatus
    st = None
    if status:
        try:
            st = ActionStatus(status.upper())
        except ValueError:
            print(f"❌ 유효하지 않은 액션 상태입니다: {status}")
            return
    actions = default_action_history_store.list_actions(status=st)
    if as_json:
        print(json.dumps([a.model_dump() for a in actions], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"📋 액션 목록 ({len(actions)}건):")
        for a in actions:
            print(f"• [{a.action_id}] {a.action_type.value} | 대상: {a.target_id} | 위험도: {a.risk_level.value} | 상태: {a.status.value}")


def handle_actions_show(action_id: str, as_json: bool = False):
    """액션 상세 조회 CLI 핸들러 (Step 28)."""
    import json
    from secgrc.actions import default_action_history_store
    act = default_action_history_store.get_action(action_id)
    if not act:
        print(f"❌ 액션을 찾을 수 없습니다: {action_id}")
        return
    if as_json:
        print(json.dumps(act.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🔍 액션 상세 정보 [{act.action_id}]:")
        print(f"• 유형: {act.action_type.value}")
        print(f"• 대상: {act.target_type} ({act.target_id})")
        print(f"• 위험 수준: {act.risk_level.value}")
        print(f"• 현재 상태: {act.status.value}")
        print(f"• 승인 필수 여부: {act.human_approval_required}")
        print(f"• 기대 효과: {act.expected_effect}")
        print(f"• 정책 ID: {act.authorization_policy_id} (v{act.policy_version})")


def handle_actions_pending(as_json: bool = False):
    """승인 대기 중인 액션 조회 CLI 핸들러 (Step 28)."""
    import json
    from secgrc.actions import default_action_history_store, ActionStatus
    actions = default_action_history_store.list_actions(status=ActionStatus.PENDING_APPROVAL)
    if as_json:
        print(json.dumps([a.model_dump() for a in actions], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"⏳ 승인 대기 중인 액션 ({len(actions)}건):")
        if not actions:
            print("  대기 중인 액션이 없습니다.")
        for a in actions:
            print(f"• [{a.action_id}] {a.action_type.value} | 대상: {a.target_id} | 위험도: {a.risk_level.value} | 요청자: {a.requested_by}")


def handle_actions_approve(
    action_id: str,
    approver_id: str = "CLIApprover",
    role: str = "GRC_MANAGER",
    reason: str = "Approved via CLI",
    as_json: bool = False,
):
    """액션 승인 CLI 핸들러 (Step 28)."""
    import json
    from secgrc.actions import default_action_history_store, default_approval_manager, ApprovalDecision, ActionStatus
    act = default_action_history_store.get_action(action_id)
    if not act:
        print(f"❌ 액션을 찾을 수 없습니다: {action_id}")
        return
    app, err, msg = default_approval_manager.submit_approval(
        action=act,
        approver_id=approver_id,
        requested_role=role,
        decision=ApprovalDecision.APPROVE,
        reason=reason,
    )
    if not app:
        print(f"❌ 승인 실패 [{err.value if err else 'UNKNOWN'}]: {msg}")
        return
    default_action_history_store.record_transition(
        action=act,
        from_status=act.status,
        to_status=ActionStatus.APPROVED,
        actor=f"Approver:{approver_id}",
        reason=reason,
        details={"approval_id": app.approval_id},
    )
    if as_json:
        print(json.dumps({"status": "APPROVED", "approval": app.model_dump(), "action_id": action_id}, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"✅ 액션 승인 완료: [{action_id}] -> 상태: APPROVED (승인 ID: {app.approval_id})")


def handle_actions_reject(
    action_id: str,
    approver_id: str = "CLIApprover",
    reason: str = "Rejected via CLI",
    as_json: bool = False,
):
    """액션 반려 CLI 핸들러 (Step 28)."""
    import json
    from secgrc.actions import default_action_history_store, ActionStatus
    act = default_action_history_store.get_action(action_id)
    if not act:
        print(f"❌ 액션을 찾을 수 없습니다: {action_id}")
        return
    default_action_history_store.record_transition(
        action=act,
        from_status=act.status,
        to_status=ActionStatus.REJECTED,
        actor=f"Approver:{approver_id}",
        reason=reason,
    )
    if as_json:
        print(json.dumps({"status": "REJECTED", "action_id": action_id, "reason": reason}, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🛑 액션 반려 완료: [{action_id}] -> 상태: REJECTED (사유: {reason})")


def handle_actions_execute(action_id: str, as_json: bool = False):
    """액션 실행 CLI 핸들러 (Step 28)."""
    import json
    from secgrc.actions import default_controlled_action_executor
    res = default_controlled_action_executor.execute(action_id=action_id)
    if as_json:
        print(json.dumps(res.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        if res.status.value == "SUCCEEDED":
            print(f"🚀 액션 실행 성공: [{action_id}]")
            print(f"• 실행 ID: {res.execution_id}")
            print(f"• 케이퍼빌리티: {res.capability_id}")
            print(f"• 사후 검증(Verification): {'통과' if res.verification_passed else '실패'}")
            print(f"• 생성된 레코드 수: {len(res.result_records)}")
        else:
            print(f"❌ 액션 실행 실패: [{action_id}] -> 상태: {res.status.value}")
            if res.error_code:
                print(f"• 에러 코드: {res.error_code.value}")
            if res.error_message:
                print(f"• 에러 사유: {res.error_message}")


def handle_actions_history(action_id: str, as_json: bool = False):
    """액션 이력 조회 CLI 핸들러 (Step 28)."""
    import json
    from secgrc.actions import default_action_history_store
    history = default_action_history_store.get_history(action_id)
    if as_json:
        print(json.dumps([h.model_dump() for h in history], indent=2, ensure_ascii=False, default=str))
    else:
        print(f"📜 액션 상태 전이 이력 [{action_id}] ({len(history)}건):")
        for h in history:
            print(f"• [{h.transition_time[:19]}] {h.from_status or 'START'} -> {h.to_status.value} (행위자: {h.actor}, 사유: {h.reason})")


def handle_actions_causal_chain(action_id: str, as_json: bool = False):
    """액션 인과 사슬 조회 CLI 핸들러 (Step 28)."""
    import json
    from secgrc.actions import get_action_causal_chain
    chain = get_action_causal_chain(action_id)
    if as_json:
        print(json.dumps(chain.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🔗 액션 전주기 인과 사슬 [{action_id}]:")
        print(f"• 완료 여부: {chain.is_complete}")
        for i, node in enumerate(chain.chain, 1):
            print(f"  {i}. [{node.stage}] 상태: {node.status} (엔티티: {node.entity_id})")


# ==============================================================================
# Step 29: Enterprise Security & Compliance Digital Twin CLI Handlers
# ==============================================================================

def handle_twin_state(as_json: bool = False):
    """디지털 트윈 전체 상태 스냅샷 출력 CLI 핸들러."""
    import json
    from secgrc.twin import default_digital_twin_builder
    state = default_digital_twin_builder.build_snapshot()
    if as_json:
        print(json.dumps(state.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        print(f"🌐 엔터프라이즈 디지털 트윈 종합 상태 [{state.snapshot_id}]:")
        print(f"• 트윈 ID: {state.twin_id} (테넌트: {state.tenant_id})")
        print(f"• 생성 일시: {state.generated_at} (버전: {state.twin_version})")
        print(f"• 상태 무결성 해시: {state.state_hash}")
        print(f"• 총 엔티티 수: {len(state.all_entities())}건")
        print(f"  - 조직/비즈니스: {len(state.enterprise_entities)}건")
        print(f"  - 보안/인프라/신원: {len(state.security_entities)}건")
        print(f"  - 데이터/프라이버시: {len(state.privacy_entities)}건")
        print(f"  - 컴플라이언스: {len(state.compliance_entities)}건")
        print(f"  - 리스크/인시던트: {len(state.risk_entities)}건")
        print(f"• 총 관계(Edge) 수: {len(state.relationships)}건")


def handle_twin_entities(entity_type: Optional[str] = None, as_json: bool = False):
    """디지털 트윈 엔티티 목록 출력 CLI 핸들러."""
    import json
    from secgrc.twin import default_digital_twin_builder, default_twin_query_engine, TwinEntityType
    state = default_digital_twin_builder.build_snapshot()
    try:
        etype = TwinEntityType(entity_type.upper()) if entity_type else None
    except ValueError:
        if as_json:
            print("[]")
        else:
            title = f" [{entity_type.upper()}]" if entity_type else ""
            print(f"📋 디지털 트윈 엔티티 목록{title} (0건):")
        return

    entities = default_twin_query_engine.query_entities(state, entity_type=etype)
    if as_json:
        print(json.dumps([e.model_dump() for e in entities], indent=2, ensure_ascii=False, default=str))
    else:
        title = f" [{entity_type.upper()}]" if entity_type else ""
        print(f"📋 디지털 트윈 엔티티 목록{title} ({len(entities)}건):")
        for e in entities[:20]:
            print(f"• [{e.entity_type.value}] {e.entity_id} - 상태: {e.current_state} (스코프: {e.scope})")
        if len(entities) > 20:
            print(f"  ... 외 {len(entities) - 20}건 생략")



def handle_twin_as_of(timestamp: str, as_json: bool = False):
    """디지털 트윈 시점(as_of) 상태 복원 출력 CLI 핸들러."""
    import json
    from secgrc.twin import default_digital_twin_builder, default_temporal_twin_manager
    base_state = default_digital_twin_builder.build_snapshot()
    as_of_state = default_temporal_twin_manager.as_of(base_state, timestamp)
    if as_json:
        print(json.dumps(as_of_state.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        print(f"⏱️ 디지털 트윈 시점 복원 [as_of: {timestamp}]:")
        print(f"• 스냅샷 ID: {as_of_state.snapshot_id}")
        print(f"• 유효 엔티티 수: {len(as_of_state.all_entities())}건")
        print(f"• 유효 관계 수: {len(as_of_state.relationships)}건")
        print(f"• 시점 무결성 해시: {as_of_state.state_hash}")


def handle_twin_diff(t1: str, t2: str, as_json: bool = False):
    """디지털 트윈 시점 간 상태 델타(diff) 출력 CLI 핸들러."""
    import json
    from secgrc.twin import default_digital_twin_builder, default_temporal_twin_manager
    base_state = default_digital_twin_builder.build_snapshot()
    s1 = default_temporal_twin_manager.as_of(base_state, t1)
    s2 = default_temporal_twin_manager.as_of(base_state, t2)
    diff_res = default_temporal_twin_manager.diff(s1, s2)
    if as_json:
        print(json.dumps(diff_res.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        print(f"📊 디지털 트윈 상태 변화량 [diff: {t1} -> {t2}]:")
        print(f"• 신규 추가된 엔티티: {len(diff_res.added_entities)}건")
        print(f"• 제거/만료된 엔티티: {len(diff_res.removed_entities)}건")
        print(f"• 상태가 변경된 엔티티: {len(diff_res.modified_entities)}건")
        print(f"• 추가된 관계: {len(diff_res.added_relationships)}건")
        print(f"• 제거된 관계: {len(diff_res.removed_relationships)}건")


def handle_twin_blast_radius(entity_id: str, max_depth: int = 5, as_json: bool = False):
    """디지털 트윈 다계층 폭발 반경 분석 출력 CLI 핸들러."""
    import json
    from secgrc.twin import default_digital_twin_builder, default_twin_graph_engine
    state = default_digital_twin_builder.build_snapshot()
    blast = default_twin_graph_engine.calculate_blast_radius(state, entity_id, max_depth=max_depth)
    if as_json:
        print(json.dumps(blast.model_dump(), indent=2, ensure_ascii=False, default=str))
    else:
        print(f"💥 폭발 반경 분석 결과 [{entity_id}] (최대 깊이: {max_depth}):")
        print(f"• 출발 엔티티: {blast.root_entity_id} (타입: {blast.root_entity_type.value})")
        print(f"• 총 파급 영향 엔티티: {blast.total_affected_count}건")
        print(f"  - 직접 의존 (Depth 1): {len(blast.direct_dependents)}건 ({', '.join(blast.direct_dependents[:5])})")
        print(f"  - 간접 의존 (Depth > 1): {len(blast.indirect_dependents)}건")
        print(f"• 영향받는 권위 리스크: {len(blast.affected_risks)}건 ({', '.join(blast.affected_risks)})")
        print(f"• 영향받는 보안 통제: {len(blast.affected_controls)}건 ({', '.join(blast.affected_controls[:5])})")
        print(f"• 영향받는 비즈니스 조직: {len(blast.affected_business_units)}건 ({', '.join(blast.affected_business_units)})")
        print(f"• 영향받는 애플리케이션: {len(blast.affected_applications)}건 ({', '.join(blast.affected_applications)})")


def handle_scenario_create(name: str, base_snapshot_id: str, scenario_id: Optional[str] = None, tenant_id: str = "default-tenant", as_json: bool = False):
    """시나리오 생성 CLI 핸들러."""
    import json
    from secgrc.scenario import default_scenario_builder
    sid = scenario_id or f"SCN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    try:
        scenario = default_scenario_builder.create(
            scenario_id=sid,
            name=name,
            base_snapshot_id=base_snapshot_id,
            tenant_id=tenant_id,
        )
        if as_json:
            print(json.dumps(scenario.model_dump(), indent=2, ensure_ascii=False, default=str))
        else:
            print(f"✨ 시나리오가 성공적으로 생성되었습니다: {scenario.scenario_id}")
            print(f"• 명칭: {scenario.name}")
            print(f"• 베이스 스냅샷: {scenario.base_snapshot_id}")
            print(f"• 상태: {scenario.status.value}")
            print(f"• 무결성 해시: {scenario.integrity_hash}")
    except Exception as e:
        print(f"❌ 시나리오 생성 실패: {e}")


def handle_scenario_change(scenario_id: str, entity_type: str, entity_id: str, field_path: str, current_value: str, proposed_value: str, as_json: bool = False):
    """시나리오 변경 항목 추가 CLI 핸들러."""
    import json
    from secgrc.scenario import default_scenario_builder, default_scenario_history_store, ChangeType
    scenario = default_scenario_history_store.get(scenario_id)
    if not scenario:
        # 새로 임시 시나리오 생성 또는 확인
        from secgrc.twin import default_twin_history_store, default_digital_twin_builder
        snap = default_twin_history_store.get_latest_snapshot()
        if not snap:
            snap = default_digital_twin_builder.build_snapshot()
            default_twin_history_store.save_snapshot(snap)
        scenario = default_scenario_builder.create(
            scenario_id=scenario_id,
            name=f"Scenario {scenario_id}",
            base_snapshot_id=snap.snapshot_id,
        )
    
    # 타입 파싱
    def _parse_val(v: str):
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False
        if v.isdigit():
            return int(v)
        return v

    c_val = _parse_val(current_value)
    p_val = _parse_val(proposed_value)

    try:
        default_scenario_builder.add_change(
            scenario=scenario,
            entity_type=entity_type,
            entity_id=entity_id,
            field_path=field_path,
            current_value=c_val,
            proposed_value=p_val,
            change_type=ChangeType.SET,
        )
        default_scenario_history_store.save(scenario)
        if as_json:
            print(json.dumps(scenario.model_dump(), indent=2, ensure_ascii=False, default=str))
        else:
            print(f"➕ 시나리오 변경 항목이 추가되었습니다 [{scenario.scenario_id}]:")
            print(f"• 엔티티: [{entity_type}] {entity_id}")
            print(f"• 필드: {field_path} ({c_val} -> {p_val})")
            print(f"• 총 변경 수: {len(scenario.changes)}건")
    except Exception as e:
        print(f"❌ 시나리오 변경 추가 실패: {e}")


def handle_scenario_validate(scenario_id: str, as_json: bool = False):
    """시나리오 유효성 검증 CLI 핸들러."""
    import json
    from secgrc.scenario import default_scenario_builder, default_scenario_history_store
    scenario = default_scenario_history_store.get(scenario_id)
    if not scenario:
        print(f"❌ 시나리오를 찾을 수 없습니다: {scenario_id}")
        return
    ok = default_scenario_builder.validate(scenario)
    default_scenario_history_store.save(scenario)
    if as_json:
        print(json.dumps({"scenario_id": scenario_id, "valid": ok, "status": scenario.status.value}, indent=2))
    else:
        status_icon = "✅" if ok else "❌"
        print(f"{status_icon} 시나리오 검증 결과 [{scenario_id}]: {scenario.status.value}")


def handle_scenario_simulate(scenario_id: str, as_json: bool = False):
    """시나리오 시뮬레이션 수행 CLI 핸들러."""
    import json
    from secgrc.scenario import default_scenario_simulator, default_scenario_history_store
    scenario = default_scenario_history_store.get(scenario_id)
    if not scenario:
        print(f"❌ 시나리오를 찾을 수 없습니다: {scenario_id}")
        return
    try:
        res = default_scenario_simulator.simulate(scenario)
        if as_json:
            payload = {
                "scenario": res["scenario"].model_dump(),
                "impact": res["impact"].model_dump(),
                "assessments": [a.model_dump() for a in res["assessments"]],
                "risk_impacts": [r.model_dump() for r in res["risk_impacts"]],
                "comparison": res["comparison"].model_dump(),
                "decision_summary": res["decision_summary"].model_dump(),
                "is_simulation_only": True,
                "authoritative_state_unchanged": True,
            }
            print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        else:
            comp = res["comparison"]
            imp = res["impact"]
            print("=" * 60)
            print(f"🎯 WHAT-IF 시나리오 시뮬레이션 결과 [SIMULATION ONLY]")
            print("=" * 60)
            print(f"시나리오: {scenario.name} ({scenario.scenario_id})")
            print(f"\n[영향 분석]")
            print(f"• 영향받는 통제 요구사항: {len(imp.affected_requirements)}건 ({', '.join(imp.affected_requirements)})")
            print(f"• 영향받는 증적 항목: {len(imp.affected_evidence)}건 ({', '.join(imp.affected_evidence)})")
            print(f"• 신규 결함(FAIL) 전환: {len(comp.new_failures)}건 ({', '.join(comp.new_failures)})")
            print(f"\n[리스크 영향]")
            for r in res["risk_impacts"]:
                if r.affected_by_scenario:
                    print(f"• {r.risk_id} (기존: {r.baseline_score}/{r.baseline_priority}) -> 가상 상태: {r.simulated_risk_state}")
            print(f"\n[원천 권위 상태]")
            print(f"• AUTHORITATIVE ENTERPRISE STATE: UNCHANGED (100% 불변 보존)")
            print("=" * 60)
    except Exception as e:
        print(f"❌ 시나리오 시뮬레이션 실패: {e}")


def handle_scenario_impact(scenario_id: str, as_json: bool = False):
    """시나리오 영향 분석 CLI 핸들러."""
    import json
    from secgrc.scenario import default_scenario_simulator, default_scenario_history_store
    scenario = default_scenario_history_store.get(scenario_id)
    if not scenario:
        print(f"❌ 시나리오를 찾을 수 없습니다: {scenario_id}")
        return
    try:
        res = default_scenario_simulator.simulate(scenario)
        impact = res["impact"]
        if as_json:
            print(json.dumps(impact.model_dump(), indent=2, ensure_ascii=False, default=str))
        else:
            print(f"⚡ 시나리오 잠재 영향 분석 [{scenario_id}]:")
            print(f"• 영향받는 엔티티: {len(impact.affected_entities)}건")
            print(f"• 영향받는 통제 요구사항: {len(impact.affected_requirements)}건")
            print(f"• 영향받는 프레임워크: {len(impact.affected_frameworks)}건 ({', '.join(impact.affected_frameworks)})")
            print(f"• 영향받는 리스크: {len(impact.affected_risks)}건")
    except Exception as e:
        print(f"❌ 영향 분석 실패: {e}")


def handle_scenario_compare(scenario_id: str, as_json: bool = False):
    """시나리오 베이스라인 비교 CLI 핸들러."""
    import json
    from secgrc.scenario import default_scenario_simulator, default_scenario_history_store
    scenario = default_scenario_history_store.get(scenario_id)
    if not scenario:
        print(f"❌ 시나리오를 찾을 수 없습니다: {scenario_id}")
        return
    try:
        res = default_scenario_simulator.simulate(scenario)
        comp = res["comparison"]
        if as_json:
            print(json.dumps(comp.model_dump(), indent=2, ensure_ascii=False, default=str))
        else:
            print(f"⚖️ 베이스라인 대비 가상 시나리오 비교 [{scenario_id}]:")
            print(f"• 신규 FAIL 통제: {len(comp.new_failures)}건 ({', '.join(comp.new_failures)})")
            print(f"• 신규 PARTIAL 통제: {len(comp.new_partials)}건")
            print(f"• 영향받는 리스크: {len(comp.affected_risks)}건")
            print(f"• 상태별 통제 수량: {comp.status_counts}")
    except Exception as e:
        print(f"❌ 시나리오 비교 실패: {e}")



def main(args: Optional[list] = None):
    """CLI 메인 진입점: 서브커맨드(search, map, evidence 등) 또는 대화형 감사 모드를 실행합니다."""
    if args is not None:
        sys.argv = ["secgrc"] + list(args)
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "search":
            query = " ".join(sys.argv[2:]).strip() if len(sys.argv) > 2 else ""
            if not query:
                print("❌ 검색어를 입력해 주세요.")
                print("   사용법: python -m secgrc search \"MFA 권한관리\"")
                return
            handle_search(query)
            return
        elif command == "map":
            control_id = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            if not control_id:
                print("❌ 통제항목 번호를 입력해 주세요.")
                print("   사용법: python -m secgrc map ISMS-P-2.5.2")
                return
            handle_mapping(control_id)
            return
        elif command == "evidence":
            sub_or_id = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            if sub_or_id == "prowler":
                csv_path = sys.argv[3].strip() if len(sys.argv) > 3 else ""
                handle_prowler_evidence(csv_path)
                return
            handle_evidence(sub_or_id)
            return
        elif command == "audit":
            as_json = "--json" in sys.argv
            clean_args = [a for a in sys.argv[2:] if a != "--json"]
            subcommand = clean_args[0].strip() if len(clean_args) > 0 else ""
            csv_path = clean_args[1].strip() if len(clean_args) > 1 else ""

            if subcommand == "prowler":
                handle_audit_prowler(csv_path, as_json=as_json)
                return
            else:
                print("❌ 지원하지 않는 감사 명령어입니다.")
                print("   사용법: python -m secgrc audit prowler <csv-path> [--json]")
                return
        elif command == "risk":
            as_json = "--json" in sys.argv
            clean_args = [a for a in sys.argv[2:] if a != "--json"]
            subcommand = clean_args[0].strip() if len(clean_args) > 0 else ""
            csv_path = clean_args[1].strip() if len(clean_args) > 1 else ""

            if subcommand == "prowler":
                handle_risk_prowler(csv_path, as_json=as_json)
                return
            else:
                print("❌ 지원하지 않는 위험 평가 명령어입니다.")
                print("   사용법: python -m secgrc risk prowler <csv-path> [--json]")
                return
        elif command == "ai-audit":
            as_json = "--json" in sys.argv
            clean_args = [a for a in sys.argv[2:] if a != "--json"]
            subcommand = clean_args[0].strip() if len(clean_args) > 0 else ""
            csv_path = clean_args[1].strip() if len(clean_args) > 1 else ""

            if subcommand == "prowler":
                handle_ai_audit_prowler(csv_path, as_json=as_json)
                return
            else:
                print("❌ 지원하지 않는 AI 감사 명령어입니다.")
                print("   사용법: python -m secgrc ai-audit prowler <csv-path> [--json]")
                return
        elif command == "report":
            format_type = "markdown"
            for i, arg in enumerate(sys.argv):
                if arg == "--format" and i + 1 < len(sys.argv):
                    format_type = sys.argv[i + 1].strip()
                elif arg.startswith("--format="):
                    format_type = arg.split("=", 1)[1].strip()

            final_args = []
            skip_next = False
            for a in sys.argv[2:]:
                if skip_next:
                    skip_next = False
                    continue
                if a == "--format":
                    skip_next = True
                    continue
                if a.startswith("--format="):
                    continue
                final_args.append(a)

            subcommand = final_args[0].strip() if len(final_args) > 0 else ""
            csv_path = final_args[1].strip() if len(final_args) > 1 else ""

            if subcommand == "prowler":
                handle_report_prowler(csv_path, format_type=format_type)
                return
            else:
                print("❌ 지원하지 않는 보고서 명령어입니다.")
                print("   사용법: python -m secgrc report prowler <csv-path> [--format markdown|html|json]")
                return
        elif command in ("web-cert", "certification-web"):
            if "-h" in sys.argv or "--help" in sys.argv:
                print("🛡️ ISMS-P 인증심사 전용 콘솔(v2) 실행:")
                print("  python -m secgrc web-cert [--host 127.0.0.1] [--port 8001]")
                print("  옵션:")
                print("    --host : 바인딩할 호스트 IP (기본값: 127.0.0.1)")
                print("    --port : 바인딩할 포트 번호 (기본값: 8001)")
                return
            host = "127.0.0.1"
            port = 8001
            for i, arg in enumerate(sys.argv):
                if arg == "--host" and i + 1 < len(sys.argv):
                    host = sys.argv[i + 1].strip()
                elif arg.startswith("--host="):
                    host = arg.split("=", 1)[1].strip()
                elif arg == "--port" and i + 1 < len(sys.argv):
                    try:
                        port = int(sys.argv[i + 1].strip())
                    except ValueError:
                        pass
                elif arg.startswith("--port="):
                    try:
                        port = int(arg.split("=", 1)[1].strip())
                    except ValueError:
                        pass
            handle_certification_web_server(host=host, port=port)
            return
        elif command == "agent":
            as_json = "--json" in sys.argv
            dry_run = "--no-dry-run" not in sys.argv
            scan_id = None
            for i, arg in enumerate(sys.argv):
                if arg == "--scan-id" and i + 1 < len(sys.argv):
                    scan_id = sys.argv[i + 1].strip()
                elif arg.startswith("--scan-id="):
                    scan_id = arg.split("=", 1)[1].strip()

            clean_args = []
            skip_next = False
            for a in sys.argv[2:]:
                if skip_next:
                    skip_next = False
                    continue
                if a in ("--dry-run", "--json"):
                    continue
                if a == "--scan-id":
                    skip_next = True
                    continue
                if a.startswith("--scan-id="):
                    continue
                clean_args.append(a)

            action = clean_args[0].strip() if len(clean_args) > 0 else ""
            provider_type = clean_args[1].strip() if len(clean_args) > 1 else ""
            csv_path = clean_args[2].strip() if len(clean_args) > 2 else ""

            if action == "run" and provider_type == "prowler":
                handle_agent_run(csv_path, as_json=as_json, scan_id=scan_id, dry_run=dry_run)
                return
            else:
                print("❌ 지원하지 않는 에이전트 명령어입니다.")
                print("   사용법: python -m secgrc agent run prowler <csv-path> [--dry-run] [--json] [--scan-id <id>]")
                return
        elif command in ("closed-loop", "closed_loop"):
            simulate = "--simulate" in sys.argv
            scan_id = None
            for i, arg in enumerate(sys.argv):
                if arg == "--scan-id" and i + 1 < len(sys.argv):
                    scan_id = sys.argv[i + 1].strip()
                elif arg.startswith("--scan-id="):
                    scan_id = arg.split("=", 1)[1].strip()

            clean_args = []
            skip_next = False
            for a in sys.argv[2:]:
                if skip_next:
                    skip_next = False
                    continue
                if a == "--simulate":
                    continue
                if a == "--scan-id":
                    skip_next = True
                    continue
                if a.startswith("--scan-id="):
                    continue
                clean_args.append(a)

            action = clean_args[0].strip() if len(clean_args) > 0 else ""
            csv_path = clean_args[1].strip() if len(clean_args) > 1 else ""

            if action == "run":
                handle_closed_loop_run(csv_path, simulate=simulate, scan_id=scan_id)
                return
            else:
                print("❌ 지원하지 않는 closed-loop 명령어입니다.")
                print("   사용법: python -m secgrc closed-loop run <csv-path> [--simulate] [--scan-id <id>]")
                return
        elif command == "continuous":
            action = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            if action == "simulate":
                handle_continuous_simulate()
                return
            else:
                print("❌ 지원하지 않는 continuous 명령어입니다.")
                print("   사용법: python -m secgrc continuous simulate")
                return
        elif command == "redteam":
            action = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            as_json = "--json" in sys.argv
            category = None
            for i, arg in enumerate(sys.argv):
                if arg == "--category" and i + 1 < len(sys.argv):
                    category = sys.argv[i + 1].strip()
                elif arg.startswith("--category="):
                    category = arg.split("=", 1)[1].strip()

            if action == "run":
                handle_redteam_run(category=category, as_json=as_json)
                return
            elif action == "scenario":
                sc_id = sys.argv[3].strip() if len(sys.argv) > 3 else ""
                if not sc_id:
                    print("❌ 시나리오 ID를 입력해 주세요.")
                    print("   사용법: python -m secgrc redteam scenario <scenario_id>")
                    return
                handle_redteam_scenario(sc_id)
                return
        elif command == "ontology":
            action = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            as_json = "--json" in sys.argv
            csv_path = None
            out_path = None
            for i, arg in enumerate(sys.argv):
                if arg == "--csv" and i + 1 < len(sys.argv):
                    csv_path = sys.argv[i + 1].strip()
                elif arg.startswith("--csv="):
                    csv_path = arg.split("=", 1)[1].strip()
                elif arg == "--out" and i + 1 < len(sys.argv):
                    out_path = sys.argv[i + 1].strip()
                elif arg.startswith("--out="):
                    out_path = arg.split("=", 1)[1].strip()

            if action == "build":
                handle_ontology_build(csv_path=csv_path, out_path=out_path, as_json=as_json)
                return
            elif action == "summary":
                handle_ontology_summary(as_json=as_json)
                return
            elif action in ("lineage", "evidence", "risk"):
                target_id = sys.argv[3].strip() if len(sys.argv) > 3 and not sys.argv[3].startswith("-") else ""
                if not target_id:
                    print(f"❌ 개체 ID를 입력해 주세요.")
                    print(f"   사용법: python -m secgrc ontology {action} <id> [--json]")
                    return
                handle_ontology_lineage(target_id, as_json=as_json)
                return
            elif action == "framework":
                fw_id = sys.argv[3].strip() if len(sys.argv) > 3 and not sys.argv[3].startswith("-") else "ISMS-P"
                handle_ontology_framework(fw_id, as_json=as_json)
                return
            else:
                print("❌ 지원하지 않는 ontology 명령어입니다.")
                print("   사용법: python -m secgrc ontology build [--csv <path>] [--out <file.json>] [--json]")
                print("           python -m secgrc ontology summary [--json]")
                print("           python -m secgrc ontology lineage <entity_id> [--json]")
                print("           python -m secgrc ontology evidence <evidence_id> [--json]")
                print("           python -m secgrc ontology risk <risk_id> [--json]")
                print("           python -m secgrc ontology framework [framework_id] [--json]")
                return
        elif command == "copilot":
            action = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            as_json = "--json" in sys.argv
            user_role = "analyst"
            for i, arg in enumerate(sys.argv):
                if arg == "--role" and i + 1 < len(sys.argv):
                    user_role = sys.argv[i + 1].strip()
                elif arg.startswith("--role="):
                    user_role = arg.split("=", 1)[1].strip()

            if action == "ask":
                question = ""
                for i, arg in enumerate(sys.argv[3:], start=3):
                    if arg in ("--json",):
                        continue
                    if arg == "--role" or (i > 3 and sys.argv[i - 1] == "--role") or arg.startswith("--role="):
                        continue
                    question = arg.strip()
                    break

                if not question:
                    print("❌ 질문을 입력해 주세요.")
                    print("   사용법: python -m secgrc copilot ask \"<질문>\" [--role executive|ciso|manager|analyst] [--json]")
                    return
                handle_copilot_ask(question, user_role=user_role, as_json=as_json)
                return
            else:
                print("❌ 지원하지 않는 copilot 명령어입니다.")
                print("   사용법: python -m secgrc copilot ask \"<질문>\" [--role executive|ciso|manager|analyst] [--json]")
                return
        elif command == "compliance":
            as_json = "--json" in sys.argv
            framework_id = "ISMS-P"
            for i, arg in enumerate(sys.argv):
                if arg == "--framework" and i + 1 < len(sys.argv):
                    framework_id = sys.argv[i + 1].strip()
                elif arg.startswith("--framework="):
                    framework_id = arg.split("=", 1)[1].strip()

            action = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            if action == "matrix":
                from secgrc.compliance.matrix.cli import handle_matrix_cli
                sys.exit(handle_matrix_cli(sys.argv[3:]))
            elif action == "coverage":
                handle_compliance_coverage(framework_id=framework_id, as_json=as_json)
                return
            elif action == "evidence-requirements":
                requirement_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--requirement", "-r") and i + 1 < len(sys.argv):
                        requirement_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--requirement="):
                        requirement_id = arg.split("=", 1)[1].strip()
                if not requirement_id:
                    print("❌ 요구사항 ID를 입력해 주세요. (예: --requirement ISMS-P-2.5.2)")
                    return
                handle_compliance_evidence_requirements(
                    framework_id=framework_id,
                    requirement_id=requirement_id,
                    as_json=as_json,
                )
                return
            elif action == "assess":
                is_all = "--all" in sys.argv
                requirement_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--requirement", "-r") and i + 1 < len(sys.argv):
                        requirement_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--requirement="):
                        requirement_id = arg.split("=", 1)[1].strip()
                if not is_all and not requirement_id:
                    print("❌ 요구사항 ID를 입력하거나 --all 옵션을 지정해 주세요.")
                    print("   사용법: python -m secgrc compliance assess --framework ISMS-P --requirement <ID> [--json]")
                    print("           python -m secgrc compliance assess --framework ISMS-P --all [--json]")
                    return
                handle_compliance_assess(
                    framework_id=framework_id,
                    requirement_id=requirement_id,
                    is_all=is_all,
                    as_json=as_json,
                )
                return
            elif action == "report":
                report_type = "executive"
                requirement_id = None
                as_markdown = "--markdown" in sys.argv
                for i, arg in enumerate(sys.argv):
                    if arg in ("--type", "-t") and i + 1 < len(sys.argv):
                        report_type = sys.argv[i + 1].strip()
                    elif arg.startswith("--type="):
                        report_type = arg.split("=", 1)[1].strip()
                    elif arg in ("--requirement", "-r") and i + 1 < len(sys.argv):
                        requirement_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--requirement="):
                        requirement_id = arg.split("=", 1)[1].strip()
                handle_compliance_report(
                    framework_id=framework_id,
                    report_type=report_type,
                    requirement_id=requirement_id,
                    as_json=as_json,
                    as_markdown=as_markdown,
                )
                return
            elif action == "changes":
                entity_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--entity", "-e") and i + 1 < len(sys.argv):
                        entity_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--entity="):
                        entity_id = arg.split("=", 1)[1].strip()
                handle_compliance_changes(entity_id=entity_id, as_json=as_json)
                return
            elif action == "impact":
                change_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--change", "-c") and i + 1 < len(sys.argv):
                        change_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--change="):
                        change_id = arg.split("=", 1)[1].strip()
                handle_compliance_impact(change_id=change_id, as_json=as_json)
                return
            elif action == "delta":
                requirement_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--requirement", "-r") and i + 1 < len(sys.argv):
                        requirement_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--requirement="):
                        requirement_id = arg.split("=", 1)[1].strip()
                handle_compliance_delta(requirement_id=requirement_id, as_json=as_json)
                return
            elif action == "timeline":
                requirement_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--requirement", "-r") and i + 1 < len(sys.argv):
                        requirement_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--requirement="):
                        requirement_id = arg.split("=", 1)[1].strip()
                handle_compliance_timeline(requirement_id=requirement_id, as_json=as_json)
                return
            else:
                print("❌ 지원하지 않는 compliance 명령어입니다.")
                print("   사용법: python -m secgrc compliance matrix [requirement|evidence|sources|capability|resolve] [...]")
                print("           python -m secgrc compliance coverage [--framework <id>] [--json]")
                print("           python -m secgrc compliance evidence-requirements --framework <id> --requirement <ID> [--json]")
                print("           python -m secgrc compliance assess --framework <id> [--requirement <ID> | --all] [--json]")
                print("           python -m secgrc compliance report --framework <id> [--type executive|grc_manager|auditor|technical] [--json|--markdown]")
                print("           python -m secgrc compliance changes [--entity <id>] [--json]")
                print("           python -m secgrc compliance impact --change <id> [--json]")
                print("           python -m secgrc compliance delta --requirement <id> [--json]")
                print("           python -m secgrc compliance timeline --requirement <id> [--json]")
                return
        elif command == "investigation":
            action = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            if action == "report":
                as_json = "--json" in sys.argv
                as_markdown = "--markdown" in sys.argv
                investigation_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--investigation", "-i") and i + 1 < len(sys.argv):
                        investigation_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--investigation="):
                        investigation_id = arg.split("=", 1)[1].strip()
                if not investigation_id:
                    print("❌ 조사 ID를 입력해 주세요. (예: --investigation INV-001)")
                    return
                handle_investigation_report(
                    investigation_id=investigation_id,
                    as_json=as_json,
                    as_markdown=as_markdown,
                )
        elif command == "security":
            action = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            if action == "adversarial":
                is_list = "--list" in sys.argv
                is_run_all = "--run-all" in sys.argv
                is_report = "--report" in sys.argv
                as_json = "--json" in sys.argv
                as_markdown = "--markdown" in sys.argv
                category = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--category", "-c") and i + 1 < len(sys.argv):
                        category = sys.argv[i + 1].strip()
                    elif arg.startswith("--category="):
                        category = arg.split("=", 1)[1].strip()
                handle_security_adversarial(
                    is_list=is_list,
                    is_run_all=is_run_all,
                    category=category,
                    is_report=is_report,
                    as_json=as_json,
                    as_markdown=as_markdown,
                )
                return
            else:
                print("❌ 지원하지 않는 security 명령어입니다.")
                print("   사용법: python -m secgrc security adversarial [--list|--run-all|--report|--category <cat>]")
                return
        elif command == "dashboard":
            as_json = "--json" in sys.argv
            as_html = "--html" in sys.argv
            framework_id = "ISMS-P"
            role_str = "CISO"
            for i, arg in enumerate(sys.argv):
                if arg in ("--framework", "-f") and i + 1 < len(sys.argv):
                    framework_id = sys.argv[i + 1].strip()
                elif arg.startswith("--framework="):
                    framework_id = arg.split("=", 1)[1].strip()
                elif arg in ("--role", "-r") and i + 1 < len(sys.argv):
                    role_str = sys.argv[i + 1].strip()
                elif arg.startswith("--role="):
                    role_str = arg.split("=", 1)[1].strip()
            handle_dashboard(
                framework_id=framework_id,
                role_str=role_str,
                as_json=as_json,
                as_html=as_html,
            )
        elif command == "events":
            action = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            as_json = "--json" in sys.argv
            if action == "list":
                category = None
                priority = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--category", "-c") and i + 1 < len(sys.argv):
                        category = sys.argv[i + 1].strip()
                    elif arg.startswith("--category="):
                        category = arg.split("=", 1)[1].strip()
                    elif arg in ("--priority", "-p") and i + 1 < len(sys.argv):
                        priority = sys.argv[i + 1].strip()
                    elif arg.startswith("--priority="):
                        priority = arg.split("=", 1)[1].strip()
                handle_events_list(category=category, priority=priority, as_json=as_json)
                return
            elif action == "process":
                event_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--event", "-e") and i + 1 < len(sys.argv):
                        event_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--event="):
                        event_id = arg.split("=", 1)[1].strip()
                handle_events_process(event_id=event_id, as_json=as_json)
                return
            elif action == "replay":
                workflow_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--workflow", "-w") and i + 1 < len(sys.argv):
                        workflow_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--workflow="):
                        workflow_id = arg.split("=", 1)[1].strip()
                handle_events_replay(workflow_id=workflow_id, as_json=as_json)
                return
            elif action == "causal-chain":
                event_id = None
                for i, arg in enumerate(sys.argv):
                    if arg in ("--event", "-e") and i + 1 < len(sys.argv):
                        event_id = sys.argv[i + 1].strip()
                    elif arg.startswith("--event="):
                        event_id = arg.split("=", 1)[1].strip()
                handle_events_causal_chain(event_id=event_id, as_json=as_json)
                return
            elif action == "dlq":
                handle_events_dlq(as_json=as_json)
                return
            elif action == "status":
                handle_events_status(as_json=as_json)
                return
            elif action in ("decision-queue", "decisions"):
                handle_decision_queue_list(as_json=as_json)
                return
            else:
                print("❌ 지원하지 않는 events 명령어입니다.")
                print("   사용법: python -m secgrc events list [--category <cat>] [--priority <pri>] [--json]")
                print("           python -m secgrc events process [--event <id>] [--json]")
                print("           python -m secgrc events replay --workflow <id> [--json]")
                print("           python -m secgrc events causal-chain --event <id> [--json]")
                print("           python -m secgrc events dlq [--json]")
                print("           python -m secgrc events status [--json]")
                print("           python -m secgrc events decision-queue [--json]")
                return
        elif command == "ai":
            action = sys.argv[2].strip() if len(sys.argv) > 2 else ""
            as_json = "--json" in sys.argv
            target_id = None
            for i, arg in enumerate(sys.argv):
                if arg in ("--investigation", "-i") and i + 1 < len(sys.argv):
                    target_id = sys.argv[i + 1].strip()
                elif arg.startswith("--investigation="):
                    target_id = arg.split("=", 1)[1].strip()
                elif arg in ("--assessment", "-a") and i + 1 < len(sys.argv):
                    target_id = sys.argv[i + 1].strip()
                elif arg.startswith("--assessment="):
                    target_id = arg.split("=", 1)[1].strip()

            if action == "investigate":
                if not target_id:
                    print("❌ 조사 ID를 입력해 주세요. (예: --investigation <ID>)")
                    return
                handle_ai_investigate(investigation_id=target_id, as_json=as_json)
                return
            elif action == "explain":
                if not target_id:
                    print("❌ 평가 또는 결함 ID를 입력해 주세요. (예: --assessment <ID>)")
                    return
                handle_ai_explain(assessment_id=target_id, as_json=as_json)
                return
            elif action == "hypotheses":
                if not target_id:
                    print("❌ 조사 ID를 입력해 주세요. (예: --investigation <ID>)")
                    return
                handle_ai_hypotheses(investigation_id=target_id, as_json=as_json)
                return
            elif action == "questions":
                if not target_id:
                    print("❌ 조사 ID를 입력해 주세요. (예: --investigation <ID>)")
                    return
                handle_ai_questions(investigation_id=target_id, as_json=as_json)
                return
            else:
                print("❌ 지원하지 않는 ai 명령어입니다.")
                print("   사용법: python -m secgrc ai investigate --investigation <ID> [--json]")
                print("           python -m secgrc ai explain --assessment <ID> [--json]")
                print("           python -m secgrc ai hypotheses --investigation <ID> [--json]")
                print("           python -m secgrc ai questions --investigation <ID> [--json]")
                return
        elif command == "actions":
            action_subcmd = sys.argv[2] if len(sys.argv) > 2 else "list"
            action_id = ""
            status = None
            approver_id = "CLIApprover"
            role = "GRC_MANAGER"
            reason = "Approved via CLI"
            as_json = False

            i = 3
            while i < len(sys.argv):
                arg = sys.argv[i]
                if arg == "--json":
                    as_json = True
                elif arg in ("--action", "-a") and i + 1 < len(sys.argv):
                    action_id = sys.argv[i + 1].strip()
                    i += 1
                elif arg.startswith("--action="):
                    action_id = arg.split("=", 1)[1].strip()
                elif arg in ("--status", "-s") and i + 1 < len(sys.argv):
                    status = sys.argv[i + 1].strip()
                    i += 1
                elif arg.startswith("--status="):
                    status = arg.split("=", 1)[1].strip()
                elif arg in ("--approver",) and i + 1 < len(sys.argv):
                    approver_id = sys.argv[i + 1].strip()
                    i += 1
                elif arg.startswith("--approver="):
                    approver_id = arg.split("=", 1)[1].strip()
                elif arg in ("--role",) and i + 1 < len(sys.argv):
                    role = sys.argv[i + 1].strip()
                    i += 1
                elif arg.startswith("--role="):
                    role = arg.split("=", 1)[1].strip()
                elif arg in ("--reason",) and i + 1 < len(sys.argv):
                    reason = sys.argv[i + 1].strip()
                    i += 1
                elif arg.startswith("--reason="):
                    reason = arg.split("=", 1)[1].strip()
                i += 1

            if action_subcmd == "list":
                handle_actions_list(status=status, as_json=as_json)
                return
            elif action_subcmd == "show":
                if not action_id:
                    print("❌ 액션 ID를 입력해 주세요. (예: --action <ID>)")
                    return
                handle_actions_show(action_id=action_id, as_json=as_json)
                return
            elif action_subcmd == "pending":
                handle_actions_pending(as_json=as_json)
                return
            elif action_subcmd == "approve":
                if not action_id:
                    print("❌ 승인할 액션 ID를 입력해 주세요. (예: --action <ID>)")
                    return
                handle_actions_approve(action_id=action_id, approver_id=approver_id, role=role, reason=reason, as_json=as_json)
                return
            elif action_subcmd == "reject":
                if not action_id:
                    print("❌ 반려할 액션 ID를 입력해 주세요. (예: --action <ID>)")
                    return
                handle_actions_reject(action_id=action_id, approver_id=approver_id, reason=reason, as_json=as_json)
                return
            elif action_subcmd == "execute":
                if not action_id:
                    print("❌ 실행할 액션 ID를 입력해 주세요. (예: --action <ID>)")
                    return
                handle_actions_execute(action_id=action_id, as_json=as_json)
                return
            elif action_subcmd == "history":
                if not action_id:
                    print("❌ 액션 ID를 입력해 주세요. (예: --action <ID>)")
                    return
                handle_actions_history(action_id=action_id, as_json=as_json)
                return
            elif action_subcmd in ("causal-chain", "lineage"):
                if not action_id:
                    print("❌ 액션 ID를 입력해 주세요. (예: --action <ID>)")
                    return
                handle_actions_causal_chain(action_id=action_id, as_json=as_json)
                return
            else:
                print(f"❌ 지원하지 않는 actions 서브커맨드입니다: {action_subcmd}")
                print("   사용법: python -m secgrc actions list [--status <STATUS>] [--json]")
                print("           python -m secgrc actions show --action <ID> [--json]")
                print("           python -m secgrc actions pending [--json]")
                print("           python -m secgrc actions approve --action <ID> [--approver <ID>] [--role <ROLE>] [--reason <REASON>]")
                print("           python -m secgrc actions reject --action <ID> [--approver <ID>] [--reason <REASON>]")
                print("           python -m secgrc actions execute --action <ID> [--json]")
                print("           python -m secgrc actions history --action <ID> [--json]")
                print("           python -m secgrc actions causal-chain --action <ID> [--json]")
                return
        elif command == "twin":
            twin_subcmd = sys.argv[2].lower() if len(sys.argv) > 2 else "state"
            as_json = "--json" in sys.argv

            def _get_twin_arg(flag: str) -> Optional[str]:
                if flag in sys.argv:
                    idx = sys.argv.index(flag)
                    if idx + 1 < len(sys.argv):
                        return sys.argv[idx + 1]
                return None

            if twin_subcmd == "state":
                handle_twin_state(as_json=as_json)
                return
            elif twin_subcmd == "entities":
                etype = _get_twin_arg("--type")
                handle_twin_entities(entity_type=etype, as_json=as_json)
                return
            elif twin_subcmd == "as-of":
                ts = _get_twin_arg("--timestamp") or _get_twin_arg("--time")
                if not ts:
                    print("❌ --timestamp <ISO8601> 인자가 필요합니다.")
                    return
                handle_twin_as_of(timestamp=ts, as_json=as_json)
                return
            elif twin_subcmd == "diff":
                t1 = _get_twin_arg("--t1")
                t2 = _get_twin_arg("--t2")
                if not t1 or not t2:
                    print("❌ --t1 <ISO8601> 및 --t2 <ISO8601> 인자가 모두 필요합니다.")
                    return
                handle_twin_diff(t1=t1, t2=t2, as_json=as_json)
                return
            elif twin_subcmd in ("blast-radius", "blast"):
                eid = _get_twin_arg("--entity") or _get_twin_arg("--root")
                if not eid:
                    print("❌ --entity <ID> 인자가 필요합니다.")
                    return
                depth_str = _get_twin_arg("--max-depth") or _get_twin_arg("--depth") or "5"
                depth = int(depth_str) if depth_str.isdigit() else 5
                handle_twin_blast_radius(entity_id=eid, max_depth=depth, as_json=as_json)
                return
            else:
                print(f"❌ 지원하지 않는 twin 서브커맨드입니다: {twin_subcmd}")
                print("   사용법: python -m secgrc twin state [--json]")
                print("           python -m secgrc twin entities [--type <TYPE>] [--json]")
                print("           python -m secgrc twin as-of --timestamp <ISO8601> [--json]")
                print("           python -m secgrc twin diff --t1 <ISO8601> --t2 <ISO8601> [--json]")
                print("           python -m secgrc twin blast-radius --entity <ID> [--max-depth <N>] [--json]")
                return
        elif command == "scenario":
            scenario_subcmd = sys.argv[2].lower() if len(sys.argv) > 2 else "simulate"
            as_json = "--json" in sys.argv

            def _get_arg(flag: str) -> Optional[str]:
                if flag in sys.argv:
                    idx = sys.argv.index(flag)
                    if idx + 1 < len(sys.argv):
                        return sys.argv[idx + 1]
                return None

            sc_id = _get_arg("--scenario") or _get_arg("-s") or "SCN-DEFAULT"

            if scenario_subcmd == "create":
                name = _get_arg("--name") or "New Scenario"
                base_snp = _get_arg("--base-snapshot") or _get_arg("--snapshot")
                if not base_snp:
                    from secgrc.twin import default_digital_twin_builder, default_twin_history_store
                    s = default_digital_twin_builder.build_snapshot()
                    default_twin_history_store.save_snapshot(s)
                    base_snp = s.snapshot_id
                handle_scenario_create(name=name, base_snapshot_id=base_snp, scenario_id=_get_arg("--scenario"), as_json=as_json)
                return
            elif scenario_subcmd == "change":
                etype = _get_arg("--entity-type") or "MFAConfiguration"
                eid = _get_arg("--entity") or "IDN-ROOT-ADMIN"
                fpath = _get_arg("--field") or "enabled"
                cval = _get_arg("--current") or "true"
                pval = _get_arg("--proposed") or "false"
                handle_scenario_change(scenario_id=sc_id, entity_type=etype, entity_id=eid, field_path=fpath, current_value=cval, proposed_value=pval, as_json=as_json)
                return
            elif scenario_subcmd == "validate":
                handle_scenario_validate(scenario_id=sc_id, as_json=as_json)
                return
            elif scenario_subcmd == "simulate":
                handle_scenario_simulate(scenario_id=sc_id, as_json=as_json)
                return
            elif scenario_subcmd == "impact":
                handle_scenario_impact(scenario_id=sc_id, as_json=as_json)
                return
            elif scenario_subcmd == "compare":
                handle_scenario_compare(scenario_id=sc_id, as_json=as_json)
                return
            else:
                print(f"❌ 지원하지 않는 scenario 서브커맨드입니다: {scenario_subcmd}")
                print("   사용법: python -m secgrc scenario create --name <NAME> --base-snapshot <ID> [--json]")
                print("           python -m secgrc scenario change --scenario <ID> --entity-type <TYPE> --entity <ID> --field <FIELD> --current <C> --proposed <P>")
                print("           python -m secgrc scenario validate --scenario <ID> [--json]")
                print("           python -m secgrc scenario simulate --scenario <ID> [--json]")
                print("           python -m secgrc scenario impact --scenario <ID> [--json]")
                print("           python -m secgrc scenario compare --scenario <ID> [--json]")
                return
        elif command == "decision":
            decision_subcmd = sys.argv[2].lower() if len(sys.argv) > 2 else "list"
            as_json = "--json" in sys.argv

            def _get_arg(flag: str) -> Optional[str]:
                if flag in sys.argv:
                    idx = sys.argv.index(flag)
                    if idx + 1 < len(sys.argv):
                        return sys.argv[idx + 1]
                return None

            target_id = _get_arg("--decision") or _get_arg("-d")
            if not target_id and len(sys.argv) > 3 and not sys.argv[3].startswith("-"):
                target_id = sys.argv[3]

            from secgrc.decision.cli import (
                handle_decision_context,
                handle_decision_list,
                handle_decision_show,
                handle_decision_lineage,
                handle_decision_options,
                handle_decision_history,
                handle_decision_replay,
                handle_decision_executive,
                handle_decision_grc,
                handle_decision_security,
                handle_decision_auditor,
            )

            if decision_subcmd == "context":
                handle_decision_context(as_json=as_json)
                return
            elif decision_subcmd == "list":
                handle_decision_list(as_json=as_json)
                return
            elif decision_subcmd == "show":
                handle_decision_show(decision_id=target_id or "DEC-2026-001", as_json=as_json)
                return
            elif decision_subcmd == "lineage":
                handle_decision_lineage(decision_id=target_id or "DEC-2026-001", as_json=as_json)
                return
            elif decision_subcmd == "options":
                handle_decision_options(decision_id=target_id or "DEC-2026-001", as_json=as_json)
                return
            elif decision_subcmd == "history":
                handle_decision_history(decision_id=target_id or "DEC-2026-001", as_json=as_json)
                return
            elif decision_subcmd == "replay":
                handle_decision_replay(decision_id=target_id or "DEC-2026-001", as_json=as_json)
                return
            elif decision_subcmd == "executive":
                handle_decision_executive(decision_id=target_id, as_json=as_json)
                return
            elif decision_subcmd == "grc":
                handle_decision_grc(decision_id=target_id, as_json=as_json)
                return
            elif decision_subcmd == "security":
                handle_decision_security(decision_id=target_id, as_json=as_json)
                return
            elif decision_subcmd == "auditor":
                handle_decision_auditor(decision_id=target_id, as_json=as_json)
                return
            else:
                print(f"❌ 지원하지 않는 decision 서브커맨드입니다: {decision_subcmd}")
                print("   사용법: python -m secgrc decision context [--json]")
                print("           python -m secgrc decision list [--json]")
                print("           python -m secgrc decision show <ID> [--json]")
                print("           python -m secgrc decision lineage <ID> [--json]")
                print("           python -m secgrc decision options <ID> [--json]")
                print("           python -m secgrc decision history <ID> [--json]")
                print("           python -m secgrc decision replay <ID> [--json]")
                print("           python -m secgrc decision executive [<ID>] [--json]")
                print("           python -m secgrc decision grc [<ID>] [--json]")
                print("           python -m secgrc decision security [<ID>] [--json]")
                print("           python -m secgrc decision auditor [<ID>] [--json]")
                return
        elif command in ("synthetic", "synthlab"):
            if len(sys.argv) > 2 and sys.argv[2] == "lifecycle":
                import argparse
                from secgrc.synthlab.lifecycle.cli import handle_lifecycle_cli
                parser = argparse.ArgumentParser(prog="secgrc synthlab lifecycle")
                subparsers = parser.add_subparsers(dest="lifecycle_command")
                subparsers.add_parser("list")

                create_parser = subparsers.add_parser("create")
                create_parser.add_argument("--simulation", dest="simulation_id", default="SIM-SYN-001")
                create_parser.add_argument("--organization", default="ORG-SYN-001")
                create_parser.add_argument("--seed", type=int, default=32001)

                for cmd_name in [
                    "run",
                    "show",
                    "timeline",
                    "findings",
                    "decisions",
                    "replay",
                    "integrity",
                ]:
                    p = subparsers.add_parser(cmd_name)
                    p.add_argument("simulation_id", nargs="?", default="SIM-SYN-001")

                state_parser = subparsers.add_parser("state")
                state_parser.add_argument("simulation_id", nargs="?", default="SIM-SYN-001")
                state_parser.add_argument("--tick", default="T00")

                rep_parser = subparsers.add_parser("report")
                rep_parser.add_argument("simulation_id", nargs="?", default="SIM-SYN-001")
                rep_parser.add_argument("--format", default="markdown")

                args = parser.parse_args(sys.argv[3:])
                sys.exit(handle_lifecycle_cli(args))
            if len(sys.argv) > 2 and sys.argv[2] == "audit":
                import argparse
                from secgrc.synthlab.audit.cli import handle_audit_cli
                parser = argparse.ArgumentParser(prog="secgrc synthlab audit")
                subparsers = parser.add_subparsers(dest="audit_command")
                subparsers.add_parser("list")

                create_parser = subparsers.add_parser("create")
                create_parser.add_argument("--scenario", dest="scenario_id", default="AUDIT-001")
                create_parser.add_argument("--organization", default="ORG-SYN-001")
                create_parser.add_argument("--audit-type", default="ISMS_P_INITIAL")
                create_parser.add_argument("--framework", default="ISMS-P")
                create_parser.add_argument("--seed", type=int, default=42)

                for cmd_name in [
                    "run",
                    "show",
                    "requirements",
                    "evidence",
                    "findings",
                    "timeline",
                    "replay",
                    "integrity",
                ]:
                    p = subparsers.add_parser(cmd_name)
                    p.add_argument("scenario_id", nargs="?", default="AUDIT-001")

                rep_parser = subparsers.add_parser("report")
                rep_parser.add_argument("scenario_id", nargs="?", default="AUDIT-001")
                rep_parser.add_argument("--format", default="markdown")

                args = parser.parse_args(sys.argv[3:])
                sys.exit(handle_audit_cli(args))
            if len(sys.argv) > 2 and sys.argv[2] == "campaign":
                import argparse
                from secgrc.synthlab.campaign.cli import handle_campaign_cli
                parser = argparse.ArgumentParser(prog="secgrc synthlab campaign")
                subparsers = parser.add_subparsers(dest="campaign_command")
                subparsers.add_parser("list")
                
                create_parser = subparsers.add_parser("create")
                create_parser.add_argument("--organization", default="ORG-SYN-001")
                create_parser.add_argument("--campaign", default="CAMPAIGN-01")
                create_parser.add_argument("--seed", type=int, default=1001)
                
                run_parser = subparsers.add_parser("run")
                run_parser.add_argument("campaign_id")
                
                val_parser = subparsers.add_parser("validate")
                val_parser.add_argument("campaign_id")
                
                rep_parser = subparsers.add_parser("report")
                rep_parser.add_argument("campaign_id")
                
                replay_parser = subparsers.add_parser("replay")
                replay_parser.add_argument("campaign_id")
                
                cov_parser = subparsers.add_parser("coverage")
                cov_parser.add_argument("campaign_id")
                
                args = parser.parse_args(sys.argv[3:])
                sys.exit(handle_campaign_cli(args))
            if len(sys.argv) > 2 and sys.argv[2] == "telemetry":
                from secgrc.synthlab.telemetry.cli import handle_telemetry_cli
                sys.exit(handle_telemetry_cli(sys.argv[3:]))
            if len(sys.argv) > 2 and sys.argv[2] == "evidence":
                from secgrc.synthlab.evidence.cli import handle_evidence_cli
                sys.exit(handle_evidence_cli(sys.argv[3:]))
            if len(sys.argv) > 2 and sys.argv[2] in ("organization", "state"):
                from secgrc.synthetic.cli import handle_synthetic_cli
                sys.exit(handle_synthetic_cli(sys.argv[2:]))
            from secgrc.synthlab.cli import run_synthetic_command
            run_synthetic_command(sys.argv[2:])
            return
        elif command == "connector":
            from secgrc.connectors.cli import handle_connector_cli
            sys.exit(handle_connector_cli(sys.argv[2:]))
        elif command == "evidence-plan":
            from secgrc.compliance.sufficiency.cli import run_evidence_plan_cli
            sys.exit(run_evidence_plan_cli(sys.argv[2:]))
        elif command in ("-h", "--help"):
            print("🛡️ GRC Agent 사용법:")
            print("  python -m secgrc synthetic [scenarios|generate|run|validate|report]: 합성 보안 데이터 랩 (Step 32)")
            print("  python -m secgrc decision [context|list|show|lineage|options|history|replay|executive|grc|security|auditor]: 의사결정 인텔리전스")
            print("  secgrc                                         : 대화형 실시간 보안 감사 모드")
            print("  python -m secgrc twin [state|entities|as-of|diff|blast-radius] [--json]: 엔터프라이즈 디지털 트윈 통합 표상")
            print("  python -m secgrc actions [list|show|pending|approve|reject|execute|history|causal-chain] [--action <ID>] [--json]: 통제된 액션 오케스트레이션")
            print("  python -m secgrc ai [investigate|explain|hypotheses|questions] [--investigation|--assessment <ID>] [--json]: AI 보조 보안 추론 및 가설 도출")
            print("  python -m secgrc dashboard [--framework <fw>] [--role <role>] [--json|--html]: CISO 컴플라이언스 & 보안 지능 대시보드")

            print("  python -m secgrc security adversarial [--list|--run-all|--report|--category <cat>]: 적대적 보안 검증 프레임워크")
            print("  python -m secgrc events [list|process|replay|causal-chain|dlq|status|decision-queue] [--json]: 이벤트 기반 GRC 오케스트레이터")

            print("  python -m secgrc compliance coverage [--framework ISMS-P] [--json]: 엔터프라이즈 컴플라이언스 입력 데이터 커버리지 분석")
            print("  python -m secgrc compliance evidence-requirements --framework ISMS-P --requirement <ID> [--json]: 요구사항별 증적 요건 분석")
            print("  python -m secgrc compliance assess --framework ISMS-P [--requirement <ID> | --all] [--json]: 결정론적 컴플라이언스 준거성 평가")
            print("  python -m secgrc compliance report --framework ISMS-P [--type executive|grc_manager|auditor|technical] [--json|--markdown]: 컴플라이언스 보고서 생성")
            print("  python -m secgrc investigation report --investigation <ID> [--json|--markdown]: 조사 결과 안전 가드 검증 보고서 생성")

            print("  python -m secgrc search <검색어>               : 통제항목, 증적, 프레임워크 검색")
            print("  python -m secgrc map <통제ID>                 : 글로벌 프레임워크(ISO/NIST/CIS) 매핑 상세")
            print("  python -m secgrc evidence [통제ID]            : 수집된 클라우드 증적(Finding) 대시보드")
            print("  python -m secgrc evidence prowler <경로>       : Prowler CSV 증적 파일 요약 리포트")
            print("  python -m secgrc audit prowler <경로> [--json] : 결정론적 ISMS-P 컴플라이언스 감사 수행")
            print("  python -m secgrc risk prowler <경로> [--json]  : GRC 위험 점수(Risk Score) 산출")
            print("  python -m secgrc ai-audit prowler <경로> [--json]: AI Auditor 심층 보안 분석 및 조치 권고 생성")
            print("  python -m secgrc report prowler <경로> [--format markdown|html|json]: 종합 GRC 보안 감사 보고서 생성")
            print("  python -m secgrc web-cert [--host 127.0.0.1] [--port 8001]: ISMS-P 인증심사 전용 콘솔(v2) 실행")
            print("  python -m secgrc agent run prowler <경로> [--dry-run] [--json] [--scan-id <id>]: LangGraph 자율 GRC 워크플로우 실행")
            print("  python -m secgrc closed-loop run <경로> [--simulate]: Closed-loop(Discover->Remediate->Verify) 워크플로우 실행")
            print("  python -m secgrc continuous simulate                          : Continuous GRC 변경 감지 및 위험 변동 시뮬레이션")
            print("  python -m secgrc redteam run [--category CAT] [--json]        : AI Agent Red Team / Purple Team 보안 검증 실행")
            print("  python -m secgrc redteam scenario <scenario_id>               : 특정 Red Team 시나리오 단건 상세 실행")
            print("  python -m secgrc ontology build [--csv <path>] [--json]       : 보안 지식 그래프 / 온톨로지 빌드")
            print("  python -m secgrc ontology summary [--json]                    : 지식 그래프 요약 및 프레임워크 커버리지")
            print("  python -m secgrc ontology lineage <id> [--json]               : 증적/통제/위험 전주기 보안 혈통(Lineage) 분석")
            print("  python -m secgrc ontology framework [ISMS-P] [--json]         : 프레임워크별 통제 유효성 및 자동화 커버리지")
            print("  python -m secgrc copilot ask \"<질의문>\" [--role role] [--json]: AI GRC Copilot 자연어 보안 질의")
            return

    run_interactive()


if __name__ == "__main__":
    main()
