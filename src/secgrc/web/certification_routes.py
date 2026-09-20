"""ISMS-P Audit Assurance 콘솔 라우터 (v2).

기존 광범위 GRC 콘솔(routes.py)과 완전히 분리된 인증심사 전용 엔드포인트.
모든 판정 데이터는 백엔드 엔진/assurance_data 서비스에서만 제공됩니다.

라우트 구성:
- HTML: /audit(Control Center), /controls(Landscape), /controls/{id}(Detail),
        /evidence, /gap, /findings, /replay + Data/Reporting/Administration
- JSON: /api/audit/* — UI가 소비하는 typed 계약 (합성 데이터는 demo:true)
"""

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from secgrc.audit_findings.manager import FindingSeverity, audit_findings_manager
from secgrc.control_engine.engine import control_engine
from secgrc.evidence.document.repository import DocumentType
from secgrc.evidence.ledger import EvidenceRecordType, evidence_ledger
from secgrc.evidence.review_workflow import EvidenceReviewWorkflow
from secgrc.reconciliation.engine import reconciliation_engine
from secgrc.web import assurance_data as ad

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates_certification"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


def _ctx(request: Request, page: str, audit_id: Optional[str] = None, **extra) -> Dict[str, Any]:
    """공통 템플릿 컨텍스트 — 감사 컨텍스트 카드 + 내비 배지."""
    ad.ensure_demo_dataset()
    fs = audit_findings_manager.get_finding_summary()
    return {
        "request": request,
        "active_page": page,
        "audit_ctx": ad.get_audit_context(audit_id),
        "nav_gaps": len(ad._GAP_CATALOG),
        "nav_findings": fs["open_findings"] + fs["in_progress_findings"],
        **extra,
    }


# ---------------------------------------------------------------------------
# Audit 그룹
# ---------------------------------------------------------------------------

@router.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/audit")


@router.get("/dashboard", include_in_schema=False)
async def legacy_dashboard() -> RedirectResponse:
    return RedirectResponse(url="/audit")


@router.get("/healthz", include_in_schema=False)
async def healthz() -> Dict[str, str]:
    return {"status": "ok", "console": "certification-assurance"}


@router.get("/audit", response_class=HTMLResponse)
async def audit_control_center(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    """Screen #1 — Audit Control Center (메인 랜딩)."""
    kpis = ad.get_kpis(audit)
    gaps = ad.get_gaps(audit_id=audit)
    return templates.TemplateResponse(request, "control_center.html",
        _ctx(request, "audit", audit,
             kpis=kpis,
             top_issues=ad.get_top_issues(5, audit_id=audit),
             recent_gaps=gaps["gaps"][:8],
             population=ad.get_population(audit)),
    )


@router.get("/controls", response_class=HTMLResponse)
async def control_landscape(request: Request, audit: Optional[str] = None,
                            state: Optional[str] = None) -> HTMLResponse:
    """Control Landscape — 101개 통제 인터랙티브 트리."""
    return templates.TemplateResponse(request, "controls.html",
        _ctx(request, "controls", audit,
             loaded_count=len(control_engine._controls),
             current_state=state),
    )


@router.get("/controls/{control_id}", response_class=HTMLResponse)
async def control_detail(request: Request, control_id: str,
                         audit: Optional[str] = None) -> HTMLResponse:
    """Control Detail Workspace — 증적 체인 노드 클릭형."""
    detail = ad.get_control_detail(control_id)
    if detail is None:
        return RedirectResponse(url="/controls")
    return templates.TemplateResponse(request, "control_detail.html", _ctx(request, "controls", audit, detail=detail)
    )


@router.get("/evidence", response_class=HTMLResponse)
async def evidence_management(request: Request, audit: Optional[str] = None,
                              status: Optional[str] = None) -> HTMLResponse:
    """Evidence Management — 원장 + 표본 요청 추적."""
    records = [
        {
            "record_id": r.record_id, "evidence_id": r.evidence_id,
            "control_id": r.control_id.replace("ISMS-P-", ""),
            "record_type": r.record_type.value, "collection_method": r.collection_method,
            "created_by": r.created_by,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "hash": r.hash,
        }
        for r in reversed(evidence_ledger._records)
    ]
    # 증적별 승인 단계 — 원장 REVIEW 레코드에서 도출 (EVIDENCE 레코드에만 표시)
    stage_cache: Dict[str, Dict[str, str]] = {}
    for rec in records:
        eid = rec["evidence_id"]
        if rec["record_type"] != "EVIDENCE":
            continue
        if eid not in stage_cache:
            st = _review_workflow.get_state(eid)
            stage_cache[eid] = {"stage": st["stage"], "stage_label": st["stage_label"]}
        rec.update(stage_cache[eid])
    return templates.TemplateResponse(request, "evidence.html",
        _ctx(request, "evidence", audit,
             records=records,
             retention=evidence_ledger.get_retention_report(),
             chain_valid=evidence_ledger.verify_chain_integrity(),
             ws=ad.get_workspace_summary(),
             filter_status=status),
    )


@router.get("/gap", response_class=HTMLResponse)
async def gap_analysis(request: Request, audit: Optional[str] = None,
                       status: Optional[str] = None) -> HTMLResponse:
    """GAP Analysis — 요구↔정책↔설정↔증적↔운영 불일치."""
    gaps = ad.get_gaps(audit_id=audit)["gaps"]
    type_counts: Dict[str, int] = {}
    sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for g in gaps:
        type_counts[g["gap_type"]] = type_counts.get(g["gap_type"], 0) + 1
        sev_counts[g["severity"]] = sev_counts.get(g["severity"], 0) + 1
    recon_results = [
        {"control_id": r.control_id.replace("ISMS-P-", ""),
         "type": r.reconciliation_type.value, "status": r.status.value,
         "severity": r.severity, "description": r.description}
        for r in reconciliation_engine.results
    ]
    return templates.TemplateResponse(request, "gap.html",
        _ctx(request, "gap", audit,
             gaps=gaps, type_counts=type_counts, sev_counts=sev_counts,
             recon_summary=reconciliation_engine.get_reconciliation_summary(),
             recon_results=recon_results),
    )


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request, audit: Optional[str] = None,
                        status: Optional[str] = None) -> HTMLResponse:
    """Findings & Actions — 지적사항 생명주기."""
    fv = ad.get_findings_view()
    return templates.TemplateResponse(request, "findings.html",
        _ctx(request, "findings", audit,
             findings=fv["findings"], summary=fv["summary"], trend=fv["trend"]),
    )


@router.get("/replay", response_class=HTMLResponse)
async def audit_replay(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    """Audit Replay — 스크립트 심사 시뮬레이션."""
    return templates.TemplateResponse(request, "replay.html", _ctx(request, "replay", audit))


# ---------------------------------------------------------------------------
# Data & Integration 그룹
# ---------------------------------------------------------------------------

@router.get("/collection", response_class=HTMLResponse)
async def collection_status(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    return templates.TemplateResponse(request, "collection.html", _ctx(request, "collection", audit, collectors=ad.get_collectors())
    )


@router.get("/intake", response_class=HTMLResponse)
async def evidence_intake(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    land = ad.get_landscape()
    # 전체 101개 통제를 도메인별 optgroup으로 — 검색·추천과 병용해 선택 부담 완화
    control_groups = [
        {"label": f"{d['id']}. {d['name']}", "controls": [c for s in d["sub"] for c in s["controls"]]}
        for d in land["domains"]
    ]
    checks = [
        {"doc": "정보보호정책_v3.2.pdf", "control": "1.1.5", "sensitive": False, "version": "v3.2", "passed": True},
        {"doc": "보안교육_실적_2026Q1.xlsx", "control": "2.2.4", "sensitive": False, "version": "v1.0", "passed": True},
        {"doc": "계정권한_현황_원본.xlsx", "control": "2.5.1", "sensitive": True, "version": "v1.1", "passed": False},
        {"doc": "IT운영위원회_회의록.pdf", "control": "1.3.2", "sensitive": False, "version": "v2.0", "passed": True},
    ]
    return templates.TemplateResponse(request, "intake.html", _ctx(request, "intake", audit, control_groups=control_groups, intake_checks=checks)
    )


@router.get("/connections", response_class=HTMLResponse)
async def connections(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    return templates.TemplateResponse(request, "connections.html", _ctx(request, "connections", audit, systems=ad.get_connections())
    )


# ---------------------------------------------------------------------------
# Reporting / Administration 그룹
# ---------------------------------------------------------------------------

_REPORTS = [
    {"key": "readiness", "name": "인증 준비도 보고서", "desc": "통제별 준비도·증적 현황·미비 항목 종합", "source": "ControlEngine+GAP", "format": "HTML (인쇄→PDF)"},
    {"key": "gap", "name": "GAP 분석 리포트", "desc": "정책↔설정↔증적 불일치 목록 및 근거", "source": "Reconciliation", "format": "HTML (인쇄→PDF)"},
    {"key": "findings", "name": "결함보고서", "desc": "지적사항 12개 분석 필드 + 보완조치 이력", "source": "FindingsManager", "format": "HTML (인쇄→PDF)"},
    {"key": "integrity", "name": "증적 무결성 증명", "desc": "원장 해시체인 검증 결과 및 수집 출처", "source": "EvidenceLedger", "format": "HTML/JSON"},
    {"key": "package", "name": "심사 제출 패키지", "desc": "증적+정합성+지적사항+조치 이력 묶음", "source": "전 계층", "format": "JSON 다운로드"},
]


@router.get("/reports", response_class=HTMLResponse)
async def reports(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    return templates.TemplateResponse(request, "reports.html", _ctx(request, "reports", audit, reports=_REPORTS)
    )


@router.get("/reports/{report_key}")
async def report_render(request: Request, report_key: str,
                        audit: Optional[str] = None) -> Any:
    """리포트 생성 — 서버가 현재 데이터로 렌더링 (데모 섹션은 demo 표기).

    package는 전 계층 JSON 묶음을 파일로 다운로드하고, 나머지는
    인쇄 가능한 HTML 보고서를 새 탭에 표시한다.
    """
    if report_key == "package":
        data = ad.build_package(audit)
        ts = datetime.now().strftime("%Y%m%d-%H%M")
        return JSONResponse(
            data,
            headers={"Content-Disposition":
                     f'attachment; filename="ismsp-audit-package-{ts}.json"'},
        )
    data = ad.build_report(report_key, audit)
    if data is None:
        return RedirectResponse(url="/reports")
    return templates.TemplateResponse(request, "report_render.html", {"request": request, "r": data})


class FindingCreateRequest(BaseModel):
    gap_id: str = ""
    control_id: str
    control_name: str = ""
    title: str = ""
    description: str = ""
    severity: str = "MEDIUM"
    system: str = ""
    owner: str = ""
    due_date: str = ""
    audit_id: str = ""


@router.post("/api/audit/findings")
async def api_create_finding(body: FindingCreateRequest) -> Dict[str, Any]:
    """GAP 항목을 지적사항으로 등록 — 같은 GAP의 중복 등록은 멱등하게 반환."""
    ad.ensure_demo_dataset()
    if body.gap_id:
        for f in audit_findings_manager._findings.values():
            if body.gap_id in (f.tags or []):
                return {"ok": True, "already": True, "finding_id": f.finding_id,
                        "defect_number": f.defect_number}
    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "MAJOR",
               "MEDIUM": "MINOR", "LOW": "OBSERVATION"}
    sev = FindingSeverity[sev_map.get(body.severity.upper(), "MINOR")]
    year = datetime.now().year
    existing = {f.defect_number for f in audit_findings_manager._findings.values()}
    n = 1
    while f"DEF-{year}-{n:03d}" in existing:
        n += 1
    try:
        due = datetime.strptime(body.due_date, "%Y-%m-%d") if body.due_date else None
    except ValueError:
        due = None
    f = audit_findings_manager.create_finding(
        audit_id=body.audit_id or "AUDIT-DEMO-001",
        control_id=body.control_id,
        control_name=body.control_name or body.control_id,
        severity=sev,
        title=body.title or f"{body.control_id} GAP 지적사항",
        description=body.description or "GAP 분석에서 확인된 불일치",
        auditor="심사대응 담당자",
        defect_number=f"DEF-{year}-{n:03d}",
        confirmed_facts=body.description or "",
        target=body.system or "관련 시스템",
        judgment_basis="GAP 분석 결과 (요구↔정책↔설정↔증적↔운영 대사)",
        additional_checks="전체 모집단 수준 점검 필요",
        submission_deadline=due,
        assignee=body.owner or None,
    )
    if body.gap_id:
        f.tags.append(body.gap_id)
    return {"ok": True, "finding_id": f.finding_id, "defect_number": f.defect_number}


@router.get("/history", response_class=HTMLResponse)
async def audit_history(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    return templates.TemplateResponse(request, "history.html", _ctx(request, "history", audit, audits=ad._DEMO_AUDITS)
    )


@router.get("/criteria", response_class=HTMLResponse)
async def isms_criteria(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    land = ad.get_landscape()
    return templates.TemplateResponse(request, "criteria.html",
        _ctx(request, "criteria", audit,
             framework=land["domains"], loaded=len(control_engine._controls)),
    )


@router.get("/users", response_class=HTMLResponse)
async def users(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    user_list = [
        {"name": "빵떼옹", "role": "심사대응 담당자", "dept": "정보보호팀", "scope": "증적 제출·조치 수행", "status": "ACTIVE"},
        {"name": "이관리", "role": "통제 담당자", "dept": "IT운영팀", "scope": "담당 통제 증적 관리", "status": "ACTIVE"},
        {"name": "정심사", "role": "독립 재검증자", "dept": "내부감사팀", "scope": "조치 완료 검증", "status": "ACTIVE"},
        {"name": "박개인", "role": "승인자", "dept": "개인정보보호팀", "scope": "잔여위험 수용 승인", "status": "ACTIVE"},
        {"name": "최인프라", "role": "관리자", "dept": "인프라팀", "scope": "커넥터·기준 버전 관리", "status": "ACTIVE"},
    ]
    return templates.TemplateResponse(request, "users.html", _ctx(request, "users", audit, users=user_list)
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    import os
    cfg = [
        {"name": "접근 인증 모드", "value": os.getenv("GRC_WEB_AUTH", "auto"),
         "desc": "auto=로컬호스트 면제 / required=전체 인증 / disabled=비활성"},
        {"name": "증적 원장", "value": "Append-only + 해시체인",
         "desc": "수정 불가 — 정정은 별도 레코드로 추가"},
        {"name": "커넥터 원칙", "value": "읽기 전용",
         "desc": "수집 커넥터는 대상 시스템을 변경하지 않음"},
        {"name": "인증기준 버전", "value": "ISMS-P 2023.10.31",
         "desc": "101개 인증기준 구조 (관리체계16+보호대책64+개인정보21)"},
        {"name": "민감정보 검사", "value": "제출 전 자동 차단",
         "desc": "비밀번호·키·개인정보 포함 증적 제출 차단"},
    ]
    return templates.TemplateResponse(request, "settings.html", _ctx(request, "settings", audit, settings=cfg)
    )


# 레거시 경로 호환 → 새 IA로 리다이렉트
@router.get("/reconciliation", include_in_schema=False)
async def legacy_recon() -> RedirectResponse:
    return RedirectResponse(url="/gap")


# ---------------------------------------------------------------------------
# JSON API — UI가 소비하는 typed 계약
# ---------------------------------------------------------------------------

@router.get("/api/audit/context")
async def api_context(audit: Optional[str] = None) -> Dict[str, Any]:
    return ad.get_audit_context(audit)


@router.get("/api/audit/kpis")
async def api_kpis(audit: Optional[str] = None) -> Dict[str, Any]:
    return ad.get_kpis(audit)


@router.get("/api/audit/landscape")
async def api_landscape() -> Dict[str, Any]:
    ad.ensure_demo_dataset()
    return ad.get_landscape()


@router.get("/api/audit/controls/{control_id}")
async def api_control(control_id: str) -> Dict[str, Any]:
    detail = ad.get_control_detail(control_id)
    if detail is None:
        return {"error": "not_found", "control_id": control_id}
    return detail


@router.get("/api/audit/gaps")
async def api_gaps(status: Optional[str] = None, audit: Optional[str] = None) -> Dict[str, Any]:
    return ad.get_gaps(status, audit_id=audit)


@router.get("/api/audit/findings")
async def api_findings() -> Dict[str, Any]:
    return ad.get_findings_view()


@router.get("/api/audit/population")
async def api_population(audit: Optional[str] = None) -> Dict[str, Any]:
    return ad.get_population(audit)


@router.get("/api/audit/trend")
async def api_trend() -> Dict[str, Any]:
    return ad.get_trend()


@router.get("/api/audit/snapshots")
async def api_snapshots() -> Any:
    return ad.get_snapshots()


@router.get("/api/audit/snapshot")
async def api_snapshot(date: Optional[str] = None) -> Dict[str, Any]:
    return ad.get_snapshot(date or datetime.now().strftime("%Y-%m-%d"))


@router.get("/api/audit/activity")
async def api_activity() -> Dict[str, Any]:
    return ad.get_activity()


@router.get("/api/audit/replay")
async def api_replay() -> Dict[str, Any]:
    return ad.get_replay_scenario()


class AssistantRequest(BaseModel):
    message: str
    page: Optional[str] = None


@router.post("/api/audit/assistant")
async def api_assistant(body: AssistantRequest) -> Dict[str, Any]:
    return ad.post_assistant(body.message, page=body.page)


class SuggestRequest(BaseModel):
    file_name: str = ""
    sample: str = ""


@router.post("/api/audit/evidence/suggest")
async def api_evidence_suggest(body: SuggestRequest) -> Dict[str, Any]:
    """파일명+본문 샘플로 통제항목을 추천한다 (advisory — 상태 변경 없음)."""
    return ad.suggest_control(body.file_name, body.sample)


# ---------------------------------------------------------------------------
# Prowler CSPM 연동 — 실구현 커넥터(connectors/prowler)를 콘솔에 연결한다.
# 실행 경로: ① Docker 컨테이너 라이브 스캔 (호스트에 Docker 데몬 + GCP ADC 필요)
#           ② 외부 실행 결과 JSON 업로드 → 정규화·원장 기록 (replay, 상시 가능)
# ---------------------------------------------------------------------------

_PROWLER_OPS: Dict[str, Dict[str, Any]] = {}   # op_id → 진행 상태 (인메모리)
_PROWLER_INCOMING = Path("data/prowler/incoming")


def _prowler_service():
    from secgrc.connectors.prowler.service import get_prowler_service
    return get_prowler_service()


def _prowler_capabilities() -> Dict[str, Any]:
    cloudrun = os.environ.get("PROWLER_EXECUTION_MODE", "").lower() == "cloudrun"
    cloudrun_ready = cloudrun and all(
        os.environ.get(k) for k in
        ("PROWLER_JOB_NAME", "PROWLER_JOB_REGION", "PROWLER_GCS_BUCKET"))
    docker_bin = shutil.which("docker")
    docker_running = False
    if docker_bin:
        try:
            docker_running = subprocess.run(
                [docker_bin, "info"], capture_output=True, timeout=5).returncode == 0
        except Exception:
            docker_running = False
    adc = Path.home() / ".config/gcloud/application_default_credentials.json"
    return {
        "execution_mode": "cloudrun" if cloudrun else "docker",
        "docker_binary": bool(docker_bin),
        "docker_running": docker_running,
        "adc_present": adc.exists(),
        "cloudrun_configured": cloudrun_ready,
        "live_scan_available": cloudrun_ready or bool(docker_running and adc.exists()),
    }


def _prowler_run_summary(run) -> Dict[str, Any]:
    return {
        "run_id": run.run_id, "status": run.status,
        "record_count": run.record_count, "accepted": run.accepted_count,
        "rejected": run.rejected_count, "exit_code": run.exit_code,
        "started_at": run.started_at, "prowler_version": run.prowler_version,
    }


def _prowler_ledger_record(run_id: str, project_id: str, record_count: int,
                           manifest_hash: str, mode: str) -> None:
    """수집 실행 자체를 불변 원장에 기록 — 수집 시각·결과 해시의 provenance."""
    evidence_ledger.append_record(
        evidence_id=f"CSPM-{run_id.upper()}",
        control_id="COLLECTION-PROWLER",
        content={
            "kind": "prowler_collection_run", "run_id": run_id,
            "project_id": project_id, "record_count": record_count,
            "manifest_hash": manifest_hash, "mode": mode,
        },
        record_type=EvidenceRecordType.EVIDENCE,
        created_by="web-console", collection_method="AUTOMATED",
        source_system="Prowler-GCP",
    )


@router.get("/api/audit/collection/prowler")
async def api_prowler_status() -> Dict[str, Any]:
    svc = _prowler_service()
    runs = [_prowler_run_summary(r) for r in svc.list_runs()]
    runs.sort(key=lambda r: r["started_at"] or "", reverse=True)
    return {
        "capabilities": _prowler_capabilities(),
        "ops": sorted(_PROWLER_OPS.values(), key=lambda o: o.get("started_at", ""), reverse=True)[:20],
        "runs": runs[:50],
    }


class ProwlerRunRequest(BaseModel):
    project_id: str
    organization_id: str = "default"
    services: str = ""   # 쉼표 구분 — 비우면 전체 체크 스캔


@router.post("/api/audit/collection/prowler/run")
async def api_prowler_run(body: ProwlerRunRequest) -> JSONResponse:
    """GCP 프로젝트 대상 라이브 스캔 — Docker 격리 실행, 백그라운드 스레드."""
    from secgrc.connectors.prowler.models import (
        GcpCredentialReference, ProwlerGcpTarget, ProwlerRuntimeConfig,
    )
    caps = _prowler_capabilities()
    if not caps["live_scan_available"]:
        reasons = []
        if caps["execution_mode"] == "cloudrun":
            reasons.append(
                "Cloud Run Job 미구성 — PROWLER_JOB_NAME·PROWLER_JOB_REGION·"
                "PROWLER_GCS_BUCKET 환경변수를 확인하세요")
        else:
            if not caps["docker_binary"]:
                reasons.append("Docker 미설치")
            elif not caps["docker_running"]:
                reasons.append("Docker 데몬 미실행 — Docker Desktop을 시작하세요")
            if not caps["adc_present"]:
                reasons.append("GCP ADC 없음 — gcloud auth application-default login 필요")
        return _reject("live_scan_unavailable", 503, reasons=reasons,
                       hint="Docker 없이도 '결과 파일 업로드'로 외부 실행 결과를 수집할 수 있습니다.")

    pid = body.project_id.strip()
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", pid):
        return _reject("invalid_project_id", 400)
    services = [s.strip().lower() for s in (body.services or "").split(",") if s.strip()]
    if any(not re.fullmatch(r"[a-z0-9_]{1,40}", s) for s in services):
        return _reject("invalid_services", 400)

    config = ProwlerRuntimeConfig()
    target = ProwlerGcpTarget(
        organization_id=(body.organization_id or "default").strip()[:100] or "default",
        tenant_id="default",
        gcp_project_ids=[pid],
        credential_ref=GcpCredentialReference(
            credential_ref_id="adc-default", auth_mode="ADC", project_ref=pid),
    )
    op_id = f"op-{uuid.uuid4().hex[:8]}"
    _PROWLER_OPS[op_id] = {
        "op_id": op_id, "status": "RUNNING", "project_id": pid,
        "started_at": datetime.now().isoformat(timespec="seconds"),
    }

    def _work() -> None:
        try:
            run = _prowler_service().execute_scan(
                config=config, target=target, timeout_seconds=600,
                services=services or None)
            _PROWLER_OPS[op_id].update(
                status=run.status, run_id=run.run_id,
                record_count=run.record_count, accepted=run.accepted_count)
            _prowler_ledger_record(run.run_id, pid, run.record_count,
                                   run.provenance.get("manifest_hash", ""), "LIVE_READ_ONLY")
        except Exception as exc:
            _PROWLER_OPS[op_id].update(status="FAILED", error=str(exc)[:300])

    threading.Thread(target=_work, daemon=True).start()
    return JSONResponse({"ok": True, "op_id": op_id, "status": "RUNNING"})


@router.post("/api/audit/collection/prowler/replay")
async def api_prowler_replay(request: Request, project_id: str = "uploaded-scan") -> JSONResponse:
    """외부에서 실행한 prowler 결과 JSON을 업로드해 정규화 — Docker/GCP 인증 불필요."""
    from secgrc.connectors.prowler.models import (
        GcpCredentialReference, ProwlerGcpTarget,
    )
    if request.headers.get("x-evidence-upload") != "1":
        return _reject("missing_upload_header", 403)
    origin = request.headers.get("origin")
    if origin:
        host = request.headers.get("host", "")
        fwd = {h.strip() for h in request.headers.get("x-forwarded-host", "").split(",") if h.strip()}
        if urlparse(origin).netloc not in ({host} | fwd):
            o_host = urlparse(origin).hostname or ""
            h_host = urlparse(f"//{host}").hostname or ""
            if not (o_host in _LOOPBACK_HOSTS and h_host in _LOOPBACK_HOSTS):
                return _reject("origin_mismatch", 403)

    raw_name = unquote(request.headers.get("x-file-name", ""))
    file_name = Path(raw_name).name.replace("\\", "/").split("/")[-1].strip()
    file_name = "".join(ch for ch in file_name if ch.isalnum() or ch in " ._-()[]")
    if not file_name.lower().endswith(".json"):
        return _reject("extension_not_allowed", 415, ext=Path(file_name).suffix)

    body = await request.body()
    if not body or len(body) > 50 * 1024 * 1024:
        return _reject("invalid_size", 400)
    try:
        json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return _reject("invalid_json", 400)

    _PROWLER_INCOMING.mkdir(parents=True, exist_ok=True)
    saved = _PROWLER_INCOMING / f"{uuid.uuid4().hex[:12]}_{file_name}"
    saved.write_bytes(body)

    pid = project_id.strip() if re.fullmatch(r"[a-zA-Z0-9._-]{1,40}", project_id.strip()) else "uploaded-scan"
    target = ProwlerGcpTarget(
        organization_id="default", tenant_id="default",
        gcp_project_ids=[pid],
        credential_ref=GcpCredentialReference(
            credential_ref_id="replay-upload", auth_mode="ADC", project_ref=pid),
    )
    try:
        run = _prowler_service().replay(str(saved), target=target)
    except Exception as exc:
        return _reject("replay_failed", 400, detail=str(exc)[:200])

    _prowler_ledger_record(run.run_id, pid, run.record_count,
                           run.provenance.get("normalized_hash", ""), "REPLAY")
    return JSONResponse({"ok": True, **_prowler_run_summary(run)})


@router.get("/api/audit/collection/prowler/runs/{run_id}")
async def api_prowler_run_detail(run_id: str) -> JSONResponse:
    if not re.fullmatch(r"[A-Za-z0-9_-]{4,60}", run_id):
        return _reject("invalid_run_id", 400)
    svc = _prowler_service()
    try:
        report = svc.get_run_report(run_id)
    except Exception:
        return _reject("not_found", 404)

    recs = svc.get_canonical_records(run_id)
    by_severity: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_service: Dict[str, int] = {}
    failed: Dict[str, Dict[str, Any]] = {}
    for r in recs:
        p = r.payload or {}
        by_severity[p.get("source_severity", "?")] = by_severity.get(p.get("source_severity", "?"), 0) + 1
        by_status[p.get("source_status", "?")] = by_status.get(p.get("source_status", "?"), 0) + 1
        if p.get("service"):
            by_service[p["service"]] = by_service.get(p["service"], 0) + 1
        if str(p.get("source_status", "")).upper() in ("FAIL", "MUTED"):
            cid = p.get("check_id", "?")
            e = failed.setdefault(cid, {"check_id": cid, "count": 0,
                                        "severity": p.get("source_severity", ""),
                                        "description": p.get("description", "")[:160]})
            e["count"] += 1
    report.update({
        "findings_by_severity": by_severity,
        "findings_by_status": by_status,
        "findings_by_service": dict(sorted(by_service.items(), key=lambda kv: -kv[1])[:10]),
        "failed_checks": sorted(failed.values(), key=lambda x: -x["count"])[:15],
    })
    return JSONResponse(report)


@router.get("/collection/prowler/runs/{run_id}/report")
async def prowler_run_report(request: Request, run_id: str,
                             audit: Optional[str] = None) -> Any:
    """Prowler 스캔 결과를 인쇄 가능한 보고서로 렌더링 (증적 제출용 문서)."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{4,60}", run_id):
        return RedirectResponse(url="/collection")
    data = ad.build_scan_report(run_id, audit)
    if data is None:
        return RedirectResponse(url="/collection")
    return templates.TemplateResponse(request, "report_render.html", {"request": request, "r": data})


_PREVIEW_MAX_BYTES = 256 * 1024
_PREVIEW_TEXT_EXT = {".txt", ".md", ".csv", ".log", ".json", ".html", ".htm"}


def _preview_of_record(rec) -> Dict[str, Any]:
    """원장 레코드를 미리보기 페이로드로 변환."""
    return {
        "kind": "record",
        "title": f"{rec.record_id} — 원장 레코드",
        "evidence_id": rec.evidence_id,
        "control_id": rec.control_id.replace("ISMS-P-", ""),
        "doc_type": rec.record_type.value,
        "uploaded_at": rec.created_at.strftime("%Y-%m-%d %H:%M"),
        "sha256": rec.hash,
        "content": json.dumps(rec.content, ensure_ascii=False, indent=2),
    }


@router.get("/api/audit/evidence/{evidence_id}/preview")
async def api_evidence_preview(evidence_id: str) -> Any:
    """증적 원문 인라인 미리보기 — 텍스트류는 본문, 그 외는 원장 레코드/메타데이터."""
    eid = evidence_id.strip().upper()

    if eid.startswith("REC-"):
        rec = evidence_ledger.get_record(eid)
        if rec is None:
            return _reject("not_found", 404)
        return _preview_of_record(rec)

    doc = ad.evidence_repo.get_document(eid)
    if doc is not None:
        meta = {
            "evidence_id": doc.evidence_id,
            "control_id": doc.control_id,
            "doc_type": doc.document_type.value,
            "file_name": doc.file_name,
            "title": doc.title or doc.file_name,
            "size": doc.file_size,
            "sha256": doc.file_hash,
            "uploaded_at": doc.uploaded_at.strftime("%Y-%m-%d %H:%M"),
        }
        ext = Path(doc.file_name).suffix.lower()
        path = Path(doc.file_path) if doc.file_path else None
        if ext not in _PREVIEW_TEXT_EXT or path is None or not path.exists():
            if ext in _PREVIEW_TEXT_EXT:
                return _reject("file_unavailable", 404)
            return {**meta, "kind": "binary", "content": ""}
        content = path.read_bytes()[:_PREVIEW_MAX_BYTES].decode("utf-8", "replace")
        return {**meta, "kind": "text", "content": content}

    rec = next((r for r in evidence_ledger._records if r.evidence_id.upper() == eid), None)
    if rec is not None:
        return _preview_of_record(rec)
    return _reject("not_found", 404)


# ---------------------------------------------------------------------------
# 증적 검토·승인 워크플로우 — 담당자 → 팀장 → CISO (원장 REVIEW 레코드 기반)
# ---------------------------------------------------------------------------

_review_workflow = EvidenceReviewWorkflow(evidence_ledger)


def _evidence_control_id(evidence_id: str) -> Optional[str]:
    rec = next((r for r in evidence_ledger._records
                if r.evidence_id.upper() == evidence_id.upper()), None)
    return rec.control_id if rec else None


class ReviewActionRequest(BaseModel):
    action: str                     # approve | reject | resubmit
    actor: str
    role: str                       # OWNER | TEAM_LEAD | CISO
    comment: str = ""


class CommentRequest(BaseModel):
    actor: str
    role: str = "OWNER"
    text: str


class ActionLogRequest(BaseModel):
    actor: str
    action_type: str = "조치"       # 조치 | 확인 | 예외승인 등
    detail: str
    status: str = "DONE"            # DONE | PLANNED | IN_PROGRESS


@router.get("/api/audit/evidence/{evidence_id}/review")
async def api_evidence_review_state(evidence_id: str) -> Any:
    if _evidence_control_id(evidence_id) is None:
        return _reject("not_found", 404)
    return _review_workflow.get_state(evidence_id)


@router.post("/api/audit/evidence/{evidence_id}/review")
async def api_evidence_review_action(evidence_id: str,
                                     body: ReviewActionRequest) -> JSONResponse:
    control_id = _evidence_control_id(evidence_id)
    if control_id is None:
        return _reject("not_found", 404)
    if not body.actor.strip():
        return _reject("actor_required", 400)
    try:
        state = _review_workflow.transition(
            evidence_id, control_id, body.action.lower().strip(),
            body.actor.strip(), body.role, body.comment)
    except (ValueError, KeyError) as e:
        return _reject("invalid_transition", 400, detail=str(e))
    return JSONResponse({"ok": True, **state})


@router.post("/api/audit/evidence/{evidence_id}/comment")
async def api_evidence_comment(evidence_id: str,
                               body: CommentRequest) -> JSONResponse:
    control_id = _evidence_control_id(evidence_id)
    if control_id is None:
        return _reject("not_found", 404)
    if not body.actor.strip():
        return _reject("actor_required", 400)
    try:
        state = _review_workflow.add_comment(
            evidence_id, control_id, body.actor.strip(),
            body.role, body.text)
    except (ValueError, KeyError) as e:
        return _reject("invalid_comment", 400, detail=str(e))
    return JSONResponse({"ok": True, **state})


@router.post("/api/audit/evidence/{evidence_id}/action")
async def api_evidence_action(evidence_id: str,
                              body: ActionLogRequest) -> JSONResponse:
    """자동 수집 증적의 담당자 조치 이력 — 원장에 불변 기록."""
    control_id = _evidence_control_id(evidence_id)
    if control_id is None:
        return _reject("not_found", 404)
    if not body.actor.strip():
        return _reject("actor_required", 400)
    try:
        state = _review_workflow.add_action(
            evidence_id, control_id, body.actor.strip(),
            body.action_type, body.detail, body.status)
    except (ValueError, KeyError) as e:
        return _reject("invalid_action", 400, detail=str(e))
    return JSONResponse({"ok": True, **state})


# ---------------------------------------------------------------------------
# 증적 파일 업로드 (Evidence Intake) — raw-body 방식, multipart 의존성 없음
# ---------------------------------------------------------------------------

_UPLOAD_MAX_BYTES = 10 * 1024 * 1024  # 10MB
_UPLOAD_ALLOWED_EXT = {
    ".pdf", ".xlsx", ".docx", ".pptx", ".png", ".jpg", ".jpeg",
    ".hwp", ".hwpx", ".txt", ".csv", ".html", ".htm", ".md", ".log", ".json", ".zip",
}
_UPLOAD_MAGIC = {
    ".pdf": b"%PDF",
    ".png": b"\x89PNG\r\n\x1a\n",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".hwp": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
}
_UPLOAD_ZIP_EXT = {".xlsx", ".docx", ".pptx", ".hwpx", ".zip"}
_UPLOAD_DOC_TYPES = {t.value for t in DocumentType}
# 주민등록번호 — 숫자 경계 필수. 하이픈형은 실제 RRN 표기와 일치(바이너리 오탐 적음),
# 무하이픈 13자리는 텍스트계열에서만 검사(PDF/ZIP 원시 바이트의 연속 숫자 오탐 방지)
_RRN_HYPHEN = re.compile(r"(?<![\d-])\d{6}-[1-4]\d{6}(?!\d)")
_RRN_BARE = re.compile(r"(?<!\d)\d{6}[1-4]\d{6}(?!\d)")
# 프리뷰/리버스 프록시 경유 시 Origin과 Host가 다른 loopback 포트가 될 수 있음
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

# assurance_data의 공유 인스턴스 — 어시스턴트가 업로드 증적을 조회할 수 있도록 동일 객체 사용
_evidence_repo = ad.evidence_repo


def _valid_control_ids() -> set:
    land = ad.get_landscape()
    return {c["control_id"] for d in land["domains"] for s in d["sub"] for c in s["controls"]}


def _reject(reason: str, status: int, **extra) -> JSONResponse:
    return JSONResponse({"ok": False, "error": reason, **extra}, status_code=status)


@router.post("/api/audit/evidence/upload")
async def api_evidence_upload(
    request: Request, control_id: str = "", doc_type: str = "POLICY_PROCEDURE"
) -> JSONResponse:
    """증적 파일 업로드 — 검증 → 민감정보 스캔 → 저장 → 불변 원장 기록.

    보안 통제:
    - 커스텀 헤더 X-Evidence-Upload 요구 (CSRF: cross-origin은 preflight 없이 설정 불가)
    - Origin 존재 시 Host/X-Forwarded-Host와 대조 — 프록시 경유는 loopback↔loopback 허용
    - 파일명 basename 추출 + 확장자 화이트리스트 + 매직바이트 대조
    - 10MB 크기 상한 (Content-Length 선차단 + 실제 바디 확인)
    - SecretGuard 민감정보 스캔 — 검출 시 저장하지 않고 차단 사실만 원장 기록
    """
    from secgrc.agent_security.secret_guard import SecretGuard

    if request.headers.get("x-evidence-upload") != "1":
        return _reject("missing_upload_header", 403)

    origin = request.headers.get("origin")
    if origin:
        host = request.headers.get("host", "")
        fwd = {h.strip() for h in request.headers.get("x-forwarded-host", "").split(",") if h.strip()}
        if urlparse(origin).netloc not in ({host} | fwd):
            o_host = urlparse(origin).hostname or ""
            h_host = urlparse(f"//{host}").hostname or ""
            if not (o_host in _LOOPBACK_HOSTS and h_host in _LOOPBACK_HOSTS):
                return _reject("origin_mismatch", 403)

    # 다중 통제 매핑 — control_id=2.5.4,2.5.3 형태로 최대 5개까지 허용.
    # 1개 증적이 복수 통제를 입증하는 것은 인증심사에서 정상적인 패턴.
    valid_ids = _valid_control_ids()
    control_ids = [c.strip() for c in (control_id or "").split(",") if c.strip()]
    control_ids = list(dict.fromkeys(control_ids))[:5]
    if not control_ids or any(c not in valid_ids for c in control_ids):
        return _reject("unknown_control", 400)
    if doc_type not in _UPLOAD_DOC_TYPES:
        return _reject("unknown_doc_type", 400)

    raw_name = unquote(request.headers.get("x-file-name", ""))
    file_name = Path(raw_name).name.replace("\\", "/").split("/")[-1].strip()
    file_name = "".join(ch for ch in file_name if ch.isalnum() or ch in " ._-()[]")
    if not file_name or file_name.startswith(".") or len(file_name) > 200:
        return _reject("invalid_filename", 400)

    ext = Path(file_name).suffix.lower()
    if ext not in _UPLOAD_ALLOWED_EXT:
        return _reject("extension_not_allowed", 415, ext=ext)

    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > _UPLOAD_MAX_BYTES:
        return _reject("file_too_large", 413, max_bytes=_UPLOAD_MAX_BYTES)
    body = await request.body()
    if not body:
        return _reject("empty_file", 400)
    if len(body) > _UPLOAD_MAX_BYTES:
        return _reject("file_too_large", 413, max_bytes=_UPLOAD_MAX_BYTES)

    if ext in _UPLOAD_MAGIC and not body.startswith(_UPLOAD_MAGIC[ext]):
        return _reject("magic_mismatch", 415, ext=ext)
    if ext in _UPLOAD_ZIP_EXT and not body.startswith(b"PK\x03\x04"):
        return _reject("magic_mismatch", 415, ext=ext)

    sha256 = hashlib.sha256(body).hexdigest()

    # 민감정보 스캔 — 시크릿은 원시 바이트에서도 유효(ASCII 패턴), RRN은 형식별 상이:
    # 하이픈형(XXXXXX-XXXXXXX)은 모든 형식에서 검사, 무하이픈 13자리는 텍스트계열만
    # (PDF·ZIP 원시 바이트의 연속 숫자열이 무하이픈 패턴에 오탐되는 문제 방지)
    sample = body[:512 * 1024].decode("utf-8", "replace")
    _, secret_found, secret_types = SecretGuard.scan_and_redact(sample)
    detected = list(secret_types)
    if _RRN_HYPHEN.search(sample) or (ext in _PREVIEW_TEXT_EXT and _RRN_BARE.search(sample)):
        detected.append("resident_id")

    if detected:
        rec = evidence_ledger.append_record(
            evidence_id=f"BLOCKED-{uuid.uuid4().hex[:8].upper()}",
            control_id=control_ids[0],
            content={
                "file_name": file_name, "sha256": sha256, "size": len(body),
                "status": "BLOCKED_SENSITIVE", "detected": detected,
                "control_ids": control_ids,
            },
            record_type=EvidenceRecordType.EVIDENCE,
            created_by="web-console", collection_method="MANUAL",
            metadata={"source": "evidence-intake"},
        )
        return JSONResponse(
            {
                "ok": False, "blocked": True, "reason": "sensitive_content",
                "detected": detected, "file_name": file_name, "sha256": sha256,
                "record_id": rec.record_id,
            },
            status_code=422,
        )

    # 파일은 1회만 저장 — 추가 통제는 동일 파일을 가리키는 연결 증적 생성.
    # 매핑별 개별 증적 ID + 원장 레코드로 통제 단위 추적을 유지.
    ugroup = uuid.uuid4().hex[:8]
    doc = _evidence_repo.upload_document(
        io.BytesIO(body), file_name, control_ids[0],
        DocumentType(doc_type), title=file_name,
        description="Evidence Intake 웹 업로드",
        uploaded_by="web-console",
        metadata={"sha256": sha256, "source": "evidence-intake",
                  "upload_group": ugroup, "control_ids": control_ids},
    )
    doc.file_hash = sha256
    docs = [doc] + [_evidence_repo.link_to_control(doc, c) for c in control_ids[1:]]

    record_ids = []
    for d, cid in zip(docs, control_ids):
        rec = evidence_ledger.append_record(
            evidence_id=d.evidence_id,
            control_id=cid,
            content={
                "file_name": file_name, "sha256": sha256, "size": len(body),
                "document_type": doc_type, "status": "RECEIVED",
                "upload_group": ugroup, "control_ids": control_ids,
            },
            record_type=EvidenceRecordType.EVIDENCE,
            created_by="web-console", collection_method="MANUAL",
            metadata={"source": "evidence-intake"},
        )
        record_ids.append(rec.record_id)

    return JSONResponse(
        {
            "ok": True,
            "evidence_id": doc.evidence_id,
            "evidence_ids": [d.evidence_id for d in docs],
            "file_name": file_name,
            "control_id": control_ids[0],
            "control_ids": control_ids,
            "doc_type": doc_type,
            "sha256": sha256,
            "size": len(body),
            "record_id": record_ids[0],
            "record_ids": record_ids,
            "chain_valid": evidence_ledger.verify_chain_integrity(),
            "sensitive": {"detected": False, "types": []},
            "demo": False,
        }
    )
