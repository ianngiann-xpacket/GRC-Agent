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
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import unquote, urlparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from secgrc.control_engine.engine import control_engine
from secgrc.evidence.document.repository import DocumentType
from secgrc.evidence.ledger import EvidenceRecordType, evidence_ledger
from secgrc.reconciliation.engine import reconciliation_engine
from secgrc.web import assurance_data as ad

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates_certification"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


def _ctx(request: Request, page: str, audit_id: Optional[str] = None, **extra) -> Dict[str, Any]:
    """공통 템플릿 컨텍스트 — 감사 컨텍스트 카드 + 내비 배지."""
    ad.ensure_demo_dataset()
    from secgrc.audit_findings.manager import audit_findings_manager
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
    gaps = ad.get_gaps()
    return templates.TemplateResponse(
        "control_center.html",
        _ctx(request, "audit", audit,
             kpis=kpis,
             top_issues=ad.get_top_issues(5),
             recent_gaps=gaps["gaps"][:8],
             population=ad.get_population()),
    )


@router.get("/controls", response_class=HTMLResponse)
async def control_landscape(request: Request, audit: Optional[str] = None,
                            state: Optional[str] = None) -> HTMLResponse:
    """Control Landscape — 101개 통제 인터랙티브 트리."""
    return templates.TemplateResponse(
        "controls.html",
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
    return templates.TemplateResponse(
        "control_detail.html", _ctx(request, "controls", audit, detail=detail)
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
    return templates.TemplateResponse(
        "evidence.html",
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
    gaps = ad.get_gaps()["gaps"]
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
    return templates.TemplateResponse(
        "gap.html",
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
    return templates.TemplateResponse(
        "findings.html",
        _ctx(request, "findings", audit,
             findings=fv["findings"], summary=fv["summary"], trend=fv["trend"]),
    )


@router.get("/replay", response_class=HTMLResponse)
async def audit_replay(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    """Audit Replay — 스크립트 심사 시뮬레이션."""
    return templates.TemplateResponse("replay.html", _ctx(request, "replay", audit))


# ---------------------------------------------------------------------------
# Data & Integration 그룹
# ---------------------------------------------------------------------------

_COLLECTORS = [
    {"name": "HR Connector", "type": "READ-ONLY", "target": "HR-ERP (입퇴사·조직이동·겸직)",
     "last_run": "10분 전", "records": 412, "status": "ACTIVE"},
    {"name": "IAM Connector", "type": "READ-ONLY", "target": "AD/IAM (계정·권한·MFA·비밀번호정책)",
     "last_run": "10분 전", "records": 2140, "status": "ACTIVE"},
    {"name": "SIEM Connector", "type": "READ-ONLY", "target": "SIEM-01 (보안 로그·접속기록)",
     "last_run": "10분 전", "records": 18327, "status": "ACTIVE"},
    {"name": "CI/CD Connector", "type": "READ-ONLY", "target": "배포 이력·변경 승인",
     "last_run": "—", "records": 0, "status": "PLANNED"},
    {"name": "ITSM Connector", "type": "READ-ONLY", "target": "변경관리·사고 티켓",
     "last_run": "—", "records": 0, "status": "PLANNED"},
    {"name": "CSPM Connector", "type": "READ-ONLY", "target": "클라우드 설정 스캔",
     "last_run": "—", "records": 0, "status": "PLANNED"},
    {"name": "Vulnerability Scanner", "type": "READ-ONLY", "target": "취약점 스캔 결과",
     "last_run": "—", "records": 0, "status": "PLANNED"},
    {"name": "DLP/개인정보 Connector", "type": "READ-ONLY", "target": "개인정보처리시스템 현황",
     "last_run": "—", "records": 0, "status": "PLANNED"},
]


@router.get("/collection", response_class=HTMLResponse)
async def collection_status(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    return templates.TemplateResponse(
        "collection.html", _ctx(request, "collection", audit, collectors=_COLLECTORS)
    )


@router.get("/intake", response_class=HTMLResponse)
async def evidence_intake(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    land = ad.get_landscape()
    controls = [c for d in land["domains"] for s in d["sub"] for c in s["controls"]]
    checks = [
        {"doc": "정보보호정책_v3.2.pdf", "control": "1.1.5", "sensitive": False, "version": "v3.2", "passed": True},
        {"doc": "보안교육_실적_2026Q1.xlsx", "control": "2.2.4", "sensitive": False, "version": "v1.0", "passed": True},
        {"doc": "계정권한_현황_원본.xlsx", "control": "2.5.1", "sensitive": True, "version": "v1.1", "passed": False},
        {"doc": "IT운영위원회_회의록.pdf", "control": "1.3.2", "sensitive": False, "version": "v2.0", "passed": True},
    ]
    return templates.TemplateResponse(
        "intake.html", _ctx(request, "intake", audit, controls=controls[:40], intake_checks=checks)
    )


@router.get("/connections", response_class=HTMLResponse)
async def connections(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    systems = [
        {"name": "Active Directory", "system_id": "AD-PROD", "status": "CONNECTED",
         "desc": "계정·권한·비밀번호 정책 수집", "last_sync": "10분 전"},
        {"name": "HR ERP", "system_id": "HR-ERP", "status": "CONNECTED",
         "desc": "입퇴사·조직이동 모집단", "last_sync": "10분 전"},
        {"name": "IAM Gateway", "system_id": "IAM-GW", "status": "CONNECTED",
         "desc": "인증·MFA·접근권한 현황", "last_sync": "10분 전"},
        {"name": "SIEM", "system_id": "SIEM-01", "status": "CONNECTED",
         "desc": "로그·접속기록 수집", "last_sync": "10분 전"},
        {"name": "VPN Gateway", "system_id": "VPN-GW", "status": "CONNECTED",
         "desc": "원격접근 로그", "last_sync": "1시간 전"},
        {"name": "Core DB", "system_id": "DB-CORE", "status": "CONNECTED",
         "desc": "개인정보 저장 현황", "last_sync": "30분 전"},
        {"name": "AWS CSPM", "system_id": "CLOUD-AWS", "status": "PLANNED",
         "desc": "클라우드 설정 스캔 (연동 예정)", "last_sync": "—"},
        {"name": "ITSM", "system_id": "ITSM", "status": "PLANNED",
         "desc": "변경관리 티켓 (연동 예정)", "last_sync": "—"},
    ]
    return templates.TemplateResponse(
        "connections.html", _ctx(request, "connections", audit, systems=systems)
    )


# ---------------------------------------------------------------------------
# Reporting / Administration 그룹
# ---------------------------------------------------------------------------

_REPORTS = [
    {"name": "인증 준비도 보고서", "desc": "통제별 준비도·증적 현황·미비 항목 종합", "source": "ControlEngine+GAP", "format": "PDF"},
    {"name": "GAP 분석 리포트", "desc": "정책↔설정↔증적 불일치 목록 및 근거", "source": "Reconciliation", "format": "PDF/XLSX"},
    {"name": "결함보고서", "desc": "지적사항 12개 분석 필드 + 보완조치 이력", "source": "FindingsManager", "format": "PDF"},
    {"name": "증적 무결성 증명", "desc": "원장 해시체인 검증 결과 및 수집 출처", "source": "EvidenceLedger", "format": "PDF/JSON"},
    {"name": "심사 제출 패키지", "desc": "증적+정합성+지적사항+조치 이력 묶음", "source": "전 계층", "format": "ZIP"},
]


@router.get("/reports", response_class=HTMLResponse)
async def reports(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    return templates.TemplateResponse(
        "reports.html", _ctx(request, "reports", audit, reports=_REPORTS)
    )


@router.get("/history", response_class=HTMLResponse)
async def audit_history(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    return templates.TemplateResponse(
        "history.html", _ctx(request, "history", audit, audits=ad._DEMO_AUDITS)
    )


@router.get("/criteria", response_class=HTMLResponse)
async def isms_criteria(request: Request, audit: Optional[str] = None) -> HTMLResponse:
    land = ad.get_landscape()
    return templates.TemplateResponse(
        "criteria.html",
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
    return templates.TemplateResponse(
        "users.html", _ctx(request, "users", audit, users=user_list)
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
    return templates.TemplateResponse(
        "settings.html", _ctx(request, "settings", audit, settings=cfg)
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
async def api_gaps(status: Optional[str] = None) -> Dict[str, Any]:
    return ad.get_gaps(status)


@router.get("/api/audit/findings")
async def api_findings() -> Dict[str, Any]:
    return ad.get_findings_view()


@router.get("/api/audit/population")
async def api_population() -> Dict[str, Any]:
    return ad.get_population()


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


@router.post("/api/audit/assistant")
async def api_assistant(body: AssistantRequest) -> Dict[str, Any]:
    return ad.post_assistant(body.message)


class SuggestRequest(BaseModel):
    file_name: str = ""
    sample: str = ""


@router.post("/api/audit/evidence/suggest")
async def api_evidence_suggest(body: SuggestRequest) -> Dict[str, Any]:
    """파일명+본문 샘플로 통제항목을 추천한다 (advisory — 상태 변경 없음)."""
    return ad.suggest_control(body.file_name, body.sample)


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
_RRN_PATTERN = re.compile(r"\d{6}-?[1-4]\d{6}")  # 주민등록번호 형태
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
    request: Request, control_id: str = "", doc_type: str = "POLICY"
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

    control_id = (control_id or "").strip()
    if control_id not in _valid_control_ids():
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

    # 민감정보 스캔 — 텍스트 추출 가능 범위(512KB)에서 시크릿·주민등록번호 탐지
    sample = body[:512 * 1024].decode("utf-8", "replace")
    _, secret_found, secret_types = SecretGuard.scan_and_redact(sample)
    detected = list(secret_types)
    if _RRN_PATTERN.search(sample):
        detected.append("resident_id")

    if detected:
        rec = evidence_ledger.append_record(
            evidence_id=f"BLOCKED-{uuid.uuid4().hex[:8].upper()}",
            control_id=control_id,
            content={
                "file_name": file_name, "sha256": sha256, "size": len(body),
                "status": "BLOCKED_SENSITIVE", "detected": detected,
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

    doc = _evidence_repo.upload_document(
        io.BytesIO(body), file_name, control_id,
        DocumentType(doc_type), title=file_name,
        description="Evidence Intake 웹 업로드",
        uploaded_by="web-console",
        metadata={"sha256": sha256, "source": "evidence-intake"},
    )
    doc.file_hash = sha256

    rec = evidence_ledger.append_record(
        evidence_id=doc.evidence_id,
        control_id=control_id,
        content={
            "file_name": file_name, "sha256": sha256, "size": len(body),
            "document_type": doc_type, "status": "RECEIVED",
        },
        record_type=EvidenceRecordType.EVIDENCE,
        created_by="web-console", collection_method="MANUAL",
        metadata={"source": "evidence-intake"},
    )

    return JSONResponse(
        {
            "ok": True,
            "evidence_id": doc.evidence_id,
            "file_name": file_name,
            "control_id": control_id,
            "doc_type": doc_type,
            "sha256": sha256,
            "size": len(body),
            "record_id": rec.record_id,
            "chain_valid": evidence_ledger.verify_chain_integrity(),
            "sensitive": {"detected": False, "types": []},
            "demo": False,
        }
    )
