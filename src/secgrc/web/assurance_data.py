"""ISMS-P Audit Assurance 데이터 서비스 계층 (v2 UI 전용).

UI가 소비하는 유일한 인터페이스. 실제 엔진(source of truth)의 데이터와
결정론적 합성(demo) 데이터를 하나의 계약으로 제공합니다.

원칙:
- PASS/FAIL·점수·결함 판정은 백엔드 엔진 결과만 사용 (프론트 자체 판정 금지)
- 합성 데이터는 항상 `demo: True` 로 명시
- 시계열/스냅샷/리플레이/어시스턴트는 백엔드 미구현이므로 결정론적 mock 제공
"""

from __future__ import annotations

import hashlib
import html as _html
import json as _json
import os
import random
import re
import unicodedata
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from secgrc.audit_findings.manager import (
    AuditFindingsManager,
    CorrectiveActionType,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    audit_findings_manager,
)
from secgrc.audit_workspace.workspace import audit_workspace
from secgrc.certification.workflow import (
    AuditType,
    CertificationTier,
    certification_audit_workflow,
)
from secgrc.control_engine.engine import control_engine
from secgrc.evidence.document.repository import EvidenceRepository
from secgrc.evidence.ledger import EvidenceRecordType, evidence_ledger
from secgrc.reconciliation.engine import ReconciliationStatus, reconciliation_engine
from secgrc.web.certification_view import _seed_demo_data

# ---------------------------------------------------------------------------
# ISMS-P 공식 101개 인증기준 구조 (2023.10.31 기준)
# ---------------------------------------------------------------------------

ISMS_P_FRAMEWORK: List[Dict[str, Any]] = [
    {
        "id": "1", "name": "관리체계 수립 및 운영", "sub": [
            ("1.1", "관리체계 기반 마련", ["경영진의 참여", "최고책임자의 지정", "조직 구성", "범위 설정", "정책 수립", "자원 할당"]),
            ("1.2", "위험 관리", ["정보자산 식별", "현황 및 흐름분석", "위험 평가", "보호대책 선정"]),
            ("1.3", "관리체계 운영", ["보호대책 구현", "보호대책 공유", "운영현황 관리"]),
            ("1.4", "관리체계 점검 및 개선", ["법적 요구사항 준수 검토", "관리체계 점검", "관리체계 개선"]),
        ],
    },
    {
        "id": "2", "name": "보호대책 요구사항", "sub": [
            ("2.1", "정책, 조직, 자산 관리", ["정책의 유지관리", "조직의 유지관리", "정보자산 관리"]),
            ("2.2", "인적 보안", ["주요 직무자 지정 및 관리", "직무 분리", "보안 서약", "인식제고 및 교육훈련", "퇴직 및 직무변경 관리", "보안 위반 시 조치"]),
            ("2.3", "외부자 보안", ["외부자 현황 관리", "외부자 계약 시 보안", "외부자 보안 이행 관리", "외부자 계약 변경 및 만료 시 보안"]),
            ("2.4", "물리 보안", ["보호구역 지정", "출입통제", "정보시스템 보호", "보호설비 운영", "보호구역 내 작업", "반출입 기기 통제", "업무환경 보안"]),
            ("2.5", "인증 및 권한관리", ["사용자 계정 관리", "사용자 식별", "사용자 인증", "비밀번호 관리", "특수 계정 및 권한 관리", "접근권한 검토"]),
            ("2.6", "접근통제", ["네트워크 접근", "정보시스템 접근", "응용프로그램 접근", "데이터베이스 접근", "무선 네트워크 접근", "원격접근 통제", "인터넷 접속 통제"]),
            ("2.7", "암호화 적용", ["암호정책 적용", "암호키 관리"]),
            ("2.8", "정보시스템 도입 및 개발 보안", ["보안 요구사항 정의", "보안 요구사항 검토 및 시험", "시험과 운영 환경 분리", "시험 데이터 보안", "소스 프로그램 관리", "운영환경 이관"]),
            ("2.9", "시스템 및 서비스 운영관리", ["변경관리", "성능 및 장애관리", "백업 및 복구관리", "로그 및 접속기록 관리", "로그 및 접속기록 점검", "시간 동기화", "정보자산의 재사용 및 폐기"]),
            ("2.10", "시스템 및 서비스 보안관리", ["보안시스템 운영", "클라우드 보안", "공개서버 보안", "전자거래 및 핀테크 보안", "정보전송 보안", "업무용 단말기기 보안", "보조저장매체 관리", "패치관리", "악성코드 통제"]),
            ("2.11", "사고 예방 및 대응", ["사고 예방 및 대응체계 구축", "취약점 점검 및 조치", "이상행위 분석 및 모니터링", "사고 대응 훈련 및 개선", "사고 대응 및 복구"]),
            ("2.12", "재해복구", ["재해, 재난 대비 안전조치", "재해 복구 시험 및 개선"]),
        ],
    },
    {
        "id": "3", "name": "개인정보 처리단계별 요구사항", "sub": [
            ("3.1", "개인정보 수집 시 보호조치", ["개인정보 수집∙이용", "개인정보 수집 제한", "주민등록번호 처리 제한", "민감정보 및 고유식별정보의 처리 제한", "개인정보 간접수집", "영상정보처리기기 설치·운영", "홍보 및 마케팅 목적 활용 시 조치"]),
            ("3.2", "개인정보 보유 및 이용 시 보호조치", ["개인정보 현황관리", "개인정보 품질보장", "이용자 단말기 접근 보호", "개인정보 목적 외 이용 및 제공", "가명정보 처리"]),
            ("3.3", "개인정보 제공 시 보호조치", ["개인정보 제3자 제공", "개인정보 처리 업무 위탁", "영업의 양도 등에 따른 개인정보 이전", "개인정보의 국외이전"]),
            ("3.4", "개인정보 파기 시 보호조치", ["개인정보의 파기", "처리목적 달성 후 보유 시 조치"]),
            ("3.5", "정보주체 권리보호", ["개인정보 처리방침 공개", "정보주체 권리보장", "정보주체에 대한 통지"]),
        ],
    },
]

# 상태 배정 — 실제 시드 데이터와 정합: 2.5.2(MFA 결함), 2.5.4(비밀번호 정책 불일치) 등
_STATE_OVERRIDE: Dict[str, str] = {
    "2.5.2": "CONFLICT",   # 실제 지적사항 DEF-2024-001 (MFA 미적용)
    "2.5.4": "CONFLICT",   # 실제 정합성 불일치 (비밀번호 정책 90일 vs 무제한)
    "2.9.4": "MISSING",    # 로그 보관주기 불일치 (빈출 결함)
    "2.2.5": "MISSING",    # 퇴직자 계정 (리플레이 시나리오 연동)
    "3.2.5": "MISSING",    # 가명정보 처리 절차 부재
    "2.6.6": "MISSING",    # 원격접근 통제 미흡
    "1.2.4": "PARTIAL",
    "1.4.2": "PARTIAL",
    "2.1.3": "PARTIAL",
    "2.4.6": "PARTIAL",
    "2.6.3": "PARTIAL",    # 접근통제 — 컨트롤 상세 데모 대상
    "2.8.4": "PARTIAL",
    "2.9.1": "PARTIAL",
    "2.10.8": "PARTIAL",
    "2.11.2": "PARTIAL",
    "3.1.6": "PARTIAL",
    "3.3.2": "PARTIAL",
}

_OWNERS = [
    ("빵떼옹", "정보보호팀"), ("이관리", "IT운영팀"), ("박개인", "개인정보보호팀"),
    ("최인프라", "인프라팀"), ("정심사", "내부감사팀"), ("한개발", "개발팀"),
]
_SYSTEMS = ["AD-PROD", "HR-ERP", "IAM-GW", "SIEM-01", "VPN-GW", "DB-CORE", "WEB-PORTAL", "CLOUD-AWS"]

# 수집 커넥터·연동 시스템 현황 — 상태·레코드 수 표시값은 demo (실시간 외부 연동 미구성).
# collects/deployment/detail은 실제 커넥터 구현(secgrc.connectors)의 스펙을 반영.
def get_collectors() -> List[Dict[str, Any]]:
    """자동 수집 커넥터 — CSPM·SIEM·DLP·EDR 체계.

    상태 표기는 실제 연동 여부 기준: CSPM(Prowler)만 실구현, 나머지는 PLANNED.
    """
    return [
        {"name": "CSPM Connector", "type": "READ-ONLY", "target": "클라우드 설정 스캔 (GCP)",
         "last_run": "—", "records": 0, "status": "READY",
         "deployment": "클라우드 (Cloud Run Job / 로컬 Docker)",
         "collects": "IAM 정책·스토리지 공개 설정·네트워크/방화벽 규칙·로깅·암호화 설정 등 GCP 구성 진단 결과",
         "detail": "Prowler 실구현 — 아래 패널에서 라이브 스캔 또는 결과 업로드로 수집. 수집 증적은 담당자 코멘트·조치 이력 및 검토·승인 대상"},
        {"name": "SIEM Connector", "type": "READ-ONLY", "target": "보안 로그·접속기록",
         "last_run": "—", "records": 0, "status": "PLANNED",
         "deployment": "온프레미스 (SIEM 연동 예정)",
         "collects": "인증 성공/실패 로그·원격접속 기록·특권 명령 이력·보안 이벤트",
         "detail": "연동 예정 — 로그 보관·접속기록 통제(2.9.x) 자동 수집 소스"},
        {"name": "DLP Connector", "type": "READ-ONLY", "target": "개인정보·데이터 유출 탐지",
         "last_run": "—", "records": 0, "status": "PLANNED",
         "deployment": "온프레미스/SaaS (DLP 연동 예정)",
         "collects": "개인정보 저장 현황·유출 탐지 이벤트·처리시스템 접근기록",
         "detail": "연동 예정 — 개인정보 보호 통제(3.x) 자동 수집 소스"},
        {"name": "EDR Connector", "type": "READ-ONLY", "target": "단말 보안 이벤트",
         "last_run": "—", "records": 0, "status": "PLANNED",
         "deployment": "온프레미스/SaaS (EDR 연동 예정)",
         "collects": "악성코드 탐지·단말 이상행위·백신/패치 현황",
         "detail": "연동 예정 — 악성코드 방지·단말 통제 증적 자동화 목적"},
    ]


def get_connections() -> List[Dict[str, Any]]:
    return [
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


_DEMO_AUDITS = [
    {"audit_id": "AUDIT-DEMO-001", "name": "ISMS-P 인증심사", "audit_type": "갱신심사",
     "tier": "표준인증", "target_date": "2026-09-30", "lead_auditor": "김심사", "demo": True},
    {"audit_id": "AUDIT-2025-SURV", "name": "ISMS-P 사후심사", "audit_type": "사후심사",
     "tier": "표준인증", "target_date": "2025-06-15", "lead_auditor": "이심사", "demo": True},
    {"audit_id": "AUDIT-2024-INIT", "name": "ISMS-P 최초심사", "audit_type": "최초심사",
     "tier": "강화인증", "target_date": "2024-11-20", "lead_auditor": "김심사", "demo": True},
]

_GAP_CATALOG = [
    # (control_id, gap_type, status_kr, description, system, severity)
    ("2.5.4", "POLICY_CONFIG_MISMATCH", "정책/설정 불일치", "비밀번호 변경주기 정책 90일 vs AD 실제 설정 무제한", "AD-PROD", "CRITICAL"),
    ("2.5.2", "REQUIREMENT_EVIDENCE", "미흡", "관리자 계정 MFA 미적용 — 모집단 5개 중 2개", "IAM-GW", "CRITICAL"),
    ("2.9.4", "POLICY_CONFIG_MISMATCH", "정책/설정 불일치", "로그 보관주기 정책 1년 vs SIEM 실제 보관 90일", "SIEM-01", "HIGH"),
    ("2.2.5", "POPULATION_MISMATCH", "모집단 불일치", "퇴직자 모집단 HR 12명 vs IAM 비활성 8명 — 4명 계정 잔존", "HR-ERP", "HIGH"),
    ("2.6.6", "MISSING_EVIDENCE", "증적부족", "원격접근 승인 기록 증적 부재 (VPN 로그만 존재)", "VPN-GW", "HIGH"),
    ("3.2.5", "MISSING_EVIDENCE", "증적부족", "가명정보 처리 절차서 및 처리 기록 부재", "DB-CORE", "HIGH"),
    ("2.6.3", "REQUIREMENT_EVIDENCE", "일부미흡", "응용프로그램 접근통제 — 웹관리자 권한검토 증적 최신성 부족", "WEB-PORTAL", "MEDIUM"),
    ("2.9.1", "PROCESS_GAP", "검토 필요", "변경관리 승인 없는 긴급변경 3건 — 사후 승인 기록 없음", "ITSM", "MEDIUM"),
    ("2.10.8", "EVIDENCE_STALE", "증적부족", "패치관리 대장 최근 분기 업데이트 누락", "CLOUD-AWS", "MEDIUM"),
    ("1.4.2", "PROCESS_GAP", "검토 필요", "관리체계 점검 결과 시정조치 이행 증적 미흡", "GRC", "MEDIUM"),
    ("2.1.3", "POPULATION_MISMATCH", "모집단 불일치", "정보자산 대장 1,824건 vs CMDB 등록 1,640건 — 184건 미등록", "CMDB", "HIGH"),
    ("2.8.4", "MISSING_EVIDENCE", "증적부족", "시험데이터 개인정보 사용 승인 기록 부재", "DEV-SYS", "MEDIUM"),
    ("2.4.6", "REQUIREMENT_EVIDENCE", "일부미흡", "반출입 기기 통제 — 반출 승인대장 표본 3건 누락", "물리보안", "MEDIUM"),
    ("3.1.6", "REQUIREMENT_EVIDENCE", "일부미흡", "CCTV 설치·운영 안내판 표본 2곳 미부착", "물리보안", "LOW"),
    ("2.11.2", "EVIDENCE_STALE", "증적부족", "취약점 점검 결과 조치 확인 증적 60일 경과", "CLOUD-AWS", "MEDIUM"),
    ("3.3.2", "POLICY_CONFIG_MISMATCH", "정책/설정 불일치", "수탁사 보안점검 계약서상 연 2회 vs 실제 연 1회 수행", "외부자관리", "HIGH"),
    ("2.2.4", "MISSING_EVIDENCE", "증적부족", "신규 입사자 보안교육 이수 증적 4명 누락", "HR-ERP", "MEDIUM"),
    ("2.5.6", "REQUIREMENT_EVIDENCE", "일부미흡", "접근권한 반기 검토 — 2분기 검토 기록 미존재", "IAM-GW", "HIGH"),
    ("1.2.4", "PROCESS_GAP", "검토 필요", "보호대책 선정 시 위험평가 연계 근거 문서화 미흡", "GRC", "LOW"),
    ("2.10.9", "REQUIREMENT_EVIDENCE", "일부미흡", "악성코드 통제 — 백신 미설치 단말 표본 2대 발견", "단말자산", "HIGH"),
    ("3.4.1", "MISSING_EVIDENCE", "증적부족", "개인정보 파기 확인서 표본 5건 중 1건 누락", "DB-CORE", "MEDIUM"),
]

# 최초심사 전용 추가 GAP — 통제 수립 단계에서 발견되는 문서화/체계 구축 이슈
_GAP_CATALOG_INIT_EXTRA = [
    ("1.1.5", "REQUIREMENT_EVIDENCE", "미흡", "ISMS-P 문서체계 초기 수립 — 심사기준·통제 매핑표 미완성", "GRC", "CRITICAL"),
    ("1.3.1", "MISSING_EVIDENCE", "증적부족", "경영진 검토 회의록 부재 — 최초 경영진 참여·승인 증적 필요", "GRC", "HIGH"),
    ("2.1.1", "MISSING_EVIDENCE", "증적부족", "정보자산 식별 절차 최초 수행 기록 부재", "CMDB", "HIGH"),
    ("3.5.2", "REQUIREMENT_EVIDENCE", "일부미흡", "개인정보 처리방침의 ISMS 체계 연계 미흡", "WEB-PORTAL", "MEDIUM"),
]

# 심사 유형별 프로필 — 감사 성격에 따라 GAP 범위·준비도를 결정론적으로 차별화
_AUDIT_PROFILES = {
    "AUDIT-DEMO-001": {   # 갱신심사 — 전체 통제 재평가 (기준 프로필)
        "gap_mode": "all",
        "readiness_factor": 1.0, "evidence_factor": 1.0, "pop_factor": 1.0,
        "desc": "갱신심사 — 인증 범위 전체 통제의 지속적 유효성 재평가",
        "trend_ready": "+4.2%", "trend_ev": "+6.8%",
    },
    "AUDIT-2025-SURV": {  # 사후심사 — 운영 지속성·표본 점검 중심
        "gap_mode": "surveillance",
        "readiness_factor": 1.10, "evidence_factor": 1.05, "pop_factor": 1.0,
        "desc": "사후심사 — 인증 유지 중 운영 증적·모집단·최신성 표본 점검 중심",
        "trend_ready": "+1.2%", "trend_ev": "+0.8%",
    },
    "AUDIT-2024-INIT": {  # 최초심사 — 수립 단계, 구조적 GAP 다수
        "gap_mode": "initial",
        "readiness_factor": 0.72, "evidence_factor": 0.60, "pop_factor": 0.85,
        "desc": "최초심사 — 통제 수립·문서화 및 초기 증적 확보 검증 중심",
        "trend_ready": "+9.1%", "trend_ev": "+11.3%",
    },
}


def _audit_profile(audit_id: Optional[str] = None) -> Dict[str, Any]:
    return _AUDIT_PROFILES.get(audit_id or "", _AUDIT_PROFILES["AUDIT-DEMO-001"])

_FINDING_SEED = [
    # (defect_number, control_id, control_name, severity, status, title)
    ("DEF-2026-002", "2.9.4", "로그 및 접속기록 관리", "MAJOR", "OPEN", "로그 보관주기 정책-시스템 불일치"),
    ("DEF-2026-003", "2.2.5", "퇴직 및 직무변경 관리", "MAJOR", "IN_PROGRESS", "퇴직자 계정 비활성화 지연 4건"),
    ("DEF-2026-004", "2.6.6", "원격접근 통제", "MINOR", "OPEN", "원격접근 승인 기록 부재"),
    ("DEF-2026-005", "3.2.5", "가명정보 처리", "MINOR", "OPEN", "가명정보 처리 절차 미수립"),
    ("DEF-2026-006", "2.10.9", "악성코드 통제", "MINOR", "IN_PROGRESS", "백신 미설치 업무 단말 2대"),
    ("DEF-2026-007", "2.5.6", "접근권한 검토", "OBSERVATION", "RESOLVED", "반기 접근권한 검토 기록 누락"),
]

_rng = random.Random(42)  # 결정론적 시드


def _norm(control_id: str) -> str:
    """'ISMS-P-2.5.2' → '2.5.2' 형태로 정규화."""
    return control_id.replace("ISMS-P-", "")


def _stable_bucket(control_id: str, mod: int = 100) -> int:
    return int(hashlib.sha256(control_id.encode()).hexdigest()[:8], 16) % mod


# ---------------------------------------------------------------------------
# 시드: 지적사항 7건·증적·정합성 확보 (기존 데모 시드 확장, 엔진 API 그대로 사용)
# ---------------------------------------------------------------------------

def ensure_demo_dataset() -> None:
    """데모 데이터셋 시드. 실제 엔진 객체를 통해 생성하므로 엔진 로직 재사용."""
    _seed_demo_data()

    existing = {f.defect_number for f in audit_findings_manager._findings.values()}
    for defect_no, cid, cname, sev, status, title in _FINDING_SEED:
        if defect_no in existing:
            continue
        f = audit_findings_manager.create_finding(
            audit_id="AUDIT-DEMO-001",
            control_id=cid,
            control_name=cname,
            severity=FindingSeverity[sev],
            title=title,
            description=f"{title} — 심사 중 확인된 사실을 바탕으로 등록된 지적사항입니다.",
            auditor="김심사",
            defect_number=defect_no,
            category=FindingCategory.ACCESS_CONTROL if cid.startswith("2.5") else FindingCategory.OTHER,
            confirmed_facts=f"{cname} 관련 결함 사실 확인",
            target="관련 시스템 및 계정",
            judgment_basis="설정값·로그·인터뷰 대조",
            additional_checks="전체 모집단 점검 필요",
            assignee=_OWNERS[_stable_bucket(cid) % len(_OWNERS)][0],
            recommendation="보완조치 수립 및 독립 재검증 필요",
        )
        audit_findings_manager.update_finding_status(f.finding_id, FindingStatus[status])
        audit_findings_manager.add_corrective_action(
            finding_id=f.finding_id,
            description=f"{cname} 통제 보완조치 수행",
            assignee=f.assignee or "보안팀",
            assignee_email="grc@company.example",
            due_date=datetime.now() + timedelta(days=10 + _stable_bucket(cid) % 20),
            action_type=CorrectiveActionType.CORRECTIVE,
            population_scope="모집단",
        )
        if status == "IN_PROGRESS":
            audit_findings_manager.update_root_cause_analysis(
                f.finding_id, phenomenon=title,
                direct_cause="운영 절차 미준수", root_cause="담당자 업무 프로세스 내 점검 단계 부재",
            )


# ---------------------------------------------------------------------------
# 프레임워크·랜드스케이프
# ---------------------------------------------------------------------------

def _control_state(control_id: str) -> str:
    if control_id in _STATE_OVERRIDE:
        return _STATE_OVERRIDE[control_id]
    return "READY"


def _control_evidence_pct(control_id: str) -> int:
    state = _control_state(control_id)
    if state == "READY":
        return 88 + _stable_bucket(control_id) % 12
    if state == "PARTIAL":
        return 55 + _stable_bucket(control_id) % 25
    if state == "MISSING":
        return 5 + _stable_bucket(control_id) % 30
    return 30 + _stable_bucket(control_id) % 30  # CONFLICT


def get_landscape() -> Dict[str, Any]:
    """통제 랜드스케이프 트리 — 공식 101개 구조 + 상태/증적율."""
    real_ids = set(control_engine._controls.keys())
    domains = []
    total = ready = 0
    for area in ISMS_P_FRAMEWORK:
        subs = []
        area_counts = {"READY": 0, "PARTIAL": 0, "MISSING": 0, "CONFLICT": 0}
        for sub_id, sub_name, items in area["sub"]:
            controls = []
            for idx, item_name in enumerate(items, start=1):
                cid = f"{sub_id}.{idx}"
                real = control_engine.get_control(cid)
                state = _control_state(cid)
                owner = real.owner.name if real else _OWNERS[_stable_bucket(cid) % len(_OWNERS)][0]
                controls.append({
                    "control_id": cid,
                    "name": real.title if real else item_name,
                    "state": state,
                    "evidence_pct": _control_evidence_pct(cid),
                    "owner": owner,
                    "loaded": cid in real_ids,
                    "synthetic": cid not in real_ids,
                })
                area_counts[state] += 1
            sub_ready = area_counts["READY"]
            subs.append({
                "sub_id": sub_id, "name": sub_name,
                "count": len(controls), "controls": controls,
            })
        n = sum(len(s["controls"]) for s in subs)
        total += n
        ready += area_counts["READY"]
        domains.append({
            "id": area["id"], "name": area["name"], "count": n,
            "ready_pct": round(area_counts["READY"] / n * 100),
            "counts": area_counts, "sub": subs,
        })
    return {"total": total, "ready": ready, "domains": domains, "demo": True}


# ---------------------------------------------------------------------------
# 컨텍스트 / KPI
# ---------------------------------------------------------------------------

def get_audit_context(audit_id: Optional[str] = None) -> Dict[str, Any]:
    audit_id = audit_id or "AUDIT-DEMO-001"
    audit = next((a for a in _DEMO_AUDITS if a["audit_id"] == audit_id), _DEMO_AUDITS[0])
    target = datetime.strptime(audit["target_date"], "%Y-%m-%d")
    d_day = (target.date() - datetime.now().date()).days
    return {**audit, "d_day": d_day, "audits": _DEMO_AUDITS,
            "desc": _audit_profile(audit_id)["desc"]}


def get_kpis(audit_id: Optional[str] = None, as_of: Optional[str] = None) -> Dict[str, Any]:
    ensure_demo_dataset()
    prof = _audit_profile(audit_id)
    land = get_landscape()
    fs = audit_findings_manager.get_finding_summary()
    n_gaps = len(get_gaps(audit_id=audit_id)["gaps"])
    total = land["total"]
    ready = min(total, round(land["ready"] * prof["readiness_factor"]))
    ev_controls = min(total, round(
        sum(1 for d in land["domains"] for s in d["sub"]
            for c in s["controls"] if c["evidence_pct"] >= 50)
        * prof["evidence_factor"]))
    actions_in_progress = fs["corrective_actions"]["by_status"].get("IN_PROGRESS", 0)
    return {
        "demo": True,
        "audit": get_audit_context(audit_id),
        "readiness": {
            "pct": round(ready / total * 100), "ready": ready, "total": total,
            "trend": prof["trend_ready"], "href": "/controls?state=READY",
        },
        "evidence": {
            "pct": round(ev_controls / total * 100), "covered": ev_controls, "total": total,
            "trend": prof["trend_ev"], "href": "/evidence?status=missing",
        },
        "gaps": {"count": n_gaps, "trend": "-3", "href": "/gap?status=open"},
        "findings": {
            "count": fs["total_findings"],
            "open": fs["open_findings"] + fs["in_progress_findings"],
            "href": "/findings?status=open",
        },
        "actions": {
            "count": actions_in_progress,
            "overdue": fs["corrective_actions"]["overdue"],
            "href": "/findings?action=in_progress",
        },
    }


# ---------------------------------------------------------------------------
# 통제 상세 — 증적 체인 (Requirement→…→Verification)
# ---------------------------------------------------------------------------

def get_control_detail(control_id: str) -> Optional[Dict[str, Any]]:
    ensure_demo_dataset()
    control_id = _norm(control_id)
    real = control_engine.get_control(control_id)
    name = None
    for area in ISMS_P_FRAMEWORK:
        for sub_id, sub_name, items in area["sub"]:
            if control_id.startswith(sub_id + "."):
                idx = int(control_id.split(".")[-1])
                if 1 <= idx <= len(items):
                    name = items[idx - 1]
    if real:
        name = real.title
    if not name:
        return None

    # 실제 원장/정합성/지적사항 데이터 연결 (통제 ID 정규화 후 매칭)
    ledger_records = [
        {
            "record_id": r.record_id, "evidence_id": r.evidence_id,
            "record_type": r.record_type.value, "method": r.collection_method,
            "created_by": r.created_by,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M"),
            "hash": r.hash[:20] + "…",
        }
        for r in evidence_ledger._records if _norm(r.control_id) == control_id
    ]
    recon = [
        {
            "result_id": r.result_id, "type": r.reconciliation_type.value,
            "status": r.status.value, "severity": r.severity,
            "description": r.description,
        }
        for r in reconciliation_engine.results if _norm(r.control_id) == control_id
    ]
    findings = [
        {
            "finding_id": f.finding_id, "defect_number": f.defect_number,
            "title": f.title, "severity": f.severity.value, "status": f.status.value,
        }
        for f in audit_findings_manager._findings.values()
        if _norm(f.control_id) == control_id
    ]

    state = _control_state(control_id)
    pct = _control_evidence_pct(control_id)
    owner = _OWNERS[_stable_bucket(control_id) % len(_OWNERS)]

    required_evidence = real.evidence_types if real else ["POLICY_DOC", "SYSTEM_CONFIG", "LOG_RECORD"]
    evidence_items = []
    for i, et in enumerate(required_evidence):
        status = "Available" if pct >= 70 or i == 0 else ("Partial" if pct >= 30 else "Missing")
        if state == "CONFLICT" and i == 1:
            status = "Conflicting"
        evidence_items.append({
            "type": et, "status": status,
            "source": _SYSTEMS[_stable_bucket(control_id + et) % len(_SYSTEMS)],
            "collected_at": (datetime.now() - timedelta(days=_stable_bucket(et + control_id) % 45)).strftime("%Y-%m-%d %H:%M"),
            "freshness_days": _stable_bucket(et + control_id) % 45,
            "evidence_id": f"EV-{control_id.replace('.', '')}-{i+1:03d}",
        })

    chain = [
        {"node": "Requirement", "label": "인증기준 요구사항", "status": "info",
         "detail": (real.requirements[:120] if real else f"{name} 관련 요구사항 준수 필요")},
        {"node": "Policy", "label": "정책/절차 문서", "status": "ok" if pct >= 50 else "warn",
         "detail": "정보보호정책 v3.2 (승인 2026-01-15)"},
        {"node": "System Configuration", "label": "시스템 설정", "status": "ok" if state == "READY" else "fail",
         "detail": recon[0]["description"] if recon else "설정 관측값 정합"},
        {"node": "Population", "label": "모집단", "status": "ok" if state != "MISSING" else "warn",
         "detail": f"모집단 {120 + _stable_bucket(control_id) % 400}건 / 표본 {5 + _stable_bucket(control_id) % 8}건"},
        {"node": "Evidence", "label": "증적", "status": "ok" if pct >= 70 else ("warn" if pct >= 30 else "fail"),
         "detail": f"확보율 {pct}% · 원장 레코드 {len(ledger_records)}건"},
        {"node": "Validation", "label": "유효성 검증", "status": "ok" if state == "READY" else "warn",
         "detail": "해시체인 무결성 검증 완료" if ledger_records else "제출 전 자동검증 대기"},
        {"node": "Finding", "label": "지적사항", "status": "fail" if findings else "ok",
         "detail": f"{len(findings)}건" if findings else "없음"},
        {"node": "Action", "label": "보완조치", "status": "warn" if findings else "info",
         "detail": "진행 중" if findings else "해당 없음"},
        {"node": "Verification", "label": "독립 재검증", "status": "info" if not findings else "warn",
         "detail": "조치자≠검증자 분리" if findings else "대기"},
    ]

    return {
        "control_id": control_id, "name": name, "state": state,
        "evidence_pct": pct, "owner": owner[0], "owner_dept": owner[1],
        "loaded": real is not None,
        "requirements": real.requirements if real else None,
        "checkpoints": real.checkpoints if real else [],
        "chain": chain,
        "evidence_items": evidence_items,
        "ledger_records": ledger_records,
        "recon": recon, "findings": findings,
        "demo": True,
    }


# ---------------------------------------------------------------------------
# GAP / 이슈 / 모집단 / 트렌드
# ---------------------------------------------------------------------------

def get_gaps(status: Optional[str] = None, audit_id: Optional[str] = None) -> Dict[str, Any]:
    ensure_demo_dataset()
    mode = _audit_profile(audit_id)["gap_mode"]
    if mode == "initial":
        catalog = _GAP_CATALOG + _GAP_CATALOG_INIT_EXTRA
    elif mode == "surveillance":
        # 사후심사 — 운영 지속성 관련 GAP만 표본 점검 대상
        keep = {"POPULATION_MISMATCH", "MISSING_EVIDENCE", "EVIDENCE_STALE", "PROCESS_GAP"}
        catalog = [g for g in _GAP_CATALOG if g[1] in keep]
    else:
        catalog = _GAP_CATALOG
    # GAP → 지적사항 등록 연계 (등록 시 gap_id를 태그로 보존)
    gap_findings = {
        tag: f for f in audit_findings_manager._findings.values() for tag in (f.tags or [])
    }
    gaps = []
    for i, (cid, gtype, status_kr, desc, system, sev) in enumerate(catalog, start=1):
        name = None
        for area in ISMS_P_FRAMEWORK:
            for sub_id, _, items in area["sub"]:
                if cid.startswith(sub_id + "."):
                    name = items[int(cid.split(".")[-1]) - 1]
        real = control_engine.get_control(cid)
        owner = _OWNERS[_stable_bucket(cid) % len(_OWNERS)]
        linked = gap_findings.get(f"GAP-{i:03d}")
        gaps.append({
            "gap_id": f"GAP-{i:03d}", "control_id": cid,
            "control_name": (real.title if real else name) or cid,
            "gap_type": gtype, "status_label": status_kr, "status": "open",
            "description": desc, "system": system, "severity": sev,
            "owner": owner[0],
            "found_date": (datetime.now() - timedelta(days=i % 14)).strftime("%Y-%m-%d"),
            "due_date": (datetime.now() + timedelta(days=30 - i)).strftime("%Y-%m-%d"),
            "finding_id": linked.finding_id if linked else None,
            "finding_defect": linked.defect_number if linked else None,
        })
    return {"gaps": gaps, "total": len(gaps), "demo": True}


def get_top_issues(limit: int = 5, audit_id: Optional[str] = None) -> List[Dict[str, Any]]:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    gaps = sorted(get_gaps(audit_id=audit_id)["gaps"], key=lambda g: sev_order.get(g["severity"], 9))
    return gaps[:limit]


def get_population(audit_id: Optional[str] = None) -> Dict[str, Any]:
    f = _audit_profile(audit_id)["pop_factor"]
    verified = round(1640 * f)
    return {
        "demo": True,
        "total_assets": 1824, "verified": verified, "exceptions": 1824 - verified,
        "systems": 96, "iam_accounts": 2140, "privileged_accounts": 87,
        "pii_systems": 14, "processors": 9, "cloud_resources": 412,
        "evidence_population": 1824,
        "sample_note": "표본 항목이 어떤 전체 모집단에 속하는지 항상 함께 표시",
    }


def get_trend() -> Dict[str, Any]:
    """12주 시계열 — 합성 데모 데이터."""
    base = datetime.now() - timedelta(weeks=11)
    readiness, evidence, gaps = [], [], []
    r, e, g = 58, 52, 34
    for i in range(12):
        r += _rng.randint(0, 4); e += _rng.randint(0, 4); g -= _rng.randint(0, 3)
        readiness.append(min(r, 96)); evidence.append(min(e, 92)); gaps.append(max(g, 14))
    labels = [(base + timedelta(weeks=i)).strftime("%m-%d") for i in range(12)]
    return {
        "demo": True, "labels": labels,
        "series": [
            {"name": "준비도", "color": "#2563eb", "data": readiness},
            {"name": "증적 확보율", "color": "#8b5cf6", "data": evidence},
            {"name": "GAP 수", "color": "#e11d48", "data": gaps},
        ],
    }


# ---------------------------------------------------------------------------
# Audit Time Machine — 시점 스냅샷 (demo)
# ---------------------------------------------------------------------------

_SNAPSHOT_OFFSETS = [90, 60, 30, 0]


def get_snapshots() -> List[Dict[str, Any]]:
    today = datetime.now().date()
    return [
        {"label": f"{d}일 전" if d else "오늘",
         "date": (today - timedelta(days=d)).isoformat(), "offset": d}
        for d in _SNAPSHOT_OFFSETS
    ]


def get_snapshot(date: str) -> Dict[str, Any]:
    """특정 시점의 상태. 결정론적 — 날짜가 과거일수록 준비도 낮음."""
    today = datetime.now().date()
    try:
        target = datetime.strptime(date, "%Y-%m-%d").date() if date else today
    except (ValueError, TypeError):
        target = today
    days_ago = max(0, (today - target).days)
    # 과거 → 현재로 갈수록 개선되는 결정론적 커브
    factor = 1 - min(days_ago, 120) / 150  # 90일 전 ≈ 0.4
    land = get_landscape()
    ready_now = land["ready"]
    ready_then = int(ready_now * factor)
    ev_then = int(round(74 * factor + 8))
    changed = {}
    if days_ago >= 60:
        changed = {"2.6.3": "MISSING", "2.5.2": "MISSING", "2.9.4": "MISSING",
                   "2.5.4": "CONFLICT", "2.2.5": "MISSING"}
    elif days_ago >= 30:
        changed = {"2.6.3": "PARTIAL", "2.5.2": "CONFLICT", "2.9.4": "MISSING",
                   "2.5.4": "CONFLICT", "2.2.5": "PARTIAL"}
    else:
        changed = {"2.6.3": "PARTIAL", "2.5.2": "CONFLICT", "2.9.4": "MISSING",
                   "2.5.4": "CONFLICT", "2.2.5": "MISSING"}
    findings_state = "OPEN" if days_ago >= 30 else "OPEN"
    return {
        "demo": True, "date": target.isoformat(), "days_ago": days_ago,
        "readiness": round(ready_then / land["total"] * 100),
        "ready": ready_then, "total": land["total"],
        "evidence_pct": min(ev_then, 95),
        "gaps": max(6, int(21 * (2 - factor) / 2)),
        "findings_open": 7 if days_ago < 60 else 9,
        "control_states": changed,
        "note": f"F-024 상태: {findings_state} · 정책버전 v{3 if days_ago >= 30 else 3}.{1 if days_ago >= 60 else 2}",
    }


# ---------------------------------------------------------------------------
# 실시간 활동 스트림 (demo — 폴링 시 새 이벤트 회전)
# ---------------------------------------------------------------------------

_ACTIVITY_POOL = [
    ("2.6.3", "접근통제 증적 수집 완료", "evidence"),
    ("2.5.4", "GAP 분석 결과 업데이트", "gap"),
    ("2.2.5", "보완조치 담당자 지정 — 이관리", "action"),
    ("—", "IAM / SIEM / CSPM 데이터 수집 완료", "collection"),
    ("2.9.4", "지적사항 DEF-2026-002 업데이트", "finding"),
    ("3.2.5", "증적 제출 전 자동검증 통과", "evidence"),
    ("2.5.2", "정합성 검사: 정책↔설정 불일치 탐지", "gap"),
    ("1.4.2", "관리체계 점검 결과 등록", "audit"),
    ("2.10.8", "패치관리 증적 신선도 경고 (60일 경과)", "evidence"),
    ("3.3.2", "수탁사 점검 일정 알림", "audit"),
]
_activity_tick = {"n": 0}


def get_activity() -> Dict[str, Any]:
    """최근 활동 목록. demo 모드에서 폴링마다 1건씩 회전 추가."""
    ensure_demo_dataset()
    _activity_tick["n"] += 1
    now = datetime.now()
    events = []
    for i in range(10):
        ctrl, text, kind = _ACTIVITY_POOL[(_activity_tick["n"] + i) % len(_ACTIVITY_POOL)]
        events.append({
            "time": (now - timedelta(minutes=i * 6 + _activity_tick["n"] % 3)).strftime("%H:%M"),
            "control_id": ctrl, "text": text, "kind": kind,
        })
    return {"demo": True, "events": events}


# ---------------------------------------------------------------------------
# Audit Replay — 스크립트 시나리오 (퇴직자 계정 점검)
# ---------------------------------------------------------------------------

def get_replay_scenario() -> Dict[str, Any]:
    return {
        "demo": True,
        "scenario_id": "REPLAY-LEAVER-001",
        "title": "퇴직자 계정 관리 심사 시뮬레이션",
        "control_id": "2.2.5",
        "steps": [
            {"idx": 0, "actor": "auditor", "kind": "question",
             "text": "최근 1년간 퇴직자 계정 현황을 보여주세요.",
             "detail": "심사원이 퇴직·직무변경 통제(2.2.5)의 운영 실효성을 확인하기 시작합니다."},
            {"idx": 1, "actor": "system", "kind": "retrieve",
             "text": "HR 모집단 조회",
             "detail": "HR-ERP에서 최근 1년 퇴직자 모집단을 조회합니다.",
             "payload": {"source": "HR-ERP", "population": 12, "period": "2025-09 ~ 2026-09",
                          "items": ["김○○(2026-01-15)", "이○○(2026-02-28)", "박○○(2026-04-10)", "최○○(2026-05-02)", "외 8명"]}},
            {"idx": 2, "actor": "system", "kind": "retrieve",
             "text": "IAM 모집단 조회",
             "detail": "IAM-GW에서 동일 인원의 계정 비활성화 상태를 조회합니다.",
             "payload": {"source": "IAM-GW", "disabled": 8, "active": 4}},
            {"idx": 3, "actor": "system", "kind": "correlate",
             "text": "HR ↔ IAM 모집단 대사",
             "detail": "퇴직일 대비 계정 비활성화일을 교차 대사합니다.",
             "payload": {"matched": 8, "exception": 4}},
            {"idx": 4, "actor": "system", "kind": "exception",
             "text": "예외 탐지 — 계정 잔존 4건",
             "detail": "퇴직 후 30일 경과에도 비활성화되지 않은 계정 4건 탐지. GAP-HIGH로 승격.",
             "payload": {"exceptions": [
                 {"user": "김○○", "left": "2026-01-15", "account": "kim.user", "status": "ACTIVE", "days_over": 247},
                 {"user": "이○○", "left": "2026-02-28", "account": "lee.dev", "status": "ACTIVE", "days_over": 203},
                 {"user": "박○○", "left": "2026-04-10", "account": "park.ops", "status": "ACTIVE", "days_over": 162},
                 {"user": "최○○", "left": "2026-05-02", "account": "choi.it", "status": "LOCKED_NO_DISABLE", "days_over": 140},
             ]}},
            {"idx": 5, "actor": "system", "kind": "evidence",
             "text": "증적 제시 — EV-225-001",
             "detail": "증적 원장의 계정 비활성화 로그와 HR 퇴직자 명단을 제시합니다. 해시체인 무결성 검증 완료.",
             "payload": {"evidence_id": "EV-225-001", "chain_valid": True,
                          "controls": ["2.2.5"], "finding": "DEF-2026-003"}},
            {"idx": 6, "actor": "auditor", "kind": "followup",
             "text": "4건의 계정이 왜 비활성화되지 않았나요? 조치 계획은?",
             "detail": "심사원 후속 질의 — 근본원인과 보완조치 요구. 예상 후속: '직무변경자 권한 재검토 주기는?'"},
            {"idx": 7, "actor": "system", "kind": "action",
             "text": "보완조치 확인 — DEF-2026-003 진행 중",
             "detail": "퇴직 즉시 계정 자동 잠금 연계(HR→IAM 프로비저닝) 조치가 진행 중입니다. 독립 재검증 예정.",
             "payload": {"finding": "DEF-2026-003", "action_status": "IN_PROGRESS",
                          "due": (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d")}},
        ],
    }


# ---------------------------------------------------------------------------
# AI 심사지원 에이전트 — 결정론적 advisory (공식 판정 아님)
# ---------------------------------------------------------------------------

# 업로드 증적 저장소 — 업로드 엔드포인트와 어시스턴트가 같은 인덱스를 공유
# (인메모리 인덱스이므로 프로세스 재시작 시 레코드 매핑은 소실, 파일 자체는 디스크에 남음)
evidence_repo = EvidenceRepository(storage_path="data/evidence_uploads")

_SUGG_DEFAULT = ["퇴직자 계정 관리를 확인해 줘", "주요 GAP 보여줘", "현재 준비도는?"]
_ID_REF = re.compile(r"\b(REC|DOC)-[0-9A-Fa-f]{6,}\b")
_FILE_REF = re.compile(
    r"[\w가-힣()\[\] ._-]+\.(?:html?|txt|csv|md|log|json|pdf|xlsx|docx|pptx|hwp|hwpx|zip|png|jpe?g)",
    re.IGNORECASE)
_CONTROL_REF = re.compile(r"\b([123]\.\d{1,2}\.\d{1,2})\b")
_TEXT_EXT = {".txt", ".md", ".csv", ".log", ".json"}
_HTML_EXT = {".html", ".htm"}
_LLM_CTX_MAX = 12000
_LLM_MODELS = ["gemini-2.5-flash", "gemini-1.5-flash", "gemini-3.6-flash"]
_Q_STOP = {"파일", "본문", "내용", "읽어", "읽어서", "인용", "그대로", "설명", "알려", "무엇", "대해",
           "그리고", "해줘", "해주세요", "작성", "명시", "정책서", "비고란", "관리"}


def _resolve_evidence_ref(message: str):
    """메시지에서 증적 참조(REC-/DOC-/파일명)를 DocumentEvidence로 해석. 없으면 None."""
    m = _ID_REF.search(message)
    if m:
        ref = m.group(0).upper()
        if ref.startswith("REC-"):
            rec = evidence_ledger.get_record(ref)
            if rec:
                doc = evidence_repo.get_document(rec.evidence_id)
                if doc:
                    return doc
        else:
            doc = evidence_repo.get_document(ref)
            if doc:
                return doc
    fm = _FILE_REF.search(message)
    if fm:
        name = fm.group(0).strip()
        for d in evidence_repo.list_documents():
            if d.file_name == name:
                return d
    return None


def _extract_doc_text(doc) -> Optional[str]:
    """텍스트계열/본문 판독 가능 형식만 추출. 바이너리·파일 부재는 None (fail-honest)."""
    p = getattr(doc, "file_path", None)
    if not p or not os.path.exists(p):
        return None
    ext = Path(p).suffix.lower()
    if ext not in _TEXT_EXT | _HTML_EXT:
        return None
    try:
        text = Path(p).read_bytes()[:_LLM_CTX_MAX * 2].decode("utf-8", errors="replace")
    except OSError:
        return None
    if ext in _HTML_EXT:
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.S | re.I)
        text = re.sub(r"<[^>]+>", " ", text)
        text = _html.unescape(text)
    return re.sub(r"[ \t]+", " ", text).strip()


def _llm_grounded(question: str, doc, text: str) -> Optional[str]:
    """증적 본문을 근거로 한 LLM 응답. SDK/키/호출 실패 시 None → 규칙 발췌로 폴백."""
    try:
        from secgrc.llm import get_gemini_api_key
        api_key = get_gemini_api_key()
        if not api_key:
            return None
        from google import genai
    except Exception:
        return None
    prompt = (
        "당신은 ISMS-P 인증심사 지원 어시스턴트입니다. 오직 아래 [증적 본문]만을 근거로 한국어로 답변하세요.\n"
        "- 인용 요청 시 원문을 그대로 인용하고, 본문에 없는 사실은 추측하지 말고 "
        "'본문에 명시되어 있지 않습니다'라고 답하세요.\n"
        "- 적합/부적합 판정은 하지 마세요. 이 응답은 참고용(advisory)입니다.\n\n"
        f"[증적 메타] 파일명: {doc.file_name} / 통제: {doc.control_id}\n"
        f"[증적 본문]\n{text[:_LLM_CTX_MAX]}\n\n[질문]\n{question}"
    )
    try:
        client = genai.Client(api_key=api_key)
        for model in _LLM_MODELS:
            try:
                r = client.models.generate_content(model=model, contents=prompt)
                if r and r.text:
                    return r.text.strip()
            except Exception:
                continue
    except Exception:
        return None
    return None


_SENSITIVE_LABELS = {
    "resident_id": "주민등록번호 형식 (앞 6자리-뒤 7자리)",
    "google_api_key": "Google API 키",
    "github_token": "GitHub 토큰",
    "oauth_access_token": "OAuth 액세스 토큰",
    "aws_access_key": "AWS 액세스 키",
    "jwt_token": "JWT 토큰",
    "private_key": "개인키(PRIVATE KEY 블록)",
    "bearer_token": "Bearer 토큰",
    "password_field": "평문 비밀번호 필드 (password=...)",
    "canary_token": "카나리 토큰",
}


def get_blocked_uploads() -> List[Dict[str, Any]]:
    """민감정보 검출로 차단된 업로드 시도 — 원장의 BLOCKED 레코드."""
    out = []
    for r in evidence_ledger._records:
        c = r.content or {}
        if c.get("status") == "BLOCKED_SENSITIVE":
            out.append({
                "record_id": r.record_id,
                "file_name": c.get("file_name", "—"),
                "detected": c.get("detected", []),
                "control_id": r.control_id.replace("ISMS-P-", ""),
                "size": c.get("size"),
                "at": r.created_at.strftime("%Y-%m-%d %H:%M"),
            })
    return out


def _llm_general(message: str, page: Optional[str]) -> Optional[str]:
    """일반 질의의 LLM 폴백 — 콘솔 런타임 상태를 컨텍스트로 실어 Gemini에 위임.
    SDK/키/호출 실패 시 None → 도움말 텍스트로 폴백."""
    try:
        from secgrc.llm import get_gemini_api_key
        api_key = get_gemini_api_key()
        if not api_key:
            return None
        from google import genai
    except Exception:
        return None
    try:
        audit = get_audit_context()
        land = get_landscape()
        fs = audit_findings_manager.get_finding_summary()
        collectors = get_collectors()
        conn = get_connections()
        docs = evidence_repo.list_documents()
        blocked = get_blocked_uploads()
        kpis = get_kpis()
        ctx = (
            f"[심사] {audit['name']} ({audit['audit_type']}, 목표 {audit['target_date']}, D{audit['d_day']:+d})\n"
            f"[준비도] {kpis['readiness']['pct']}% ({kpis['readiness']['ready']}/{kpis['readiness']['total']}) · "
            f"증적커버 {kpis['evidence']['pct']}% · GAP {kpis['gaps']['count']}건 · 미해결 지적 {kpis['findings']['open']}건\n"
            f"[커넥터] " + "; ".join(
                f"{c['name']}({c['status']}, {c['deployment']}, 수집:{c['collects']})"
                for c in collectors) + "\n"
            f"[연결 시스템] " + "; ".join(
                f"{s['system_id']}={s['name']}({s['status']})" for s in conn) + "\n"
            f"[업로드 증적] {len(docs)}건 · [지적사항] 총 {fs['total_findings']}건\n"
            + (f"[차단된 업로드] " + "; ".join(
                f"{b['file_name']}(검출:{','.join(b['detected'])}, {b['at']})"
                for b in blocked) + " — 파일은 저장되지 않음\n" if blocked
               else "[차단된 업로드] 없음\n")
            + f"[페이지] {page or 'unknown'}\n"
            f"[주의] 커넥터 상태·레코드 수·준비도는 데모 표시값. 실제 데이터는 업로드 증적·"
            f"원장·지적사항뿐이며 실시간 외부 연동은 미구성."
        )
        prompt = (
            "당신은 ISMS-P 인증심사 지원 어시스턴트입니다. 아래 [콘솔 상태]를 근거로 한국어로 "
            "간결하게 답하세요 (최대 8문장).\n"
            "- [콘솔 상태]에 없는 사실은 추측하지 말고 '확인할 수 없습니다'라고 답하세요.\n"
            "- 데모 표시값은 데모임을 명시하고, 실제 데이터와 구분하세요.\n"
            "- 적합/부적합 판정·인증 결론은 하지 마세요. 이 응답은 참고용(advisory)입니다.\n\n"
            f"{ctx}\n\n[질문]\n{message}"
        )
        client = genai.Client(api_key=api_key)
        for model in _LLM_MODELS:
            try:
                r = client.models.generate_content(model=model, contents=prompt)
                if r and r.text:
                    return r.text.strip()
            except Exception:
                continue
    except Exception:
        return None
    return None


def _best_excerpts(question: str, text: str, limit: int = 6) -> List[str]:
    """질문 토큰과 겹치는 본문 라인을 원문 순서대로 발췌 (LLM 미사용 폴백)."""
    toks = [t for t in re.split(r"\s+", question)
            if len(t) >= 2 and t not in _Q_STOP]
    lines = [l.strip() for l in text.splitlines() if len(l.strip()) >= 4]
    scored = sorted(
        ((sum(1 for t in toks if t in l), i, l) for i, l in enumerate(lines)),
        key=lambda x: (-x[0], x[1]))
    seen, picked = set(), []
    for hits, i, l in scored:
        if not hits or l[:40] in seen:
            continue
        seen.add(l[:40])
        picked.append((i, l))
        if len(picked) >= limit:
            break
    return [l for _, l in sorted(picked)]


def _answer_document_question(message: str, doc):
    doc_type = getattr(doc.document_type, "value", doc.document_type)
    meta = (f"**{doc.file_name}** — 증적 `{doc.evidence_id}` · 통제 `{doc.control_id}`"
            f" · 유형 {doc_type}")
    links = [{"label": "통제 상세", "href": f"/controls/{doc.control_id}"},
             {"label": "증적 관리", "href": "/evidence"}]
    sugg = ["이 통제의 다른 부족 항목은?", "주요 GAP 보여줘", "현재 준비도는?"]

    text = _extract_doc_text(doc)
    if text is None:
        return (f"{meta}\n\n본문 판독을 지원하지 않는 형식이거나, "
                f"서버 재시작으로 증적 인덱스가 소실되어 파일을 찾지 못했습니다.\n"
                f"(본문 판독 지원: TXT/MD/CSV/LOG/JSON/HTML — 바이너리 형식은 메타데이터만 표시)",
                links, sugg, "rule")

    llm = _llm_grounded(message, doc, text)
    if llm:
        return (f"{meta}\n\n{llm}\n\n— LLM 생성 응답 · 본문 근거 (advisory)",
                links, sugg, "llm")

    excerpts = _best_excerpts(message, text)
    if excerpts:
        body = "\n".join(f'- "{e}"' for e in excerpts)
        return (f"{meta}\n\n질문과 관련된 본문 발췌입니다 (규칙 기반 — LLM 미연동):\n{body}",
                links, sugg, "rule")
    preview = " / ".join(text.splitlines()[:2])[:200]
    return (f"{meta}\n\n질문과 직접 일치하는 본문 문구를 찾지 못했습니다. 문서 시작부: {preview}…",
            links, sugg, "rule")


def _answer_control_question(message: str):
    cid = _CONTROL_REF.search(message).group(1)
    land = get_landscape()
    ctrl = next(
        (c for d in land["domains"] for s in d["sub"] for c in s["controls"]
         if c["control_id"] == cid), None)
    if not ctrl:
        return (f"통제 `{cid}`을(를) ISMS-P 통제 목록에서 찾지 못했습니다.",
                [{"label": "통제 목록", "href": "/controls"}], _SUGG_DEFAULT, "rule")
    docs = evidence_repo.list_documents(control_id=cid)
    doc_lines = "\n".join(f"- {d.file_name} (`{d.evidence_id}`)" for d in docs[:5]) \
        or "- 업로드된 증적 없음"
    gaps = [g for g in get_gaps()["gaps"] if g["control_id"] == cid]
    sugg = [f"{docs[0].file_name} 본문 읽어줘"] if docs else _SUGG_DEFAULT
    if len(sugg) < 3:
        sugg += ["주요 GAP 보여줘", "현재 준비도는?"][:3 - len(sugg)]
    return (
        f"**{cid} {ctrl['name']}** — 상태 {ctrl['state']} · 증적 충족률 {ctrl['evidence_pct']}%\n\n"
        f"연결 증적 ({len(docs)}건):\n{doc_lines}\n"
        f"관련 GAP: {len(gaps)}건"
        + ("".join(f"\n- {g['gap_id']} {g['status_label']} ({g['severity']})" for g in gaps[:3]))
        + "\n\n증적 본문 인용이 필요하면 증적 ID(REC-/DOC-)나 파일명을 포함해 질문해 주세요.",
        [{"label": "통제 상세", "href": f"/controls/{cid}"},
         {"label": "GAP 분석", "href": "/gap"}], sugg, "rule")


_PAGE_HINTS = {
    "audit": "현재 페이지(Audit Control Center)에서는 준비도·우선 확인 항목을 물어볼 수 있습니다.",
    "controls": "현재 페이지(Control Landscape)에서는 통제 ID로 상태를 물어볼 수 있습니다 — 예: \"2.5.4 상태는?\"",
    "evidence": "현재 페이지(Evidence Management)에서는 증적 파일명·ID로 본문을 조회할 수 있습니다.",
    "gap": "현재 페이지(GAP 분석)에서는 \"주요 GAP 보여줘\", \"CRITICAL 이슈는?\" 같은 질의가 유용합니다.",
    "findings": "현재 페이지(Findings)에서는 지적사항 상태·보완조치 진행률을 물어볼 수 있습니다.",
    "intake": "현재 페이지(Evidence Intake)에서는 \"업로드된 파일명.html 본문 읽어줘\" 같이 증적 내용을 바로 질의할 수 있습니다.",
    "replay": "현재 페이지(Audit Replay)에서는 심사원 예상 질의를 물어볼 수 있습니다.",
}


def post_assistant(message: str, page: Optional[str] = None) -> Dict[str, Any]:
    """어시스턴트 의도 라우팅 — 증적 참조 > 통제 참조 > 일반 질의. 응답은 전부 advisory."""
    ensure_demo_dataset()
    top = get_top_issues(1)[0]
    land = get_landscape()
    fs = audit_findings_manager.get_finding_summary()
    generated_by = "rule"

    doc = _resolve_evidence_ref(message)
    has_ref = bool(_ID_REF.search(message) or _FILE_REF.search(message))
    if doc is not None:
        reply, links, sugg, generated_by = _answer_document_question(message, doc)
    elif _CONTROL_REF.search(message):
        reply, links, sugg, generated_by = _answer_control_question(message)
    elif has_ref:
        reply = (
            "메시지에 증적 참조(REC-/DOC- ID 또는 파일명)가 포함되어 있지만 해당 증적을 찾지 못했습니다.\n\n"
            "- 증적 ID·파일명이 정확한지 확인해 주세요 (증적 관리 화면에서 확인 가능)\n"
            "- 서버가 재시작된 경우 업로드 이력과 파일의 연결이 끊어질 수 있습니다. "
            "파일 자체는 보존되어 있으니, 같은 파일을 다시 업로드하거나 파일명으로 질의해 주세요"
        )
        links = [{"label": "증적 관리", "href": "/evidence"},
                 {"label": "증적 업로드", "href": "/intake"}]
        sugg = _SUGG_DEFAULT
    elif any(k in message for k in ["LLM", "llm", "모델", "제미니", "Gemini", "gemini", "인공지능", "어떤 AI", "API를", "API 호출"]):
        sdk_ok = key_ok = False
        try:
            from google import genai  # noqa: F401
            sdk_ok = True
        except Exception:
            pass
        try:
            from secgrc.llm import get_gemini_api_key
            key_ok = bool(get_gemini_api_key())
        except Exception:
            pass
        reply = (
            "이 어시스턴트는 **하이브리드 구조**입니다.\n\n"
            "- 기본 응답: 결정론적 규칙 엔진 — 의도 라우팅 + 증적·통제 조회\n"
            "- LLM 호출: **업로드 증적의 본문 질의** 시에만 Google Gemini API 사용 "
            "(후보 모델: gemini-2.5-flash, gemini-1.5-flash, gemini-3.6-flash)\n\n"
            f"현재 LLM 가용 상태: SDK **{'설치됨' if sdk_ok else '미설치'}** · "
            f"API 키 **{'설정됨' if key_ok else '미설정'}**\n\n"
            "각 응답의 `generated_by` 표기로 실제 LLM 사용 여부를 확인할 수 있습니다 — "
            "`llm`은 실제 API 호출, `rule`은 규칙 기반 응답입니다. "
            "방금 이 답변처럼 `rule`로 표시된 응답은 LLM을 호출하지 않은 것입니다."
        )
        links = [{"label": "증적 업로드 후 본문 질의", "href": "/intake"}]
        sugg = ["업로드된 증적 파일 본문 읽어줘", "실제 데이터와 합성 데이터는 뭐가 달라?"]
    elif any(k in message for k in ["실제 데이터", "실제 시스템", "합성", "데모 데이터", "가짜", "진짜", "데이터 소스", "데이터를 가져오", "어디서 가져"]):
        reply = (
            "이 콘솔의 데이터 출처는 다음과 같이 구분됩니다.\n\n"
            "**실제 시스템 데이터 (런타임 상태)**\n"
            "- `/intake`에서 업로드한 증적 파일과 그 본문 (data/evidence_uploads)\n"
            "- 증적 원장(Evidence Ledger) — SHA-256 해시체인 WORM 기록\n"
            "- 지적사항·보완조치 상태 (audit_findings_manager의 실제 생명주기)\n\n"
            "**데모/합성 데이터 (demo 배지 표기)**\n"
            "- 통제 준비도·GAP 카탈로그·모집단 수치·트렌드 차트·활동 스트림\n"
            "- 커넥터 수집 상태 표시값\n\n"
            "외부 시스템(HR/IAM/SIEM) 실시간 수집은 커넥터 연동이 필요하며, "
            "현재 인스턴스는 미연결 상태입니다. `demo` 배지가 없는 업로드 증적·원장·지적사항만 "
            "실제 데이터입니다."
        )
        links = [{"label": "증적 관리", "href": "/evidence"},
                 {"label": "시스템 연동 상태", "href": "/connections"}]
        sugg = _SUGG_DEFAULT
    elif any(k in message for k in ["수집", "커넥터", "연동", "연결된 시스템", "어떤 시스템", "시스템에서 데이터", "데이터를 가져오는"]):
        # 특정 커넥터/시스템이 지목되면 그것만 상세 응답, 아니면 전체 개요
        _ALIAS = {
            "SIEM Connector": ["siem", "로그", "siem-01"],
            "CSPM Connector": ["cspm", "prowler", "클라우드", "cloud", "aws", "gcp"],
            "DLP Connector": ["dlp", "개인정보", "유출"],
            "EDR Connector": ["edr", "단말", "악성코드", "엔드포인트"],
        }
        low = message.lower()
        named = [c for c in get_collectors()
                 if c["name"].lower() in low or any(a in low for a in _ALIAS.get(c["name"], []))]
        if named:
            lines = []
            for c in named:
                st = ("수집 중" if c["status"] == "ACTIVE"
                      else "수집 가능 — Prowler 패널에서 실행" if c["status"] == "READY"
                      else "아직 수집하지 않음 (연동 예정)")
                lines.append(
                    f"**{c['name']}** — {st}\n"
                    f"- 대상: {c['target']}\n"
                    f"- 위치: {c['deployment']}\n"
                    f"- 수집 항목: {c['collects']}\n"
                    f"- 상세: {c['detail']}"
                    + (f"\n- 마지막 수집 {c['last_run']} · {c['records']:,}건 (표시값은 demo)"
                       if c["status"] == "ACTIVE" else ""))
            reply = "\n\n".join(lines) + (
                "\n\n커넥터 상태·레코드 수는 데모 표시값입니다. 실제 수집 데이터는 수동 업로드 증적뿐이며, "
                "실시간 연동은 Collection Status에서 설정합니다.")
            links = [{"label": "Collection Status", "href": "/collection"},
                     {"label": "System Connections", "href": "/connections"}]
            sugg = ["수집 중인 커넥터 전체 보여줘", "실제 데이터와 합성 데이터는 뭐가 달라?"]
        else:
            cols = get_collectors()
            rdy = [c for c in cols if c["status"] in ("ACTIVE", "READY")]
            pln = [c for c in cols if c["status"] == "PLANNED"]
            conn = [s for s in get_connections() if s["status"] == "CONNECTED"]
            rdy_lines = "\n".join(
                f"- **{c['name']}** → {c['target']}" for c in rdy) or "- 없음"
            pln_line = " · ".join(c["name"] for c in pln)
            conn_line = " · ".join(s["system_id"] for s in conn)
            reply = (
                f"자동 수집 커넥터는 **{len(cols)}개**(CSPM·SIEM·DLP·EDR) 체계입니다.\n\n"
                f"**수집 가능**\n{rdy_lines}\n\n"
                f"**연결된 시스템**: {conn_line}\n"
                f"**연동 예정 (PLANNED)**: {pln_line}\n\n"
                "실제 수집 경로: CSPM은 Prowler로 GCP 구성 진단을 실행·수집하고 "
                "(Collection Status의 Prowler 패널), SIEM·DLP·EDR는 커넥터 연동이 필요합니다. "
                "수집된 증적은 담당자 코멘트·조치 이력과 함께 팀장→CISO 검토·승인을 거칩니다."
            )
            links = [{"label": "Collection Status", "href": "/collection"},
                     {"label": "System Connections", "href": "/connections"}]
            sugg = ["CSPM은 어떤 정보를 수집해?", "EDR connector는 어디서 수집해?", "실제 데이터와 합성 데이터는 뭐가 달라?"]
    elif any(k in message for k in ["차단", "민감정보", "검출", "blocked", "업로드가 안", "등록이 안", "거부"]):
        blocked = get_blocked_uploads()
        if not blocked:
            reply = ("차단된 업로드 기록이 없습니다 — 최근 제출은 모두 통과했습니다.\n\n"
                     "민감정보(주민등록번호·API 키·토큰·평문 비밀번호 등)가 검출되면 파일은 "
                     "저장되지 않고 차단 사실만 불변 원장에 기록됩니다.")
        else:
            lines = "\n".join(
                f"- **{b['file_name']}** — 검출: "
                f"{', '.join(_SENSITIVE_LABELS.get(t, t) for t in b['detected'])} "
                f"({b['at']} · 원장 {b['record_id']})"
                for b in blocked[:5])
            reply = (
                f"민감정보 검출로 차단된 업로드 **{len(blocked)}건**이 원장에 기록되어 있습니다.\n\n"
                f"{lines}\n\n"
                "차단 시 파일은 저장되지 않습니다(차단 사실만 해시체인 원장에 기록).\n\n"
                "**재업로드 방법**\n"
                "1. 문서에서 검출된 민감정보를 마스킹/삭제 — 주민등록번호는 `******-*******`, "
                "예시 비밀번호는 `********` 형태로 치환\n"
                "2. 동일 통제를 선택해 다시 업로드\n\n"
                "실제 주민등록번호가 포함된 문서라면 제출 자체가 개인정보보호 통제 위반일 수 있으므로, "
                "마스킹본을 증적으로 사용하는 것이 적절합니다.\n\n"
                "참고 — 실제 민감정보가 없는데 차단됐다면 오탐일 수 있습니다. "
                "PDF 등 바이너리 원시 데이터의 연속 숫자열이 주민번호 패턴과 유사할 수 있으니, "
                "해당 부분을 확인한 뒤 TXT/HTML 등 텍스트 형식으로 변환해 업로드하면 정확히 검사됩니다."
            )
        links = [{"label": "증적 업로드", "href": "/intake"},
                 {"label": "증적 원장", "href": "/evidence"}]
        sugg = ["업로드된 증적 목록 보여줘", "현재 준비도는?", "주요 GAP 보여줘"]
    elif any(k in message for k in ["확인", "퇴직", "계정", "먼저"]):
        reply = (
            f"가장 먼저 확인할 항목은 **{top['control_id']} {top['control_name']}**입니다.\n\n"
            f"- 사유: {top['description']}\n"
            f"- 심각도: {top['severity']} · 대상: {top['system']} · 담당: {top['owner']}\n"
            f"- 관련 지적사항: DEF-2026-003 (진행 중)\n\n"
            f"Audit Replay에서 심사원이 이 항목을 어떻게 질의하는지 미리 확인할 수 있습니다."
        )
        links = [{"label": "Audit Replay 실행", "href": "/replay"},
                 {"label": "통제 상세 보기", "href": f"/controls/{top['control_id']}"}]
        sugg = _SUGG_DEFAULT
    elif (any(k in message for k in ["gap", "GAP", "이슈", "부족", "미흡"])
          or "다른 항목" in message):
        issues = get_top_issues(3)
        lines = "\n".join(
            f"{i+1}. **{g['control_id']} {g['control_name']}** — {g['status_label']} ({g['severity']})"
            for i, g in enumerate(issues))
        reply = f"현재 상위 이슈 {len(issues)}건입니다:\n\n{lines}\n\n각 항목을 클릭하면 근거 증적과 연결된 지적사항을 확인할 수 있습니다."
        links = [{"label": "GAP 분석", "href": "/gap?status=open"}]
        sugg = _SUGG_DEFAULT
    elif any(k in message for k in ["준비도", "현황", "전체", "진척"]):
        reply = (
            f"현재 인증 준비 현황입니다.\n\n"
            f"- 준비도: **{round(land['ready']/land['total']*100)}%** ({land['ready']}/{land['total']} 통제)\n"
            f"- 미해결 지적사항: {fs['open_findings'] + fs['in_progress_findings']}건\n"
            f"- 심각도 높은 GAP: {len([g for g in get_gaps()['gaps'] if g['severity'] in ('CRITICAL','HIGH')])}건\n\n"
            f"준비도가 가장 낮은 영역은 '개인정보 처리단계별 요구사항'입니다."
        )
        links = [{"label": "준비 현황", "href": "/audit"}, {"label": "GAP 분석", "href": "/gap"}]
        sugg = _SUGG_DEFAULT
    else:
        # 의도 라우터에 매칭되지 않는 일반 질의 → 콘솔 상태를 컨텍스트로 Gemini에 위임.
        # 실패 시 도움말로 폴백 (LLM 미연동 환경에서도 정직하게 rule 표기).
        llm_reply = _llm_general(message, page)
        if llm_reply:
            reply = llm_reply + "\n\n— LLM 생성 응답 · 콘솔 상태 근거 (advisory)"
            generated_by = "llm"
            links = []
            sugg = _SUGG_DEFAULT
        else:
            page_hint = _PAGE_HINTS.get(page or "", "")
            reply = (
                "ISMS-P 인증심사와 관련해 다음을 도와드릴 수 있습니다.\n\n"
                + (page_hint + "\n\n" if page_hint else "")
                + "- 통제별 증적 현황 및 부족 항목 요약\n"
                "- 업로드 증적 본문 질의 — 예: \"비밀번호 관리 정책.html의 최소 길이·변경 주기를 인용해 줘\"\n"
                "- 심사원 예상 질의 시뮬레이션 (Audit Replay)\n"
                "- 지적사항·보완조치 상태 설명\n- 정합성 불일치(정책↔설정) 위치 안내\n\n"
                "예: \"퇴직자 계정 관리를 확인해 줘\", \"현재 준비도는?\", \"2.5.4 검토 요약\""
            )
            links = []
            sugg = _SUGG_DEFAULT

    return {
        "demo": True, "advisory": True, "generated_by": generated_by,
        "disclaimer": "AI 제안은 참고용이며 공식 인증 판정이 아닙니다.",
        "reply": reply, "links": links, "suggestions": sugg,
    }


# ---------------------------------------------------------------------------
# 심사 워크스페이스 (L5 세션/표본 — Evidence 페이지용)
# ---------------------------------------------------------------------------

def get_workspace_summary() -> Dict[str, Any]:
    ensure_demo_dataset()
    sessions, requests = [], []
    for s in audit_workspace._sessions.values():
        summ = audit_workspace.get_session_summary(s.session_id)
        if summ:
            sessions.append({
                "session_id": summ["session_id"], "auditor": summ["auditor"],
                "audit_date": summ["audit_date"].strftime("%Y-%m-%d"),
                "status": summ["status"], "progress": summ["progress"],
                "pending": summ["pending_items"],
            })
    for r in audit_workspace._sample_requests.values():
        requests.append({
            "request_id": r.request_id, "control_id": _norm(r.control_id),
            "description": r.request_description,
            "assigned_to": r.assigned_to or "미할당",
            "due_date": r.due_date.strftime("%Y-%m-%d"),
            "status": r.status.value,
        })
    return {"sessions": sessions, "requests": requests}


def get_findings_view() -> Dict[str, Any]:
    ensure_demo_dataset()
    findings = []
    for f in audit_findings_manager._findings.values():
        findings.append({
            "finding_id": f.finding_id, "defect_number": f.defect_number,
            "control_id": _norm(f.control_id), "control_name": f.control_name,
            "title": f.title, "severity": f.severity.value, "status": f.status.value,
            "category": f.category.value, "auditor": f.auditor,
            "confirmed_facts": f.confirmed_facts, "target": f.target, "sample": f.sample,
            "judgment_basis": f.judgment_basis, "occurrence_period": f.occurrence_period,
            "impact": f.impact, "current_controls": f.current_controls,
            "additional_checks": f.additional_checks,
            "phenomenon": f.phenomenon, "direct_cause": f.direct_cause,
            "root_cause": f.root_cause, "control_failure": f.control_failure,
            "independent_reviewer": f.independent_reviewer,
            "residual_risk_reported": f.residual_risk_reported,
            "recurrence_monitoring": f.recurrence_monitoring,
            "assignee": f.assignee,
            "corrective_actions": [
                {"action_id": a.action_id, "type": a.action_type.value,
                 "description": a.description, "assignee": a.assignee,
                 "due_date": a.due_date.strftime("%Y-%m-%d"), "status": a.status.value}
                for a in f.corrective_actions
            ],
        })
    return {
        "findings": findings,
        "summary": audit_findings_manager.get_finding_summary(),
        "trend": audit_findings_manager.get_trend_analysis(),
    }


# ---------------------------------------------------------------------------
# 증적 → 통제항목 자동 매핑 추천 (advisory — 최종 매핑은 사용자가 확정)
# ---------------------------------------------------------------------------

import re as _re

# 증적 문서 빈출어 → 관련 통제 후보 (통제명 직매칭을 보강하는 동의어/연관어)
_EVIDENCE_HINTS: Dict[str, List[str]] = {
    "정책": ["1.1.5", "2.1.1", "3.5.1"], "지침": ["1.1.5", "2.1.1"],
    "규정": ["1.1.5", "2.1.1"], "방침": ["3.5.1", "1.1.5"],
    "교육": ["2.2.4"], "훈련": ["2.2.4", "2.11.4"], "인식제고": ["2.2.4"],
    "서약": ["2.2.3"], "직무 분리": ["2.2.2"], "직무분리": ["2.2.2"],
    "퇴직": ["2.2.5", "2.5.1"], "퇴사": ["2.2.5", "2.5.1"],
    "직무변경": ["2.2.5"], "보안 위반": ["2.2.6"],
    "외부자": ["2.3.1", "2.3.2"], "용역": ["2.3.1"], "협력사": ["2.3.1"],
    "계약": ["2.3.2", "3.3.2"], "보호구역": ["2.4.1"], "출입": ["2.4.2"],
    "cctv": ["2.4.4", "3.1.6"], "반출": ["2.4.6"], "업무환경": ["2.4.7"],
    "계정": ["2.5.1", "2.2.5"], "아이디": ["2.5.1"], "사용자 등록": ["2.5.1"],
    "비밀번호": ["2.5.4"], "패스워드": ["2.5.4"], "password": ["2.5.4"],
    "mfa": ["2.5.3"], "다중인증": ["2.5.3"], "otp": ["2.5.3"],
    "특권": ["2.5.5"], "관리자 권한": ["2.5.5"], "관리자계정": ["2.5.5"],
    "admin": ["2.5.5"], "접근권한": ["2.5.6", "2.6.2"], "권한 검토": ["2.5.6"],
    "방화벽": ["2.6.1"], "네트워크": ["2.6.1"], "침입": ["2.6.1", "2.10.1"],
    "정보시스템 접근": ["2.6.2"], "응용프로그램": ["2.6.3"],
    "데이터베이스": ["2.6.4"], "db접근": ["2.6.4"],
    "무선": ["2.6.5"], "vpn": ["2.6.6"], "원격": ["2.6.6"],
    "인터넷": ["2.6.7"], "암호키": ["2.7.2"], "키 관리": ["2.7.2"],
    "암호화": ["2.7.1"], "암호": ["2.7.1"],
    "소스": ["2.8.5"], "개발": ["2.8.1"], "운영환경": ["2.8.6", "2.8.3"],
    "변경관리": ["2.9.1"], "변경": ["2.9.1"], "장애": ["2.9.2"],
    "성능": ["2.9.2"], "백업": ["2.9.3"], "복구": ["2.9.3", "2.12.1"],
    "로그": ["2.9.4", "2.9.5"], "접속기록": ["2.9.4"], "감사로그": ["2.9.4"],
    "시간 동기": ["2.9.6"], "ntp": ["2.9.6"], "폐기": ["2.9.7", "3.4.1"],
    "보안시스템": ["2.10.1"], "클라우드": ["2.10.2"], "공개서버": ["2.10.3"],
    "핀테크": ["2.10.4"], "전자거래": ["2.10.4"], "정보전송": ["2.10.5"],
    "단말": ["2.10.6"], "usb": ["2.10.7"], "보조저장매체": ["2.10.7"],
    "패치": ["2.10.8"], "악성코드": ["2.10.9"], "백신": ["2.10.9"],
    "랜섬웨어": ["2.10.9"],
    "사고 대응": ["2.11.1", "2.11.5"], "취약점": ["2.11.2"],
    "모의해킹": ["2.11.2"], "모니터링": ["2.11.3"], "이상행위": ["2.11.3"],
    "침해": ["2.11.5"], "재해": ["2.12.1"], "재난": ["2.12.1"],
    "개인정보 수집": ["3.1.1"], "동의": ["3.1.1"],
    "주민등록번호": ["3.1.3"], "민감정보": ["3.1.4"],
    "영상정보": ["3.1.6"], "마케팅": ["3.1.7"],
    "개인정보 현황": ["3.2.1"], "품질": ["3.2.2"], "목적 외": ["3.2.4"],
    "가명": ["3.2.5"], "제3자": ["3.3.1"], "위탁": ["3.3.2"],
    "수탁": ["3.3.2"], "양도": ["3.3.3"], "국외": ["3.3.4"],
    "파기": ["3.4.1"], "처리방침": ["3.5.1"], "정보주체": ["3.5.2"],
    "통지": ["3.5.3"],
    "회의록": ["1.3.3"], "위원회": ["1.3.3"], "경영진": ["1.1.1"],
    "책임자": ["1.1.2"], "조직도": ["1.1.3"], "범위": ["1.1.4"],
    "자산 식별": ["1.2.1"], "정보자산": ["1.2.1", "2.1.3"],
    "흐름분석": ["1.2.2"], "위험 평가": ["1.2.3"], "위험평가": ["1.2.3"],
    "리스크": ["1.2.3"], "보호대책 선정": ["1.2.4"],
    "법적": ["1.4.1"], "점검": ["1.4.2"], "개선": ["1.4.3"],
    "자원 할당": ["1.1.6"], "예산": ["1.1.6"],
}


def _control_names() -> Dict[str, str]:
    """control_id → 통제명 맵 (프레임워크 원본 기준)."""
    names: Dict[str, str] = {}
    for area in ISMS_P_FRAMEWORK:
        for sub_id, _sub_name, items in area["sub"]:
            for idx, item_name in enumerate(items, start=1):
                names[f"{sub_id}.{idx}"] = item_name
    return names


def _control_catalog() -> str:
    """LLM 프롬프트용 통제항목 목록 (id + 이름, 코드순 정렬)."""
    names = _control_names()
    return "\n".join(
        f"{cid} {names[cid]}"
        for cid in sorted(names, key=lambda x: [int(p) for p in x.split(".")])
    )


def _llm_suggest_controls(file_name: str, sample: str) -> Optional[List[Dict[str, Any]]]:
    """LLM 의미 분석 기반 통제 추천 — advisory 전용.

    본문은 외부 API 전송 전 민감정보를 마스킹한다.
    SDK/키/호출/파싱 실패 시 None → 호출자가 규칙 결과로 폴백한다.
    """
    try:
        from secgrc.llm import get_gemini_api_key
        api_key = get_gemini_api_key()
        if not api_key:
            return None
        from google import genai
    except Exception:
        return None

    safe_sample = ""
    if sample:
        try:
            from secgrc.agent_security.secret_guard import SecretGuard
            safe_sample, _found, _types = SecretGuard.scan_and_redact(sample[:8000])
        except Exception:
            safe_sample = ""
        safe_sample = re.sub(r"\d{6}-[1-4]\d{6}", "******-*******", safe_sample)
        safe_sample = re.sub(r"(?<!\d)\d{6}[1-4]\d{6}(?!\d)", "*************", safe_sample)

    prompt = (
        "당신은 ISMS-P 인증심사 증적 분석 어시스턴트입니다.\n"
        "아래 [증적 파일]의 파일명과 본문 일부를 보고, 이 증적이 입증할 수 있는 통제항목을\n"
        "[통제항목 목록]에서 최대 3개까지 고르세요.\n"
        "- 반드시 목록에 있는 control_id만 사용하세요.\n"
        "- 각 항목에 한국어 한 줄 근거(reason)를 적으세요.\n"
        "- 확실한 것만 고르세요. 해당 항목이 없으면 빈 배열 []만 반환하세요.\n"
        "- JSON 배열만 출력하고 다른 텍스트는 쓰지 마세요.\n"
        '  예: [{"control_id":"2.5.4","reason":"비밀번호 구성·변경 기준을 정한 절차 문서"}]\n\n'
        f"[통제항목 목록]\n{_control_catalog()}\n\n"
        f"[증적 파일]\n파일명: {file_name}\n본문 일부:\n{safe_sample[:4000]}\n"
    )
    names = _control_names()
    try:
        client = genai.Client(api_key=api_key)
        for model in _LLM_MODELS:
            try:
                r = client.models.generate_content(model=model, contents=prompt)
                if not (r and r.text):
                    continue
                m = re.search(r"\[.*\]", r.text, re.S)
                if not m:
                    continue
                items = _json.loads(m.group(0))
                if not isinstance(items, list):
                    continue
                out: List[Dict[str, Any]] = []
                for it in items:
                    cid = str(it.get("control_id", "")).strip() if isinstance(it, dict) else ""
                    if cid in names and all(o["control_id"] != cid for o in out):
                        out.append({
                            "control_id": cid,
                            "name": names[cid],
                            "reason": str(it.get("reason", ""))[:200],
                        })
                    if len(out) >= 3:
                        break
                if out:
                    return out
            except Exception:
                continue
    except Exception:
        return None
    return None


def suggest_control(file_name: str, sample: str = "") -> Dict[str, Any]:
    """파일명+본문 샘플의 키워드 스코어링으로 통제항목을 추천한다.

    advisory 전용 — 자동 매핑이 아니라 추천이며, 최종 매핑은 사용자가 확인한다.
    1차: 결정론적 규칙 기반(키워드·빈출어 일치). 신뢰도가 high가 아니면
    2차: LLM 의미 분석으로 보강 (민감정보 마스킹 후 전송, 실패 시 규칙 결과 유지).
    """
    # macOS 드래그 파일명은 NFD(분해형 자모)로 올 수 있어 NFC로 정규화해야 한글 매칭이 된다
    file_name = unicodedata.normalize("NFC", file_name or "")[:300]
    sample = unicodedata.normalize("NFC", sample or "")[:65536]
    name_l = file_name.lower()
    text_l = f"{file_name}\n{sample}".lower()

    names = _control_names()
    scores: Dict[str, int] = {}
    matched: Dict[str, set] = {}

    def hit(cid: str, term: str, weight: int) -> None:
        scores[cid] = scores.get(cid, 0) + weight
        matched.setdefault(cid, set()).add(term)

    # 1) 통제명·중분류명 토큰 직접 매칭
    for area in ISMS_P_FRAMEWORK:
        for sub_id, sub_name, items in area["sub"]:
            terms = [t.strip() for t in _re.split(r"[\s·/()]+", sub_name) if len(t.strip()) >= 2]
            for idx, item_name in enumerate(items, start=1):
                cid = f"{sub_id}.{idx}"
                ctl_terms = terms + [
                    t.strip() for t in _re.split(r"[\s·/()]+", item_name) if len(t.strip()) >= 2
                ]
                for term in set(ctl_terms):
                    tl = term.lower()
                    if tl in name_l:
                        hit(cid, term, 3)
                    elif tl in text_l:
                        hit(cid, term, 1)

    # 2) 증적 빈출어 힌트 (파일명 가중치 ↑)
    for term, cids in _EVIDENCE_HINTS.items():
        tl = term.lower()
        weight = 4 if tl in name_l else (1 if tl in text_l else 0)
        if weight:
            for cid in cids:
                hit(cid, term, weight)

    top = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    candidates = [
        {
            "control_id": cid,
            "name": names.get(cid, ""),
            "score": score,
            "matched": sorted(matched.get(cid, []))[:6],
        }
        for cid, score in top
    ]
    best = top[0][1] if top else 0
    confidence = "high" if best >= 6 else ("medium" if best >= 3 else ("low" if best >= 1 else "none"))

    # 키워드 신뢰도가 낮으면 LLM 의미 분석으로 보강 (advisory — 최종 매핑은 사용자 확정)
    source = "rule"
    if confidence != "high":
        llm_cands = _llm_suggest_controls(file_name, sample)
        if llm_cands:
            candidates = llm_cands
            source = "llm"
            confidence = "medium"
    return {
        "candidates": candidates,
        "confidence": confidence,
        "source": source,
        "advisory": True,
        "note": "자동 추천이며 최종 통제 매핑은 사용자가 확인합니다.",
    }


# ---------------------------------------------------------------------------
# 리포트 생성 — 현재 런타임/데모 데이터를 표준 구조로 집계
# (summary_rows: KPI 격자 / tables: 공통 테이블 / notes: 출처·한계 명시)
# ---------------------------------------------------------------------------

def _report_base(report_key: str, title: str, audit_id: Optional[str]) -> Dict[str, Any]:
    return {
        "key": report_key,
        "title": title,
        "audit": get_audit_context(audit_id),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "demo": True,
        "summary_rows": [],
        "tables": [],
        "notes": [],
    }


def build_report(report_key: str, audit_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """리포트 표준 구조 생성 — report_render.html이 렌더링하는 계약."""
    ensure_demo_dataset()
    if report_key == "readiness":
        kpis = get_kpis(audit_id)
        land = get_landscape()
        issues = get_top_issues(10, audit_id=audit_id)
        pop = get_population(audit_id)
        r = _report_base(report_key, "인증 준비도 보고서", audit_id)
        r["summary_rows"] = [
            {"label": "준비도", "value": f"{kpis['readiness']['pct']}% ({kpis['readiness']['ready']}/{kpis['readiness']['total']})"},
            {"label": "증적 확보율", "value": f"{kpis['evidence']['pct']}% ({kpis['evidence']['covered']}/{kpis['evidence']['total']})"},
            {"label": "GAP 발견", "value": f"{kpis['gaps']['count']}건"},
            {"label": "미해결 지적사항", "value": f"{kpis['findings']['open']}건"},
            {"label": "보완조치 진행 중", "value": f"{kpis['actions']['count']}건 (기한초과 {kpis['actions']['overdue']})"},
        ]
        r["tables"] = [
            {
                "title": "도메인별 준비 현황",
                "columns": ["도메인", "통제 수", "READY", "PARTIAL", "MISSING", "CONFLICT", "준비율"],
                "rows": [[
                    f"{d['id']}. {d['name']}", d["count"],
                    d["counts"]["READY"], d["counts"]["PARTIAL"],
                    d["counts"]["MISSING"], d["counts"]["CONFLICT"],
                    f"{d['ready_pct']}%",
                ] for d in land["domains"]],
            },
            {
                "title": "주요 미해결 이슈 TOP 10",
                "columns": ["통제", "항목명", "유형", "심각도", "내용", "담당자", "기한"],
                "rows": [[
                    g["control_id"], g["control_name"], g["status_label"],
                    g["severity"], g["description"], g["owner"], g["due_date"],
                ] for g in issues],
            },
            {
                "title": "범위·모집단 검증 현황",
                "columns": ["항목", "수치"],
                "rows": [
                    ["인증범위 자산", f"{pop['total_assets']:,}건"],
                    ["검증 완료", f"{pop['verified']:,}건"],
                    ["검증 필요(예외)", f"{pop['exceptions']}건"],
                    ["연결 시스템", f"{pop['systems']}개"],
                    ["IAM 계정", f"{pop['iam_accounts']:,}개"],
                    ["특권 계정", f"{pop['privileged_accounts']}개"],
                ],
            },
        ]
        r["notes"] = [
            "준비도·증적율·GAP 수치는 데모 데이터(demo)입니다 — 실제 커넥터 연동 시 실측값으로 대체됩니다.",
            "지적사항·증적 원장 수치는 현재 런타임의 실제 상태입니다.",
        ]
        return r

    if report_key == "gap":
        gaps = get_gaps(audit_id=audit_id)["gaps"]
        recon = reconciliation_engine.get_reconciliation_summary()
        recon_rows = [
            [r.control_id.replace("ISMS-P-", ""), r.reconciliation_type.value,
             r.status.value, r.severity, r.description]
            for r in reconciliation_engine.results
        ]
        r = _report_base(report_key, "GAP 분석 리포트", audit_id)
        r["summary_rows"] = [
            {"label": "GAP 총계", "value": f"{len(gaps)}건"},
            {"label": "CRITICAL", "value": f"{sum(1 for g in gaps if g['severity'] == 'CRITICAL')}건"},
            {"label": "HIGH", "value": f"{sum(1 for g in gaps if g['severity'] == 'HIGH')}건"},
            {"label": "정합성 일치율", "value": f"{recon['match_rate']:.1f}% ({recon['total_checks']}건 검사)"},
        ]
        r["tables"] = [
            {
                "title": "GAP 목록 (요구↔정책↔설정↔증적↔운영 대사)",
                "columns": ["GAP", "통제", "항목명", "유형/상태", "심각도", "내용", "시스템", "담당자", "기한"],
                "rows": [[
                    g["gap_id"], g["control_id"], g["control_name"], g["status_label"],
                    g["severity"], g["description"], g["system"], g["owner"], g["due_date"],
                ] for g in gaps],
            },
            {
                "title": "정합성 엔진 검사 결과 (실측)",
                "columns": ["통제", "유형", "상태", "심각도", "내용"],
                "rows": recon_rows or [["—", "—", "—", "—", "관측된 불일치 없음"]],
            },
        ]
        r["notes"] = [
            "GAP 목록은 데모 카탈로그 기반이며, 정합성 엔진 결과는 실제 런타임 관측값입니다.",
            "각 GAP는 '지적사항 등록'으로 FindingsManager의 실제 생명주기에 연결할 수 있습니다.",
        ]
        return r

    if report_key == "findings":
        fv = get_findings_view()
        s = fv["summary"]
        r = _report_base(report_key, "결함보고서", audit_id)
        r["summary_rows"] = [
            {"label": "전체 지적사항", "value": f"{s['total_findings']}건"},
            {"label": "치명적/주요", "value": f"{s['critical_findings']}/{s['major_findings']}건"},
            {"label": "미해결", "value": f"{s['open_findings'] + s['in_progress_findings']}건"},
            {"label": "기한초과 조치", "value": f"{s['corrective_actions']['overdue']}건"},
        ]
        rows = []
        for f in fv["findings"]:
            actions = "; ".join(
                f"[{a['status']}] {a['description']} (담당 {a['assignee']}, 기한 {a['due_date']})"
                for a in f["corrective_actions"]) or "—"
            rows.append([
                f["defect_number"], f["control_id"], f["title"], f["severity"], f["status"],
                f["confirmed_facts"] or "—", f["assignee"] or "미지정",
                f["independent_reviewer"] or "미실시", actions,
            ])
        r["tables"] = [{
            "title": "지적사항 상세 (12개 분석 필드 요약 + 보완조치)",
            "columns": ["결함번호", "통제", "제목", "심각도", "상태", "확인된 사실", "담당자", "독립재검증", "보완조치"],
            "rows": rows or [["—"] * 9],
        }]
        r["notes"] = [
            "지적사항·보완조치는 FindingsManager의 실제 생명주기 데이터입니다.",
            "종결은 독립 재검증(조치자≠검증자) 완료 후에만 가능합니다.",
        ]
        return r

    if report_key == "integrity":
        ret = evidence_ledger.get_retention_report()
        valid = evidence_ledger.verify_chain_integrity()
        r = _report_base(report_key, "증적 무결성 증명", audit_id)
        r["summary_rows"] = [
            {"label": "해시체인 검증", "value": "무결 ✓ — 변조 없음" if valid else "손상 감지 — 조사 필요"},
            {"label": "총 레코드", "value": f"{ret['total_records']}건"},
            {"label": "만료 임박/만료", "value": f"{ret['expiring_soon']} / {ret['expired_records']}건"},
            {"label": "검증 시각", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        ]
        r["tables"] = [{
            "title": "원장 레코드 (Append-Only · SHA-256 해시체인)",
            "columns": ["레코드 ID", "증적 ID", "통제", "유형", "수집", "생성자", "생성 시각", "해시"],
            "rows": [[
                rec.record_id, rec.evidence_id, rec.control_id.replace("ISMS-P-", ""),
                rec.record_type.value, rec.collection_method, rec.created_by,
                rec.created_at.strftime("%Y-%m-%d %H:%M:%S"), rec.hash,
            ] for rec in reversed(evidence_ledger._records)] or [["—"] * 8],
        }]
        r["notes"] = [
            "모든 레코드는 이전 레코드 해시를 포함한 체인으로 연결되어 소급 생성·변조가 탐지됩니다.",
            "민감정보 검출로 차단된 제출 시도도 BLOCKED 레코드로 보존됩니다.",
        ]
        return r
    return None


def build_package(audit_id: Optional[str] = None) -> Dict[str, Any]:
    """심사 제출 패키지 — 전 계층 데이터를 하나의 JSON 묶음으로."""
    ensure_demo_dataset()
    return {
        "manifest": {
            "package_type": "ISMS-P audit submission package",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "contents": ["audit", "kpis", "landscape", "gaps", "findings",
                         "reconciliation", "ledger", "integrity"],
        },
        "audit": get_audit_context(audit_id),
        "kpis": get_kpis(audit_id),
        "landscape": get_landscape(),
        "gaps": get_gaps(audit_id=audit_id),
        "findings": get_findings_view(),
        "reconciliation": {
            "summary": reconciliation_engine.get_reconciliation_summary(),
            "results": [
                {"control_id": r.control_id, "type": r.reconciliation_type.value,
                 "status": r.status.value, "severity": r.severity,
                 "description": r.description}
                for r in reconciliation_engine.results
            ],
        },
        "ledger": {
            "retention": evidence_ledger.get_retention_report(),
            "chain_valid": evidence_ledger.verify_chain_integrity(),
            "records": [
                {"record_id": r.record_id, "evidence_id": r.evidence_id,
                 "control_id": r.control_id, "type": r.record_type.value,
                 "collection_method": r.collection_method, "created_by": r.created_by,
                 "created_at": r.created_at.isoformat(), "hash": r.hash,
                 "content": r.content}
                for r in evidence_ledger._records
            ],
        },
        "integrity": {
            "algorithm": "SHA-256 hash chain (append-only)",
            "verified_at": datetime.now().isoformat(timespec="seconds"),
            "valid": evidence_ledger.verify_chain_integrity(),
        },
        "demo": True,
    }


def build_scan_report(run_id: str, audit_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Prowler 스캔 실행 결과 → report_render.html 계약. 실제 수집 데이터이므로 demo=False."""
    from ..connectors.prowler.service import ProwlerGcpService

    svc = ProwlerGcpService()
    report = svc.get_run_report(run_id)
    if not report.get("manifest"):
        return None
    m = report["manifest"]
    records = svc.get_canonical_records(run_id)

    by_sev: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_svc: Dict[str, int] = {}
    for rec in records:
        p = rec.payload or {}
        by_sev[p.get("source_severity", "?")] = by_sev.get(p.get("source_severity", "?"), 0) + 1
        by_status[p.get("source_status", "?")] = by_status.get(p.get("source_status", "?"), 0) + 1
        if p.get("service"):
            by_svc[p["service"]] = by_svc.get(p["service"], 0) + 1

    def _sev(s):
        return {"Critical": "치명", "High": "높음", "Medium": "중간", "Low": "낮음"}.get(s, s or "-")

    r = _report_base("prowler_scan", "클라우드 구성 진단 결과 보고서 (Prowler)", audit_id)
    r["demo"] = False
    r["summary_rows"] = [
        {"label": "스캔 상태", "value": report["status"]},
        {"label": "수집 항목", "value": f"{report['record_count']}건 (수용 {report['accepted_count']})"},
        {"label": "FAIL", "value": f"{by_status.get('FAIL', 0)}건"},
        {"label": "높음+치명", "value": f"{by_sev.get('Critical', 0) + by_sev.get('High', 0)}건"},
        {"label": "Prowler 버전", "value": report["prowler_version"]},
        {"label": "대상 프로젝트", "value": ", ".join(m.get("project_refs") or ["-"])},
    ]
    tables = [
        {
            "title": "심각도 분포",
            "columns": ["심각도", "건수"],
            "rows": [[_sev(k), v] for k, v in
                     sorted(by_sev.items(), key=lambda kv: -kv[1])] or [["-", 0]],
        },
        {
            "title": "상태 분포",
            "columns": ["상태", "건수"],
            "rows": [[k, v] for k, v in
                     sorted(by_status.items(), key=lambda kv: -kv[1])] or [["-", 0]],
        },
        {
            "title": "서비스 분포",
            "columns": ["서비스", "건수"],
            "rows": [[k, v] for k, v in
                     sorted(by_svc.items(), key=lambda kv: -kv[1])] or [["-", 0]],
        },
    ]
    if records:
        tables.append({
            "title": f"전체 진단 결과 ({len(records)}건)",
            "columns": ["체크", "심각도", "상태", "서비스", "리전", "리소스", "내용"],
            "rows": [[
                rec.payload.get("check_id", ""), _sev(rec.payload.get("source_severity")),
                rec.payload.get("source_status", ""), rec.payload.get("service", ""),
                rec.payload.get("region", ""), rec.payload.get("resource_id", ""),
                (rec.payload.get("description", "") or "")[:400],
            ] for rec in records],
        })
        action = [rec for rec in records if rec.payload.get("source_status") in ("FAIL", "MANUAL")]
        if action:
            tables.append({
                "title": f"조치 검토 대상 ({len(action)}건 — FAIL·MANUAL)",
                "columns": ["체크", "심각도", "상태", "발견 내용", "권고 조치"],
                "rows": [[
                    rec.payload.get("check_id", ""), _sev(rec.payload.get("source_severity")),
                    rec.payload.get("source_status", ""),
                    (rec.payload.get("description", "") or "-")[:300],
                    (rec.payload.get("remediation_guidance", "") or "-")[:300],
                ] for rec in action],
            })
    r["tables"] = tables
    r["notes"] = [
        "본 보고서는 Prowler 읽기전용 스캔의 실제 수집 결과입니다. 데모 데이터가 아닙니다.",
        "상태 의미 — FAIL: 부적합 확인됨 · PASS: 적합 확인됨 · MANUAL: 자동 판정 불가(관련 API 미활성·권한 부족 등)로 사람 검토 필요. MANUAL은 취약점이 확정된 것이 아니라 '평가가 안 된 항목'입니다.",
    ]
    if report.get("rejected_count"):
        r["notes"].append(
            f"⚠ 수집 {report['record_count']}건 중 {report['rejected_count']}건이 정규화에서 제외됐습니다 — "
            "입력 파일이 파인딩이 아닌 프레임워크 매핑 데이터이거나 필드가 누락된 경우입니다. "
            "원본 raw 파일과 매니페스트 해시로 원인을 대조하세요.")
    r["notes"] += [
        f"원시 출력 해시(SHA-256): {m.get('raw_output_hash', '-')}",
        f"정규화 출력 해시: {m.get('normalized_output_hash', '-')} · 매니페스트 해시: {m.get('manifest_hash', '-')}",
        f"실행 이미지: {m.get('runtime_image', '-')} · 매핑 버전: {m.get('mapping_version', '-')}",
        "판정 지위: NON_AUTHORITATIVE / NOT_EVALUATED — 진단 결과는 관찰 증거이며 통제 충족 판정이 아닙니다. ISMS-P 통제와의 매핑·충족 여부는 담당자 검토 후 별도 확정합니다.",
    ]
    return r
