"""심사 대응 워크스페이스 - 심사 세션 관리, 표본 요청 추적, 제출 전 자동 검증"""

from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid
import re
import json


class AuditSessionStatus(str, Enum):
    """심사 세션 상태"""
    SCHEDULED = "SCHEDULED"         # 예정됨
    IN_PROGRESS = "IN_PROGRESS"     # 진행 중
    COMPLETED = "COMPLETED"         # 완료
    CANCELLED = "CANCELLED"         # 취소됨


class SampleRequestStatus(str, Enum):
    """표본 요청 상태"""
    REQUESTED = "REQUESTED"         # 요청됨
    ASSIGNED = "ASSIGNED"           # 담당자 할당됨
    COLLECTING = "COLLECTING"       # 증적 수집 중
    SUBMITTED = "SUBMITTED"         # 제출됨
    VERIFIED = "VERIFIED"           # 검증됨
    REJECTED = "REJECTED"           # 거부됨


class AuditSession(BaseModel):
    """심사 세션"""
    session_id: str = Field(default_factory=lambda: f"SESSION-{uuid.uuid4().hex[:8].upper()}")
    audit_id: str = Field(description="심사 ID")
    auditor_name: str = Field(description="심사원명")
    audit_date: datetime = Field(description="심사일")
    status: AuditSessionStatus = Field(default=AuditSessionStatus.SCHEDULED)
    requested_items: List[str] = Field(default_factory=list, description="요청 항목")
    submitted_items: List[str] = Field(default_factory=list, description="제출 항목")
    pending_items: List[str] = Field(default_factory=list, description="미제출 항목")
    notes: str = Field(default="", description="비고")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class SampleRequest(BaseModel):
    """표본 요청"""
    request_id: str = Field(default_factory=lambda: f"REQ-{uuid.uuid4().hex[:8].upper()}")
    session_id: str = Field(description="심사 세션 ID")
    control_id: str = Field(description="통제 ID")
    request_description: str = Field(description="요청 설명")
    requested_by: str = Field(description="요청자")
    assigned_to: Optional[str] = Field(default=None, description="담당자")
    due_date: datetime = Field(description="제출 기한")
    status: SampleRequestStatus = Field(default=SampleRequestStatus.REQUESTED)
    evidence_ids: List[str] = Field(default_factory=list, description="증적 ID 목록")
    submission_notes: str = Field(default="", description="제출 노트")
    verification_notes: str = Field(default="", description="검증 노트")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class EvidenceSubmissionCheck(BaseModel):
    """증적 제출 전 검증 결과"""
    check_id: str = Field(default_factory=lambda: f"CHK-{uuid.uuid4().hex[:8].upper()}")
    evidence_id: str = Field(description="증적 ID")
    passed: bool = Field(description="통과 여부")
    checks: Dict[str, bool] = Field(default_factory=dict, description="검증 항목")
    issues: List[str] = Field(default_factory=list, description="발견된 문제")
    checked_at: datetime = Field(default_factory=datetime.now)


class AuditWorkspace:
    """심사 대응 워크스페이스"""

    def __init__(self):
        self._sessions: Dict[str, AuditSession] = {}
        self._sample_requests: Dict[str, SampleRequest] = {}
        self._submission_checks: Dict[str, EvidenceSubmissionCheck] = {}
        self._audit_requests: Dict[str, List[str]] = {}  # audit_id -> session_ids

    def create_audit_session(self, audit_id: str, auditor_name: str, 
                           audit_date: datetime, requested_items: List[str]) -> AuditSession:
        """심사 세션 생성"""
        session = AuditSession(
            audit_id=audit_id,
            auditor_name=auditor_name,
            audit_date=audit_date,
            requested_items=requested_items,
            pending_items=requested_items.copy()
        )
        
        self._sessions[session.session_id] = session
        
        if audit_id not in self._audit_requests:
            self._audit_requests[audit_id] = []
        self._audit_requests[audit_id].append(session.session_id)
        
        return session

    def get_session(self, session_id: str) -> Optional[AuditSession]:
        """심사 세션 조회"""
        return self._sessions.get(session_id)

    def update_session_status(self, session_id: str, status: AuditSessionStatus) -> bool:
        """심사 세션 상태 업데이트"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        session.status = status
        session.updated_at = datetime.now()
        return True

    def request_sample(self, session_id: str, control_id: str, 
                      request_description: str, requested_by: str,
                      due_date: datetime) -> Optional[SampleRequest]:
        """표본 요청 생성"""
        session = self.get_session(session_id)
        if not session:
            return None
        
        request = SampleRequest(
            session_id=session_id,
            control_id=control_id,
            request_description=request_description,
            requested_by=requested_by,
            due_date=due_date
        )
        
        self._sample_requests[request.request_id] = request
        
        # 세션에 요청 항목 추가
        if control_id not in session.requested_items:
            session.requested_items.append(control_id)
            session.pending_items.append(control_id)
            session.updated_at = datetime.now()
        
        return request

    def assign_sample_request(self, request_id: str, assigned_to: str) -> bool:
        """표본 요청 담당자 할당"""
        request = self._sample_requests.get(request_id)
        if not request:
            return False
        
        request.assigned_to = assigned_to
        request.status = SampleRequestStatus.ASSIGNED
        request.updated_at = datetime.now()
        return True

    def submit_sample_evidence(self, request_id: str, evidence_ids: List[str],
                             submission_notes: str = "") -> bool:
        """표본 증적 제출"""
        request = self._sample_requests.get(request_id)
        if not request:
            return False
        
        request.evidence_ids.extend(evidence_ids)
        request.submission_notes = submission_notes
        request.status = SampleRequestStatus.SUBMITTED
        request.updated_at = datetime.now()
        
        # 세션 상태 업데이트
        session = self.get_session(request.session_id)
        if session and request.control_id in session.pending_items:
            session.pending_items.remove(request.control_id)
            session.submitted_items.append(request.control_id)
            session.updated_at = datetime.now()
        
        return True

    def verify_sample_request(self, request_id: str, verification_notes: str = "") -> bool:
        """표본 요청 검증"""
        request = self._sample_requests.get(request_id)
        if not request:
            return False
        
        request.verification_notes = verification_notes
        request.status = SampleRequestStatus.VERIFIED
        request.updated_at = datetime.now()
        return True

    def reject_sample_request(self, request_id: str, rejection_reason: str) -> bool:
        """표본 요청 거부"""
        request = self._sample_requests.get(request_id)
        if not request:
            return False
        
        request.status = SampleRequestStatus.REJECTED
        request.verification_notes = rejection_reason
        request.updated_at = datetime.now()
        return True

    def validate_evidence_submission(self, evidence_content: Dict[str, Any]) -> EvidenceSubmissionCheck:
        """증적 제출 전 자동 검증"""
        checks = {}
        issues = []
        
        # 비밀번호/키/토큰/개인정보 포함 여부 검사
        sensitive_patterns = {
            "password": r'password|pwd|pass|passwd|비밀번호',
            "api_key": r'api[_-]?key|secret[_-]?key|token|bearer',
            "private_key": r'private[_-]?key|rsa|ssh[_-]?key',
            "personal_info": r'주민등록번호|여권번호|운전면허번호|계좌번호|카드번호|전화번호|이메일|주소'
        }
        
        content_str = json.dumps(evidence_content, ensure_ascii=False).lower()
        
        for pattern_name, pattern in sensitive_patterns.items():
            if re.search(pattern, content_str):
                checks[f"no_{pattern_name}"] = False
                issues.append(f"민감 정보({pattern_name})가 포함되어 있습니다.")
            else:
                checks[f"no_{pattern_name}"] = True
        
        # 필수 필드 검사
        required_fields = ["title", "description", "collected_at", "source"]
        for field in required_fields:
            if field not in evidence_content or not evidence_content[field]:
                checks[f"has_{field}"] = False
                issues.append(f"필수 필드 '{field}'가 누락되었습니다.")
            else:
                checks[f"has_{field}"] = True
        
        # 타임스탬프 유효성 검사
        if "collected_at" in evidence_content:
            try:
                collected_at = datetime.fromisoformat(evidence_content["collected_at"].replace('Z', '+00:00'))
                if collected_at > datetime.now():
                    checks["valid_timestamp"] = False
                    issues.append("증적 수집 시간이 미래입니다.")
                else:
                    checks["valid_timestamp"] = True
            except:
                checks["valid_timestamp"] = False
                issues.append("유효하지 않은 수집 시간 형식입니다.")
        
        passed = all(checks.values()) and not issues
        
        check = EvidenceSubmissionCheck(
            evidence_id=evidence_content.get("evidence_id", "UNKNOWN"),
            passed=passed,
            checks=checks,
            issues=issues
        )
        
        self._submission_checks[check.check_id] = check
        return check

    def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """심사 세션 요약"""
        session = self.get_session(session_id)
        if not session:
            return None
        
        requests = [r for r in self._sample_requests.values() if r.session_id == session_id]
        
        status_counts = {}
        for req in requests:
            status = req.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "session_id": session_id,
            "audit_id": session.audit_id,
            "auditor": session.auditor_name,
            "audit_date": session.audit_date,
            "status": session.status.value,
            "total_requests": len(requests),
            "status_counts": status_counts,
            "pending_items": session.pending_items,
            "submitted_items": session.submitted_items,
            "progress": len(session.submitted_items) / len(session.requested_items) * 100 if session.requested_items else 0
        }

    def get_audit_sessions(self, audit_id: str) -> List[AuditSession]:
        """심사별 세션 목록"""
        session_ids = self._audit_requests.get(audit_id, [])
        return [self._sessions[sid] for sid in session_ids if sid in self._sessions]

    def get_pending_requests(self, days_ahead: int = 7) -> List[SampleRequest]:
        """기한 임박 요청 조회"""
        cutoff_date = datetime.now() + timedelta(days=days_ahead)
        
        return [
            req for req in self._sample_requests.values()
            if req.status in [SampleRequestStatus.REQUESTED, SampleRequestStatus.ASSIGNED, SampleRequestStatus.COLLECTING]
            and req.due_date <= cutoff_date
        ]

    def get_submission_check_history(self, evidence_id: str) -> List[EvidenceSubmissionCheck]:
        """증적 제출 검증 이력"""
        return [
            check for check in self._submission_checks.values()
            if check.evidence_id == evidence_id
        ]

    def generate_audit_response_plan(self, audit_id: str, 
                                   preparation_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """심사 대응 계획 생성"""
        sessions = self.get_audit_sessions(audit_id)
        
        plan = {
            "audit_id": audit_id,
            "total_sessions": len(sessions),
            "scheduled_sessions": len([s for s in sessions if s.status == AuditSessionStatus.SCHEDULED]),
            "in_progress_sessions": len([s for s in sessions if s.status == AuditSessionStatus.IN_PROGRESS]),
            "completed_sessions": len([s for s in sessions if s.status == AuditSessionStatus.COMPLETED]),
            "preparation_items": preparation_items,
            "pending_requests": len(self.get_pending_requests()),
            "response_timeline": []
        }
        
        # 타임라인 생성
        for session in sessions:
            plan["response_timeline"].append({
                "session_id": session.session_id,
                "auditor": session.auditor_name,
                "date": session.audit_date,
                "status": session.status.value,
                "items": session.requested_items
            })
        
        return plan


# 전역 인스턴스
audit_workspace = AuditWorkspace()
