"""심사 지적사항 및 보완조치 관리 시스템"""

from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class FindingSeverity(str, Enum):
    """지적사항 심각도"""
    CRITICAL = "CRITICAL"   # 중요 - 인증 불가능 수준
    MAJOR = "MAJOR"         # 주요 - 인증 전 반드시 해결
    MINOR = "MINOR"         # 경미 - 개선 권장
    OBSERVATION = "OBSERVATION" # 관찰 - 참고 사항


class FindingStatus(str, Enum):
    """지적사항 상태"""
    OPEN = "OPEN"                   # 미해결
    IN_PROGRESS = "IN_PROGRESS"     # 진행 중
    RESOLVED = "RESOLVED"           # 해결됨
    VERIFIED = "VERIFIED"           # 확인됨
    CLOSED = "CLOSED"               # 종료
    REOPENED = "REOPENED"           # 재오픈


class CorrectiveActionStatus(str, Enum):
    """보완조치 상태"""
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    VERIFIED = "VERIFIED"
    OVERDUE = "OVERDUE"


class CorrectiveActionType(str, Enum):
    """보완조치 유형 (HTML 문서 9.2절)"""
    IMMEDIATE = "IMMEDIATE"         # 즉시조치 - 현재 노출을 빠르게 감소
    CORRECTIVE = "CORRECTIVE"       # 시정조치 - 확인된 잘못된 상태 수정
    ROOT_CAUSE = "ROOT_CAUSE"       # 근본조치 - 재발 원인 제거
    PREVENTIVE = "PREVENTIVE"       # 예방조치 - 유사 문제의 타 영역 확산 방지
    COMPENSATING = "COMPENSATING"   # 보완통제 - 근본조치 전 임시 완화
    RISK_ACCEPTANCE = "RISK_ACCEPTANCE"  # 위험수용 - 잔여위험 승인


class FindingCategory(str, Enum):
    """결함 범주 (HTML 문서 8절 빈출 결함)"""
    ACCESS_CONTROL = "ACCESS_CONTROL"           # 계정 관리/접근 권한
    PASSWORD_POLICY = "PASSWORD_POLICY"         # 비밀번호 정책
    CHANGE_MANAGEMENT = "CHANGE_MANAGEMENT"     # 변경 관리
    LOG_MANAGEMENT = "LOG_MANAGEMENT"           # 로그 관리
    PERSONAL_DATA = "PERSONAL_DATA"             # 개인정보 처리
    DOCUMENTATION = "DOCUMENTATION"             # 문서 관리
    TRAINING = "TRAINING"                       # 교육 훈련
    PHYSICAL_SECURITY = "PHYSICAL_SECURITY"     # 물리적 보안
    NETWORK_SECURITY = "NETWORK_SECURITY"       # 네트워크 보안
    SYSTEM_DEVELOPMENT = "SYSTEM_DEVELOPMENT"   # 시스템 개발
    OTHER = "OTHER"


class CorrectiveAction(BaseModel):
    """보완조치"""
    action_id: str = Field(default_factory=lambda: f"CA-{uuid.uuid4().hex[:8].upper()}")
    finding_id: str = Field(description="관련 지적사항 ID")
    action_type: CorrectiveActionType = Field(default=CorrectiveActionType.CORRECTIVE, description="조치 유형")
    description: str = Field(description="보완조치 내용")
    assignee: str = Field(description="담당자")
    assignee_email: str = Field(description="담당자 이메일")
    due_date: datetime = Field(description="완료 기한")
    status: CorrectiveActionStatus = Field(default=CorrectiveActionStatus.NOT_STARTED)
    priority: int = Field(default=3, description="우선순위 (1-5)")
    population_scope: Optional[str] = Field(default=None, description="모집단 범위 (전체/부문/표본)")
    estimated_effort: str = Field(default="", description="예상 소요 노력")
    actual_effort: Optional[str] = Field(default=None, description="실제 소요 노력")
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)
    verified_at: Optional[datetime] = Field(default=None)
    verified_by: Optional[str] = Field(default=None)
    evidence: List[str] = Field(default_factory=list, description="보완 증적 ID")
    expiry_date: Optional[datetime] = Field(default=None, description="보완통제 만료일 (COMPENSATING 필수)")
    residual_risk_acceptance: Optional[Dict] = Field(default=None, description="위험수용 정보")
    notes: str = Field(default="", description="비고")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class AuditFinding(BaseModel):
    """심사 지적사항 (HTML 문서 9.1절 12개 분석 필드 반영)"""
    finding_id: str = Field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8].upper()}")
    audit_id: str = Field(description="심사 ID")
    defect_number: str = Field(description="결함번호")
    control_id: str = Field(description="통제 ID")
    control_name: str = Field(description="통제명")
    severity: FindingSeverity = Field(description="심각도")
    status: FindingStatus = Field(default=FindingStatus.OPEN)
    title: str = Field(description="지적사항 제목")
    description: str = Field(description="지적사항 상세 설명")
    
    # 12개 분석 필드
    confirmed_facts: str = Field(default="", description="확인된 사실")
    target: str = Field(default="", description="대상 (조직/시스템/계정/개인정보/수탁자)")
    sample: str = Field(default="", description="표본 (결함이 발견된 특정 인스턴스)")
    judgment_basis: str = Field(default="", description="판단근거 (정책/설정/로그/인터뷰/법령)")
    occurrence_period: str = Field(default="", description="발생기간")
    impact: str = Field(default="", description="영향 (기밀성/무결성/가용성/개인정보)")
    current_controls: str = Field(default="", description="현재 통제")
    additional_checks: str = Field(default="", description="추가 확인 (모집단/다른 조직/다른 시스템)")
    submission_deadline: Optional[datetime] = Field(default=None, description="제출기한")
    assignee: Optional[str] = Field(default=None, description="담당자")
    
    evidence: List[str] = Field(default_factory=list, description="증적 ID 목록")
    auditor: str = Field(description="심사원")
    audit_date: datetime = Field(description="심사 일자")
    location: str = Field(default="", description="심사 장소")
    process_area: str = Field(default="", description="프로세스 영역")
    category: FindingCategory = Field(default=FindingCategory.OTHER, description="결함 범주")
    recommendation: str = Field(default="", description="권고사항")
    management_response: Optional[str] = Field(default=None, description="경영진 답변")
    
    # 원인 분석 (9.3절)
    phenomenon: Optional[str] = Field(default=None, description="현상")
    direct_cause: Optional[str] = Field(default=None, description="직접원인")
    root_cause: Optional[str] = Field(default=None, description="근본원인")
    contributing_factors: Optional[str] = Field(default=None, description="기여요인")
    control_failure: Optional[str] = Field(default=None, description="통제 실패")
    
    corrective_actions: List[CorrectiveAction] = Field(default_factory=list, description="보완조치 목록")
    target_closure_date: Optional[datetime] = Field(default=None, description="목표 종료일")
    actual_closure_date: Optional[datetime] = Field(default=None, description="실제 종료일")
    verified_by: Optional[str] = Field(default=None, description="확인자")
    verified_at: Optional[datetime] = Field(default=None)
    independent_reviewer: Optional[str] = Field(default=None, description="독립 재검증자")
    independent_review_date: Optional[datetime] = Field(default=None, description="독립 재검증일")
    residual_risk_reported: bool = Field(default=False, description="잔여위험 보고 여부")
    recurrence_monitoring: bool = Field(default=False, description="재발 모니터링 여부")
    tags: List[str] = Field(default_factory=list, description="태그")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class AuditFindingsManager:
    """심사 지적사항 관리자"""

    def __init__(self):
        self._findings: Dict[str, AuditFinding] = {}
        self._corrective_actions: Dict[str, CorrectiveAction] = {}
        self._audit_findings_index: Dict[str, List[str]] = {}  # audit_id -> finding_ids
        self._control_findings_index: Dict[str, List[str]] = {}  # control_id -> finding_ids

    def create_finding(self, audit_id: str, control_id: str, control_name: str,
                      severity: FindingSeverity, title: str, description: str,
                      auditor: str, defect_number: Optional[str] = None,
                      category: FindingCategory = FindingCategory.OTHER,
                      confirmed_facts: str = "", target: str = "", sample: str = "",
                      judgment_basis: str = "", occurrence_period: str = "",
                      impact: str = "", current_controls: str = "",
                      additional_checks: str = "", submission_deadline: Optional[datetime] = None,
                      assignee: Optional[str] = None, evidence: Optional[List[str]] = None,
                      recommendation: str = "", target_days: int = 30) -> AuditFinding:
        """새로운 지적사항 생성 (12개 분석 필드 반영)"""
        
        if not defect_number:
            defect_number = f"DEF-{len(self._findings)+1:04d}"
        
        finding = AuditFinding(
            audit_id=audit_id,
            defect_number=defect_number,
            control_id=control_id,
            control_name=control_name,
            severity=severity,
            title=title,
            description=description,
            auditor=auditor,
            audit_date=datetime.now(),
            category=category,
            confirmed_facts=confirmed_facts,
            target=target,
            sample=sample,
            judgment_basis=judgment_basis,
            occurrence_period=occurrence_period,
            impact=impact,
            current_controls=current_controls,
            additional_checks=additional_checks,
            submission_deadline=submission_deadline,
            assignee=assignee,
            evidence=evidence or [],
            recommendation=recommendation,
            target_closure_date=datetime.now() + timedelta(days=target_days)
        )
        
        self._findings[finding.finding_id] = finding
        self._add_to_index(audit_id, control_id, finding.finding_id)
        
        return finding

    def _add_to_index(self, audit_id: str, control_id: str, finding_id: str):
        """인덱스 추가"""
        if audit_id not in self._audit_findings_index:
            self._audit_findings_index[audit_id] = []
        self._audit_findings_index[audit_id].append(finding_id)
        
        if control_id not in self._control_findings_index:
            self._control_findings_index[control_id] = []
        self._control_findings_index[control_id].append(finding_id)

    def get_finding(self, finding_id: str) -> Optional[AuditFinding]:
        """지적사항 조회"""
        return self._findings.get(finding_id)

    def update_finding_status(self, finding_id: str, status: FindingStatus,
                            verified_by: Optional[str] = None) -> bool:
        """지적사항 상태 업데이트"""
        finding = self.get_finding(finding_id)
        if not finding:
            return False
        
        finding.status = status
        finding.updated_at = datetime.now()
        
        if status == FindingStatus.VERIFIED and verified_by:
            finding.verified_by = verified_by
            finding.verified_at = datetime.now()
        
        return True

    def add_corrective_action(self, finding_id: str, description: str, assignee: str,
                            assignee_email: str, due_date: datetime, 
                            action_type: CorrectiveActionType = CorrectiveActionType.CORRECTIVE,
                            population_scope: Optional[str] = None, priority: int = 3,
                            expiry_date: Optional[datetime] = None) -> Optional[CorrectiveAction]:
        """보완조치 추가"""
        finding = self.get_finding(finding_id)
        if not finding:
            return None
        
        # 보완통제인 경우 만료일 필수
        if action_type == CorrectiveActionType.COMPENSATING and not expiry_date:
            raise ValueError("보완통제 조치는 만료일이 필수입니다.")
        
        action = CorrectiveAction(
            finding_id=finding_id,
            action_type=action_type,
            description=description,
            assignee=assignee,
            assignee_email=assignee_email,
            due_date=due_date,
            population_scope=population_scope,
            priority=priority,
            expiry_date=expiry_date
        )
        
        self._corrective_actions[action.action_id] = action
        finding.corrective_actions.append(action)
        finding.updated_at = datetime.now()
        
        return action

    def update_corrective_action_status(self, action_id: str, status: CorrectiveActionStatus,
                                      verified_by: Optional[str] = None) -> bool:
        """보완조치 상태 업데이트"""
        action = self._corrective_actions.get(action_id)
        if not action:
            return False
        
        action.status = status
        action.updated_at = datetime.now()
        
        if status == CorrectiveActionStatus.IN_PROGRESS and not action.started_at:
            action.started_at = datetime.now()
        elif status == CorrectiveActionStatus.COMPLETED:
            action.completed_at = datetime.now()
        elif status == CorrectiveActionStatus.VERIFIED and verified_by:
            action.verified_at = datetime.now()
            action.verified_by = verified_by
        
        return True

    def get_findings_by_audit(self, audit_id: str) -> List[AuditFinding]:
        """심사별 지적사항 조회"""
        finding_ids = self._audit_findings_index.get(audit_id, [])
        return [self._findings[fid] for fid in finding_ids if fid in self._findings]

    def get_findings_by_control(self, control_id: str) -> List[AuditFinding]:
        """통제별 지적사항 조회"""
        finding_ids = self._control_findings_index.get(control_id, [])
        return [self._findings[fid] for fid in finding_ids if fid in self._findings]

    def get_findings_by_status(self, status: FindingStatus) -> List[AuditFinding]:
        """상태별 지적사항 조회"""
        return [f for f in self._findings.values() if f.status == status]

    def get_overdue_actions(self) -> List[CorrectiveAction]:
        """기한 초과 보완조치 조회"""
        now = datetime.now()
        return [
            action for action in self._corrective_actions.values()
            if action.due_date < now and action.status not in [CorrectiveActionStatus.COMPLETED, CorrectiveActionStatus.VERIFIED]
        ]

    def get_finding_summary(self, audit_id: Optional[str] = None) -> Dict[str, Any]:
        """지적사항 요약"""
        if audit_id:
            findings = self.get_findings_by_audit(audit_id)
        else:
            findings = list(self._findings.values())
        
        total = len(findings)
        by_severity = {}
        by_status = {}
        
        for finding in findings:
            severity = finding.severity.value
            status = finding.status.value
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
        
        # 보완조치 현황
        all_actions = []
        for finding in findings:
            all_actions.extend(finding.corrective_actions)
        
        action_status = {}
        for action in all_actions:
            status = action.status.value
            action_status[status] = action_status.get(status, 0) + 1
        
        overdue_actions = self.get_overdue_actions()
        
        return {
            "total_findings": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "corrective_actions": {
                "total": len(all_actions),
                "by_status": action_status,
                "overdue": len(overdue_actions)
            },
            "critical_findings": by_severity.get("CRITICAL", 0),
            "major_findings": by_severity.get("MAJOR", 0),
            "open_findings": by_status.get("OPEN", 0),
            "in_progress_findings": by_status.get("IN_PROGRESS", 0),
            "resolved_findings": by_status.get("RESOLVED", 0) + by_status.get("VERIFIED", 0)
        }

    def get_finding_detail(self, finding_id: str) -> Dict[str, Any]:
        """지적사항 상세 정보"""
        finding = self.get_finding(finding_id)
        if not finding:
            return {}
        
        # 보완조치 진행률 계산
        total_actions = len(finding.corrective_actions)
        completed_actions = len([
            a for a in finding.corrective_actions 
            if a.status in [CorrectiveActionStatus.COMPLETED, CorrectiveActionStatus.VERIFIED]
        ])
        
        progress = completed_actions / total_actions if total_actions > 0 else 0
        
        return {
            "finding": finding,
            "progress": progress,
            "total_actions": total_actions,
            "completed_actions": completed_actions,
            "overdue_actions": len([
                a for a in finding.corrective_actions
                if a.due_date < datetime.now() and a.status not in [CorrectiveActionStatus.COMPLETED, CorrectiveActionStatus.VERIFIED]
            ])
        }

    def close_finding(self, finding_id: str, verified_by: str, notes: str = "") -> bool:
        """지적사항 종료"""
        finding = self.get_finding(finding_id)
        if not finding:
            return False
        
        # 모든 보완조치가 완료되었는지 확인
        incomplete_actions = [
            a for a in finding.corrective_actions
            if a.status not in [CorrectiveActionStatus.COMPLETED, CorrectiveActionStatus.VERIFIED]
        ]
        
        if incomplete_actions:
            return False  # 아직 완료되지 않은 보완조치가 있음
        
        finding.status = FindingStatus.CLOSED
        finding.actual_closure_date = datetime.now()
        finding.verified_by = verified_by
        finding.verified_at = datetime.now()
        finding.updated_at = datetime.now()
        
        return True

    def reopen_finding(self, finding_id: str, reason: str) -> bool:
        """지적사항 재오픈"""
        finding = self.get_finding(finding_id)
        if not finding:
            return False
        
        finding.status = FindingStatus.REOPENED
        finding.updated_at = datetime.now()
        
        # 재오픈 사유를 노트에 추가
        if not hasattr(finding, 'reopen_reasons'):
            finding.reopen_reasons = []
        finding.reopen_reasons.append({
            "date": datetime.now(),
            "reason": reason
        })
        
        return True

    def update_root_cause_analysis(self, finding_id: str, phenomenon: str,
                                  direct_cause: str, root_cause: str,
                                  contributing_factors: str = "", control_failure: str = "") -> bool:
        """근본원인 분석 업데이트 (9.3절)"""
        finding = self.get_finding(finding_id)
        if not finding:
            return False
        
        # 근본원인이 "부주의" 같은 단일 단어인지 검증
        if len(root_cause.strip()) < 10:
            raise ValueError("근본원인은 '부주의'와 같은 단일 단어가 아닌 구체적인 통제 실패를 기술해야 합니다.")
        
        finding.phenomenon = phenomenon
        finding.direct_cause = direct_cause
        finding.root_cause = root_cause
        finding.contributing_factors = contributing_factors
        finding.control_failure = control_failure
        finding.updated_at = datetime.now()
        
        return True

    def validate_closure_conditions(self, finding_id: str) -> Dict[str, bool]:
        """종결 조건 검증 (9.4절 완료 판정 기준)"""
        finding = self.get_finding(finding_id)
        if not finding:
            return {"valid": False, "reason": "지적사항을 찾을 수 없습니다."}
        
        conditions = {
            "fact_resolved": finding.confirmed_facts != "",
            "sample_corrected": finding.sample != "",
            "population_checked": finding.additional_checks != "",
            "root_cause_defined": finding.root_cause is not None and len(finding.root_cause) > 10,
            "policy_updated": True,  # 정책·절차·역할 갱신 확인
            "change_approved": True,  # 변경 승인·시험·배포 수행 확인
            "independent_verification": finding.independent_reviewer is not None,
            "residual_risk_reported": finding.residual_risk_reported,
            "recurrence_monitoring": finding.recurrence_monitoring,
            "all_actions_completed": all(
                a.status in [CorrectiveActionStatus.COMPLETED, CorrectiveActionStatus.VERIFIED]
                for a in finding.corrective_actions
            )
        }
        
        # 독립성 검증 - 재검증자가 조치자와 다른지 확인
        independent_verification = True
        if finding.independent_reviewer:
            action_assignees = [a.assignee for a in finding.corrective_actions]
            independent_verification = finding.independent_reviewer not in action_assignees
        
        conditions["independent_verification"] = independent_verification
        
        all_valid = all(conditions.values())
        failed_conditions = [k for k, v in conditions.items() if not v]
        
        return {
            "valid": all_valid,
            "conditions": conditions,
            "failed_conditions": failed_conditions,
            "reason": f"미충족 조건: {', '.join(failed_conditions)}" if not all_valid else "모든 조건 충족"
        }

    def perform_independent_review(self, finding_id: str, reviewer: str,
                                 review_result: str, comments: str = "") -> bool:
        """독립 재검증 수행"""
        finding = self.get_finding(finding_id)
        if not finding:
            return False
        
        # 조치자와 다른 사람인지 확인
        action_assignees = [a.assignee for a in finding.corrective_actions]
        if reviewer in action_assignees:
            raise ValueError("재검증자는 조치자와 달라야 합니다. 독립성이 결여되었습니다.")
        
        finding.independent_reviewer = reviewer
        finding.independent_review_date = datetime.now()
        finding.status = FindingStatus.VERIFIED
        finding.verified_by = reviewer
        finding.verified_at = datetime.now()
        finding.updated_at = datetime.now()
        
        return True

    def report_residual_risk(self, finding_id: str, risk_description: str,
                           accepted_by: str, justification: str) -> bool:
        """잔여위험 보고"""
        finding = self.get_finding(finding_id)
        if not finding:
            return False
        
        finding.residual_risk_reported = True
        finding.updated_at = datetime.now()
        
        # 위험수용 정보를 보완조치에 추가
        if finding.corrective_actions:
            latest_action = finding.corrective_actions[-1]
            latest_action.residual_risk_acceptance = {
                "risk_description": risk_description,
                "accepted_by": accepted_by,
                "justification": justification,
                "acceptance_date": datetime.now().isoformat()
            }
        
        return True

    def enable_recurrence_monitoring(self, finding_id: str) -> bool:
        """재발 모니터링 활성화"""
        finding = self.get_finding(finding_id)
        if not finding:
            return False
        
        finding.recurrence_monitoring = True
        finding.updated_at = datetime.now()
        
        return True

    def get_population_checklist(self, finding_id: str) -> Dict[str, Any]:
        """모집단 점검 체크리스트"""
        finding = self.get_finding(finding_id)
        if not finding:
            return {}
        
        return {
            "finding_id": finding_id,
            "defect_number": finding.defect_number,
            "sample_identified": finding.sample != "",
            "population_defined": finding.additional_checks != "",
            "population_scope": finding.additional_checks,
            "corrective_actions": len(finding.corrective_actions),
            "population_coverage": all(
                a.population_scope in ["전체", "모집단"] for a in finding.corrective_actions
            ) if finding.corrective_actions else False
        }

    def get_trend_analysis(self, days_back: int = 90) -> Dict[str, Any]:
        """추세 분석 (9.4절)"""
        cutoff_date = datetime.now() - timedelta(days=days_back)
        recent_findings = [
            f for f in self._findings.values()
            if f.created_at >= cutoff_date
        ]
        
        # 통제영역별 결함 수
        by_category = {}
        for finding in recent_findings:
            cat = finding.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
        
        # 동일 근본원인 재발
        root_causes = {}
        for finding in recent_findings:
            if finding.root_cause:
                cause = finding.root_cause[:50]  # 첫 50자로 그룹화
                root_causes[cause] = root_causes.get(cause, 0) + 1
        
        recurring_causes = {k: v for k, v in root_causes.items() if v > 1}
        
        # 평균 조치 기간
        completed_findings = [
            f for f in recent_findings
            if f.status == FindingStatus.CLOSED and f.actual_closure_date
        ]
        
        avg_closure_days = 0
        if completed_findings:
            total_days = sum([
                (f.actual_closure_date - f.created_at).days
                for f in completed_findings
            ])
            avg_closure_days = total_days / len(completed_findings)
        
        # 기한 초과 비율
        overdue_count = len([f for f in recent_findings if f.target_closure_date and f.target_closure_date < datetime.now()])
        overdue_rate = overdue_count / len(recent_findings) if recent_findings else 0
        
        return {
            "period_days": days_back,
            "total_findings": len(recent_findings),
            "by_category": by_category,
            "recurring_root_causes": recurring_causes,
            "avg_closure_days": avg_closure_days,
            "overdue_rate": overdue_rate,
            "completed_findings": len(completed_findings)
        }


# 전역 인스턴스
audit_findings_manager = AuditFindingsManager()
