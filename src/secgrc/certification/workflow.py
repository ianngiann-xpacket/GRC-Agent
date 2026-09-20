"""인증심사 워크플로우 엔진 - 인증심사 전체 생명주기 관리"""

from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class AuditStage(str, Enum):
    """인증심사 단계"""
    PREPARATION = "PREPARATION"           # 준비 단계
    DOCUMENT_REVIEW = "DOCUMENT_REVIEW"   # 문서 심사
    ON_SITE_AUDIT = "ON_SITE_AUDIT"       # 현장 심사
    FINDINGS = "FINDINGS"                 # 지적사항
    CORRECTIVE_ACTION = "CORRECTIVE_ACTION" # 보완조치
    VERIFICATION = "VERIFICATION"         # 확인 심사
    CERTIFICATION = "CERTIFICATION"       # 인증 발급


class AuditStatus(str, Enum):
    """심사 상태"""
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    ON_HOLD = "ON_HOLD"
    CANCELLED = "CANCELLED"


class AuditType(str, Enum):
    """심사 유형 (HTML 문서 기준)"""
    INITIAL = "INITIAL"           # 최초심사
    SURVEILLANCE = "SURVEILLANCE" # 사후심사
    RENEWAL = "RENEWAL"           # 갱신심사


class CertificationTier(str, Enum):
    """인증 등급 (HTML 문서 제도 개편방향)"""
    ENHANCED = "ENHANCED"   # 강화인증
    STANDARD = "STANDARD"   # 표준인증
    SIMPLIFIED = "SIMPLIFIED" # 간편인증


class AuditChecklistItem(BaseModel):
    """심사 체크리스트 항목"""
    item_id: str = Field(description="체크리스트 항목 ID")
    stage: AuditStage = Field(description="심사 단계")
    control_id: str = Field(description="통제 ID")
    description: str = Field(description="항목 설명")
    required: bool = Field(default=True, description="필수 여부")
    completed: bool = Field(default=False, description="완료 여부")
    evidence_required: List[str] = Field(default_factory=list, description="필요 증적 유형")
    assignee: Optional[str] = Field(default=None, description="담당자")
    due_date: Optional[datetime] = Field(default=None, description="기한")
    notes: str = Field(default="", description="비고")


class AuditSchedule(BaseModel):
    """심사 일정"""
    stage: AuditStage
    planned_start: datetime
    planned_end: datetime
    actual_start: Optional[datetime] = None
    actual_end: Optional[datetime] = None
    status: AuditStatus = AuditStatus.NOT_STARTED


class CertificationAudit(BaseModel):
    """인증심사 전체 정보"""
    audit_id: str = Field(default_factory=lambda: f"AUDIT-{uuid.uuid4().hex[:8].upper()}")
    organization_id: str = Field(description="조직 ID")
    framework: str = Field(default="ISMS-P", description="인증 프레임워크")
    framework_version: str = Field(default="2024-07", description="프레임워크 버전")
    audit_type: AuditType = Field(default=AuditType.INITIAL, description="심사 유형")
    certification_tier: CertificationTier = Field(default=CertificationTier.STANDARD, description="인증 등급")
    scope: str = Field(description="인증 범위")
    lead_auditor: str = Field(description="심사원 대표")
    audit_team: List[str] = Field(default_factory=list, description="심사 팀원")
    current_stage: AuditStage = Field(default=AuditStage.PREPARATION)
    status: AuditStatus = Field(default=AuditStatus.NOT_STARTED)
    start_date: datetime = Field(default_factory=datetime.now)
    target_certification_date: Optional[datetime] = None
    checklist: List[AuditChecklistItem] = Field(default_factory=list)
    schedule: List[AuditSchedule] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class CertificationAuditWorkflow:
    """인증심사 워크플로우 엔진"""

    def __init__(self):
        self._audits: Dict[str, CertificationAudit] = {}
        self._checklist_templates: Dict[str, List[AuditChecklistItem]] = {}
        self._initialize_default_checklist()

    def _initialize_default_checklist(self):
        """기본 체크리스트 템플릿 초기화"""
        # ISMS-P 기본 체크리스트
        ismsp_checklist = [
            # 준비 단계
            AuditChecklistItem(
                item_id="PREP-001",
                stage=AuditStage.PREPARATION,
                control_id="ISMS-P-1.1.1",
                description="경영진 참여 및 지원 체계 확인",
                evidence_required=["문서", "회의록", "승인기록"],
                assignee="경영진"
            ),
            AuditChecklistItem(
                item_id="PREP-002",
                stage=AuditStage.PREPARATION,
                control_id="ISMS-P-1.1.2",
                description="CISO/CPO 지정 및 자격 확인",
                evidence_required=["문서", "임명장", "조직도"],
                assignee="인사팀"
            ),
            AuditChecklistItem(
                item_id="PREP-003",
                stage=AuditStage.PREPARATION,
                control_id="ISMS-P-1.2.2",
                description="위험평가 수행 및 관리계획 수립",
                evidence_required=["문서", "위험평가보고서"],
                assignee="보안팀"
            ),
            # 문서 심사 단계
            AuditChecklistItem(
                item_id="DOC-001",
                stage=AuditStage.DOCUMENT_REVIEW,
                control_id="ISMS-P-2.5.1",
                description="사용자 인증 정책 및 절차 문서 검토",
                evidence_required=["정책문서", "절차서"],
                assignee="보안팀"
            ),
            AuditChecklistItem(
                item_id="DOC-002",
                stage=AuditStage.DOCUMENT_REVIEW,
                control_id="ISMS-P-2.6.3",
                description="네트워크 접근통제 정책 문서 검토",
                evidence_required=["정책문서", "네트워크구성도"],
                assignee="인프라팀"
            ),
            # 현장 심사 단계
            AuditChecklistItem(
                item_id="SITE-001",
                stage=AuditStage.ON_SITE_AUDIT,
                control_id="ISMS-P-2.5.2",
                description="사용자 권한 관리 실태 점검",
                evidence_required=["시스템설정", "권한목록", "승인기록"],
                assignee="보안팀"
            ),
            AuditChecklistItem(
                item_id="SITE-002",
                stage=AuditStage.ON_SITE_AUDIT,
                control_id="ISMS-P-2.7.1",
                description="암호화 정책 적용 실태 점검",
                evidence_required=["시스템설정", "암호화정책"],
                assignee="보안팀"
            ),
        ]
        self._checklist_templates["ISMS-P"] = ismsp_checklist

    def create_audit(self, organization_id: str, scope: str, lead_auditor: str, 
                     audit_type: AuditType = AuditType.INITIAL,
                     certification_tier: CertificationTier = CertificationTier.STANDARD,
                     target_date: Optional[datetime] = None) -> CertificationAudit:
        """새로운 인증심사 생성"""
        audit = CertificationAudit(
            organization_id=organization_id,
            scope=scope,
            lead_auditor=lead_auditor,
            audit_type=audit_type,
            certification_tier=certification_tier,
            target_certification_date=target_date
        )
        
        # 기본 체크리스트 적용
        audit.checklist = self._checklist_templates.get("ISMS-P", []).copy()
        
        # 기본 일정 생성
        audit.schedule = self._create_default_schedule(audit.start_date, target_date)
        
        self._audits[audit.audit_id] = audit
        return audit

    def _create_default_schedule(self, start_date: datetime, target_date: Optional[datetime]) -> List[AuditSchedule]:
        """기본 심사 일정 생성"""
        schedule = []
        current_date = start_date
        
        # 준비 단계 (2주)
        schedule.append(AuditSchedule(
            stage=AuditStage.PREPARATION,
            planned_start=current_date,
            planned_end=current_date + timedelta(days=14)
        ))
        current_date += timedelta(days=14)
        
        # 문서 심사 (1주)
        schedule.append(AuditSchedule(
            stage=AuditStage.DOCUMENT_REVIEW,
            planned_start=current_date,
            planned_end=current_date + timedelta(days=7)
        ))
        current_date += timedelta(days=7)
        
        # 현장 심사 (3일)
        schedule.append(AuditSchedule(
            stage=AuditStage.ON_SITE_AUDIT,
            planned_start=current_date,
            planned_end=current_date + timedelta(days=3)
        ))
        current_date += timedelta(days=3)
        
        # 지적사항 및 보완조치 (4주)
        schedule.append(AuditSchedule(
            stage=AuditStage.CORRECTIVE_ACTION,
            planned_start=current_date,
            planned_end=current_date + timedelta(days=28)
        ))
        
        return schedule

    def get_audit(self, audit_id: str) -> Optional[CertificationAudit]:
        """심사 정보 조회"""
        return self._audits.get(audit_id)

    def update_audit_stage(self, audit_id: str, new_stage: AuditStage) -> bool:
        """심사 단계 업데이트"""
        audit = self.get_audit(audit_id)
        if not audit:
            return False
        
        audit.current_stage = new_stage
        audit.updated_at = datetime.now()
        return True

    def complete_checklist_item(self, audit_id: str, item_id: str, notes: str = "") -> bool:
        """체크리스트 항목 완료 처리"""
        audit = self.get_audit(audit_id)
        if not audit:
            return False
        
        for item in audit.checklist:
            if item.item_id == item_id:
                item.completed = True
                item.notes = notes
                audit.updated_at = datetime.now()
                return True
        return False

    def get_stage_progress(self, audit_id: str, stage: AuditStage) -> Dict[str, Any]:
        """단계별 진행 상황 조회"""
        audit = self.get_audit(audit_id)
        if not audit:
            return {}
        
        stage_items = [item for item in audit.checklist if item.stage == stage]
        completed_items = [item for item in stage_items if item.completed]
        
        return {
            "stage": stage.value,
            "total_items": len(stage_items),
            "completed_items": len(completed_items),
            "completion_rate": len(completed_items) / len(stage_items) if stage_items else 0,
            "pending_items": [item.item_id for item in stage_items if not item.completed]
        }

    def get_audit_summary(self, audit_id: str) -> Dict[str, Any]:
        """심사 전체 요약"""
        audit = self.get_audit(audit_id)
        if not audit:
            return {}
        
        total_items = len(audit.checklist)
        completed_items = len([item for item in audit.checklist if item.completed])
        
        stage_progress = {}
        for stage in AuditStage:
            stage_progress[stage.value] = self.get_stage_progress(audit_id, stage)
        
        return {
            "audit_id": audit.audit_id,
            "organization_id": audit.organization_id,
            "framework": audit.framework,
            "current_stage": audit.current_stage.value,
            "status": audit.status.value,
            "overall_progress": completed_items / total_items if total_items else 0,
            "total_items": total_items,
            "completed_items": completed_items,
            "stage_progress": stage_progress,
            "target_date": audit.target_certification_date,
            "created_at": audit.created_at
        }

    def list_audits(self, organization_id: Optional[str] = None) -> List[CertificationAudit]:
        """심사 목록 조회"""
        if organization_id:
            return [audit for audit in self._audits.values() if audit.organization_id == organization_id]
        return list(self._audits.values())


# 전역 인스턴스
certification_audit_workflow = CertificationAuditWorkflow()
