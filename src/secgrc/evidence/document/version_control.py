"""문서 버전 관리 시스템 - 정책/절차서 버전 및 승인 워크플로우"""

from enum import Enum
from datetime import datetime
from typing import Dict, List, Optional, Any, BinaryIO
from pydantic import BaseModel, Field
import uuid
import hashlib
import os
from pathlib import Path


class DocumentStatus(str, Enum):
    """문서 상태"""
    DRAFT = "DRAFT"             # 초안
    UNDER_REVIEW = "UNDER_REVIEW" # 검토 중
    APPROVED = "APPROVED"       # 승인됨
    PUBLISHED = "PUBLISHED"     # 발행됨
    ARCHIVED = "ARCHIVED"       # 보관됨
    OBSOLETE = "OBSOLETE"       # 폐기됨


class ApprovalStatus(str, Enum):
    """승인 상태"""
    PENDING = "PENDING"         # 대기
    APPROVED = "APPROVED"       # 승인
    REJECTED = "REJECTED"       # 반려
    CANCELLED = "CANCELLED"     # 취소


class DocumentVersion(BaseModel):
    """문서 버전"""
    version_id: str = Field(default_factory=lambda: f"VER-{uuid.uuid4().hex[:8].upper()}")
    document_id: str = Field(description="문서 ID")
    version_number: str = Field(description="버전 번호")
    status: DocumentStatus = Field(default=DocumentStatus.DRAFT)
    file_path: str = Field(description="파일 경로")
    file_hash: str = Field(description="파일 해시")
    file_size: int = Field(description="파일 크기")
    created_by: str = Field(description="작성자")
    created_at: datetime = Field(default_factory=datetime.now)
    approved_by: Optional[str] = Field(default=None, description="승인자")
    approved_at: Optional[datetime] = Field(default=None)
    published_by: Optional[str] = Field(default=None, description="발행자")
    published_at: Optional[datetime] = Field(default=None)
    effective_date: Optional[datetime] = Field(default=None, description="시행일")
    expiry_date: Optional[datetime] = Field(default=None, description="만료일")
    change_summary: str = Field(default="", description="변경 요약")
    change_details: str = Field(default="", description="변경 상세")
    approval_comments: str = Field(default="", description="승인 의견")


class ApprovalWorkflow(BaseModel):
    """승인 워크플로우"""
    workflow_id: str = Field(default_factory=lambda: f"WF-{uuid.uuid4().hex[:8].upper()}")
    document_id: str = Field(description="문서 ID")
    version_id: str = Field(description="버전 ID")
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING)
    requested_by: str = Field(description="요청자")
    requested_at: datetime = Field(default_factory=datetime.now)
    approvers: List[str] = Field(description="승인자 목록")
    current_approver: Optional[str] = Field(default=None, description="현재 승인자")
    approval_history: List[Dict[str, Any]] = Field(default_factory=list, description="승인 이력")
    completed_at: Optional[datetime] = Field(default=None)
    comments: str = Field(default="", description="코멘트")


class Document(BaseModel):
    """문서"""
    document_id: str = Field(default_factory=lambda: f"DOC-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(description="문서 제목")
    description: str = Field(description="문서 설명")
    document_type: str = Field(description="문서 유형")
    control_ids: List[str] = Field(description="관련 통제 ID 목록")
    owner: str = Field(description="소유자")
    department: str = Field(description="부서")
    status: DocumentStatus = Field(default=DocumentStatus.DRAFT)
    current_version: Optional[str] = Field(default=None, description="현재 버전 ID")
    versions: List[DocumentVersion] = Field(default_factory=list, description="버전 목록")
    approval_workflows: List[ApprovalWorkflow] = Field(default_factory=list, description="승인 워크플로우")
    tags: List[str] = Field(default_factory=list, description="태그")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="메타데이터")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class DocumentVersionControl:
    """문서 버전 관리 시스템"""

    def __init__(self, storage_path: str = "document_storage"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # 문서 저장 경로
        self.documents_path = self.storage_path / "documents"
        self.documents_path.mkdir(exist_ok=True)
        
        # 버전 저장 경로
        self.versions_path = self.storage_path / "versions"
        self.versions_path.mkdir(exist_ok=True)
        
        # 인메모리 저장소
        self._documents: Dict[str, Document] = {}
        self._versions: Dict[str, DocumentVersion] = {}
        self._workflows: Dict[str, ApprovalWorkflow] = {}
        self._control_index: Dict[str, List[str]] = {}  # control_id -> document_ids

    def create_document(self, title: str, description: str, document_type: str,
                       control_ids: List[str], owner: str, department: str,
                       tags: Optional[List[str]] = None, metadata: Optional[Dict] = None) -> Document:
        """새 문서 생성"""
        document = Document(
            title=title,
            description=description,
            document_type=document_type,
            control_ids=control_ids,
            owner=owner,
            department=department,
            tags=tags or [],
            metadata=metadata or {}
        )
        
        self._documents[document.document_id] = document
        
        # 통제 인덱스 추가
        for control_id in control_ids:
            if control_id not in self._control_index:
                self._control_index[control_id] = []
            self._control_index[control_id].append(document.document_id)
        
        return document

    def create_version(self, document_id: str, file: BinaryIO, version_number: str,
                      created_by: str, change_summary: str = "", change_details: str = "") -> Optional[DocumentVersion]:
        """문서 버전 생성"""
        document = self._documents.get(document_id)
        if not document:
            return None
        
        # 파일 저장
        file_content = file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        file_size = len(file_content)
        
        version_id = f"VER-{uuid.uuid4().hex[:8].upper()}"
        file_name = f"{version_id}_{document_id}.pdf"
        file_path = self.versions_path / file_name
        
        with open(file_path, "wb") as f:
            f.write(file_content)
        
        # 버전 생성
        version = DocumentVersion(
            version_id=version_id,
            document_id=document_id,
            version_number=version_number,
            file_path=str(file_path),
            file_hash=file_hash,
            file_size=file_size,
            created_by=created_by,
            change_summary=change_summary,
            change_details=change_details
        )
        
        self._versions[version_id] = version
        document.versions.append(version)
        document.current_version = version_id
        document.updated_at = datetime.now()
        
        return version

    def submit_for_approval(self, document_id: str, version_id: str,
                          requested_by: str, approvers: List[str]) -> Optional[ApprovalWorkflow]:
        """승인 요청"""
        document = self._documents.get(document_id)
        version = self._versions.get(version_id)
        
        if not document or not version:
            return None
        
        # 승인 워크플로우 생성
        workflow = ApprovalWorkflow(
            document_id=document_id,
            version_id=version_id,
            requested_by=requested_by,
            approvers=approvers,
            current_approver=approvers[0] if approvers else None
        )
        
        self._workflows[workflow.workflow_id] = workflow
        document.approval_workflows.append(workflow)
        document.status = DocumentStatus.UNDER_REVIEW
        document.updated_at = datetime.now()
        
        # 버전 상태 업데이트
        version.status = DocumentStatus.UNDER_REVIEW
        
        return workflow

    def approve_version(self, workflow_id: str, approver: str, comments: str = "") -> bool:
        """버전 승인"""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False
        
        # 승인 이력 추가
        workflow.approval_history.append({
            "approver": approver,
            "status": ApprovalStatus.APPROVED,
            "timestamp": datetime.now(),
            "comments": comments
        })
        
        # 다음 승인자 설정
        current_index = workflow.approvers.index(approver) if approver in workflow.approvers else -1
        if current_index >= 0 and current_index < len(workflow.approvers) - 1:
            workflow.current_approver = workflow.approvers[current_index + 1]
        else:
            # 모든 승인 완료
            workflow.status = ApprovalStatus.APPROVED
            workflow.completed_at = datetime.now()
            
            # 문서 상태 업데이트
            document = self._documents.get(workflow.document_id)
            version = self._versions.get(workflow.version_id)
            if document and version:
                document.status = DocumentStatus.APPROVED
                version.status = DocumentStatus.APPROVED
                version.approved_by = approver
                version.approved_at = datetime.now()
                document.updated_at = datetime.now()
        
        return True

    def reject_version(self, workflow_id: str, approver: str, comments: str = "") -> bool:
        """버전 반려"""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False
        
        # 반려 이력 추가
        workflow.approval_history.append({
            "approver": approver,
            "status": ApprovalStatus.REJECTED,
            "timestamp": datetime.now(),
            "comments": comments
        })
        
        workflow.status = ApprovalStatus.REJECTED
        workflow.completed_at = datetime.now()
        workflow.comments = comments
        
        # 문서 상태 업데이트
        document = self._documents.get(workflow.document_id)
        version = self._versions.get(workflow.version_id)
        if document and version:
            document.status = DocumentStatus.DRAFT
            version.status = DocumentStatus.DRAFT
            document.updated_at = datetime.now()
        
        return True

    def publish_version(self, document_id: str, version_id: str,
                       published_by: str, effective_date: Optional[datetime] = None) -> bool:
        """버전 발행"""
        document = self._documents.get(document_id)
        version = self._versions.get(version_id)
        
        if not document or not version:
            return False
        
        # 승인된 버전인지 확인
        if version.status != DocumentStatus.APPROVED:
            return False
        
        # 발행 처리
        document.status = DocumentStatus.PUBLISHED
        version.status = DocumentStatus.PUBLISHED
        version.published_by = published_by
        version.published_at = datetime.now()
        version.effective_date = effective_date or datetime.now()
        
        document.updated_at = datetime.now()
        
        return True

    def get_document(self, document_id: str) -> Optional[Document]:
        """문서 조회"""
        return self._documents.get(document_id)

    def get_version(self, version_id: str) -> Optional[DocumentVersion]:
        """버전 조회"""
        return self._versions.get(version_id)

    def get_documents_by_control(self, control_id: str) -> List[Document]:
        """통제별 문서 조회"""
        document_ids = self._control_index.get(control_id, [])
        return [self._documents[did] for did in document_ids if did in self._documents]

    def get_pending_approvals(self, approver: str) -> List[ApprovalWorkflow]:
        """승인 대기 목록 조회"""
        return [
            workflow for workflow in self._workflows.values()
            if workflow.current_approver == approver and workflow.status == ApprovalStatus.PENDING
        ]

    def get_document_history(self, document_id: str) -> List[DocumentVersion]:
        """문서 버전 이력 조회"""
        document = self._documents.get(document_id)
        if not document:
            return []
        
        return sorted(document.versions, key=lambda v: v.created_at, reverse=True)

    def get_document_summary(self) -> Dict[str, Any]:
        """문서 현황 요약"""
        total_docs = len(self._documents)
        
        by_status = {}
        by_type = {}
        total_versions = 0
        
        for doc in self._documents.values():
            status = doc.status.value
            doc_type = doc.document_type
            
            by_status[status] = by_status.get(status, 0) + 1
            by_type[doc_type] = by_type.get(doc_type, 0) + 1
            total_versions += len(doc.versions)
        
        # 승인 대기 현황
        pending_approvals = len([
            w for w in self._workflows.values()
            if w.status == ApprovalStatus.PENDING
        ])
        
        return {
            "total_documents": total_docs,
            "total_versions": total_versions,
            "by_status": by_status,
            "by_type": by_type,
            "pending_approvals": pending_approvals,
            "controls_with_documents": len(self._control_index)
        }

    def archive_document(self, document_id: str, archived_by: str) -> bool:
        """문서 보관"""
        document = self._documents.get(document_id)
        if not document:
            return False
        
        document.status = DocumentStatus.ARCHIVED
        document.updated_at = datetime.now()
        
        return True

    def get_expiring_documents(self, days_ahead: int = 30) -> List[Document]:
        """만료 예정 문서 조회"""
        expiry_date = datetime.now() + timedelta(days=days_ahead)
        
        expiring_docs = []
        for doc in self._documents.values():
            # 현재 버전의 만료일 확인
            if doc.current_version:
                version = self._versions.get(doc.current_version)
                if version and version.expiry_date and version.expiry_date <= expiry_date:
                    expiring_docs.append(doc)
        
        return expiring_docs


# 전역 인스턴스
document_version_control = DocumentVersionControl()
