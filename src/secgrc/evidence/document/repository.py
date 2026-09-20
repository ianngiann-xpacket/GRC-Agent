"""통합 증적 관리 시스템 - 시스템 + 문서 증적 통합 관리"""

from enum import Enum
from datetime import datetime
from typing import Dict, List, Optional, Any, BinaryIO
from pydantic import BaseModel, Field
import uuid
import os
from pathlib import Path


class EvidenceType(str, Enum):
    """증적 유형"""
    SYSTEM = "SYSTEM"           # 시스템 자동 수집 증적
    DOCUMENT = "DOCUMENT"       # 문서 증적
    INTERVIEW = "INTERVIEW"     # 인터뷰/설문 증적
    OBSERVATION = "OBSERVATION" # 현장 관찰 증적


class DocumentType(str, Enum):
    """문서 증적 유형"""
    POLICY = "POLICY"               # 정책 문서
    PROCEDURE = "PROCEDURE"         # 절차서
    MEETING_MINUTES = "MEETING_MINUTES" # 회의록
    TRAINING_RECORD = "TRAINING_RECORD" # 교육 기록
    AUDIT_REPORT = "AUDIT_REPORT"   # 감사 보고서
    APPROVAL_RECORD = "APPROVAL_RECORD" # 승인 기록
    ORGANIZATION_CHART = "ORGANIZATION_CHART" # 조직도
    CONTRACT = "CONTRACT"           # 계약서
    OTHER = "OTHER"                 # 기타


class EvidenceStatus(str, Enum):
    """증적 상태"""
    DRAFT = "DRAFT"             # 초안
    SUBMITTED = "SUBMITTED"     # 제출됨
    UNDER_REVIEW = "UNDER_REVIEW" # 검토 중
    APPROVED = "APPROVED"       # 승인됨
    REJECTED = "REJECTED"       # 반려됨
    ARCHIVED = "ARCHIVED"       # 보관됨


class DocumentEvidence(BaseModel):
    """문서 증적"""
    evidence_id: str = Field(default_factory=lambda: f"DOC-{uuid.uuid4().hex[:8].upper()}")
    control_id: str = Field(description="관련 통제 ID")
    document_type: DocumentType = Field(description="문서 유형")
    title: str = Field(description="문서 제목")
    description: str = Field(default="", description="문서 설명")
    file_path: Optional[str] = Field(default=None, description="파일 경로")
    file_name: str = Field(description="파일명")
    file_size: int = Field(default=0, description="파일 크기 (bytes)")
    file_hash: Optional[str] = Field(default=None, description="파일 해시")
    version: str = Field(default="1.0", description="문서 버전")
    status: EvidenceStatus = Field(default=EvidenceStatus.DRAFT)
    uploaded_by: str = Field(description="업로드자")
    uploaded_at: datetime = Field(default_factory=datetime.now)
    reviewed_by: Optional[str] = Field(default=None, description="검토자")
    reviewed_at: Optional[datetime] = Field(default=None)
    approved_by: Optional[str] = Field(default=None, description="승인자")
    approved_at: Optional[datetime] = Field(default=None)
    effective_date: Optional[datetime] = Field(default=None, description="시행일")
    expiry_date: Optional[datetime] = Field(default=None, description="만료일")
    tags: List[str] = Field(default_factory=list, description="태그")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="추가 메타데이터")


class SystemEvidence(BaseModel):
    """시스템 증적 (자동 수집)"""
    evidence_id: str = Field(default_factory=lambda: f"SYS-{uuid.uuid4().hex[:8].upper()}")
    control_id: str = Field(description="관련 통제 ID")
    source_type: str = Field(description="소스 유형 (CSPM, IAM, SIEM, VULNERABILITY 등)")
    source_system: str = Field(description="소스 시스템명")
    resource_id: str = Field(description="리소스 ID")
    resource_type: str = Field(description="리소스 유형")
    collected_at: datetime = Field(default_factory=datetime.now)
    data: Dict[str, Any] = Field(description="증적 데이터")
    status: EvidenceStatus = Field(default=EvidenceStatus.SUBMITTED)
    hash: Optional[str] = Field(default=None, description="데이터 해시")
    tags: List[str] = Field(default_factory=list, description="태그")


class EvidenceRepository:
    """통합 증적 저장소"""

    def __init__(self, storage_path: str = "evidence_storage"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # 문서 증적 저장 경로
        self.document_path = self.storage_path / "documents"
        self.document_path.mkdir(exist_ok=True)
        
        # 시스템 증적 저장 경로
        self.system_path = self.storage_path / "system"
        self.system_path.mkdir(exist_ok=True)
        
        # 인메모리 저장소 (실제 운영에서는 DB 사용)
        self._documents: Dict[str, DocumentEvidence] = {}
        self._system_evidence: Dict[str, SystemEvidence] = {}
        self._evidence_index: Dict[str, List[str]] = {}  # control_id -> evidence_ids

    def upload_document(self, file: BinaryIO, file_name: str, control_id: str,
                       document_type: DocumentType, title: str, description: str,
                       uploaded_by: str, metadata: Optional[Dict] = None) -> DocumentEvidence:
        """문서 증적 업로드"""
        
        # 파일 저장
        file_id = str(uuid.uuid4())
        file_ext = Path(file_name).suffix
        saved_file_name = f"{file_id}{file_ext}"
        file_path = self.document_path / saved_file_name
        
        with open(file_path, "wb") as f:
            f.write(file.read())
        
        # 파일 크기 계산
        file_size = os.path.getsize(file_path)
        
        # 문서 증적 생성
        doc_evidence = DocumentEvidence(
            control_id=control_id,
            document_type=document_type,
            title=title,
            description=description,
            file_path=str(file_path),
            file_name=file_name,
            file_size=file_size,
            uploaded_by=uploaded_by,
            metadata=metadata or {}
        )
        
        self._documents[doc_evidence.evidence_id] = doc_evidence
        self._add_to_index(control_id, doc_evidence.evidence_id)
        
        return doc_evidence

    def add_system_evidence(self, control_id: str, source_type: str, source_system: str,
                           resource_id: str, resource_type: str, data: Dict[str, Any],
                           tags: Optional[List[str]] = None) -> SystemEvidence:
        """시스템 증적 추가"""
        
        sys_evidence = SystemEvidence(
            control_id=control_id,
            source_type=source_type,
            source_system=source_system,
            resource_id=resource_id,
            resource_type=resource_type,
            data=data,
            tags=tags or []
        )
        
        self._system_evidence[sys_evidence.evidence_id] = sys_evidence
        self._add_to_index(control_id, sys_evidence.evidence_id)
        
        return sys_evidence

    def _add_to_index(self, control_id: str, evidence_id: str):
        """증적 인덱스 추가"""
        if control_id not in self._evidence_index:
            self._evidence_index[control_id] = []
        self._evidence_index[control_id].append(evidence_id)

    def get_evidence_by_control(self, control_id: str) -> Dict[str, List[Any]]:
        """통제별 증적 조회"""
        evidence_ids = self._evidence_index.get(control_id, [])
        
        documents = [self._documents[eid] for eid in evidence_ids if eid in self._documents]
        system_evidence = [self._system_evidence[eid] for eid in evidence_ids if eid in self._system_evidence]
        
        return {
            "control_id": control_id,
            "documents": documents,
            "system_evidence": system_evidence,
            "total_count": len(documents) + len(system_evidence)
        }

    def get_document(self, evidence_id: str) -> Optional[DocumentEvidence]:
        """문서 증적 조회"""
        return self._documents.get(evidence_id)

    def get_system_evidence(self, evidence_id: str) -> Optional[SystemEvidence]:
        """시스템 증적 조회"""
        return self._system_evidence.get(evidence_id)

    def update_document_status(self, evidence_id: str, status: EvidenceStatus,
                             reviewed_by: Optional[str] = None, approved_by: Optional[str] = None) -> bool:
        """문서 증적 상태 업데이트"""
        doc = self.get_document(evidence_id)
        if not doc:
            return False
        
        doc.status = status
        if reviewed_by:
            doc.reviewed_by = reviewed_by
            doc.reviewed_at = datetime.now()
        if approved_by:
            doc.approved_by = approved_by
            doc.approved_at = datetime.now()
        
        return True

    def list_documents(self, control_id: Optional[str] = None, 
                      document_type: Optional[DocumentType] = None,
                      status: Optional[EvidenceStatus] = None) -> List[DocumentEvidence]:
        """문서 증적 목록 조회"""
        documents = list(self._documents.values())
        
        if control_id:
            documents = [d for d in documents if d.control_id == control_id]
        if document_type:
            documents = [d for d in documents if d.document_type == document_type]
        if status:
            documents = [d for d in documents if d.status == status]
        
        return documents

    def list_system_evidence(self, control_id: Optional[str] = None,
                           source_type: Optional[str] = None) -> List[SystemEvidence]:
        """시스템 증적 목록 조회"""
        evidence = list(self._system_evidence.values())
        
        if control_id:
            evidence = [e for e in evidence if e.control_id == control_id]
        if source_type:
            evidence = [e for e in evidence if e.source_type == source_type]
        
        return evidence

    def get_evidence_summary(self) -> Dict[str, Any]:
        """증적 현황 요약"""
        total_documents = len(self._documents)
        total_system = len(self._system_evidence)
        
        doc_by_type = {}
        for doc in self._documents.values():
            doc_type = doc.document_type.value
            doc_by_type[doc_type] = doc_by_type.get(doc_type, 0) + 1
        
        sys_by_type = {}
        for sys_ev in self._system_evidence.values():
            sys_type = sys_ev.source_type
            sys_by_type[sys_type] = sys_by_type.get(sys_type, 0) + 1
        
        doc_by_status = {}
        for doc in self._documents.values():
            status = doc.status.value
            doc_by_status[status] = doc_by_status.get(status, 0) + 1
        
        return {
            "total_evidence": total_documents + total_system,
            "documents": {
                "total": total_documents,
                "by_type": doc_by_type,
                "by_status": doc_by_status
            },
            "system_evidence": {
                "total": total_system,
                "by_type": sys_by_type
            },
            "controls_with_evidence": len(self._evidence_index)
        }

    def delete_document(self, evidence_id: str) -> bool:
        """문서 증적 삭제"""
        doc = self.get_document(evidence_id)
        if not doc:
            return False
        
        # 파일 삭제
        if doc.file_path and os.path.exists(doc.file_path):
            os.remove(doc.file_path)
        
        # 인덱스에서 제거
        if doc.control_id in self._evidence_index:
            self._evidence_index[doc.control_id].remove(evidence_id)
        
        # 저장소에서 제거
        del self._documents[evidence_id]
        return True


# 전역 인스턴스
evidence_repository = EvidenceRepository()
