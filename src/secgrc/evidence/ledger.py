"""증적 원장 - 불변 레코드 + 해시체인 + WORM 스토리지"""

from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import hashlib
import json
import uuid


class EvidenceRecordType(str, Enum):
    """증적 레코드 유형"""
    EVIDENCE = "EVIDENCE"           # 증적
    CORRECTION = "CORRECTION"       # 정정
    ANNOTATION = "ANNOTATION"       # 주석
    REVIEW = "REVIEW"               # 검토


class EvidenceRecord(BaseModel):
    """증적 레코드 (불변)"""
    record_id: str = Field(default_factory=lambda: f"REC-{uuid.uuid4().hex[:8].upper()}")
    evidence_id: str = Field(description="증적 ID")
    record_type: EvidenceRecordType = Field(description="레코드 유형")
    control_id: str = Field(description="통제 ID")
    content: Dict[str, Any] = Field(description="레코드 내용")
    created_at: datetime = Field(default_factory=datetime.now)
    created_by: str = Field(description="생성자")
    approved_by: Optional[str] = Field(default=None, description="승인자")
    source_system: Optional[str] = Field(default=None, description="출처 시스템")
    collection_method: str = Field(default="MANUAL", description="수집 방식")
    hash: str = Field(description="레코드 해시")
    previous_hash: Optional[str] = Field(default=None, description="이전 레코드 해시")
    retention_period: Optional[int] = Field(default=None, description="보존 기간 (일)")
    expiry_date: Optional[datetime] = Field(default=None, description="만료일")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="메타데이터")


class EvidenceLedger:
    """증적 원장 (Append-only, WORM)"""

    def __init__(self):
        self._records: List[EvidenceRecord] = []
        self._record_index: Dict[str, EvidenceRecord] = {}
        self._evidence_index: Dict[str, List[str]] = {}  # evidence_id -> record_ids
        self._control_index: Dict[str, List[str]] = {}   # control_id -> record_ids
        self._hash_chain: List[str] = []  # 해시 체인

    def _calculate_hash(self, content: Dict[str, Any], previous_hash: Optional[str] = None) -> str:
        """레코드 해시 계산"""
        # 해시 체인을 위한 결합
        hash_input = json.dumps(content, sort_keys=True, ensure_ascii=False)
        if previous_hash:
            hash_input += previous_hash
        
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

    def append_record(self, evidence_id: str, control_id: str, content: Dict[str, Any],
                     record_type: EvidenceRecordType = EvidenceRecordType.EVIDENCE,
                     created_by: str = "SYSTEM", source_system: Optional[str] = None,
                     collection_method: str = "MANUAL", 
                     retention_period: Optional[int] = None,
                     metadata: Optional[Dict] = None) -> EvidenceRecord:
        """증적 레코드 추가 (Append-only)"""
        
        # 이전 해시 가져오기 (해시 체인)
        previous_hash = self._hash_chain[-1] if self._hash_chain else None
        
        # 레코드 해시 계산
        record_hash = self._calculate_hash(content, previous_hash)
        
        # 만료일 계산
        expiry_date = None
        if retention_period:
            expiry_date = datetime.now() + timedelta(days=retention_period)
        
        # 레코드 생성
        record = EvidenceRecord(
            evidence_id=evidence_id,
            record_type=record_type,
            control_id=control_id,
            content=content,
            created_by=created_by,
            source_system=source_system,
            collection_method=collection_method,
            hash=record_hash,
            previous_hash=previous_hash,
            retention_period=retention_period,
            expiry_date=expiry_date,
            metadata=metadata or {}
        )
        
        # 저장
        self._records.append(record)
        self._record_index[record.record_id] = record
        
        # 인덱스 업데이트
        if evidence_id not in self._evidence_index:
            self._evidence_index[evidence_id] = []
        self._evidence_index[evidence_id].append(record.record_id)
        
        if control_id not in self._control_index:
            self._control_index[control_id] = []
        self._control_index[control_id].append(record.record_id)
        
        # 해시 체인 업데이트
        self._hash_chain.append(record_hash)
        
        return record

    def get_record(self, record_id: str) -> Optional[EvidenceRecord]:
        """레코드 조회"""
        return self._record_index.get(record_id)

    def get_evidence_records(self, evidence_id: str) -> List[EvidenceRecord]:
        """증적별 레코드 조회"""
        record_ids = self._evidence_index.get(evidence_id, [])
        return [self._record_index[rid] for rid in record_ids if rid in self._record_index]

    def get_control_records(self, control_id: str) -> List[EvidenceRecord]:
        """통제별 레코드 조회"""
        record_ids = self._control_index.get(control_id, [])
        return [self._record_index[rid] for rid in record_ids if rid in self._record_index]

    def verify_integrity(self, record_id: str) -> bool:
        """레코드 무결성 검증"""
        record = self.get_record(record_id)
        if not record:
            return False
        
        # 해시 재계산
        calculated_hash = self._calculate_hash(record.content, record.previous_hash)
        return calculated_hash == record.hash

    def verify_chain_integrity(self) -> bool:
        """해시 체인 무결성 검증"""
        for i, record in enumerate(self._records):
            if not self.verify_integrity(record.record_id):
                return False
            
            # 이전 해시 검증 (첫 번째 레코드 제외)
            if i > 0:
                expected_previous = self._records[i-1].hash
                if record.previous_hash != expected_previous:
                    return False
        
        return True

    def get_latest_record(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """최신 레코드 조회"""
        records = self.get_evidence_records(evidence_id)
        if not records:
            return None
        return max(records, key=lambda r: r.created_at)

    def get_records_by_type(self, record_type: EvidenceRecordType) -> List[EvidenceRecord]:
        """유형별 레코드 조회"""
        return [r for r in self._records if r.record_type == record_type]

    def get_expired_records(self) -> List[EvidenceRecord]:
        """만료된 레코드 조회"""
        now = datetime.now()
        return [r for r in self._records if r.expiry_date and r.expiry_date < now]

    def get_retention_report(self) -> Dict[str, Any]:
        """보존 기간 현황 보고서"""
        now = datetime.now()
        
        expired = len(self.get_expired_records())
        expiring_soon = len([
            r for r in self._records 
            if r.expiry_date and r.expiry_date > now and (r.expiry_date - now).days <= 30
        ])
        
        by_type = {}
        for record in self._records:
            rec_type = record.record_type.value
            by_type[rec_type] = by_type.get(rec_type, 0) + 1
        
        return {
            "total_records": len(self._records),
            "expired_records": expired,
            "expiring_soon": expiring_soon,
            "by_type": by_type,
            "chain_integrity": self.verify_chain_integrity(),
            "latest_hash": self._hash_chain[-1] if self._hash_chain else None
        }

    def get_evidence_timeline(self, evidence_id: str) -> List[Dict[str, Any]]:
        """증적 타임라인 조회"""
        records = self.get_evidence_records(evidence_id)
        records.sort(key=lambda r: r.created_at)
        
        timeline = []
        for record in records:
            timeline.append({
                "record_id": record.record_id,
                "type": record.record_type.value,
                "created_at": record.created_at,
                "created_by": record.created_by,
                "hash": record.hash[:16] + "...",
                "content_summary": str(record.content)[:100] + "..." if len(str(record.content)) > 100 else str(record.content)
            })
        
        return timeline

    def add_correction(self, evidence_id: str, control_id: str, 
                      original_record_id: str, correction_content: Dict[str, Any],
                      corrected_by: str, reason: str) -> Optional[EvidenceRecord]:
        """정정 레코드 추가"""
        
        # 원본 레코드 확인
        original = self.get_record(original_record_id)
        if not original:
            return None
        
        # 정정 내용에 원본 참조 추가
        correction_content["original_record_id"] = original_record_id
        correction_content["correction_reason"] = reason
        correction_content["original_hash"] = original.hash
        
        return self.append_record(
            evidence_id=evidence_id,
            control_id=control_id,
            content=correction_content,
            record_type=EvidenceRecordType.CORRECTION,
            created_by=corrected_by,
            collection_method="MANUAL"
        )

    def add_annotation(self, evidence_id: str, control_id: str,
                      annotation: str, annotated_by: str) -> EvidenceRecord:
        """주석 추가"""
        content = {
            "annotation": annotation,
            "annotated_by": annotated_by,
            "annotation_type": "REVIEW_COMMENT"
        }
        
        return self.append_record(
            evidence_id=evidence_id,
            control_id=control_id,
            content=content,
            record_type=EvidenceRecordType.ANNOTATION,
            created_by=annotated_by,
            collection_method="MANUAL"
        )

    def add_review(self, evidence_id: str, control_id: str,
                  reviewer: str, review_result: str, comments: str = "") -> EvidenceRecord:
        """검토 레코드 추가"""
        content = {
            "reviewer": reviewer,
            "review_result": review_result,
            "comments": comments,
            "review_timestamp": datetime.now().isoformat()
        }
        
        return self.append_record(
            evidence_id=evidence_id,
            control_id=control_id,
            content=content,
            record_type=EvidenceRecordType.REVIEW,
            created_by=reviewer,
            collection_method="MANUAL"
        )


# 전역 인스턴스
evidence_ledger = EvidenceLedger()
