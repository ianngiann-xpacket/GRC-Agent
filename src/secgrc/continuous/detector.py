"""Deterministic Change Detector for Canonical Enterprise Security Data (Step 25).

Compares already-normalized Canonical Data (Step 23.5A) to detect creations,
deletions, field updates, status changes, and generates deterministic ChangeEvents.
"""

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from secgrc.continuous.models import (
    ChangeClassification,
    ChangeEvent,
    ChangeType,
    FieldChange,
    NormalizedChangeEvent,
)


def compute_change_hash(change_event: ChangeEvent) -> str:
    """타임스탬프 등 런타임 가변 필드를 제외한 순수 논리적 변경 SHA-256 해시를 계산합니다 (Section 9).
    
    동일한 논리적 변경은 시각과 관계없이 동일한 해시를 산출합니다.
    """
    raw = change_event.model_dump()
    # 런타임 전용 필드 및 자기 자신 해시 제외
    for volatile in ("detected_at", "integrity_hash"):
        raw.pop(volatile, None)

    # changed_fields 정렬 보장
    if "changed_fields" in raw and isinstance(raw["changed_fields"], list):
        raw["changed_fields"] = sorted(
            raw["changed_fields"],
            key=lambda fc: (fc.get("field_name", ""), str(fc.get("new_value", ""))),
        )

    canonical_json = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _extract_record_dict(record: Any) -> Dict[str, Any]:
    """CanonicalSecurityData 또는 딕셔너리에서 정규화된 딕셔너리를 추출합니다."""
    if record is None:
        return {}
    if hasattr(record, "model_dump"):
        return record.model_dump()
    if isinstance(record, dict):
        return dict(record)
    # Generic object
    return getattr(record, "__dict__", {})


def _compute_state_hash(record_dict: Dict[str, Any]) -> str:
    """레코드 상태 해시를 계산합니다."""
    if not record_dict:
        return ""
    # Strip volatile fields if present
    clean = {k: v for k, v in record_dict.items() if k not in ("observed_at", "detected_at", "created_at")}
    canonical_json = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class ChangeDetector:
    """정규 데이터 변경 감지기 및 이전 하위호환 분류기."""

    # --- Step 25 Public APIs ---

    @classmethod
    def detect(
        cls,
        previous_record: Optional[Any],
        current_record: Optional[Any],
        change_id: Optional[str] = None,
        tenant_id: str = "default",
        source_system: Optional[str] = None,
        occurred_at: Optional[str] = None,
        observed_at: Optional[str] = None,
    ) -> Optional[ChangeEvent]:
        """두 정규 레코드(이전 vs 현재)를 비교하여 변경이 발생한 경우 결정론적 ChangeEvent를 생성합니다.
        
        변경이 없으면 None을 반환합니다.
        """
        if previous_record is None and current_record is None:
            return None

        prev_dict = _extract_record_dict(previous_record)
        curr_dict = _extract_record_dict(current_record)

        prev_hash = _compute_state_hash(prev_dict)
        curr_hash = _compute_state_hash(curr_dict)

        # 내용 변동이 없으면 None
        if prev_dict and curr_dict and prev_hash == curr_hash:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        occ_time = occurred_at or curr_dict.get("occurred_at") or prev_dict.get("occurred_at") or now_iso
        obs_time = observed_at or curr_dict.get("observed_at") or prev_dict.get("observed_at") or now_iso

        # 메타데이터 추출
        ref_dict = curr_dict if curr_dict else prev_dict
        source_sys = source_system or ref_dict.get("source_system") or ref_dict.get("source") or "unknown"
        source_rec_id = str(ref_dict.get("data_id") or ref_dict.get("record_id") or ref_dict.get("id") or "rec-001")
        raw_et = ref_dict.get("entity_type") or ref_dict.get("data_type") or "UnknownEntity"
        if hasattr(raw_et, "value"):
            raw_et = raw_et.value
        elif "." in str(raw_et):
            raw_et = str(raw_et).split(".")[-1]
        entity_type = str(raw_et)
        entity_id = str(ref_dict.get("entity_id") or ref_dict.get("resource_id") or source_rec_id)
        scope = str(ref_dict.get("scope") or ref_dict.get("environment") or "GLOBAL")
        t_id = str(ref_dict.get("tenant_id") or tenant_id)

        # 변경 유형 판정
        field_changes: List[FieldChange] = []

        if not prev_dict and curr_dict:
            # 생성 (CREATE)
            chg_type = ChangeType.CREATE
            for k, v in curr_dict.items():
                if k in ("observed_at", "detected_at", "occurred_at"):
                    continue
                if k == "payload" and isinstance(v, dict):
                    for sub_k, sub_v in v.items():
                        field_changes.append(FieldChange(field_name=sub_k, old_value=None, new_value=sub_v, change_type=ChangeType.CREATE))
                else:
                    field_changes.append(FieldChange(field_name=k, old_value=None, new_value=v, change_type=ChangeType.CREATE))
        elif prev_dict and not curr_dict:
            # 삭제 (DELETE)
            chg_type = ChangeType.DELETE
            for k, v in prev_dict.items():
                if k in ("observed_at", "detected_at", "occurred_at"):
                    continue
                if k == "payload" and isinstance(v, dict):
                    for sub_k, sub_v in v.items():
                        field_changes.append(FieldChange(field_name=sub_k, old_value=sub_v, new_value=None, change_type=ChangeType.DELETE))
                else:
                    field_changes.append(FieldChange(field_name=k, old_value=v, new_value=None, change_type=ChangeType.DELETE))
        else:
            # 수정 (UPDATE / SPECIFIC CHANGE)
            all_keys = sorted(list(set(prev_dict.keys()) | set(curr_dict.keys())))
            for k in all_keys:
                if k in ("observed_at", "detected_at", "occurred_at"):
                    continue
                old_v = prev_dict.get(k)
                new_v = curr_dict.get(k)
                if old_v != new_v:
                    if k == "payload" and isinstance(old_v, dict) and isinstance(new_v, dict):
                        sub_keys = sorted(list(set(old_v.keys()) | set(new_v.keys())))
                        for sub_k in sub_keys:
                            sub_old = old_v.get(sub_k)
                            sub_new = new_v.get(sub_k)
                            if sub_old != sub_new:
                                field_changes.append(
                                    FieldChange(
                                        field_name=sub_k,
                                        old_value=sub_old,
                                        new_value=sub_new,
                                        change_type=ChangeType.UPDATE,
                                    )
                                )
                    else:
                        field_changes.append(
                            FieldChange(
                                field_name=k,
                                old_value=old_v,
                                new_value=new_v,
                                change_type=ChangeType.UPDATE,
                            )
                        )

            # 특화 변경 유형 판정
            changed_names = {fc.field_name.lower() for fc in field_changes}
            entity_type_lower = entity_type.lower()

            if "status" in changed_names:
                chg_type = ChangeType.STATUS_CHANGE
            elif any("policy" in name for name in changed_names) or "policy" in entity_type_lower:
                chg_type = ChangeType.POLICY_CHANGE
            elif any(p in changed_names for p in ("action", "permission", "permissions", "role", "effect")):
                chg_type = ChangeType.PERMISSION_CHANGE
            elif any("config" in name for name in changed_names):
                chg_type = ChangeType.CONFIGURATION_CHANGE
            elif "vulnerability" in entity_type_lower or any("vuln" in name for name in changed_names):
                chg_type = ChangeType.VULNERABILITY_CHANGE
            elif "evidence" in entity_type_lower or any("evidence" in name for name in changed_names):
                chg_type = ChangeType.EVIDENCE_CHANGE
            elif "document" in entity_type_lower:
                chg_type = ChangeType.DOCUMENT_CHANGE
            elif "processing" in entity_type_lower or "activity" in entity_type_lower:
                chg_type = ChangeType.PROCESSING_CHANGE
            elif "asset" in entity_type_lower:
                chg_type = ChangeType.ASSET_CHANGE
            elif "identity" in entity_type_lower or "user" in entity_type_lower or "principal" in changed_names:
                chg_type = ChangeType.IDENTITY_CHANGE
            else:
                chg_type = ChangeType.UPDATE

        c_id = change_id or f"CHG-{entity_type}-{entity_id}-{curr_hash[:8] or prev_hash[:8]}"
        # Ensure clean identifier
        c_id = re.sub(r'[^A-Za-z0-9_-]', '-', c_id)

        event = ChangeEvent(
            change_id=c_id,
            tenant_id=t_id,
            source_system=source_sys,
            source_record_id=source_rec_id,
            entity_type=entity_type,
            entity_id=entity_id,
            change_type=chg_type,
            occurred_at=occ_time,
            observed_at=obs_time,
            detected_at=now_iso,
            previous_hash=prev_hash,
            new_hash=curr_hash,
            scope=scope,
            changed_fields=field_changes,
            provenance={
                "detector": "ChangeDetector.detect",
                "engine_version": "1.0",
                "field_count": len(field_changes),
            },
            integrity_hash="",
        )

        # Compute deterministic logical hash
        l_hash = compute_change_hash(event)
        return event.model_copy(update={"integrity_hash": l_hash})

    @classmethod
    def detect_batch(
        cls,
        previous_records: List[Any],
        current_records: List[Any],
        tenant_id: str = "default",
    ) -> List[ChangeEvent]:
        """레코드 목록 간의 차이를 배치 비교하여 ChangeEvent 목록을 결정론적으로 생성합니다."""
        # Map by unique identifier (entity_id or data_id)
        prev_map = {}
        for r in previous_records:
            d = _extract_record_dict(r)
            uid = str(d.get("entity_id") or d.get("data_id") or d.get("id"))
            prev_map[uid] = r

        curr_map = {}
        for r in current_records:
            d = _extract_record_dict(r)
            uid = str(d.get("entity_id") or d.get("data_id") or d.get("id"))
            curr_map[uid] = r

        all_keys = sorted(list(set(prev_map.keys()) | set(curr_map.keys())))
        changes: List[ChangeEvent] = []

        for uid in all_keys:
            prev_r = prev_map.get(uid)
            curr_r = curr_map.get(uid)
            ev = cls.detect(prev_r, curr_r, tenant_id=tenant_id)
            if ev:
                changes.append(ev)

        return changes

    # --- Backward Compatibility APIs (Step 6) ---

    @staticmethod
    def _matches_any(text: str, patterns: list) -> bool:
        for p in patterns:
            cleaned_p = re.escape(p.replace("_", " "))
            if re.search(rf"\b{cleaned_p}\b", text):
                return True
        return False

    @classmethod
    def classify(cls, event: NormalizedChangeEvent) -> ChangeClassification:
        """기존 하위 호환성 분류 메서드."""
        from secgrc.continuous.models import ChangeClassification
        raw_combined = f"{event.event_type} {event.resource_type} {event.resource_id} {str(event.metadata)}".upper()
        normalized_text = re.sub(r'[^A-Z0-9]+', ' ', raw_combined)

        non_sec = ["DISPLAY_NAME", "LABEL_UPDATED", "TAG_UPDATED", "DESCRIPTION_CHANGED", "COLOR", "ALIAS", "COMMENT"]
        sec_pats = ["FIREWALL", "INGRESS", "EGRESS", "PORT", "PUBLIC_ACCESS", "IAM", "ROLE", "PERMISSION", "KMS", "KEY", "SECRET"]
        comp_pats = ["LOGGING", "AUDIT_LOG", "RETENTION", "BACKUP", "DISASTER_RECOVERY", "ACCESS_LOG"]

        if cls._matches_any(normalized_text, non_sec) and not cls._matches_any(normalized_text, sec_pats + comp_pats):
            event.classification = ChangeClassification.NON_SECURITY
            return ChangeClassification.NON_SECURITY

        if cls._matches_any(normalized_text, sec_pats):
            event.classification = ChangeClassification.SECURITY_RELEVANT
            return ChangeClassification.SECURITY_RELEVANT

        if cls._matches_any(normalized_text, comp_pats):
            event.classification = ChangeClassification.COMPLIANCE_RELEVANT
            return ChangeClassification.COMPLIANCE_RELEVANT

        event.classification = ChangeClassification.UNKNOWN
        return ChangeClassification.UNKNOWN
