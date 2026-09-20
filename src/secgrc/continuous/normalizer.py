"""이종 클라우드/플랫폼 변경 이벤트를 공통 스키마로 변환하고 살균하는 EventNormalizer 모듈입니다."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from secgrc.agent_security.input_guard import InputGuard
from secgrc.continuous.models import (
    ChangeClassification,
    ChangeType,
    NormalizedChangeEvent,
)


class EventNormalizer:
    """GCP Audit Logs, Cloud Logging, GitHub, IAM 등 이종 소스의 원본 이벤트를 NormalizedChangeEvent로 변환합니다."""

    @staticmethod
    def _parse_change_type(raw_type: str) -> ChangeType:
        """문자열로부터 ChangeType Enum을 안전하게 파싱합니다."""
        t = str(raw_type).upper()
        if "CREATE" in t or "ADD" in t or "INSERT" in t:
            return ChangeType.CREATE
        elif "DELETE" in t or "REMOVE" in t or "DESTROY" in t:
            return ChangeType.DELETE
        elif "POLICY" in t:
            return ChangeType.POLICY_CHANGE
        elif "PERMISSION" in t or "ROLE" in t or "GRANT" in t:
            return ChangeType.PERMISSION_CHANGE
        elif "CONFIG" in t:
            return ChangeType.CONFIG_CHANGE
        return ChangeType.UPDATE

    @classmethod
    def normalize(cls, raw: Dict[str, Any]) -> NormalizedChangeEvent:
        """단일 원본 이벤트 딕셔너리를 NormalizedChangeEvent 객체로 정규화합니다.
        
        보안 가드레일:
        - actor 및 metadata 텍스트 필드에 프롬프트 인젝션이 포함되어 있는지 InputGuard로 검사합니다.
        - 인젝션 탐지 시 악의적 지시어가 에이전트 실행에 영향을 주지 않도록 순수 DATA로 격리 및 중화합니다.
        """
        e_id = raw.get("event_id") or raw.get("id") or raw.get("insertId") or f"EVT-{hash(str(raw))}"
        ts = raw.get("timestamp") or raw.get("time") or datetime.now(timezone.utc).isoformat()
        src = str(raw.get("source") or "gcp").lower()
        e_type = str(raw.get("event_type") or raw.get("methodName") or "CONFIG_CHANGED").upper()
        r_type = str(raw.get("resource_type") or raw.get("resourceType") or "generic_resource").lower()
        r_id = str(raw.get("resource_id") or raw.get("resourceName") or raw.get("target") or "unknown-resource")
        c_type = cls._parse_change_type(raw.get("change_type") or raw.get("operation") or "UPDATE")
        actor = str(raw.get("actor") or raw.get("principalEmail") or "system")
        env = str(raw.get("environment") or "production")
        meta = dict(raw.get("metadata") or {})

        # 1. Prompt Injection 검사 및 살균 (Input Guard 결합)
        scan_actor = InputGuard.detect_injection(actor)
        if scan_actor.detected:
            cat_name = scan_actor.category.value if scan_actor.category else "INJECTION"
            actor = f"[UNTRUSTED_INJECTION_DETECTED: {cat_name}] {actor}"
            meta["_security_warning"] = f"Prompt injection attempt in actor field: {cat_name}"

        # metadata 내부 텍스트 검사
        for k, v in list(meta.items()):
            if isinstance(v, str):
                scan_v = InputGuard.detect_injection(v)
                if scan_v.detected:
                    cat_name = scan_v.category.value if scan_v.category else "INJECTION"
                    meta[k] = f"[DATA_ONLY_NEUTRALIZED: {cat_name}] {v}"

        # 2. 정규화 객체 생성 (분류는 ChangeDetector에서 수행)
        return NormalizedChangeEvent(
            event_id=e_id,
            timestamp=ts,
            source=src,
            event_type=e_type,
            resource_type=r_type,
            resource_id=r_id,
            change_type=c_type,
            actor=actor,
            environment=env,
            metadata=meta,
            classification=ChangeClassification.UNKNOWN,
        )
