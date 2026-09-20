"""보안 거버넌스 불변 감사 로그(Security Audit Logger) 모듈입니다."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from secgrc.agent_security.models import SecurityAuditEvent
from secgrc.agent_security.secret_guard import SecretGuard


class SecurityAuditLogger:
    """에이전트 보안 정책 검사, 주입 탐지, 도구 인가, 승인 이벤트를 시크릿 마스킹하여 불변 기록합니다."""

    def __init__(self):
        self._events: List[SecurityAuditEvent] = []

    def log_event(
        self,
        agent_id: str,
        event: str,
        agent_version: str = "1.0.0",
        tool: Optional[str] = None,
        decision: Optional[str] = None,
        risk_level: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityAuditEvent:
        """단일 보안 거버넌스 감사 이벤트를 기록합니다 (시크릿 자동 마스킹)."""
        safe_details = SecretGuard.redact(details or {})
        safe_reason = SecretGuard.redact(reason) if reason else None

        record = SecurityAuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            agent_version=agent_version,
            event=event,
            tool=tool,
            decision=decision,
            risk_level=risk_level,
            reason=safe_reason,
            details=safe_details,
        )
        self._events.append(record)
        return record

    def get_events(self, agent_id: Optional[str] = None, event_type: Optional[str] = None) -> List[SecurityAuditEvent]:
        """기록된 감사 이벤트를 필터링하여 조회합니다."""
        filtered = self._events
        if agent_id:
            filtered = [e for e in filtered if e.agent_id == agent_id]
        if event_type:
            filtered = [e for e in filtered if e.event == event_type]
        return list(filtered)

    def count_events(self) -> Dict[str, int]:
        """이벤트 유형별 통계 카운트를 반환합니다."""
        counts: Dict[str, int] = {}
        for e in self._events:
            counts[e.event] = counts.get(e.event, 0) + 1
        return counts


global_security_audit_logger = SecurityAuditLogger()
