"""Continuous GRC 알림(Alert) 생성, 관리 및 라우팅 모듈입니다."""

from datetime import datetime, timezone
import hashlib
from typing import Dict, List, Optional
from secgrc.continuous.models import ContinuousAlert


class AlertManager:
    """위험 증가 및 보안 위반 이벤트에 대한 알림을 관리하는 매니저입니다."""

    def __init__(self):
        self._alerts: Dict[str, ContinuousAlert] = {}

    def create_alert(
        self,
        control_id: str,
        change_event_id: str,
        risk_before: float,
        risk_after: float,
        message: str,
        priority: str = "P2",
        action_required: str = "Human review required",
    ) -> ContinuousAlert:
        """새로운 ContinuousAlert 객체를 생성하고 저장합니다."""
        raw = f"{control_id}:{change_event_id}:{risk_after}:{datetime.now(timezone.utc).isoformat()}"
        alert_id = f"ALT-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:10]}"

        delta = round(risk_after - risk_before, 2)

        alert = ContinuousAlert(
            alert_id=alert_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            control_id=control_id,
            change_event_id=change_event_id,
            risk_before=round(risk_before, 2),
            risk_after=round(risk_after, 2),
            risk_delta=delta,
            priority=priority,
            message=message,
            action_required=action_required,
            status="OPEN",
        )
        self._alerts[alert_id] = alert
        return alert

    def list_alerts(self, status: Optional[str] = None) -> List[ContinuousAlert]:
        """알림 목록을 최신순으로 조회합니다."""
        all_alerts = list(self._alerts.values())
        if status:
            s_up = status.upper()
            all_alerts = [a for a in all_alerts if a.status.upper() == s_up]
        return sorted(all_alerts, key=lambda a: a.timestamp, reverse=True)

    def get_alert(self, alert_id: str) -> Optional[ContinuousAlert]:
        """특정 알림 단건을 조회합니다."""
        return self._alerts.get(alert_id)

    def resolve_alert(self, alert_id: str) -> bool:
        """알림을 해결 완료(RESOLVED) 상태로 변경합니다."""
        if alert_id in self._alerts:
            self._alerts[alert_id].status = "RESOLVED"
            return True
        return False
