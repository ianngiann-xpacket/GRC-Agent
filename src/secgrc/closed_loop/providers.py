"""Closed-loop 시정조치 프로바이더 추상 인터페이스 및 Mock 프로바이더 모듈입니다."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set

from secgrc.closed_loop.models import RemediationActionModel, RemediationResult
from secgrc.models.evidence import NormalizedEvidence


def generate_action_id(scan_id: str, risk_id: str, action_type: str, target: str) -> str:
    """멱등성(Idempotency) 보장을 위한 결정론적 액션 ID 해시를 생성합니다."""
    raw = f"{scan_id}:{risk_id}:{action_type}:{target}"
    return f"ACT-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"


class RemediationProvider(ABC):
    """시정조치 프로바이더 추상 기반 클래스 (Remediation Provider Interface)"""

    @abstractmethod
    def plan(self, finding: Any, scan_id: str = "SCAN-DEFAULT", risk_id: str = "RSK-DEFAULT") -> RemediationActionModel:
        """취약점 발견 항목에 대한 표준 시정조치 계획을 수립합니다."""
        pass

    @abstractmethod
    def validate(self, action: RemediationActionModel) -> bool:
        """조치 대상 및 파라미터의 정합성을 사전에 검증합니다."""
        pass

    @abstractmethod
    def execute(self, action: RemediationActionModel, mode: str = "DRY_RUN") -> RemediationResult:
        """시정조치를 수행합니다 (DRY_RUN 또는 SIMULATED)."""
        pass

    @abstractmethod
    def rollback(self, action: RemediationActionModel) -> bool:
        """장애 또는 실패 시 이전 상태로 롤백합니다."""
        pass


class MockRemediationProvider(RemediationProvider):
    """실제 클라우드 리소스 변경 없이 가상 인프라 상태(Synthetic State)를 교정하는 Mock 프로바이더입니다.
    
    1. Production 변경 절대 금지: 오직 인메모리 Synthetic State만 제어합니다.
    2. 멱등성 보장: 동일한 Action ID는 1회만 적용되며 중복 실행 시 ALREADY_REMEDIATED를 반환합니다.
    3. 실행 모드: DRY_RUN(기본) 및 SIMULATED 지원.
    """

    def __init__(self):
        # 대상 리소스별 Synthetic 속성 상태
        self.synthetic_state: Dict[str, Dict[str, Any]] = {
            "firewall-rule-001": {"public_access": True, "source_ranges": ["0.0.0.0/0"]},
            "sample-storage-bucket": {"uniform_bucket_level_access": False, "public_access": True},
            "sample-kms-key": {"rotation_period_days": 365, "auto_rotate": False},
            "sample-iam-binding": {"role": "roles/owner", "allUsers": True},
            "sample-sql-instance": {"require_ssl": False, "public_ip": True},
        }
        # 이미 완료된 action_id 추적
        self.remediated_actions: Set[str] = set()
        # 롤백을 위한 스냅샷 저장소
        self.snapshots: Dict[str, Dict[str, Any]] = {}

    def plan(self, finding: Any, scan_id: str = "SCAN-DEFAULT", risk_id: str = "RSK-DEFAULT") -> RemediationActionModel:
        """발견된 Finding의 유형에 부합하는 Remediation Action 모델을 수립합니다."""
        target = "unknown-resource"
        check_id = ""
        control_id = "ISMS-P-UNKNOWN"

        if isinstance(finding, dict):
            target = finding.get("resource_name") or finding.get("resource_uid") or str(finding.get("resource_id", "unknown-resource"))
            check_id = str(finding.get("check_id") or finding.get("finding_id") or "")
            control_id = str(finding.get("control_id", "ISMS-P-UNKNOWN"))
        elif hasattr(finding, "target"):
            target = finding.target
            control_id = getattr(finding, "control_id", "ISMS-P-UNKNOWN")

        # 조치 유형 결정 매핑
        action_type = "REMEDIATE_GENERIC"
        reason = "Resolve security compliance non-compliance"
        expected = "Resource configured to compliant state"
        impact = "Low (Virtual simulated configuration change)"
        rollback = "Revert synthetic property to previous value"

        c_lower = check_id.lower()
        if "firewall" in c_lower or "ingress" in c_lower or "public" in target:
            action_type = "RESTRICT_PUBLIC_ACCESS"
            reason = "Disable 0.0.0.0/0 ingress and restrict public access"
            expected = "Public access disabled, firewall restricted"
        elif "storage" in c_lower or "bucket" in c_lower:
            action_type = "ENABLE_UNIFORM_BUCKET_ACCESS"
            reason = "Enforce uniform bucket-level access and remove public grants"
            expected = "Uniform bucket-level access enabled"
        elif "kms" in c_lower or "key" in c_lower or "rotation" in c_lower:
            action_type = "ENABLE_KEY_ROTATION"
            reason = "Configure automated 90-day KMS key rotation"
            expected = "KMS key rotation enabled at 90 days"
        elif "iam" in c_lower or "serviceaccount" in c_lower:
            action_type = "REVOKE_OVERPRIVILEGED_ROLE"
            reason = "Revoke overprivileged IAM role and remove allUsers"
            expected = "Least-privilege role assigned"
        elif "sql" in c_lower or "database" in c_lower:
            action_type = "ENFORCE_DATABASE_SSL"
            reason = "Enforce SSL/TLS encryption for database connections"
            expected = "require_ssl set to true"

        act_id = generate_action_id(scan_id, risk_id, action_type, target)

        return RemediationActionModel(
            action_id=act_id,
            risk_id=risk_id,
            control_id=control_id,
            action_type=action_type,
            target=target,
            reason=reason,
            expected_result=expected,
            impact=impact,
            rollback_plan=rollback,
            required_approval=True,
            status="PLANNED",
        )

    def validate(self, action: RemediationActionModel) -> bool:
        """조치 파라미터가 유효한지 검증합니다."""
        if not action.action_id or not action.target or not action.action_type:
            return False
        return True

    def execute(self, action: RemediationActionModel, mode: str = "DRY_RUN") -> RemediationResult:
        """시정조치를 안전하게 실행합니다."""
        if not self.validate(action):
            return RemediationResult(
                action_id=action.action_id,
                status="FAILED",
                execution_mode=mode,
                details="Action validation failed: missing required parameters",
            )

        # 멱등성 검증: 이미 성공한 조치인지 확인
        if action.action_id in self.remediated_actions:
            return RemediationResult(
                action_id=action.action_id,
                status="ALREADY_REMEDIATED",
                execution_mode=mode,
                details=f"Action {action.action_id} was already executed previously. Skipped for idempotency.",
                changes={},
            )

        # DRY_RUN 모드
        if mode == "DRY_RUN":
            return RemediationResult(
                action_id=action.action_id,
                status="SUCCESS",
                execution_mode="DRY_RUN",
                details=f"DRY-RUN: Simulated execution plan verified for target '{action.target}' ({action.action_type}). No mutations made.",
                changes={"target": action.target, "mode": "DRY_RUN"},
            )

        # SIMULATED 모드 (가상 인프라 상태 변경)
        target = action.target
        prev_state = dict(self.synthetic_state.get(target, {}))
        self.snapshots[action.action_id] = prev_state

        # Synthetic 상태 갱신
        if action.action_type == "RESTRICT_PUBLIC_ACCESS":
            self.synthetic_state[target] = {"public_access": False, "source_ranges": ["10.0.0.0/16"]}
        elif action.action_type == "ENABLE_UNIFORM_BUCKET_ACCESS":
            self.synthetic_state[target] = {"uniform_bucket_level_access": True, "public_access": False}
        elif action.action_type == "ENABLE_KEY_ROTATION":
            self.synthetic_state[target] = {"rotation_period_days": 90, "auto_rotate": True}
        elif action.action_type == "REVOKE_OVERPRIVILEGED_ROLE":
            self.synthetic_state[target] = {"role": "roles/viewer", "allUsers": False}
        elif action.action_type == "ENFORCE_DATABASE_SSL":
            self.synthetic_state[target] = {"require_ssl": True, "public_ip": False}
        else:
            self.synthetic_state[target] = {"compliant": True, "public_access": False}

        self.remediated_actions.add(action.action_id)
        action.status = "EXECUTED"
        action.executed_at = datetime.now(timezone.utc).isoformat()

        return RemediationResult(
            action_id=action.action_id,
            status="SUCCESS",
            execution_mode="SIMULATED",
            details=f"SIMULATED: Successfully applied synthetic remediation '{action.action_type}' to '{action.target}'.",
            changes={"target": target, "before": prev_state, "after": self.synthetic_state[target]},
        )

    def rollback(self, action: RemediationActionModel) -> bool:
        """장애 조치 시 직전 상태로 롤백합니다."""
        if action.action_id not in self.snapshots:
            return False
        prev = self.snapshots[action.action_id]
        self.synthetic_state[action.target] = prev
        if action.action_id in self.remediated_actions:
            self.remediated_actions.remove(action.action_id)
        action.status = "ROLLED_BACK"
        return True
