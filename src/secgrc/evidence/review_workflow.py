"""증적 검토·승인 워크플로우 — 담당자 → 팀장 → CISO 3단계.

상태는 DB를 별도로 두지 않고 불변 원장(EvidenceLedger)의 REVIEW 레코드로
표현한다 — 전이 자체가 감사 추적이며, 과거 시점 조작이 구조적으로 불가하다.

흐름:
  증적 등록(수작업/자동수집) → TEAM_LEAD_REVIEW (팀장 검토 대기)
    팀장 승인 → CISO_REVIEW (CISO 승인 대기)
    CISO 승인 → APPROVED (확정 — 심사 제출 가능)
    팀장/CISO 반려 → REJECTED (담당자 보완 후 재제출 → TEAM_LEAD_REVIEW)

자동 수집 증적(CSPM 등)도 동일 체인을 따르며, 담당자 코멘트·조치 이력은
ANNOTATION 레코드로 누적된다.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from secgrc.evidence.ledger import EvidenceLedger, EvidenceRecordType


class ReviewRole(str, Enum):
    OWNER = "OWNER"            # 담당자
    TEAM_LEAD = "TEAM_LEAD"    # 팀장
    CISO = "CISO"              # CISO


ROLE_LABELS = {
    ReviewRole.OWNER: "담당자",
    ReviewRole.TEAM_LEAD: "팀장",
    ReviewRole.CISO: "CISO",
}


class WorkflowStage(str, Enum):
    TEAM_LEAD_REVIEW = "TEAM_LEAD_REVIEW"   # 팀장 검토 대기
    CISO_REVIEW = "CISO_REVIEW"             # CISO 승인 대기
    APPROVED = "APPROVED"                   # 확정
    REJECTED = "REJECTED"                   # 반려 — 담당자 보완 대기


STAGE_LABELS = {
    WorkflowStage.TEAM_LEAD_REVIEW: "팀장 검토 대기",
    WorkflowStage.CISO_REVIEW: "CISO 승인 대기",
    WorkflowStage.APPROVED: "승인 확정",
    WorkflowStage.REJECTED: "반려 — 담당자 보완 대기",
}

# stage → 허용되는 (action, acting_role, resulting_stage)
_TRANSITIONS = {
    WorkflowStage.TEAM_LEAD_REVIEW: {
        "approve": (ReviewRole.TEAM_LEAD, WorkflowStage.CISO_REVIEW),
        "reject": (ReviewRole.TEAM_LEAD, WorkflowStage.REJECTED),
    },
    WorkflowStage.CISO_REVIEW: {
        "approve": (ReviewRole.CISO, WorkflowStage.APPROVED),
        "reject": (ReviewRole.CISO, WorkflowStage.REJECTED),
    },
    WorkflowStage.REJECTED: {
        "resubmit": (ReviewRole.OWNER, WorkflowStage.TEAM_LEAD_REVIEW),
    },
    WorkflowStage.APPROVED: {},
}

# 담당자는 어느 단계에서든 코멘트·조치 이력을 남길 수 있다
ACTION_KINDS = ("workflow", "comment", "action")


def _role_label(v: str) -> str:
    try:
        return ROLE_LABELS[ReviewRole(v)]
    except ValueError:
        return v


def _stage_label(v: str) -> str:
    try:
        return STAGE_LABELS[WorkflowStage(v)]
    except ValueError:
        return v


class EvidenceReviewWorkflow:
    """원장 레코드 기반 검토·승인 상태기계."""

    def __init__(self, ledger: EvidenceLedger):
        self.ledger = ledger

    # ------------------------------------------------------------------
    # 상태 조회
    # ------------------------------------------------------------------
    def _review_records(self, evidence_id: str):
        return [
            r for r in self.ledger.get_evidence_records(evidence_id)
            if r.record_type in (EvidenceRecordType.REVIEW,
                                 EvidenceRecordType.ANNOTATION)
            and isinstance(r.content, dict)
            and r.content.get("kind") in ACTION_KINDS
        ]

    def current_stage(self, evidence_id: str) -> WorkflowStage:
        stage = WorkflowStage.TEAM_LEAD_REVIEW  # 등록 즉시 팀장 검토 대기
        for r in self._review_records(evidence_id):
            if r.content.get("kind") == "workflow" and r.content.get("to_stage"):
                try:
                    stage = WorkflowStage(r.content["to_stage"])
                except ValueError:
                    pass
        return stage

    def get_state(self, evidence_id: str) -> Dict[str, Any]:
        history: List[Dict[str, Any]] = []
        comments: List[Dict[str, Any]] = []
        actions: List[Dict[str, Any]] = []
        for r in self._review_records(evidence_id):
            c = r.content
            item = {
                "record_id": r.record_id,
                "actor": c.get("actor", r.created_by),
                "role": c.get("role", ""),
                "role_label": _role_label(c.get("role", "")),
                "at": r.created_at.strftime("%Y-%m-%d %H:%M"),
                "hash": r.hash[:16],
            }
            if c.get("kind") == "workflow":
                item.update({
                    "action": c.get("action"),
                    "from_stage": c.get("from_stage"),
                    "to_stage": c.get("to_stage"),
                    "to_label": _stage_label(c.get("to_stage", "")),
                    "comment": c.get("comment", ""),
                })
                history.append(item)
            elif c.get("kind") == "comment":
                item["text"] = c.get("text", "")
                comments.append(item)
            elif c.get("kind") == "action":
                item.update({
                    "action_type": c.get("action_type", ""),
                    "detail": c.get("detail", ""),
                    "action_status": c.get("status", "DONE"),
                })
                actions.append(item)

        stage = self.current_stage(evidence_id)
        return {
            "evidence_id": evidence_id,
            "stage": stage.value,
            "stage_label": STAGE_LABELS[stage],
            "next_actor": {
                WorkflowStage.TEAM_LEAD_REVIEW: "팀장",
                WorkflowStage.CISO_REVIEW: "CISO",
                WorkflowStage.APPROVED: None,
                WorkflowStage.REJECTED: "담당자",
            }[stage],
            "allowed_actions": sorted(_TRANSITIONS.get(stage, {}).keys()),
            "history": history,
            "comments": comments,
            "actions": actions,
        }

    # ------------------------------------------------------------------
    # 전이
    # ------------------------------------------------------------------
    def transition(self, evidence_id: str, control_id: str, action: str,
                   actor: str, role: str, comment: str = "") -> Dict[str, Any]:
        role_e = ReviewRole(role.upper())
        stage = self.current_stage(evidence_id)
        allowed = _TRANSITIONS.get(stage, {})
        if action not in allowed:
            raise ValueError(
                f"현재 단계({STAGE_LABELS[stage]})에서 '{action}' 불가 — "
                f"허용: {sorted(allowed) or '없음'}")
        need_role, to_stage = allowed[action]
        if role_e != need_role:
            raise ValueError(
                f"이 단계는 {ROLE_LABELS[need_role]}만 처리할 수 있습니다")
        if action == "reject" and not comment.strip():
            raise ValueError("반려 시 사유(코멘트)는 필수입니다")

        self.ledger.append_record(
            evidence_id=evidence_id,
            control_id=control_id,
            content={
                "kind": "workflow", "action": action,
                "from_stage": stage.value, "to_stage": to_stage.value,
                "actor": actor, "role": role_e.value, "comment": comment,
            },
            record_type=EvidenceRecordType.REVIEW,
            created_by=actor,
        )
        return self.get_state(evidence_id)

    # ------------------------------------------------------------------
    # 코멘트·조치 이력 (자동 수집 증적 포함 모든 증적에 적용)
    # ------------------------------------------------------------------
    def add_comment(self, evidence_id: str, control_id: str,
                    actor: str, role: str, text: str) -> Dict[str, Any]:
        if not text.strip():
            raise ValueError("코멘트 내용이 비어 있습니다")
        self.ledger.append_record(
            evidence_id=evidence_id,
            control_id=control_id,
            content={"kind": "comment", "actor": actor,
                     "role": ReviewRole(role.upper()).value, "text": text},
            record_type=EvidenceRecordType.ANNOTATION,
            created_by=actor,
        )
        return self.get_state(evidence_id)

    def add_action(self, evidence_id: str, control_id: str, actor: str,
                   action_type: str, detail: str,
                   status: str = "DONE") -> Dict[str, Any]:
        """담당자 조치 이력 — 자동 수집 증적의 대응 내역을 원장에 기록."""
        if not detail.strip():
            raise ValueError("조치 내용이 비어 있습니다")
        self.ledger.append_record(
            evidence_id=evidence_id,
            control_id=control_id,
            content={
                "kind": "action", "actor": actor,
                "role": ReviewRole.OWNER.value,
                "action_type": action_type, "detail": detail,
                "status": status.upper(),
            },
            record_type=EvidenceRecordType.ANNOTATION,
            created_by=actor,
        )
        return self.get_state(evidence_id)
