"""결정론적 GRC 위험 점수 산출 및 평가 엔진(RiskEngine) 모듈입니다.

LLM이나 외부 API 호출 없이,
AuditResult(판정 상태, 결함 심각도)와 자산 중요도, 통제 영향도, 매핑 신뢰도를 결합한
수학적 가중치 공식(Weighted Formula)으로 객관적 위험도(Risk Score)를 계산합니다.
"""

from typing import Any, Dict, List, Optional

from secgrc.audit.models import AuditResult, AuditSeverity, AuditStatus
from secgrc.models.evidence import NormalizedEvidence
from secgrc.risk.models import RiskAssessment, RiskLevel, RiskPriority

# 1. 결정론적 심각도 기본 점수 매핑
SEVERITY_SCORES: Dict[AuditSeverity, float] = {
    AuditSeverity.CRITICAL: 100.0,
    AuditSeverity.HIGH: 75.0,
    AuditSeverity.MEDIUM: 50.0,
    AuditSeverity.LOW: 25.0,
    AuditSeverity.INFO: 10.0,
    AuditSeverity.UNKNOWN: 0.0,
}

# 2. 통제항목별 비즈니스 영향도 기본값 (미지정 시 50.0)
DEFAULT_CONTROL_IMPACT: Dict[str, float] = {
    "ISMS-P-2.7.1": 90.0,  # 데이터 암호화 및 보호 (핵심 보안 통제)
    "ISMS-P-2.5.2": 85.0,  # 식별 및 인증 / MFA (침해사고 1차 방어선)
    "ISMS-P-2.6.3": 85.0,  # 원격 접근 통제 / 네트워크 경계 보호
    "ISMS-P-2.5.3": 80.0,  # 권한 관리 및 특권 오남용 방지
    "ISMS-P-2.5.1": 75.0,  # 사용자 계정 라이프사이클 관리
    "ISMS-P-2.8.1": 70.0,  # 백업 및 비즈니스 연속성
    "ISMS-P-2.9.2": 70.0,  # 로그 관리 및 사후 추적성
    "ISMS-P-3.2.1": 65.0,  # 개인정보 파기 및 컴플라이언스
    "ISMS-P-1.1.2": 60.0,  # CISO 조직 및 거버넌스
    "ISMS-P-1.1.1": 60.0,  # 경영진 참여 및 예산
}

# 3. 위험도 등급 임계값 상수
THRESHOLD_CRITICAL = 90.0
THRESHOLD_HIGH = 70.0
THRESHOLD_MEDIUM = 40.0
THRESHOLD_LOW = 20.0


class RiskEngine:
    """결정론적 GRC 위험 점수 산출 및 우선순위 결정 엔진."""

    def __init__(
        self,
        control_impact_map: Optional[Dict[str, float]] = None,
        default_asset_criticality: float = 50.0,
    ):
        """위험 엔진 초기화.

        Args:
            control_impact_map: 통제항목별 영향도 재정의 맵
            default_asset_criticality: CMDB 미연동 시 기본 자산 중요도 (기본값: 50.0)
        """
        self.control_impact_map = (
            control_impact_map if control_impact_map is not None else DEFAULT_CONTROL_IMPACT
        )
        self.default_asset_criticality = default_asset_criticality

    def _resolve_asset_criticality(
        self, audit: AuditResult, evidence_list: Optional[List[NormalizedEvidence]] = None
    ) -> float:
        """증적 리소스의 유형 및 특성을 기반으로 자산 중요도를 결정합니다."""
        if not evidence_list:
            # 증적 목록이 직접 전달되지 않은 경우, 결함 심각도 기반 기본 가중치 적용
            if audit.severity == AuditSeverity.CRITICAL:
                return 70.0
            return self.default_asset_criticality

        matched_ev = [
            e for e in evidence_list
            if (e.get("finding_uid") in audit.evidence_ids) or (e.get("evidence_id") in audit.evidence_ids)
        ]
        if not matched_ev:
            matched_ev = evidence_list

        max_crit = self.default_asset_criticality
        for e in matched_ev:
            res_str = f"{e.get('resource_uid', '')} {e.get('resource_type', '')} {e.get('description', '')}".lower()
            # 고위험 자산 휴리스틱 식별
            if any(k in res_str for k in ("allusers", "0.0.0.0/0", "owner", "admin", "kms")):
                crit = 80.0
            elif any(k in res_str for k in ("bucket", "firewall", "serviceaccount", "dataset")):
                crit = 70.0
            else:
                crit = 50.0

            if crit > max_crit:
                max_crit = crit

        return max_crit

    def _resolve_control_impact(self, control_id: str) -> float:
        """통제항목 번호에 해당하는 비즈니스 영향도를 조회합니다."""
        return self.control_impact_map.get(control_id, 50.0)

    def _determine_risk_level_and_priority(
        self, score: float
    ) -> tuple[RiskLevel, RiskPriority]:
        """위험 점수(Score)를 바탕으로 위험 레벨과 우선순위(P1~P5)를 결정합니다."""
        if score >= THRESHOLD_CRITICAL:
            return RiskLevel.CRITICAL, RiskPriority.P1
        elif score >= THRESHOLD_HIGH:
            return RiskLevel.HIGH, RiskPriority.P2
        elif score >= THRESHOLD_MEDIUM:
            return RiskLevel.MEDIUM, RiskPriority.P3
        elif score >= THRESHOLD_LOW:
            return RiskLevel.LOW, RiskPriority.P4
        else:
            return RiskLevel.INFO, RiskPriority.P5

    def assess_single(
        self,
        audit: AuditResult,
        evidence_list: Optional[List[NormalizedEvidence]] = None,
    ) -> RiskAssessment:
        """단일 AuditResult에 대해 결정론적 위험 평가(RiskAssessment)를 수행합니다."""
        control_id = audit.control_id
        control_title = audit.control_title
        status = audit.status
        severity = audit.severity

        # 1. 팩터 수치 확보
        severity_score = SEVERITY_SCORES.get(severity, 0.0)
        asset_crit = self._resolve_asset_criticality(audit, evidence_list)
        control_impact = self._resolve_control_impact(control_id)
        confidence = getattr(audit, "mapping_confidence", 1.0)

        # 2. 컴플라이언스 상태에 따른 조건부 가중치 계산 (원칙 8 분리 정책 적용)
        if status == AuditStatus.NO_EVIDENCE:
            risk_score = 0.0
            risk_level = RiskLevel.INFO
            priority = RiskPriority.P5
            rationale = (
                f"Evidence gap detected: no automated cloud evidence was available for control {control_id}. "
                f"Requires manual audit and offline evidence verification."
            )

        elif status == AuditStatus.PASS:
            # 기술적 기준 충족 -> 위험도 최소화 (INFO 등급 보장)
            risk_score = round(min(15.0, (0.10 * control_impact) + (0.05 * severity_score)), 1)
            risk_level = RiskLevel.INFO
            priority = RiskPriority.P5
            rationale = (
                f"INFO risk (Score: {risk_score}): Technical compliance verified (PASS). "
                f"Routine configuration monitoring and log reviews recommended."
            )

        elif status == AuditStatus.MANUAL:
            # 수동 검토 대상 -> 중간 수준의 기본 위험 부여
            risk_score = round(
                (0.40 * 50.0) + (0.30 * asset_crit) + (0.30 * control_impact), 1
            )
            risk_level, priority = self._determine_risk_level_and_priority(risk_score)
            rationale = (
                f"{risk_level.value} risk (Score: {risk_score}) pending manual review: "
                f"Automated tool cannot verify control {control_id}. Auditor review required."
            )

        else:
            # FAIL 또는 PARTIAL: 가중치 공식 적용
            # Risk Score = 0.40 * Severity + 0.25 * AssetCrit + 0.20 * ControlImpact + 0.15 * Confidence*100
            raw_score = (
                (0.40 * severity_score)
                + (0.25 * asset_crit)
                + (0.20 * control_impact)
                + (0.15 * (confidence * 100.0))
            )
            risk_score = round(max(0.0, min(100.0, raw_score)), 1)
            risk_level, priority = self._determine_risk_level_and_priority(risk_score)

            if status == AuditStatus.PARTIAL:
                rationale = (
                    f"{risk_level.value} risk (Score: {risk_score}) due to partial compliance failure: "
                    f"Control {control_id} has active {severity.value} severity finding(s) on critical assets."
                )
            else:
                rationale = (
                    f"{risk_level.value} risk (Score: {risk_score}) because control {control_id} "
                    f"failed compliance with {severity.value} severity (Asset Criticality: {asset_crit:.0f}, Control Impact: {control_impact:.0f})."
                )

        return RiskAssessment(
            risk_id=f"RSK-{control_id}",
            control_id=control_id,
            control_title=control_title,
            audit_status=status,
            severity=severity,
            asset_criticality=asset_crit,
            evidence_confidence=confidence,
            control_impact=control_impact,
            risk_score=risk_score,
            risk_level=risk_level,
            priority=priority,
            rationale=rationale,
            evidence_ids=audit.evidence_ids,
            recommendations=audit.recommendations,
        )

    def assess(
        self,
        audit_results: List[AuditResult],
        evidence_list: Optional[List[NormalizedEvidence]] = None,
    ) -> List[RiskAssessment]:
        """AuditResult 목록 전체를 평가하여 위험도 순으로 정렬된 RiskAssessment 목록을 반환합니다."""
        assessments: List[RiskAssessment] = []
        for audit in audit_results:
            assessments.append(self.assess_single(audit, evidence_list))

        # 위험 점수(risk_score) 내림차순 정렬 (높은 위험이 상위)
        assessments.sort(key=lambda a: a.risk_score, reverse=True)
        return assessments

    def summary(self, assessments: List[RiskAssessment]) -> Dict[str, Any]:
        """위험 평가 결과 목록의 집계 통계를 생성합니다."""
        stats: Dict[str, Any] = {
            "total": len(assessments),
            "critical": sum(1 for a in assessments if a.risk_level == RiskLevel.CRITICAL),
            "high": sum(1 for a in assessments if a.risk_level == RiskLevel.HIGH),
            "medium": sum(1 for a in assessments if a.risk_level == RiskLevel.MEDIUM),
            "low": sum(1 for a in assessments if a.risk_level == RiskLevel.LOW),
            "info": sum(1 for a in assessments if a.risk_level == RiskLevel.INFO),
            "manual_review": sum(1 for a in assessments if a.audit_status == AuditStatus.MANUAL),
            "evidence_gap": sum(1 for a in assessments if a.audit_status == AuditStatus.NO_EVIDENCE),
            "p1": sum(1 for a in assessments if a.priority == RiskPriority.P1),
            "p2": sum(1 for a in assessments if a.priority == RiskPriority.P2),
            "p3": sum(1 for a in assessments if a.priority == RiskPriority.P3),
            "p4": sum(1 for a in assessments if a.priority == RiskPriority.P4),
            "p5": sum(1 for a in assessments if a.priority == RiskPriority.P5),
        }
        return stats
