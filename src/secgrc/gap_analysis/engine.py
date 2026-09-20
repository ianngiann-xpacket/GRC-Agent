"""GAP 분석 엔진 - 인증 기준 대비 현재 상태 분석"""

from enum import Enum
from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import json

from secgrc.compliance.evidence_requirements import EvidenceRequirementRegistry
from secgrc.evidence.document.repository import EvidenceRepository


class GapSeverity(str, Enum):
    """GAP 심각도"""
    CRITICAL = "CRITICAL"   # 치명적 - 인증 불가능
    HIGH = "HIGH"           # 높음 - 즉시 조치 필요
    MEDIUM = "MEDIUM"       # 중간 - 계획적 조치 필요
    LOW = "LOW"             # 낮음 - 개선 권장
    NONE = "NONE"           # 없음 - 기준 충족


class GapType(str, Enum):
    """GAP 유형"""
    MISSING_EVIDENCE = "MISSING_EVIDENCE"       # 증적 부재
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE" # 증적 불충분
    OUTDATED_EVIDENCE = "OUTDATED_EVIDENCE"     # 증적 만료
    MISSING_CONTROL = "MISSING_CONTROL"         # 통제 부재
    PARTIAL_CONTROL = "PARTIAL_CONTROL"         # 통제 부분 적용
    DOCUMENT_MISSING = "DOCUMENT_MISSING"       # 문서 부재
    PROCESS_GAP = "PROCESS_GAP"                 # 프로세스 갭


class ControlGap(BaseModel):
    """통제별 GAP 분석 결과"""
    control_id: str = Field(description="통제 ID")
    control_name: str = Field(description="통제명")
    gap_type: GapType = Field(description="GAP 유형")
    severity: GapSeverity = Field(description="심각도")
    description: str = Field(description="GAP 설명")
    required_evidence: List[str] = Field(default_factory=list, description="필요 증적")
    available_evidence: List[str] = Field(default_factory=list, description="보유 증적")
    missing_evidence: List[str] = Field(default_factory=list, description="부족 증적")
    recommendations: List[str] = Field(default_factory=list, description="개선 권고사항")
    effort_estimate: str = Field(default="", description="예상 소요 노력")
    priority: int = Field(default=3, description="우선순위 (1-5, 1이 가장 높음)")


class ReadinessAssessment(BaseModel):
    """인증 준비도 평가 결과"""
    assessment_id: str = Field(description="평가 ID")
    organization_id: str = Field(description="조직 ID")
    framework: str = Field(description="평가 프레임워크")
    assessment_date: datetime = Field(default_factory=datetime.now)
    overall_score: float = Field(description="종합 점수 (0-100)")
    control_coverage: float = Field(description="통제 적용률 (%)")
    evidence_sufficiency: float = Field(description="증적 충족도 (%)")
    document_completeness: float = Field(description="문서 완성도 (%)")
    process_maturity: float = Field(description="프로세스 성숙도 (%)")
    critical_gaps: int = Field(description="치명적 GAP 수")
    high_gaps: int = Field(description="높은 GAP 수")
    medium_gaps: int = Field(description="중간 GAP 수")
    low_gaps: int = Field(description="낮은 GAP 수")
    gaps: List[ControlGap] = Field(default_factory=list, description="GAP 목록")
    recommendations: List[str] = Field(default_factory=list, description="종합 권고사항")
    estimated_time_to_ready: Optional[str] = Field(default=None, description="준비 예상 기간")


class GapAnalysisEngine:
    """GAP 분석 엔진"""

    def __init__(self):
        self.evidence_registry = EvidenceRequirementRegistry()
        self.evidence_repo = EvidenceRepository()
        self._load_isms_p_controls()

    def _load_isms_p_controls(self):
        """ISMS-P 통제 기준 로드"""
        try:
            with open("/Users/taesunhwang/GRC Agent/src/secgrc/data/isms_p_controls.json", "r", encoding="utf-8") as f:
                self.controls = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load ISMS-P controls: {e}")
            self.controls = []

    def analyze_gaps(self, organization_id: str = "DEFAULT") -> ReadinessAssessment:
        """조직의 인증 준비도 GAP 분석"""
        
        gaps = []
        total_controls = len(self.controls)
        compliant_controls = 0
        
        for control in self.controls:
            control_id = control["control_id"]
            control_gaps = self._analyze_control_gap(control_id, control)
            gaps.extend(control_gaps)
            
            # 통제 적용 여부 판단 (GAP이 없거나 낮은 수준인 경우)
            if not any(gap.severity in [GapSeverity.CRITICAL, GapSeverity.HIGH] for gap in control_gaps):
                compliant_controls += 1
        
        # 점수 계산
        control_coverage = (compliant_controls / total_controls) * 100 if total_controls > 0 else 0
        
        # 증적 충족도 계산
        evidence_sufficiency = self._calculate_evidence_sufficiency()
        
        # 문서 완성도 계산
        document_completeness = self._calculate_document_completeness()
        
        # 프로세스 성숙도 (간단한 추정)
        process_maturity = (control_coverage + evidence_sufficiency) / 2
        
        # 종합 점수 (가중 평균)
        overall_score = (
            control_coverage * 0.4 +
            evidence_sufficiency * 0.3 +
            document_completeness * 0.2 +
            process_maturity * 0.1
        )
        
        # GAP 심각도별 집계
        critical_gaps = len([g for g in gaps if g.severity == GapSeverity.CRITICAL])
        high_gaps = len([g for g in gaps if g.severity == GapSeverity.HIGH])
        medium_gaps = len([g for g in gaps if g.severity == GapSeverity.MEDIUM])
        low_gaps = len([g for g in gaps if g.severity == GapSeverity.LOW])
        
        # 권고사항 생성
        recommendations = self._generate_recommendations(gaps, overall_score)
        
        # 준비 예상 기간 추정
        estimated_time = self._estimate_preparation_time(overall_score, critical_gaps, high_gaps)
        
        assessment = ReadinessAssessment(
            assessment_id=f"GAP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            organization_id=organization_id,
            framework="ISMS-P",
            overall_score=overall_score,
            control_coverage=control_coverage,
            evidence_sufficiency=evidence_sufficiency,
            document_completeness=document_completeness,
            process_maturity=process_maturity,
            critical_gaps=critical_gaps,
            high_gaps=high_gaps,
            medium_gaps=medium_gaps,
            low_gaps=low_gaps,
            gaps=gaps,
            recommendations=recommendations,
            estimated_time_to_ready=estimated_time
        )
        
        return assessment

    def _analyze_control_gap(self, control_id: str, control: Dict) -> List[ControlGap]:
        """개별 통제 GAP 분석"""
        gaps = []
        
        # 1. 증적 요구사항 조회
        evidence_reqs = self.evidence_registry.list_evidence_requirements(
            framework_id="ISMS-P",
            framework_version="2024-07",
            requirement_id=control_id
        )
        
        # 2. 현재 증적 현황 조회
        current_evidence = self.evidence_repo.get_evidence_by_control(control_id)
        
        # 3. GAP 분석
        required_evidence_types = set()
        for req in evidence_reqs:
            required_evidence_types.add(req.evidence_type)
        
        available_evidence_types = set()
        for doc in current_evidence.get("documents", []):
            available_evidence_types.add(doc.document_type.value)
        for sys_ev in current_evidence.get("system_evidence", []):
            available_evidence_types.add(sys_ev.source_type)
        
        # 4. GAP 식별
        missing_evidence = required_evidence_types - available_evidence_types
        
        if missing_evidence:
            # 증적 부재 GAP
            gap = ControlGap(
                control_id=control_id,
                control_name=control.get("name", ""),
                gap_type=GapType.MISSING_EVIDENCE,
                severity=self._determine_severity(control, missing_evidence),
                description=f"통제 '{control.get('name', '')}'에 필요한 증적이 부족합니다.",
                required_evidence=list(required_evidence_types),
                available_evidence=list(available_evidence_types),
                missing_evidence=list(missing_evidence),
                recommendations=self._generate_control_recommendations(control, missing_evidence),
                effort_estimate=self._estimate_effort(missing_evidence),
                priority=self._determine_priority(control, missing_evidence)
            )
            gaps.append(gap)
        
        # 5. 문서 증적 부재 확인
        if not current_evidence.get("documents"):
            gap = ControlGap(
                control_id=control_id,
                control_name=control.get("name", ""),
                gap_type=GapType.DOCUMENT_MISSING,
                severity=GapSeverity.MEDIUM,
                description=f"통제 '{control.get('name', '')}'에 대한 문서 증적이 없습니다.",
                required_evidence=["정책문서", "절차서", "기록"],
                available_evidence=list(available_evidence_types),
                missing_evidence=["정책문서", "절차서"],
                recommendations=["관련 정책 및 절차 문서를 작성하고 승인받으세요."],
                effort_estimate="2-3주",
                priority=3
            )
            gaps.append(gap)
        
        return gaps

    def _determine_severity(self, control: Dict, missing_evidence: set) -> GapSeverity:
        """GAP 심각도 결정"""
        # 통제 중요도에 따른 심각도 결정
        category = control.get("category", "")
        
        if "개인정보" in category or "보호대책" in category:
            if len(missing_evidence) > 2:
                return GapSeverity.CRITICAL
            elif len(missing_evidence) > 1:
                return GapSeverity.HIGH
            else:
                return GapSeverity.MEDIUM
        else:
            if len(missing_evidence) > 2:
                return GapSeverity.HIGH
            elif len(missing_evidence) > 1:
                return GapSeverity.MEDIUM
            else:
                return GapSeverity.LOW

    def _determine_priority(self, control: Dict, missing_evidence: set) -> int:
        """우선순위 결정 (1-5, 1이 가장 높음)"""
        severity = self._determine_severity(control, missing_evidence)
        
        if severity == GapSeverity.CRITICAL:
            return 1
        elif severity == GapSeverity.HIGH:
            return 2
        elif severity == GapSeverity.MEDIUM:
            return 3
        else:
            return 4

    def _generate_control_recommendations(self, control: Dict, missing_evidence: set) -> List[str]:
        """통제별 개선 권고사항 생성"""
        recommendations = []
        
        for evidence_type in missing_evidence:
            if evidence_type == "MFA_CONFIGURATION":
                recommendations.append("다중요소인증(MFA) 설정을 활성화하고 구성 증적을 수집하세요.")
            elif evidence_type == "FIREWALL_RULESET":
                recommendations.append("방화벽 정책을 검토하고 룰셋 구성 증적을 수집하세요.")
            elif evidence_type == "POLICY":
                recommendations.append("관련 정책 문서를 작성하고 승인받으세요.")
            elif evidence_type == "PROCEDURE":
                recommendations.append("절차서를 작성하고 관련 부서와 공유하세요.")
            else:
                recommendations.append(f"{evidence_type} 유형의 증적을 수집하세요.")
        
        # 통제별 특화 권고
        control_name = control.get("name", "")
        if "경영진" in control_name:
            recommendations.append("경영진 참여 증적(회의록, 승인 기록)을 체계적으로 관리하세요.")
        elif "위험" in control_name:
            recommendations.append("정기적인 위험평가를 수행하고 결과를 문서화하세요.")
        
        return recommendations

    def _estimate_effort(self, missing_evidence: set) -> str:
        """예상 소요 노력 추정"""
        if len(missing_evidence) > 3:
            return "4-6주"
        elif len(missing_evidence) > 2:
            return "2-4주"
        elif len(missing_evidence) > 1:
            return "1-2주"
        else:
            return "1주 이내"

    def _calculate_evidence_sufficiency(self) -> float:
        """증적 충족도 계산"""
        total_reqs = 0
        satisfied_reqs = 0
        
        for control in self.controls:
            control_id = control["control_id"]
            evidence_reqs = self.evidence_registry.list_evidence_requirements(
                framework_id="ISMS-P",
                framework_version="2024-07",
                requirement_id=control_id
            )
            total_reqs += len(evidence_reqs)
            
            current_evidence = self.evidence_repo.get_evidence_by_control(control_id)
            available_types = set()
            for doc in current_evidence.get("documents", []):
                available_types.add(doc.document_type.value)
            for sys_ev in current_evidence.get("system_evidence", []):
                available_types.add(sys_ev.source_type)
            
            for req in evidence_reqs:
                if req.evidence_type in available_types:
                    satisfied_reqs += 1
        
        return (satisfied_reqs / total_reqs) * 100 if total_reqs > 0 else 0

    def _calculate_document_completeness(self) -> float:
        """문서 완성도 계산"""
        total_controls = len(self.controls)
        controls_with_docs = 0
        
        for control in self.controls:
            control_id = control["control_id"]
            current_evidence = self.evidence_repo.get_evidence_by_control(control_id)
            
            if current_evidence.get("documents"):
                controls_with_docs += 1
        
        return (controls_with_docs / total_controls) * 100 if total_controls > 0 else 0

    def _generate_recommendations(self, gaps: List[ControlGap], overall_score: float) -> List[str]:
        """종합 권고사항 생성"""
        recommendations = []
        
        if overall_score < 50:
            recommendations.append("🚨 인증 준비도가 매우 낮습니다. 즉시 체계적인 준비 계획을 수립하세요.")
        elif overall_score < 70:
            recommendations.append("⚠️ 인증 준비도가 부족합니다. 우선순위가 높은 GAP부터 해결하세요.")
        elif overall_score < 90:
            recommendations.append("✅ 인증 준비도가 양호합니다. 남은 GAP을 해결하면 인증 가능합니다.")
        else:
            recommendations.append("🎉 인증 준비도가 우수합니다. 최종 점검 후 인증 신청이 가능합니다.")
        
        # 심각도별 권고
        critical_gaps = [g for g in gaps if g.severity == GapSeverity.CRITICAL]
        if critical_gaps:
            recommendations.append(f"🔴 치명적 GAP {len(critical_gaps)}개를 즉시 해결해야 합니다.")
        
        high_gaps = [g for g in gaps if g.severity == GapSeverity.HIGH]
        if high_gaps:
            recommendations.append(f"🟠 높은 우선순위 GAP {len(high_gaps)}개를 계획적으로 해결하세요.")
        
        # 문서 관련 권고
        doc_gaps = [g for g in gaps if g.gap_type == GapType.DOCUMENT_MISSING]
        if doc_gaps:
            recommendations.append("📄 정책 및 절차 문서 체계를 구축하고 승인 프로세스를 마련하세요.")
        
        # 증적 관련 권고
        evidence_gaps = [g for g in gaps if g.gap_type == GapType.MISSING_EVIDENCE]
        if evidence_gaps:
            recommendations.append("🔍 시스템 증적 수집 체계를 자동화하고 정기적으로 점검하세요.")
        
        return recommendations

    def _estimate_preparation_time(self, overall_score: float, critical_gaps: int, high_gaps: int) -> str:
        """준비 예상 기간 추정"""
        if overall_score >= 90:
            return "1-2주 (최종 점검)"
        elif overall_score >= 70:
            return "1-2개월"
        elif overall_score >= 50:
            return "3-6개월"
        elif critical_gaps > 5:
            return "6개월 이상"
        elif high_gaps > 10:
            return "4-6개월"
        else:
            return "2-4개월"

    def get_control_gap_detail(self, control_id: str) -> Optional[ControlGap]:
        """특정 통제의 상세 GAP 정보 조회"""
        control = next((c for c in self.controls if c["control_id"] == control_id), None)
        if not control:
            return None
        
        gaps = self._analyze_control_gap(control_id, control)
        return gaps[0] if gaps else None

    def get_top_priority_gaps(self, limit: int = 10) -> List[ControlGap]:
        """우선순위가 높은 GAP 목록 조회"""
        assessment = self.analyze_gaps()
        sorted_gaps = sorted(assessment.gaps, key=lambda g: (g.priority, g.severity.value))
        return sorted_gaps[:limit]


# 전역 인스턴스
gap_analysis_engine = GapAnalysisEngine()
