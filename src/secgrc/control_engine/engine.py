"""통제 정의 엔진 - 통제 항목별 운영 메타데이터 관리"""

from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import json
from pathlib import Path


class ReviewFrequency(str, Enum):
    """점검 주기"""
    MONTHLY = "MONTHLY"         # 월간
    QUARTERLY = "QUARTERLY"     # 분기
    SEMI_ANNUAL = "SEMI_ANNUAL" # 반기
    ANNUAL = "ANNUAL"           # 연간
    CONTINUOUS = "CONTINUOUS"   # 지속적


class AssessmentMethod(str, Enum):
    """평가 방법"""
    AUTOMATED = "AUTOMATED"     # 자동화
    MANUAL = "MANUAL"           # 수동
    HYBRID = "HYBRID"           # 혼합


class ControlOwner(BaseModel):
    """통제 담당자"""
    name: str = Field(description="담당자명")
    email: str = Field(description="이메일")
    department: str = Field(description="부서")
    role: str = Field(description="역할")
    backup: Optional[str] = Field(default=None, description="대리 담당자")


class RelatedLaw(BaseModel):
    """관련 법령"""
    law_name: str = Field(description="법령명")
    article: str = Field(description="관련 조항")
    description: str = Field(description="법령 설명")
    mandatory: bool = Field(default=True, description="필수 여부")


class ControlDefinition(BaseModel):
    """통제 정의"""
    control_id: str = Field(description="통제 ID")
    title: str = Field(description="통제명")
    category: str = Field(description="통제 분류")
    description: str = Field(description="통제 설명")
    objective: str = Field(description="통제 목적")
    requirements: str = Field(description="요구사항")
    checkpoints: List[str] = Field(default_factory=list, description="점검 항목")
    evidence_types: List[str] = Field(default_factory=list, description="증적 유형")
    owner: ControlOwner = Field(description="담당자")
    review_frequency: ReviewFrequency = Field(description="점검 주기")
    assessment_method: AssessmentMethod = Field(description="평가 방법")
    related_laws: List[RelatedLaw] = Field(default_factory=list, description="관련 법령")
    related_controls: List[str] = Field(default_factory=list, description="관련 통제")
    maturity_level: int = Field(default=1, description="성숙도 수준 (1-5)")
    automation_level: str = Field(default="MANUAL", description="자동화 수준")
    last_review_date: Optional[datetime] = Field(default=None, description="최근 점검일")
    next_review_date: Optional[datetime] = Field(default=None, description="다음 점검일")
    tags: List[str] = Field(default_factory=list, description="태그")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class ControlEngine:
    """통제 정의 엔진"""

    def __init__(self):
        self._controls: Dict[str, ControlDefinition] = {}
        self._load_isms_p_controls()
        self._initialize_control_definitions()

    def _load_isms_p_controls(self):
        """ISMS-P 통제 기준 로드"""
        try:
            controls_path = Path(__file__).resolve().parent.parent / "data" / "isms_p_controls.json"
            with open(controls_path, "r", encoding="utf-8") as f:
                self.base_controls = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load ISMS-P controls: {e}")
            self.base_controls = []

    def _initialize_control_definitions(self):
        """통제 정의 초기화"""
        for control_data in self.base_controls:
            control_id = control_data["control_id"]
            
            # 기본 통제 정의 생성
            control_def = self._create_control_definition(control_data)
            self._controls[control_id] = control_def

    def _create_control_definition(self, control_data: Dict) -> ControlDefinition:
        """통제 데이터로부터 통제 정의 생성"""
        control_id = control_data["control_id"]
        
        # 담당자 설정 (기본값)
        owner = ControlOwner(
            name="보안팀",
            email="security@company.com",
            department="정보보호팀",
            role="보안담당자"
        )
        
        # 카테고리별 담당자 및 주기 설정
        category = control_data.get("category", "")
        if "경영진" in category or "관리체계" in category:
            owner = ControlOwner(
                name="경영지원팀",
                email="management@company.com",
                department="경영지원팀",
                role="관리책임자"
            )
            review_freq = ReviewFrequency.ANNUAL
        elif "개인정보" in category:
            owner = ControlOwner(
                name="개인정보보호팀",
                email="privacy@company.com",
                department="개인정보보호팀",
                role="개인정보보호책임자"
            )
            review_freq = ReviewFrequency.QUARTERLY
        elif "시스템" in category or "네트워크" in category:
            owner = ControlOwner(
                name="인프라팀",
                email="infra@company.com",
                department="인프라팀",
                role="시스템관리자"
            )
            review_freq = ReviewFrequency.MONTHLY
        else:
            review_freq = ReviewFrequency.QUARTERLY
        
        # 관련 법령 설정
        related_laws = self._get_related_laws(control_id, control_data)
        
        # 평가 방법 설정
        assessment_method = AssessmentMethod.HYBRID
        if "자동" in control_data.get("requirements", "") or "시스템" in control_data.get("requirements", ""):
            assessment_method = AssessmentMethod.AUTOMATED
        elif "문서" in control_data.get("requirements", "") or "절차" in control_data.get("requirements", ""):
            assessment_method = AssessmentMethod.MANUAL
        
        # 통제 정의 생성
        control_def = ControlDefinition(
            control_id=control_id,
            title=control_data.get("name", ""),
            category=category,
            description=control_data.get("requirements", ""),
            objective=f"{control_data.get('name', '')}을(를) 통한 정보보호 체계 강화",
            requirements=control_data.get("requirements", ""),
            checkpoints=control_data.get("checkpoints", []),
            evidence_types=self._get_evidence_types(control_data),
            owner=owner,
            review_frequency=review_freq,
            assessment_method=assessment_method,
            related_laws=related_laws,
            related_controls=self._get_related_controls(control_id),
            maturity_level=self._estimate_maturity_level(control_data),
            automation_level=self._estimate_automation_level(control_data)
        )
        
        return control_def

    def _get_evidence_types(self, control_data: Dict) -> List[str]:
        """증적 유형 추출"""
        evidence_types = []
        
        # 키워드 기반 증적 유형 추정
        requirements = control_data.get("requirements", "")
        checkpoints = control_data.get("checkpoints", [])
        
        text = requirements + " ".join(checkpoints)
        
        if "문서" in text or "정책" in text or "절차" in text:
            evidence_types.append("DOCUMENT")
        if "시스템" in text or "설정" in text or "로그" in text:
            evidence_types.append("SYSTEM")
        if "회의" in text or "보고" in text:
            evidence_types.append("MEETING_MINUTES")
        if "교육" in text or "훈련" in text:
            evidence_types.append("TRAINING_RECORD")
        if "승인" in text or "결재" in text:
            evidence_types.append("APPROVAL_RECORD")
        
        return evidence_types if evidence_types else ["DOCUMENT", "SYSTEM"]

    def _get_related_laws(self, control_id: str, control_data: Dict) -> List[RelatedLaw]:
        """관련 법령 추출"""
        laws = []
        
        # 통제 ID 기반 관련 법령 매핑
        if "2.5" in control_id or "인증" in control_data.get("name", ""):
            laws.append(RelatedLaw(
                law_name="개인정보보호법",
                article="제24조 (개인정보의 처리)",
                description="개인정보처리자는 개인정보를 처리하는 경우 안전성 확보 조치를 하여야 한다.",
                mandatory=True
            ))
        
        if "2.7" in control_id or "암호" in control_data.get("name", ""):
            laws.append(RelatedLaw(
                law_name="개인정보보호법",
                article="제24조의2 (개인정보의 안전성 확보 조치)",
                description="개인정보처리자는 개인정보가 분실·도난·유출·위조·변조 또는 훼손되지 않도록 안전성 확보 조치를 하여야 한다.",
                mandatory=True
            ))
        
        if "3" in control_id or "개인정보" in control_data.get("category", ""):
            laws.append(RelatedLaw(
                law_name="개인정보보호법",
                article="제3조 (개인정보 보호 원칙)",
                description="개인정보처리자는 개인정보의 처리 목적을 명확하게 하고, 그 목적에 필요한 범위에서 최소한의 개인정보만을 적법하고 정당하게 수집하여야 한다.",
                mandatory=True
            ))
        
        if "로그" in control_data.get("name", "") or "기록" in control_data.get("name", ""):
            laws.append(RelatedLaw(
                law_name="정보통신망법",
                article="제28조 (개인정보의 보호조치)",
                description="정보통신서비스 제공자는 개인정보의 안전한 처리를 위하여 대통령령으로 정하는 바에 따라 개인정보의 안전한 처리를 위한 조치를 하여야 한다.",
                mandatory=True
            ))
        
        return laws

    def _get_related_controls(self, control_id: str) -> List[str]:
        """관련 통제 추출"""
        related = []
        
        # 같은 카테고리의 다른 통제
        category_prefix = ".".join(control_id.split(".")[:2])
        for control_data in self.base_controls:
            other_id = control_data["control_id"]
            if other_id.startswith(category_prefix) and other_id != control_id:
                related.append(other_id)
        
        return related[:5]  # 최대 5개

    def _estimate_maturity_level(self, control_data: Dict) -> int:
        """성숙도 수준 추정 (1-5)"""
        # 요구사항과 점검항목의 복잡도에 따른 추정
        requirements_len = len(control_data.get("requirements", ""))
        checkpoints_count = len(control_data.get("checkpoints", []))
        
        if requirements_len > 200 and checkpoints_count > 3:
            return 3
        elif requirements_len > 100 and checkpoints_count > 2:
            return 2
        else:
            return 1

    def _estimate_automation_level(self, control_data: Dict) -> str:
        """자동화 수준 추정"""
        text = control_data.get("requirements", "") + " ".join(control_data.get("checkpoints", []))
        
        if "시스템" in text or "자동" in text or "설정" in text:
            return "AUTOMATED"
        elif "문서" in text or "절차" in text or "수기" in text:
            return "MANUAL"
        else:
            return "HYBRID"

    def get_control(self, control_id: str) -> Optional[ControlDefinition]:
        """통제 정의 조회"""
        return self._controls.get(control_id)

    def get_controls_by_owner(self, owner_name: str) -> List[ControlDefinition]:
        """담당자별 통제 조회"""
        return [c for c in self._controls.values() if c.owner.name == owner_name]

    def get_controls_by_frequency(self, frequency: ReviewFrequency) -> List[ControlDefinition]:
        """점검 주기별 통제 조회"""
        return [c for c in self._controls.values() if c.review_frequency == frequency]

    def get_controls_due_for_review(self, days_ahead: int = 30) -> List[ControlDefinition]:
        """점검 예정 통제 조회"""
        due_date = datetime.now() + timedelta(days=days_ahead)
        return [
            c for c in self._controls.values()
            if c.next_review_date and c.next_review_date <= due_date
        ]

    def update_review_date(self, control_id: str, review_date: datetime) -> bool:
        """점검일 업데이트"""
        control = self.get_control(control_id)
        if not control:
            return False
        
        control.last_review_date = review_date
        
        # 다음 점검일 계산
        if control.review_frequency == ReviewFrequency.MONTHLY:
            control.next_review_date = review_date + timedelta(days=30)
        elif control.review_frequency == ReviewFrequency.QUARTERLY:
            control.next_review_date = review_date + timedelta(days=90)
        elif control.review_frequency == ReviewFrequency.SEMI_ANNUAL:
            control.next_review_date = review_date + timedelta(days=180)
        elif control.review_frequency == ReviewFrequency.ANNUAL:
            control.next_review_date = review_date + timedelta(days=365)
        else:
            control.next_review_date = None
        
        control.updated_at = datetime.now()
        return True

    def get_control_summary(self) -> Dict[str, Any]:
        """통제 현황 요약"""
        total_controls = len(self._controls)
        
        by_frequency = {}
        by_method = {}
        by_maturity = {}
        by_owner = {}
        
        for control in self._controls.values():
            freq = control.review_frequency.value
            method = control.assessment_method.value
            maturity = f"Level {control.maturity_level}"
            owner = control.owner.name
            
            by_frequency[freq] = by_frequency.get(freq, 0) + 1
            by_method[method] = by_method.get(method, 0) + 1
            by_maturity[maturity] = by_maturity.get(maturity, 0) + 1
            by_owner[owner] = by_owner.get(owner, 0) + 1
        
        # 점검 예정 통제
        due_for_review = len(self.get_controls_due_for_review())
        
        return {
            "total_controls": total_controls,
            "by_frequency": by_frequency,
            "by_method": by_method,
            "by_maturity": by_maturity,
            "by_owner": by_owner,
            "due_for_review": due_for_review,
            "automated_controls": by_method.get("AUTOMATED", 0),
            "manual_controls": by_method.get("MANUAL", 0),
            "hybrid_controls": by_method.get("HYBRID", 0)
        }

    def update_control_owner(self, control_id: str, owner: ControlOwner) -> bool:
        """통제 담당자 업데이트"""
        control = self.get_control(control_id)
        if not control:
            return False
        
        control.owner = owner
        control.updated_at = datetime.now()
        return True

    def add_related_law(self, control_id: str, law: RelatedLaw) -> bool:
        """관련 법령 추가"""
        control = self.get_control(control_id)
        if not control:
            return False
        
        control.related_laws.append(law)
        control.updated_at = datetime.now()
        return True

    def get_control_matrix(self) -> Dict[str, Any]:
        """통제 매트릭스 (카테고리별 통제 현황)"""
        matrix = {}
        
        for control in self._controls.values():
            category = control.category
            if category not in matrix:
                matrix[category] = []
            matrix[category].append(control)
        
        return matrix


# 전역 인스턴스
control_engine = ControlEngine()
