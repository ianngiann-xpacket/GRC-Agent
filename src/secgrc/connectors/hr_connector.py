"""HR 시스템 커넥터 - 입퇴사, 조직 이동, 겸직 정보 수집"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import uuid


class EmployeeRecord(BaseModel):
    """직원 레코드"""
    employee_id: str = Field(description="직원 ID")
    name: str = Field(description="이름")
    email: str = Field(description="이메일")
    department: str = Field(description="부서")
    position: str = Field(description="직책")
    employment_status: str = Field(description="고용 상태 (ACTIVE/TERMINATED/LEAVE)")
    hire_date: datetime = Field(description="입사일")
    termination_date: Optional[datetime] = Field(default=None, description="퇴사일")
    manager: Optional[str] = Field(default=None, description="상사")
    roles: List[str] = Field(default_factory=list, description="역할 목록")
    concurrent_positions: List[str] = Field(default_factory=list, description="겸직 목록")


class HRConnector:
    """HR 시스템 커넥터 (읽기 전용)"""

    def __init__(self, hr_system_endpoint: Optional[str] = None):
        self.endpoint = hr_system_endpoint
        self._employees: Dict[str, EmployeeRecord] = {}
        self._initialized = False

    def initialize(self):
        """커넥터 초기화 (실제 구현에서는 HR 시스템 연결)"""
        # 여기서는 시뮬레이션 데이터를 생성합니다
        self._employees = {
            "EMP001": EmployeeRecord(
                employee_id="EMP001",
                name="김철수",
                email="kim@company.com",
                department="IT",
                position="보안팀장",
                employment_status="ACTIVE",
                hire_date=datetime(2020, 1, 15),
                roles=["CISO", "보안관리자"]
            ),
            "EMP002": EmployeeRecord(
                employee_id="EMP002",
                name="이영희",
                email="lee@company.com",
                department="개발",
                position="팀장",
                employment_status="ACTIVE",
                hire_date=datetime(2019, 3, 10),
                roles=["개발팀장"],
                concurrent_positions=["CPO"]  # 겸직 위반 가능성
            ),
            "EMP003": EmployeeRecord(
                employee_id="EMP003",
                name="박민수",
                email="park@company.com",
                department="인사",
                position="대리",
                employment_status="TERMINATED",
                hire_date=datetime(2021, 5, 20),
                termination_date=datetime(2024, 8, 15),
                roles=["인사담당자"]
            ),
        }
        self._initialized = True

    def get_employee(self, employee_id: str) -> Optional[EmployeeRecord]:
        """직원 정보 조회"""
        if not self._initialized:
            self.initialize()
        return self._employees.get(employee_id)

    def get_all_employees(self) -> List[EmployeeRecord]:
        """모든 직원 조회"""
        if not self._initialized:
            self.initialize()
        return list(self._employees.values())

    def get_terminated_employees(self, days_back: int = 30) -> List[EmployeeRecord]:
        """최근 퇴사 직원 조회"""
        if not self._initialized:
            self.initialize()
        
        cutoff_date = datetime.now() - timedelta(days=days_back)
        return [
            emp for emp in self._employees.values()
            if emp.employment_status == "TERMINATED" and emp.termination_date and emp.termination_date >= cutoff_date
        ]

    def get_employees_with_concurrent_positions(self) -> List[EmployeeRecord]:
        """겸직 직원 조회"""
        if not self._initialized:
            self.initialize()
        
        return [
            emp for emp in self._employees.values()
            if emp.concurrent_positions
        ]

    def get_department_employees(self, department: str) -> List[EmployeeRecord]:
        """부서별 직원 조회"""
        if not self._initialized:
            self.initialize()
        
        return [
            emp for emp in self._employees.values()
            if emp.department == department
        ]

    def check_ciso_cpo_compliance(self) -> Dict[str, Any]:
        """CISO/CPO 지정 및 겸직 규정 준수 확인"""
        if not self._initialized:
            self.initialize()
        
        ciso = None
        cpo = None
        violations = []
        
        for emp in self._employees.values():
            if "CISO" in emp.roles:
                ciso = emp
            if "CPO" in emp.roles:
                cpo = emp
        
        # CISO/CPO 겸직 확인
        if ciso and cpo and ciso.employee_id == cpo.employee_id:
            violations.append("CISO와 CPO가 동일인에 의해 겸직되고 있습니다.")
        
        # 겸직 규정 확인
        if ciso:
            if ciso.concurrent_positions:
                violations.append(f"CISO {ciso.name}이(가) {ciso.concurrent_positions}을(를) 겸직하고 있습니다.")
        
        return {
            "ciso_designated": ciso is not None,
            "ciso_name": ciso.name if ciso else None,
            "cpo_designated": cpo is not None,
            "cpo_name": cpo.name if cpo else None,
            "violations": violations,
            "total_employees": len(self._employees)
        }


# 전역 인스턴스
hr_connector = HRConnector()
