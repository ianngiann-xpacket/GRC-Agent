"""IAM/AD 시스템 커넥터 - 계정, 권한, 비밀번호 정책 수집"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field


class UserAccount(BaseModel):
    """사용자 계정"""
    account_id: str = Field(description="계정 ID")
    username: str = Field(description="사용자명")
    display_name: str = Field(description="표시명")
    email: str = Field(description="이메일")
    department: str = Field(description="부서")
    account_type: str = Field(description="계정 유형 (USER/ADMIN/SERVICE)")
    status: str = Field(description="계정 상태 (ACTIVE/DISABLED/LOCKED)")
    created_date: datetime = Field(description="생성일")
    last_login: Optional[datetime] = Field(default=None, description="최근 로그인")
    password_last_changed: Optional[datetime] = Field(default=None, description="비밀번호 변경일")
    mfa_enabled: bool = Field(default=False, description="MFA 활성화 여부")
    groups: List[str] = Field(default_factory=list, description="그룹 멤버십")
    permissions: List[str] = Field(default_factory=list, description="권한 목록")


class IAMConnector:
    """IAM/AD 시스템 커넥터 (읽기 전용)"""

    def __init__(self, iam_endpoint: Optional[str] = None):
        self.endpoint = iam_endpoint
        self._accounts: Dict[str, UserAccount] = {}
        self._password_policy: Dict[str, Any] = {}
        self._initialized = False

    def initialize(self):
        """커넥터 초기화 (실제 구현에서는 IAM 시스템 연결)"""
        # 시뮬레이션 데이터 생성
        self._accounts = {
            "user001": UserAccount(
                account_id="user001",
                username="kim.cs",
                display_name="김철수",
                email="kim@company.com",
                department="IT",
                account_type="USER",
                status="ACTIVE",
                created_date=datetime(2020, 1, 15),
                last_login=datetime.now() - timedelta(days=2),
                password_last_changed=datetime.now() - timedelta(days=45),
                mfa_enabled=True,
                groups=["IT-Staff", "Security-Team"],
                permissions=["read", "write"]
            ),
            "admin001": UserAccount(
                account_id="admin001",
                username="admin",
                display_name="관리자",
                email="admin@company.com",
                department="IT",
                account_type="ADMIN",
                status="ACTIVE",
                created_date=datetime(2019, 1, 1),
                last_login=datetime.now() - timedelta(hours=3),
                password_last_changed=datetime.now() - timedelta(days=30),
                mfa_enabled=True,
                groups=["Domain-Admins", "Enterprise-Admins"],
                permissions=["all"]
            ),
            "service001": UserAccount(
                account_id="service001",
                username="svc_backup",
                display_name="백업 서비스",
                email="svc.backup@company.com",
                department="IT",
                account_type="SERVICE",
                status="ACTIVE",
                created_date=datetime(2020, 6, 1),
                last_login=datetime.now() - timedelta(hours=1),
                password_last_changed=datetime.now() - timedelta(days=180),
                mfa_enabled=False,
                groups=["Service-Accounts"],
                permissions=["backup", "restore"]
            ),
            "user002": UserAccount(
                account_id="user002",
                username="lee.yh",
                display_name="이영희",
                email="lee@company.com",
                department="개발",
                account_type="USER",
                status="ACTIVE",
                created_date=datetime(2019, 3, 10),
                last_login=datetime.now() - timedelta(days=1),
                password_last_changed=datetime.now() - timedelta(days=120),
                mfa_enabled=False,  # MFA 미적용
                groups=["Dev-Team"],
                permissions=["read", "write", "deploy"]
            ),
        }
        
        # 비밀번호 정책 시뮬레이션
        self._password_policy = {
            "min_length": 8,
            "max_age_days": 90,
            "complexity_required": True,
            "history_count": 5,
            "lockout_threshold": 5,
            "lockout_duration_minutes": 30
        }
        
        self._initialized = True

    def get_account(self, account_id: str) -> Optional[UserAccount]:
        """계정 정보 조회"""
        if not self._initialized:
            self.initialize()
        return self._accounts.get(account_id)

    def get_all_accounts(self) -> List[UserAccount]:
        """모든 계정 조회"""
        if not self._initialized:
            self.initialize()
        return list(self._accounts.values())

    def get_active_accounts(self) -> List[UserAccount]:
        """활성 계정 조회"""
        if not self._initialized:
            self.initialize()
        return [acc for acc in self._accounts.values() if acc.status == "ACTIVE"]

    def get_admin_accounts(self) -> List[UserAccount]:
        """관리자 계정 조회"""
        if not self._initialized:
            self.initialize()
        return [acc for acc in self._accounts.values() if acc.account_type == "ADMIN"]

    def get_service_accounts(self) -> List[UserAccount]:
        """서비스 계정 조회"""
        if not self._initialized:
            self.initialize()
        return [acc for acc in self._accounts.values() if acc.account_type == "SERVICE"]

    def get_accounts_without_mfa(self) -> List[UserAccount]:
        """MFA 미적용 계정 조회"""
        if not self._initialized:
            self.initialize()
        return [acc for acc in self._accounts.values() if not acc.mfa_enabled]

    def get_password_policy(self) -> Dict[str, Any]:
        """비밀번호 정책 조회"""
        if not self._initialized:
            self.initialize()
        return self._password_policy

    def check_password_policy_compliance(self) -> Dict[str, Any]:
        """비밀번호 정책 준수 확인"""
        if not self._initialized:
            self.initialize()
        
        violations = []
        
        # 비밀번호 만료 초과 계정 확인
        now = datetime.now()
        for acc in self._accounts.values():
            if acc.password_last_changed:
                days_since_change = (now - acc.password_last_changed).days
                if days_since_change > self._password_policy["max_age_days"]:
                    violations.append({
                        "account": acc.username,
                        "issue": f"비밀번호 변경 후 {days_since_change}일 경과 (정책: {self._password_policy['max_age_days']}일)",
                        "severity": "MEDIUM"
                    })
        
        # MFA 미적용 계정 확인
        no_mfa_accounts = [acc.username for acc in self.get_accounts_without_mfa()]
        if no_mfa_accounts:
            violations.append({
                "issue": f"MFA 미적용 계정 {len(no_mfa_accounts)}개: {', '.join(no_mfa_accounts)}",
                "severity": "HIGH",
                "accounts": no_mfa_accounts
            })
        
        return {
            "policy": self._password_policy,
            "violations": violations,
            "total_accounts": len(self._accounts),
            "active_accounts": len(self.get_active_accounts()),
            "admin_accounts": len(self.get_admin_accounts()),
            "service_accounts": len(self.get_service_accounts()),
            "mfa_enabled_accounts": len([acc for acc in self._accounts.values() if acc.mfa_enabled])
        }


# 전역 인스턴스
iam_connector = IAMConnector()
