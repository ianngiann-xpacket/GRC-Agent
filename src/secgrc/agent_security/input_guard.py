"""7대 카테고리 기반 프롬프트 인젝션 탐지 및 입력 검증(Input Guard) 모듈입니다."""

import re
from typing import Any, Dict, List, Tuple
from secgrc.agent_security.models import InjectionCategory, InjectionDetectionResult

# 7대 인젝션 카테고리별 정밀 정규식 패턴 및 위험도/신뢰도 설정
CATEGORY_DETECTORS: Dict[InjectionCategory, Dict[str, Any]] = {
    InjectionCategory.INSTRUCTION_OVERRIDE: {
        "severity": "HIGH",
        "base_confidence": 0.95,
        "patterns": [
            re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above|former)\s+(instructions?|directions?|rules?|directives?)"),
            re.compile(r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|context|prompts?|directives?|rules?)"),
            re.compile(r"(?i)forget\s+(all\s+)?(your\s+)?(rules|instructions|system\s+prompts?)"),
            re.compile(r"(?i)override\s+(all\s+)?(previous|current)\s+settings"),
            re.compile(r"(?i)(모든\s*)?(이전|기존|앞의)\s*(지침|지시|규칙|설정|명령)(을|를)?\s*(무시|무효화|삭제|취소|잊어)"),
            re.compile(r"(?i)ignore\s+(the\s+)?(grc\s+)?(policy|rules|system)"),
        ],
    },
    InjectionCategory.SYSTEM_PROMPT_EXTRACTION: {
        "severity": "HIGH",
        "base_confidence": 0.90,
        "patterns": [
            re.compile(r"(?i)(reveal|show|print|display|dump|repeat|output|copy)\s+(your\s+)?(?:(?:initial|system|hidden|internal)\s+)*(prompt|instructions|developer\s+message)"),
            re.compile(r"(?i)what\s+are\s+your\s+(exact\s+)?(instructions|system\s+prompts?)"),
            re.compile(r"(?i)tell\s+me\s+what\s+you\s+were\s+told\s+to\s+do"),
            re.compile(r"(?i)(시스템\s*프롬프트|내부\s*지침|가드레일\s*프롬프트|system\s*prompt)(를|을)?\s*(보여|출력|공개|복사|알려|덤프|그대로)"),
            re.compile(r"(?i)너의\s*(초기|내부)?\s*(지침|지시|프롬프트)"),
            re.compile(r"(?i)(copilot|guardrail)\s+system\s+(instruction|prompt)"),
        ],
    },
    InjectionCategory.ROLE_MANIPULATION: {
        "severity": "HIGH",
        "base_confidence": 0.90,
        "patterns": [
            re.compile(r"(?i)you\s+are\s+(now\s+)?(an?\s+)?(administrator|admin|root|system|superuser|developer|dan)"),
            re.compile(r"(?i)act\s+as\s+(an?\s+)?(unrestricted|jailbroken|root|superuser|administrator|admin)"),
            re.compile(r"(?i)pretend\s+to\s+be\s+(an?\s+)?(admin|owner|root)"),
            re.compile(r"(?i)switch\s+role\s+to\s+(administrator|admin|ciso|root)"),
            re.compile(r"(?i)(관리자|admin|ciso|보안책임자|루트|root)(\s*(?:로|로서|로\s*전환|역할을|권한으로|권한을))"),
            re.compile(r"(?i)(bypass|override|ignore)\s+.*?(role|permission|restriction|privilege)"),
            re.compile(r"(?i)(role|권한)(을|를)?\s*(bypass|우회|무시)"),
        ],
    },
    InjectionCategory.FAKE_AUTHORITY: {
        "severity": "HIGH",
        "base_confidence": 0.85,
        "patterns": [
            re.compile(r"(?i)by\s+order\s+of\s+(the\s+)?(security\s+team|ciso|management|ceo|director)"),
            re.compile(r"(?i)emergency\s+override\s+(code|protocol|token|alpha)"),
            re.compile(r"(?i)special\s+authorization\s+granted"),
            re.compile(r"(?i)(the\s+)?(compliance\s+)?(auditor|ciso|security\s+team)\s+has\s+authorized"),
            re.compile(r"(?i)authorized\s+unrestricted\s+tool\s+access"),
            re.compile(r"(?i)i\s+am\s+(the\s+)?(ciso|administrator|admin|auditor)"),
            re.compile(r"(?i)나는\s*(ciso|보안책임자|관리자|최고관리자|admin)다"),
            re.compile(r"(?i)(ciso|보안팀|관리자)(의\s*명령|의\s*지시|의\s*승인)"),
        ],
    },
    InjectionCategory.TOOL_INVOCATION_REQUEST: {
        "severity": "CRITICAL",
        "base_confidence": 0.95,
        "patterns": [
            re.compile(r"(?i)run\s+(the\s+)?gcloud\s+"),
            re.compile(r"(?i)execute\s+(bash|sh|cmd|powershell|shell)"),
            re.compile(r"(?i)gcloud\s+(compute|storage|iam|kms)\s+(instances\s+)?(delete|destroy|stop|modify)"),
            re.compile(r"(?i)subprocess\.run|os\.system|exec\("),
            re.compile(r"(?i)(execute|run|apply)\s+remediation"),
            re.compile(r"(?i)(call|invoke)\s+mcp\s+tool"),
            re.compile(r"(?i)(방화벽|iam|정책|클라우드|리소스|자원|cloud|resource|권한).*?(변경|수정|삭제|생성|폐쇄|적용|delete|modify|destroy)"),
            re.compile(r"(?i)(remediation|조치|시정조치)(를|을)?\s*(실행|수행|적용)"),
            re.compile(r"(?i)(mcp\s*도구|mcp\s*tool|도구)(를|을)?\s*(호출|실행)"),
        ],
    },
    InjectionCategory.SECRET_EXTRACTION: {
        "severity": "CRITICAL",
        "base_confidence": 0.95,
        "patterns": [
            re.compile(r"(?i)(print|reveal|expose|give\s+me|dump|leak|return)\s+(?:the\s+|all\s+|internal\s+|env\s+)*(api[_\s-]?keys?|secrets?|passwords?|credentials?|private[_\s-]?keys?|tokens?|metadata)"),
            re.compile(r"(?i)what\s+is\s+the\s+(gemini[_-]?api[_-]?key|api[_-]?key|admin\s+password)"),
            re.compile(r"(?i)(dump|exfiltrate|leak|export)\s+all\s+(internal\s+)?(metadata|secrets?|credentials?)"),
            re.compile(r"(?i)canary_secret[_\w]*"),
            re.compile(r"(?i)(환경변수|시크릿|비밀번호|패스워드|토큰|api\s*키|api\s*key|인증정보)(를|을)?\s*(보여|출력|알려|덤프|유출|추출)"),
        ],
    },
    InjectionCategory.POLICY_OVERRIDE: {
        "severity": "CRITICAL",
        "base_confidence": 0.90,
        "patterns": [
            re.compile(r"(?i)(ignore|bypass|disable|override)\s+(the\s+)?(audit\s+policy|security\s+policy|guardrails?|compliance\s+rules?|risk\s+engine)"),
            re.compile(r"(?i)(force|mark)\s+(this\s+control\s+as\s+)?pass"),
            re.compile(r"(?i)change\s+(audit\s+status|verdict)\s+to\s+pass"),
            re.compile(r"(?i)change\s+[A-Za-z0-9_.-]+\s+(?:risk\s+score|status|verdict)\s+to\s+"),
            re.compile(r"(?i)(change|set|modify|update)\s+.*?(risk\s*score|score|status|verdict)\s*(to|=)\s*"),
            re.compile(r"(?i)(상태|결과|판정)(를|을)?\s*pass(로|로\s*변경|로\s*처리|로\s*수정)"),
            re.compile(r"(?i)(위험\s*점수|점수)(를|을)?\s*(\d+)(점)?(으로\s*변경|으로\s*수정|으로\s*조정)"),
            re.compile(r"(?i)pass(라고|로)\s*(해줘|판정|처리)"),
        ],
    },
}


class InputGuard:
    """프롬프트 인젝션 및 비신뢰 입력(Untrusted Input)을 탐지, 차단, 중화하는 보안 가드입니다."""

    @classmethod
    def detect_injection(cls, text: str) -> InjectionDetectionResult:
        """문자열에서 7대 카테고리 인젝션 시도를 정밀 분석합니다."""
        if not text or not isinstance(text, str):
            return InjectionDetectionResult(detected=False, action="ALLOW")

        for category, config in CATEGORY_DETECTORS.items():
            for pattern in config["patterns"]:
                match = pattern.search(text)
                if match:
                    sev = config["severity"]
                    action = "BLOCK" if sev in ("HIGH", "CRITICAL") else "NEUTRALIZE"
                    sanitized = pattern.sub(f"[UNTRUSTED_{category.value}_REMOVED]", text)
                    return InjectionDetectionResult(
                        detected=True,
                        category=category,
                        severity=sev,
                        confidence=config["base_confidence"],
                        action=action,
                        matched_pattern=match.group(0),
                        sanitized_text=sanitized,
                    )

        return InjectionDetectionResult(
            detected=False,
            severity="LOW",
            confidence=0.0,
            action="ALLOW",
            sanitized_text=text,
        )

    @classmethod
    def sanitize(cls, text: str) -> str:
        """모든 인젝션 의심 구문을 안전한 데이터 태그로 치환하여 반환합니다."""
        if not text or not isinstance(text, str):
            return ""

        sanitized = text
        for category, config in CATEGORY_DETECTORS.items():
            for pattern in config["patterns"]:
                if pattern.search(sanitized):
                    sanitized = pattern.sub(f"[UNTRUSTED_{category.value}_REMOVED]", sanitized)
        return sanitized

    @classmethod
    def validate_input(cls, text: str) -> Tuple[bool, InjectionDetectionResult]:
        """입력이 안전한지 평가하고, 차단 대상(BLOCK)인 경우 False를 반환합니다."""
        res = cls.detect_injection(text)
        if res.detected and res.action == "BLOCK":
            return False, res
        return True, res
