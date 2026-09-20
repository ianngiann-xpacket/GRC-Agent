"""AI 조사 컨텍스트 및 안전 빌더 모듈 (Section 21 - 23, 26)."""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from pydantic import Field, field_validator

from secgrc.ai.models import AIBaseModel, validate_id_str, validate_id_list
from secgrc.ai.policy import AIInvestigationPolicy, DEFAULT_AI_POLICY


class AIInvestigationContext(AIBaseModel):
    """범위가 한정된 AI 조사 컨텍스트 모델 (Section 21, 23).
    
    오직 검증된 사실, 증적, 관계, 권위 있는 평가 결과 및 변경 이벤트만을 담습니다.
    도구 실행 권한(allowed_operations)은 항상 빈 목록([])이어야 합니다.
    """
    scope: str = Field(description="인가된 조사 스코프")
    tenant_id: str = Field(default="default", description="테넌트 식별자")
    investigation_id: str = Field(description="소속 조사 식별자")
    allowed_entity_ids: List[str] = Field(default_factory=list, description="인가된 엔티티 ID 목록")
    allowed_data_types: List[str] = Field(default_factory=lambda: ["FACT", "EVIDENCE", "RELATIONSHIP", "ASSESSMENT"], description="인가된 데이터 유형")
    allowed_operations: List[str] = Field(default_factory=list, description="도구 실행 권한 (반드시 빈 목록)")
    facts: List[Dict[str, Any]] = Field(default_factory=list, description="검증된 사실 목록")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="검증된 증적 목록")
    relationships: List[Dict[str, Any]] = Field(default_factory=list, description="검증된 관계 목록")
    assessments: List[Dict[str, Any]] = Field(default_factory=list, description="권위 있는 평가 결과 목록")
    changes: List[Dict[str, Any]] = Field(default_factory=list, description="변경 감지 이벤트 목록")
    context_hash: str = Field(default="", description="컨텍스트 SHA-256 해시")

    @field_validator("investigation_id")
    @classmethod
    def check_inv_id(cls, v: str) -> str:
        return validate_id_str(v, "investigation_id")

    @field_validator("allowed_entity_ids")
    @classmethod
    def check_entities_list(cls, v: List[str]) -> List[str]:
        return validate_id_list(v, "allowed_entity_ids")

    @field_validator("allowed_operations")
    @classmethod
    def check_no_tools(cls, v: List[str]) -> List[str]:
        if v:
            raise ValueError("LLM has no tools. allowed_operations must strictly be empty (Section 23).")
        return []

    def compute_context_hash(self) -> str:
        """컨텍스트 내용 기반 결정론적 SHA-256 해시를 계산합니다."""
        payload = {
            "scope": self.scope,
            "tenant_id": self.tenant_id,
            "investigation_id": self.investigation_id,
            "allowed_entity_ids": sorted(self.allowed_entity_ids),
            "allowed_data_types": sorted(self.allowed_data_types),
            "facts": self.facts,
            "evidence": self.evidence,
            "relationships": self.relationships,
            "assessments": self.assessments,
            "changes": self.changes,
        }
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class AIContextBuilder:
    """조사 데이터로부터 안전하고 스코프가 격리된 AI 컨텍스트를 구성하는 빌더 (Section 22, 26)."""

    def __init__(self, policy: Optional[AIInvestigationPolicy] = None):
        self.policy = policy or DEFAULT_AI_POLICY

    @staticmethod
    def redact_secrets_text(text: str) -> str:
        """텍스트 내 API 키, 베어러 토큰, 패스워드, 개인키를 마스킹합니다."""
        if not text or not isinstance(text, str):
            return ""
        # 1. 개인키 블록
        redacted = re.sub(
            r"-----BEGIN[ A-Z_-]+PRIVATE KEY-----[\s\S]*?-----END[ A-Z_-]+PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
            text,
        )
        # 2. 키/토큰/비밀번호 패턴
        redacted = re.sub(
            r"(?i)\b(bearer)\s+[A-Za-z0-9_\-\.]{8,}",
            r"\1 [REDACTED]",
            redacted,
        )
        redacted = re.sub(
            r"(?i)(api[_-]?key|bearer|token|secret|password|passwd|auth)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{8,}['\"]?",
            r"\1: [REDACTED]",
            redacted,
        )
        return redacted

    @classmethod
    def sanitize_untrusted_data(cls, raw_val: Any) -> Any:
        """임의의 입력 증적 및 필드를 안전하게 무해화하고 XML 구분 태그 탈출을 방지합니다."""
        if isinstance(raw_val, str):
            clean = cls.redact_secrets_text(raw_val)
            clean = clean.replace("</UNTRUSTED_DATA>", "[ESCAPED_UNTRUSTED_DATA]")
            clean = clean.replace("<UNTRUSTED_DATA>", "[ESCAPED_UNTRUSTED_DATA]")
            return clean
        elif isinstance(raw_val, dict):
            return {k: cls.sanitize_untrusted_data(v) for k, v in raw_val.items()}
        elif isinstance(raw_val, list):
            return [cls.sanitize_untrusted_data(x) for x in raw_val]
        return raw_val

    @classmethod
    def wrap_untrusted(cls, content: str) -> str:
        """간접 프롬프트 인젝션 방어를 위해 외부/증적 데이터를 태그로 감쌉니다 (Section 26)."""
        safe_content = cls.sanitize_untrusted_data(content)
        return f"<UNTRUSTED_DATA>\n{safe_content}\n</UNTRUSTED_DATA>"

    def build_context(
        self,
        investigation_id: str,
        scope: str,
        allowed_entity_ids: List[str],
        facts: Optional[List[Dict[str, Any]]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
        relationships: Optional[List[Dict[str, Any]]] = None,
        assessments: Optional[List[Dict[str, Any]]] = None,
        changes: Optional[List[Dict[str, Any]]] = None,
        tenant_id: str = "default",
    ) -> AIInvestigationContext:
        """정책 제약과 스코프를 검증하여 정제된 컨텍스트를 빌드합니다."""
        facts = facts or []
        evidence = evidence or []
        relationships = relationships or []
        assessments = assessments or []
        changes = changes or []

        # 1. 총 레코드 수 제한 검사
        total_records = len(facts) + len(evidence) + len(relationships) + len(assessments) + len(changes)
        if total_records > self.policy.max_context_records:
            raise ValueError(
                f"Context record count ({total_records}) exceeds policy limit ({self.policy.max_context_records})."
            )

        # 2. 엔티티 스코프 필터링 및 살균
        allowed_set = set(allowed_entity_ids)

        filtered_facts = []
        for f in facts:
            ent = f.get("entity_id") or f.get("source_id")
            if not allowed_set or ent in allowed_set or f.get("fact_id") in allowed_set:
                filtered_facts.append(self.sanitize_untrusted_data(f))

        filtered_evidence = []
        for e in evidence:
            ent = e.get("entity_id") or e.get("resource_id") or e.get("evidence_id")
            if not allowed_set or ent in allowed_set or e.get("evidence_id") in allowed_set:
                filtered_evidence.append(self.sanitize_untrusted_data(e))

        filtered_relationships = [self.sanitize_untrusted_data(r) for r in relationships]
        filtered_assessments = [self.sanitize_untrusted_data(a) for a in assessments]
        filtered_changes = [self.sanitize_untrusted_data(c) for c in changes]

        ctx = AIInvestigationContext(
            scope=scope,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            allowed_entity_ids=allowed_entity_ids,
            allowed_operations=[],  # 빈 리스트 보장
            facts=filtered_facts,
            evidence=filtered_evidence,
            relationships=filtered_relationships,
            assessments=filtered_assessments,
            changes=filtered_changes,
        )
        ctx.context_hash = ctx.compute_context_hash()

        # 3. 바이트 크기 제한 검사
        serialized_len = len(json.dumps(ctx.model_dump(), default=str).encode("utf-8"))
        if serialized_len > self.policy.max_context_bytes:
            raise ValueError(
                f"Context payload size ({serialized_len} bytes) exceeds policy limit ({self.policy.max_context_bytes} bytes)."
            )

        return ctx
