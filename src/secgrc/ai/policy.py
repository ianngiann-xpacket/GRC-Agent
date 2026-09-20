"""AI 조사 정책 및 예산 한도 모듈 (Section 57)."""

from pydantic import Field, field_validator
from secgrc.ai.models import AIBaseModel


class AIInvestigationPolicy(AIBaseModel):
    """AI 조사 추론 예산 및 자원 상한 정책 (Section 57, 58).
    
    인공지능 추론이 무한 루프(Agentic loop)를 돌거나 대량의 저장소 데이터를 무분별하게
    읽어들이지 못하도록 엄격한 상한을 강제합니다.
    """
    max_context_records: int = Field(default=100, ge=1, le=500, description="최대 컨텍스트 레코드 수")
    max_context_bytes: int = Field(default=262144, ge=1024, le=1048576, description="최대 컨텍스트 바이트 수 (기본 256KB)")
    max_output_tokens: int = Field(default=4096, ge=128, le=16384, description="최대 출력 토큰")
    max_questions: int = Field(default=10, ge=1, le=50, description="최대 생성 질문 수")
    max_hypotheses: int = Field(default=5, ge=1, le=20, description="최대 생성 가설 수")
    max_reasoning_rounds: int = Field(default=1, ge=1, le=1, description="최대 추론 라운드 (Step 27은 엄격히 1라운드 단일 실행)")
    enforce_grounding: bool = Field(default=True, description="주장 접지 강제 여부")
    allow_unverified_claims: bool = Field(default=False, description="미검증 주장 허용 여부 (항상 False)")

    @field_validator("max_reasoning_rounds")
    @classmethod
    def check_no_agentic_loop(cls, v: int) -> int:
        if v != 1:
            raise ValueError("Step 27 strictly prohibits multi-round agentic loops (max_reasoning_rounds must be 1).")
        return 1

    @field_validator("allow_unverified_claims")
    @classmethod
    def check_unverified_claims(cls, v: bool) -> bool:
        if v:
            raise ValueError("Unverified claims are strictly forbidden in AI reasoning.")
        return False


DEFAULT_AI_POLICY = AIInvestigationPolicy()
