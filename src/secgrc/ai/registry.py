"""AI 프로바이더 및 프롬프트 템플릿 레지스트리 모듈."""

from typing import Dict, Optional
from secgrc.ai.prompts import PromptTemplate, STANDARD_REASONING_TEMPLATES
from secgrc.ai.provider import LLMProvider, MockLLMProvider


class AIProviderRegistry:
    """LLM 프로바이더 등록 및 조회 레지스트리"""

    def __init__(self):
        self._providers: Dict[str, LLMProvider] = {}
        # 기본 결정론적 목 프로바이더 자동 등록
        mock = MockLLMProvider()
        self._providers[mock.provider_id] = mock

    def register(self, provider: LLMProvider) -> None:
        self._providers[provider.provider_id] = provider

    def get(self, provider_id: str) -> Optional[LLMProvider]:
        return self._providers.get(provider_id)

    def get_default(self) -> LLMProvider:
        if "mock-provider" in self._providers:
            return self._providers["mock-provider"]
        return next(iter(self._providers.values()))


class AIPromptRegistry:
    """버전 관리되는 프롬프트 템플릿 레지스트리"""

    def __init__(self):
        self._templates: Dict[str, PromptTemplate] = {}
        for tpl in STANDARD_REASONING_TEMPLATES.values():
            self._templates[tpl.template_id] = tpl

    def register(self, template: PromptTemplate) -> None:
        key = template.template_id
        self._templates[key] = template

    def get(self, template_id: str) -> Optional[PromptTemplate]:
        return self._templates.get(template_id)


default_provider_registry = AIProviderRegistry()
default_prompt_registry = AIPromptRegistry()
