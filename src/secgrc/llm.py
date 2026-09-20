"""Google Gemini LLM 연동 및 보안 감사 추론 모듈입니다.

.env 파일에서 GEMINI_API_KEY를 안전하게 로드하고,
RAG로 검색된 ISMS-P 기준을 컨텍스트로 주입하여 전문 심사 소견을 생성합니다.
"""

import os
from pathlib import Path
from typing import Dict, Any

# python-dotenv를 통한 환경 변수 로드 (override=True로 .env 우선 적용)
try:
    from dotenv import load_dotenv
    from pathlib import Path
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    load_dotenv(dotenv_path=env_path, override=True)
except ImportError:
    pass


def get_gemini_api_key() -> str:
    """환경 변수에서 GEMINI_API_KEY를 안전하게 조회합니다."""
    key = (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()
    if not key or key == "your_gemini_api_key_here":
        return ""
    os.environ["GEMINI_API_KEY"] = key
    return key


def audit_with_llm(
    query: str,
    control_id: str,
    control_name: str,
    requirements: str
) -> Dict[str, Any]:
    """
    ISMS-P 기준과 사용자 질의를 바탕으로 LLM 감사 분석을 수행합니다.
    트래픽 급증(503) 시 대체 가용 모델로 자동 재시도하며, 실패 시 규칙 기반 모드로 안전 폴백합니다.
    """
    api_key = get_gemini_api_key()

    # [1] API Key가 설정되지 않은 경우 -> 규칙 기반 시뮬레이션 모드 작동
    if not api_key:
        return _fallback_rule_evaluation(query, control_id, control_name, requirements)

    # [2] Google GenAI SDK를 통한 실제 LLM 호출
    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        prompt = f"""당신은 대한민국 KISA ISMS-P 공인 수석 보안심사원입니다.
아래의 [ISMS-P 통제기준]을 바탕으로 사용자의 [보안 현황]을 전문적으로 감사하세요.

[ISMS-P 통제기준]
- 통제번호 및 명칭: ISMS-P {control_id} ({control_name})
- 핵심 요구사항: {requirements}

[점검 대상 보안 현황]
"{query}"

반드시 아래 형식과 구분자(===)를 엄격히 지켜 답변하세요:

판정: [적합 또는 부적합]
소견: [ISMS-P 기준과 비교한 구체적 발견 사실 및 이유]
조치: [적합 시 증적 유지 방안 / 부적합 시 구체적인 기술적·관리적 시정조치 권고]
"""

        # 트래픽 과부하(503)에 대비한 단계적 모델 폴백 리스트
        candidate_models = ["gemini-2.5-flash", "gemini-1.5-flash", "gemini-3.6-flash"]
        response = None
        last_err = None

        config = types.GenerateContentConfig(temperature=0.2)

        for model_name in candidate_models:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config,
                )
                if response and response.text:
                    break
            except Exception as err:
                last_err = err
                continue

        if response is None:
            raise last_err or RuntimeError("모든 Gemini 모델 호출 실패")

        response_text = response.text.strip()
        return _parse_llm_response(response_text, control_id, control_name)

    except ImportError:

        # 라이브러리가 아직 설치되지 않은 경우
        return _fallback_rule_evaluation(
            query, control_id, control_name, requirements,
            notice="[안내] google-genai 패키지 설치가 필요합니다 ('pip install -e .'). 현재는 규칙 기반 모드로 동작합니다."
        )
    except Exception as e:
        # 네트워크 오류 또는 유효하지 않은 API 키 처리
        masked_key = f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) >= 10 else "KEY_TOO_SHORT"
        return _fallback_rule_evaluation(
            query, control_id, control_name, requirements,
            notice=f"[안내] Gemini API 호출 실패 (식별된 키: {masked_key} / {e}). 규칙 기반 모드로 대체 동작합니다."
        )



def _parse_llm_response(text: str, control_id: str, control_name: str) -> Dict[str, Any]:
    """LLM이 생성한 텍스트에서 판정, 소견, 조치를 파싱합니다."""
    is_compliant = "부적합" not in text.splitlines()[0] and "적합" in text.splitlines()[0]

    findings = text
    recommendation = "LLM 감사 소견을 참고하여 보호대책을 이행하세요."

    lines = text.splitlines()
    for line in lines:
        if line.startswith("조치:"):
            recommendation = line.replace("조치:", "").strip()
        elif line.startswith("소견:"):
            findings = line.replace("소견:", "").strip()

    return {
        "is_compliant": is_compliant,
        "findings": f"[AI 심사 소견 (ISMS-P {control_id} {control_name})]\n{text}",
        "recommendation": recommendation,
    }


def _fallback_rule_evaluation(
    query: str,
    control_id: str,
    control_name: str,
    requirements: str,
    notice: str = "[알림: .env에 유효한 GEMINI_API_KEY가 설정되지 않아 규칙 기반 모드로 동작합니다.]"
) -> Dict[str, Any]:
    """API Key 부재 시 안전하게 동작하는 규칙 기반 폴백 함수"""
    risk_keywords = [
        "평문", "암호화하지", "공유", "미지정", "강제",
        "삭제하지", "파기하지", "미삭제", "미파기", "보관하고", "영구",
        "없이", "미수행", "미적용", "방치", "겸직"
    ]
    has_risk = any(keyword in query for keyword in risk_keywords)

    if has_risk:
        return {
            "is_compliant": False,
            "findings": (
                f"{notice}\n"
                f"[근거: ISMS-P {control_id} {control_name}]\n"
                f"요구사항: {requirements}\n"
                f"발견사실: 보안 위반 사항이 확인되어 부적합(결함)으로 판정합니다."
            ),
            "recommendation": f"[시정조치 권고] ISMS-P {control_id}({control_name}) 결함 사항에 대해 즉시 보호대책을 수립하세요.",
        }
    else:
        return {
            "is_compliant": True,
            "findings": (
                f"{notice}\n"
                f"[근거: ISMS-P {control_id} {control_name}]\n"
                f"요구사항: {requirements}\n"
                f"발견사실: 요구사항에 부합하는 안전한 보안 통제가 적용되어 적합으로 판정합니다."
            ),
            "recommendation": f"[적합 유지 권고] ISMS-P {control_id} 인증 유지를 위해 증적을 주기적으로 관리하세요.",
        }
