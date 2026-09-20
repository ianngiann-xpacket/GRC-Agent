"""Red Team 보안 보증 보고서(Markdown 및 JSON) 생성 모듈입니다."""

import json
from typing import Any, Dict, List
from secgrc.redteam.models import RedTeamResult, RedTeamSummary


class RedTeamReporter:
    """Red Team 검증 결과로부터 경영진 및 보안 담당자용 보고서를 생성하는 리포터"""

    @staticmethod
    def generate_markdown_report(summary: RedTeamSummary, results: List[RedTeamResult]) -> str:
        """Markdown 형식의 AI Agent Security Assurance Report 생성"""
        lines = [
            "# AI AGENT SECURITY ASSURANCE REPORT",
            "",
            f"**Overall Status:** {summary.overall_status}",
            f"**Resilience Score:** {summary.resilience_score} / 100",
            "",
            "## Summary Metrics",
            f"- **Scenarios Evaluated:** {summary.total_scenarios}",
            f"- **Detected:** {summary.detected} ({summary.detection_rate}%)",
            f"- **Blocked:** {summary.blocked} ({summary.block_rate}%)",
            f"- **Allowed (Neutralized/Benign):** {summary.allowed}",
            "",
            "## Severe Threat Indicators",
            f"- **Secret Leakage:** {summary.secret_leakages}",
            f"- **Unauthorized Tool Execution:** {summary.unauthorized_tool_executions}",
            f"- **Approval Bypass:** {summary.approval_bypasses}",
            f"- **Policy Violations:** {summary.policy_violations}",
            "",
        ]

        # 주요 취약점(Critical Findings) 섹션
        if summary.critical_findings:
            lines.append("## Critical Findings")
            lines.append("")
            for f in summary.critical_findings:
                lines.extend([
                    f"### [{f.get('severity', 'P1')}] {f.get('category')}",
                    f"- **Scenario:** `{f.get('scenario_id')}`",
                    f"- **Status:** FAIL",
                    f"- **Expected Decision:** `{f.get('expected')}`",
                    f"- **Actual Decision:** `{f.get('actual')}`",
                    "",
                    "**Evidence / Explanation:**",
                    f"```text\n{f.get('explanation')}\n```",
                    "",
                    "**Recommendation:**",
                    f"> {f.get('remediation')}",
                    "",
                    "**Retest:** Required",
                    "",
                ])
        else:
            lines.append("## Security Findings")
            lines.append("✅ **No critical security control failures detected.** All simulated attack scenarios were successfully contained and blocked by the deterministic defense layer.")
            lines.append("")

        # 전체 시나리오 실행 결과 표
        lines.append("## Detailed Scenario Results")
        lines.append("| Scenario ID | Category | Severity | Blocked | Detected | Actual Decision | Status |")
        lines.append("|:---|:---|:---|:---:|:---:|:---|:---:|")

        for r in results:
            st = "PASS" if r.blocked and not r.policy_violated and not r.secret_leaked else "FAIL"
            b_mark = "✅" if r.blocked else "❌"
            d_mark = "✅" if r.detected else "❌"
            lines.append(
                f"| `{r.scenario_id}` | {r.category.value} | {r.severity} | {b_mark} | {d_mark} | `{r.actual_decision}` | **{st}** |"
            )

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def generate_json_report(summary: RedTeamSummary, results: List[RedTeamResult]) -> str:
        """JSON 형식의 완전한 기계 판독형 보고서 직렬화"""
        payload = {
            "summary": summary.model_dump(),
            "results": [r.model_dump() for r in results],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)
