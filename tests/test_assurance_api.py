"""ISMS-P Audit Assurance 콘솔(v2) API·페이지 계약 테스트.

실행: PYTHONPATH=src python3 -m unittest tests.test_assurance_api -v
(pytest 미설치 환경이므로 stdlib unittest + FastAPI TestClient 사용)
"""

import os
import unittest

os.environ.setdefault("GRC_WEB_AUTH", "disabled")  # 테스트는 인증 없이 실행

from fastapi.testclient import TestClient

from secgrc.web.certification_app import app


class AssuranceAPITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    # ---------- 페이지 렌더링 ----------
    def test_all_pages_render(self):
        for path in [
            "/audit", "/controls", "/controls/2.6.3", "/evidence", "/gap",
            "/findings", "/replay", "/collection", "/intake", "/connections",
            "/reports", "/history", "/criteria", "/users", "/settings",
        ]:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_root_redirects_to_control_center(self):
        res = self.client.get("/", follow_redirects=False)
        self.assertEqual(res.status_code, 307)
        self.assertEqual(res.headers["location"], "/audit")

    def test_control_center_shell(self):
        html = self.client.get("/audit").text
        for marker in ["Audit Control Center", "준비도", "증적 확보율",
                       "통제항목 현황", "주요 이슈", "실시간 활동 내역",
                       "AI 심사지원 에이전트", "Audit Time Machine"]:
            self.assertIn(marker, html)
        # 레거시 메뉴 부재
        for legacy in ["Red Team", "에이전트 보안", "연속 GRC", "Closed Loop"]:
            self.assertNotIn(legacy, html)

    # ---------- API 계약 ----------
    def test_kpis_contract(self):
        d = self.client.get("/api/audit/kpis").json()
        self.assertTrue(d["demo"])
        for k in ["readiness", "evidence", "gaps", "findings", "actions"]:
            self.assertIn(k, d)
        self.assertEqual(d["readiness"]["total"], 101)
        self.assertTrue(d["readiness"]["href"].startswith("/controls"))

    def test_landscape_structure(self):
        d = self.client.get("/api/audit/landscape").json()
        self.assertEqual(d["total"], 101)
        self.assertEqual([x["count"] for x in d["domains"]], [16, 64, 21])
        counts = sum(sum(s["counts"].values()) for s in [d] for s in [])  # noqa
        states = {}
        for dom in d["domains"]:
            for sub in dom["sub"]:
                for c in sub["controls"]:
                    states[c["state"]] = states.get(c["state"], 0) + 1
        self.assertEqual(sum(states.values()), 101)

    def test_control_detail_chain(self):
        d = self.client.get("/api/audit/controls/2.5.4").json()
        self.assertEqual(d["control_id"], "2.5.4")
        self.assertEqual(len(d["chain"]), 9)
        nodes = [n["node"] for n in d["chain"]]
        self.assertEqual(nodes[0], "Requirement")
        self.assertEqual(nodes[-1], "Verification")

    def test_control_detail_unknown(self):
        d = self.client.get("/api/audit/controls/9.9.9").json()
        self.assertEqual(d.get("error"), "not_found")

    def test_gaps_have_links(self):
        d = self.client.get("/api/audit/gaps").json()
        self.assertGreaterEqual(d["total"], 20)
        for g in d["gaps"]:
            self.assertIn("control_id", g)
            self.assertIn("owner", g)
            self.assertIn("severity", g)

    def test_snapshot_temporal_diff(self):
        snaps = self.client.get("/api/audit/snapshots").json()
        self.assertEqual(len(snaps), 4)
        oldest = self.client.get(
            f"/api/audit/snapshot?date={snaps[0]['date']}").json()
        newest = self.client.get(
            f"/api/audit/snapshot?date={snaps[-1]['date']}").json()
        self.assertLess(oldest["readiness"], newest["readiness"])
        self.assertTrue(oldest["demo"])

    def test_replay_scenario(self):
        d = self.client.get("/api/audit/replay").json()
        self.assertTrue(d["demo"])
        self.assertGreaterEqual(len(d["steps"]), 6)
        self.assertEqual(d["steps"][0]["actor"], "auditor")
        kinds = [s["kind"] for s in d["steps"]]
        self.assertIn("correlate", kinds)
        self.assertIn("exception", kinds)

    def test_assistant_is_advisory(self):
        res = self.client.post(
            "/api/audit/assistant", json={"message": "현재 준비도는?"}).json()
        self.assertTrue(res["advisory"])
        self.assertIn("판정이 아닙니다", res["disclaimer"])
        self.assertIn("reply", res)

    def test_activity_feed(self):
        d = self.client.get("/api/audit/activity").json()
        self.assertTrue(d["demo"])
        self.assertGreaterEqual(len(d["events"]), 5)

    def test_findings_api(self):
        d = self.client.get("/api/audit/findings").json()
        self.assertGreaterEqual(d["summary"]["total_findings"], 7)
        f = d["findings"][0]
        for k in ["defect_number", "control_id", "severity", "status",
                  "confirmed_facts", "corrective_actions"]:
            self.assertIn(k, f)

    # ---------- 상태 보존 ----------
    def test_state_param_flows_to_page(self):
        html = self.client.get("/controls?state=MISSING").text
        self.assertIn("미충족", html)

    def test_healthz(self):
        d = self.client.get("/healthz").json()
        self.assertEqual(d["status"], "ok")


if __name__ == "__main__":
    unittest.main()
