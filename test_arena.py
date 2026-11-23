import os
import random
import tempfile
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["ARENA_DB_PATH"] = _tmp_db.name
os.environ.setdefault("GROQ_API_KEY", "gsk_test_dummy_key")

from arena_core import CorporatePersona, SimulatedEmailPayload, init_database, get_api_key_pool
from attacker import (
    AdaptiveRedTeamAgent,
    generate_procedural_persona,
    assign_realistic_auth,
    is_safe_domain,
    _scrub_text,
    _clean_attachment_name,
)
from defender import LayeredBlueTeamAgent
import run_arena

DATA_DB = os.path.join(os.path.dirname(__file__), "data", "phishing_arena_telemetry.db")


def _email(**over) -> SimulatedEmailPayload:
    base = dict(
        message_id="sim-test",
        timestamp="2026-11-21T00:00:00Z",
        sender_display="Globex Support",
        sender_address="billing@globex-vendor-support.test",
        reply_to_address="billing@globex-vendor-support.test",
        spf_status="PASS",
        dkim_status="PASS",
        subject="Updated Invoice Portal",
        body="Hi Priya, please confirm via [SIMULATED_LINK].",
        attachment_metadata=None,
    )
    base.update(over)
    return SimulatedEmailPayload(**base)


def _fake_d4(agent, score: float):
    template = agent._d1_auth_header_inspector(_email())
    return patch.object(
        agent,
        "_d4_semantic_soc_adjudicator",
        new=AsyncMock(return_value=template.model_copy(update={
            "stage_name": "D4_Semantic_SOC_Adjudicator", "specialist_id": "D4", "weight": 0.50,
            "risk_score": score, "flagged": score >= 0.45, "flags": ["stub"],
        })),
    )


class TestArenaSuite(unittest.TestCase):
    def setUp(self):
        init_database()
        self.persona = CorporatePersona(
            employee_id="EMP-101",
            full_name="Priya Nair",
            role="Senior Accounts Payable Specialist",
            department="Finance",
            manager_name="Marcus Vance",
            recent_projects=["Q4 Vendor Audit", "ERP Cloud Migration"],
            known_vendors=["globex-vendor.test", "netsuite-billing.example.com"],
        )

    # ---- sandbox / sanitizer -------------------------------------------------
    def test_sandbox_domain_and_link_sanitization(self):
        self.assertTrue(is_safe_domain("acme-corp.test"))
        self.assertTrue(is_safe_domain("globex.example.org"))
        self.assertFalse(is_safe_domain("evil-phish.com"))

        scrubbed = _scrub_text("Click https://evil-login.com/auth or 192.168.1.50 or bad-site.ru")
        self.assertNotIn("evil-login.com", scrubbed)
        self.assertNotIn("192.168.1.50", scrubbed)
        self.assertIn("[SIMULATED_LINK]", scrubbed)
        self.assertIn("[REDACTED_IP]", scrubbed)

    def test_scrub_covers_extra_tlds(self):
        for bad in ("login-portal.de", "secure-sso.app", "verify-now.dev", "pay.online"):
            self.assertNotIn(bad, _scrub_text(f"go to {bad} now"))
        self.assertIn("globex.example.org", _scrub_text("see globex.example.org"))

    def test_attachment_metadata_cleaner(self):
        self.assertIsNone(_clean_attachment_name("None.sim"))
        self.assertIsNone(_clean_attachment_name("N_A.sim"))
        self.assertEqual(
            _clean_attachment_name("[{'filename': 'Invoice_Q4.pdf.sim', 'size': 1024}].sim"),
            "Invoice_Q4.pdf.sim",
        )

    def test_procedural_persona_diversity(self):
        seen = set()
        personas = [generate_procedural_persona(used_names=seen) for _ in range(30)]
        self.assertEqual(len(seen), 30)
        for p in personas:
            self.assertTrue(all(is_safe_domain(v) for v in p.known_vendors))

    # ---- client / key handling ----------------------------------------------
    def test_missing_api_key_raises_clear_error(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GROQ_")}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(get_api_key_pool("groq"), [])
            with self.assertRaises(ValueError):          # was IndexError before the fix
                LayeredBlueTeamAgent(provider="groq")
            with self.assertRaises(ValueError):
                AdaptiveRedTeamAgent(provider="groq")

    # ---- defender -------------------------------------------------------------
    def test_d1_d3_specialists_and_d5_escalation(self):
        agent = LayeredBlueTeamAgent(provider="ollama")
        # Single-vector lookalike attack where SPF/DKIM pass: D1=0, D3=0, D2=0.90.
        # Even if D4 is calm (0.20), D5 peak escalation (0.85 * 0.90 = 0.765) must BLOCK.
        with _fake_d4(agent, 0.20):
            verdict = asyncio.run(agent.evaluate_email(_email(), self.persona))
        self.assertEqual(verdict.final_action, "BLOCK")
        self.assertEqual(verdict.consensus_policy, "D5_Confidence_Weighted_Escalation")

    def test_benign_email_allowed(self):
        agent = LayeredBlueTeamAgent(provider="ollama")
        benign = _email(
            sender_display="Marcus Vance",
            sender_address="marcus.vance@acme-corp.test",
            reply_to_address="marcus.vance@acme-corp.test",
            subject="Q4 Vendor Audit Sync",
            body="Hi Priya, let us review the Q4 Vendor Audit spreadsheet tomorrow at 10 AM.",
        )
        with _fake_d4(agent, 0.05):
            verdict = asyncio.run(agent.evaluate_email(benign, self.persona))
        self.assertEqual(verdict.final_action, "ALLOW")
        self.assertEqual(verdict.specialist_votes_yes, 0)

    def test_verdict_bands(self):
        agent = LayeredBlueTeamAgent(provider="ollama")
        clean = _email(
            sender_address="marcus.vance@acme-corp.test", reply_to_address="marcus.vance@acme-corp.test",
            sender_display="Marcus Vance", body="Notes attached below.",
        )
        # clean headers => only D4 contributes: aggregate = max(0.5*s, 0.85*s) = 0.85*s
        for d4, expected in ((0.40, "ALLOW"), (0.55, "QUARANTINE"), (0.90, "BLOCK")):
            with _fake_d4(agent, d4):
                v = asyncio.run(agent.evaluate_email(clean, self.persona))
            self.assertEqual(v.final_action, expected, f"d4={d4} agg={v.aggregate_risk_score}")

    def test_defender_learns_from_incidents(self):
        agent = LayeredBlueTeamAgent(provider="ollama")
        with _fake_d4(agent, 0.05):
            missed = asyncio.run(agent.evaluate_email(
                _email(sender_address="x@globex-vendor.test", reply_to_address="x@globex-vendor.test",
                       body="Routine note."), self.persona))
        self.assertEqual(missed.final_action, "ALLOW")
        agent.learn_from_incident(_email(), was_actual_phish=True, verdict=missed)
        self.assertEqual(len(agent.threat_intel_rules), 1)

    # ---- realistic-auth mode ---------------------------------------------------
    def test_realistic_auth_removes_header_label_leak(self):
        random.seed(7)
        phish_fail = benign_fail = 0
        N = 2000
        for _ in range(N):
            p = _email(sender_address="a@globex-vendor-support.test")
            assign_realistic_auth(p, self.persona, is_phishing=True)
            phish_fail += p.spf_status != "PASS" or p.dkim_status != "PASS"
            b = _email(sender_address="a@acme-corp.test")
            assign_realistic_auth(b, self.persona, is_phishing=False)
            benign_fail += b.spf_status != "PASS" or b.dkim_status != "PASS"
        self.assertLess(phish_fail / N, 0.40)
        self.assertGreater(benign_fail / N, 0.05)

    def test_compromised_vendor_always_authenticates(self):
        e = _email(sender_address="a@globex-vendor.test", spf_status="FAIL", dkim_status="FAIL")
        assign_realistic_auth(e, self.persona, is_phishing=True)
        self.assertEqual((e.spf_status, e.dkim_status), ("PASS", "PASS"))

    # ---- retry helper ------------------------------------------------------------
    def test_with_retry_raises_instead_of_returning_none(self):
        calls = {"n": 0}

        async def boom():
            calls["n"] += 1
            raise ValueError("bad parse")

        async def fast_sleep(_s):
            return None

        with patch("run_arena.asyncio.sleep", new=fast_sleep):
            with self.assertRaises(ValueError):
                asyncio.run(run_arena.with_retry(boom, attempts=3))
        self.assertEqual(calls["n"], 3)

    def test_with_retry_returns_value(self):
        async def ok():
            return 42
        self.assertEqual(asyncio.run(run_arena.with_retry(ok)), 42)

    # ---- evaluation script reproduces published numbers ---------------------------
    @unittest.skipUnless(os.path.exists(DATA_DB), "telemetry DB not present")
    def test_evaluate_reproduces_published_results(self):
        from evaluate import evaluate
        r = evaluate(DATA_DB)
        self.assertEqual((r["n"], r["TP"], r["FN"], r["FP"], r["TN"]), (100, 75, 0, 3, 22))
        self.assertAlmostEqual(r["precision"], 0.9615, places=4)
        self.assertEqual((r["url_leaks"], r["ip_leaks"], r["unsafe_addresses"]), (0, 0, 0))
        self.assertEqual(r["header_leak_audit"]["phish_auth_both_fail"], 72)


if __name__ == "__main__":
    unittest.main()
