"""The CLI (vhlocal.run) must expose the same knobs as the web UI: multi-sample
voting, IaC lens, remediation, redaction, ledger, budget cap, per-role models, the
OpenRouter backend, and config profiles — with correct default < profile < explicit
precedence."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vhlocal.run as run  # noqa: E402
from vhlocal.client import Usage  # noqa: E402

_SKILL = str(Path(__file__).resolve().parent.parent / "skill")


class _FakeResult:
    seconds = 1.0
    results_dir = Path(tempfile.mkdtemp())

    def __init__(self):
        self.usage = Usage()


class CLI(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self._orig = run.execute_scan
        self._spec = {}

        def fake(spec, attach_log_handler=False):
            self._spec["spec"] = spec
            return _FakeResult()
        run.execute_scan = fake

    def tearDown(self):
        run.execute_scan = self._orig

    def _run(self, *extra):
        self._spec.clear()
        rc = run.main(["--repo", self.repo, "--skill-dir", _SKILL, *extra])
        return self._spec.get("spec"), rc

    def test_defaults(self):
        s, rc = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(s.hunt_samples, 1)
        self.assertTrue(s.iac_lens)
        self.assertFalse(s.remediate)
        self.assertFalse(s.redact)
        self.assertFalse(s.ledger)
        self.assertEqual(s.max_budget_usd, 0.0)
        self.assertEqual(s.phase2_mode, "split")

    def test_feature_flags_reach_spec(self):
        s, _ = self._run("--hunt-samples", "3", "--remediate", "--redact",
                         "--ledger", "--max-budget-usd", "5")
        self.assertEqual(s.hunt_samples, 3)
        self.assertTrue(s.remediate and s.redact and s.ledger)
        self.assertEqual(s.max_budget_usd, 5.0)

    def test_profile_applied(self):
        s, _ = self._run("--profile", "thorough")
        self.assertEqual(s.hunt_samples, 3)      # from profile
        self.assertTrue(s.remediate)
        self.assertEqual(s.max_partitions, 8)

    def test_explicit_flag_overrides_profile(self):
        s, _ = self._run("--profile", "thorough", "--hunt-samples", "1", "--no-iac-lens")
        self.assertEqual(s.hunt_samples, 1)      # explicit wins over profile's 3
        self.assertFalse(s.iac_lens)             # --no-iac-lens wins
        self.assertTrue(s.remediate)             # untouched profile value survives

    def test_hunt_samples_clamped(self):
        s, _ = self._run("--hunt-samples", "99")
        self.assertEqual(s.hunt_samples, 5)      # clamped to 5

    def test_per_role_models(self):
        s, _ = self._run("--verify-model", "gpt-oss:120b", "--recon-model", "x:1",
                         "--reproduce-backend", "openai")
        self.assertEqual(s.verify_model, "gpt-oss:120b")
        self.assertEqual(s.recon_model, "x:1")
        self.assertEqual(s.reproduce_backend, "openai")

    def test_openrouter_requires_key(self):
        import vhlocal.openai_client as oc
        prev = oc.get_openrouter_key()
        oc.set_openrouter_key("")
        try:
            s, rc = self._run("--backend", "openrouter", "--model", "z-ai/glm-5.3")
            self.assertEqual(rc, 2)              # refused: no key
            self.assertIsNone(s)                 # never reached execute_scan
        finally:
            oc.set_openrouter_key(prev)

    def test_openrouter_backend_with_key(self):
        import vhlocal.openai_client as oc
        prev = oc.get_openrouter_key()
        oc.set_openrouter_key("k")
        try:
            s, rc = self._run("--backend", "openrouter", "--model", "z-ai/glm-5.3")
            self.assertEqual(rc, 0)
            self.assertEqual(s.backend, "openrouter")
            self.assertIn("openrouter.ai", s.host)   # fixed host applied
        finally:
            oc.set_openrouter_key(prev)


if __name__ == "__main__":
    unittest.main()
