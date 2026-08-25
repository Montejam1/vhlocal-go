"""Tranche 5 — config profiles (named ScanSpec presets) and multi-repo batch."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import profiles, batch  # noqa: E402


class Profiles(unittest.TestCase):
    def test_builtins_present(self):
        names = {p["name"] for p in profiles.list_profiles()}
        self.assertTrue({"quick", "thorough", "share", "benchmark"} <= names)

    def test_thorough_presets_recall_knobs(self):
        ov = profiles.load_profile("thorough")
        self.assertEqual(ov["hunt_samples"], 3)
        self.assertEqual(ov["phase2_mode"], "split")
        self.assertTrue(ov["iac_lens"])

    def test_profile_never_pins_a_model(self):
        # Structural knobs only — a profile must not carry model/host/backend.
        for p in profiles.list_profiles():
            for banned in ("model", "host", "backend", "verify_model", "repo"):
                self.assertNotIn(banned, p["overrides"])

    def test_apply_profile_user_value_wins(self):
        merged = profiles.apply_profile({"hunt_samples": 1}, "thorough")
        self.assertEqual(merged["hunt_samples"], 1)          # explicit user wins
        self.assertEqual(merged["phase2_mode"], "split")     # profile fills the rest

    def test_unknown_profile_is_empty(self):
        self.assertEqual(profiles.load_profile("nope"), {})

    def test_user_profile_overrides_and_is_sanitized(self):
        d = Path(tempfile.mkdtemp())
        import os
        prev = os.environ.get("VHLOCAL_PROFILES_DIR")
        os.environ["VHLOCAL_PROFILES_DIR"] = str(d)
        try:
            (d / "mine.json").write_text(json.dumps({
                "name": "mine", "description": "custom",
                "overrides": {"hunt_samples": 2, "model": "should-be-dropped"}}))
            ov = profiles.load_profile("mine")
            self.assertEqual(ov["hunt_samples"], 2)
            self.assertNotIn("model", ov)                    # sanitized out
        finally:
            if prev is None:
                os.environ.pop("VHLOCAL_PROFILES_DIR", None)
            else:
                os.environ["VHLOCAL_PROFILES_DIR"] = prev


class Batch(unittest.TestCase):
    def _csv(self, body):
        d = Path(tempfile.mkdtemp())
        (d / "r.csv").write_text(body, encoding="utf-8")
        return d / "r.csv"

    def test_parse_with_header(self):
        rows = batch.parse_repos_csv(self._csv(
            "repo,app_id\n/code/a,Shop\n/code/b,Shop\n# c\n/code/c,Bill\n"))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0], {"repo": "/code/a", "app_id": "Shop"})

    def test_parse_headerless_defaults_app_to_basename(self):
        rows = batch.parse_repos_csv(self._csv("/code/foo-api\n/code/bar\n"))
        self.assertEqual(rows[0]["app_id"], "foo-api")   # basename fallback
        self.assertEqual(rows[1]["app_id"], "bar")

    def test_summary_groups_by_app_and_totals(self):
        results = [
            {"repo": "/c/a", "app_id": "Shop", "status": "done", "total": 4,
             "counts": {"High": 4}, "coverage": "complete"},
            {"repo": "/c/b", "app_id": "Shop", "status": "done", "total": 2,
             "counts": {"Low": 2}, "coverage": "degraded"},
            {"repo": "/c/c", "app_id": "Bill", "error": "boom", "total": 0},
        ]
        md = batch.build_batch_summary(results)
        self.assertIn("## Shop — 6 finding(s)", md)
        self.assertIn("## Bill — 0 finding(s)", md)
        self.assertIn("❌", md)                            # error row rendered
        self.assertIn("Total across batch: 6", md)

    def test_run_batch_with_stub_runner(self):
        rows = [{"repo": "/c/a", "app_id": "X"}, {"repo": "/c/b", "app_id": "X"}]
        ws = Path(tempfile.mkdtemp())

        class Res:
            def __init__(self, rd):
                self.results_dir = rd
                self.cancelled = False

        def runner(spec):
            rd = Path(tempfile.mkdtemp())
            (rd / "findings.json").write_text(json.dumps(
                {"counts": {"High": 1}, "run_status": {"coverage_status": "complete"}}))
            return Res(str(rd))

        out = batch.run_batch(rows, {"model": "m"}, runner, workspace=ws)
        self.assertEqual(len(out["results"]), 2)
        self.assertEqual(out["results"][0]["total"], 1)
        self.assertTrue((ws / batch.BATCH_SUMMARY_FILE).exists())

    def test_run_batch_isolates_a_failing_repo(self):
        rows = [{"repo": "/c/a", "app_id": "X"}, {"repo": "/c/b", "app_id": "X"}]

        def runner(spec):
            if spec["repo"] == "/c/a":
                raise RuntimeError("clone failed")
            class R:
                results_dir = ""
                cancelled = False
            return R()
        out = batch.run_batch(rows, {}, runner, workspace=Path(tempfile.mkdtemp()))
        self.assertIn("error", out["results"][0])          # first captured
        self.assertEqual(len(out["results"]), 2)           # batch continued


if __name__ == "__main__":
    unittest.main()
