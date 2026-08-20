"""Tests for the deterministic entry-point inventory and partition resolution.

These guard the P1-E fallback: a run must never silently collapse to one
whole-repo partition when the repo has discoverable routes, and every fallback
must be recorded so coverage can be marked degraded.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.inventory import (  # noqa: E402
    build_coverage_ledger,
    deterministic_partitions,
    enumerate_entry_points,
    subsystem_for,
)
from vhlocal.inventory import route_inventory_markdown  # noqa: E402
from vhlocal.phases import (  # noqa: E402
    Partition,
    augment_partitions_for_coverage,
    parse_partition_json,
    resolve_partitions,
)

FASTAPI_OPS = '''
from fastapi import APIRouter
router = APIRouter(prefix="/ops")

@router.post("/bundle/dispatch-thaw-172")
async def dispatch_bundle_thaw(raw: bytes):
    return raw

@router.get("/trace")
def trace_endpoint():
    return {}
'''

FASTAPI_AUTH = '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/login")
def login(): ...

@app.api_route("/password/reset", methods=["POST", "PUT"])
def reset(): ...
'''


def _repo(files):
    d = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return d


class TestEnumerate(unittest.TestCase):
    def setUp(self):
        self.repo = _repo({"backend/app/ops.py": FASTAPI_OPS,
                           "backend/app/auth.py": FASTAPI_AUTH})

    def test_router_prefix_applied(self):
        eps = {e.path for e in enumerate_entry_points(self.repo)}
        self.assertIn("/ops/bundle/dispatch-thaw-172", eps)
        self.assertIn("/ops/trace", eps)

    def test_methods_extracted(self):
        eps = enumerate_entry_points(self.repo)
        methods = {(e.path, e.method) for e in eps}
        self.assertIn(("/login", "POST"), methods)
        # api_route with methods=[POST, PUT] yields two entries.
        self.assertIn(("/password/reset", "POST"), methods)
        self.assertIn(("/password/reset", "PUT"), methods)

    def test_subsystem_classification(self):
        self.assertEqual(subsystem_for("/ops/trace", "backend/app/ops.py"), "ops")
        self.assertEqual(subsystem_for("/login", "auth.py"), "auth")
        self.assertEqual(subsystem_for("/password/reset", "auth.py"), "auth")

    def test_test_files_excluded(self):
        repo = _repo({"app/api.py": FASTAPI_AUTH,
                     "tests/test_api.py": FASTAPI_OPS})
        files = {e.file for e in enumerate_entry_points(repo)}
        self.assertNotIn("tests/test_api.py", files)


class TestDeterministicPartitions(unittest.TestCase):
    def test_partitions_by_subsystem_not_whole_repo(self):
        repo = _repo({"backend/app/ops.py": FASTAPI_OPS,
                     "backend/app/auth.py": FASTAPI_AUTH})
        parts = deterministic_partitions(repo)
        self.assertGreater(len(parts), 1)
        subs = {p.subsystem for p in parts}
        self.assertIn("ops", subs)
        self.assertIn("auth", subs)

    def test_structureless_repo_single_partition(self):
        repo = _repo({"notes.txt": "hello"})
        parts = deterministic_partitions(repo)
        self.assertEqual(len(parts), 1)


class TestBug2NoDoubleCover(unittest.TestCase):
    """Regression: vague partitions (no filenames, e.g. from the JSON retry)
    must NOT cause coverage to re-cover files, ballooning partition count."""

    def setUp(self):
        self.repo = _repo({"backend/app/ops.py": FASTAPI_OPS,
                          "backend/app/auth.py": FASTAPI_AUTH,
                          "backend/app/io_csv.py":
                              "from fastapi import APIRouter\n"
                              "router = APIRouter(prefix='/csv')\n"
                              "@router.post('/import')\ndef imp(): ...\n"})

    def test_empty_base_yields_complete_nonoverlapping_plan(self):
        # The model_retry fix passes [] as the base → the full deterministic set.
        aug = augment_partitions_for_coverage([], self.repo, max_partitions=8)
        files = aug.added_files
        # Every file covered exactly once (no duplicates across partitions).
        self.assertEqual(len(files), len(set(files)))
        self.assertEqual(aug.uncovered_remaining, [])

    def test_vague_base_would_double_cover(self):
        # Demonstrates the bug the fix avoids: stacking on path-free descriptions
        # re-covers everything, so the fix uses [] instead for model_retry.
        vague = [Partition("SG-1", "auth"), Partition("SG-2", "ops")]
        stacked = augment_partitions_for_coverage(vague, self.repo, max_partitions=8)
        # auth.py/ops.py get re-added despite the vague partitions "covering" them.
        self.assertTrue(any("auth.py" in f or "ops.py" in f
                            for f in stacked.added_files))


class TestResolvePartitions(unittest.TestCase):
    def _p1(self, body):
        d = Path(tempfile.mkdtemp())
        (d / "phase1_output.md").write_text(body, encoding="utf-8")
        return d / "phase1_output.md"

    def test_clean_table_is_not_fallback(self):
        p1 = self._p1("### Subgraph Partitions\n|P|I|\n|---|---|\n"
                      "| SG-1 | x |\n| SG-2 | y |\n")
        res = resolve_partitions(p1, repo=None)
        self.assertEqual(res.source, "model_table")
        self.assertFalse(res.fallback)
        self.assertFalse(res.collapsed)
        self.assertEqual([p.ident for p in res.partitions], ["SG-1", "SG-2"])

    def test_corrective_retry_recovers_json(self):
        p1 = self._p1("recon prose with no parseable table")

        def retry(_text, _hint):
            return ('Here you go:\n[{"id":"SG-1","description":"auth"},'
                    '{"id":"SG-2","description":"ops"}]')

        res = resolve_partitions(p1, repo=None, repartition_fn=retry)
        self.assertEqual(res.source, "model_retry")
        self.assertTrue(res.fallback)
        self.assertEqual(len(res.partitions), 2)

    def test_deterministic_fallback_when_retry_fails(self):
        repo = _repo({"backend/app/ops.py": FASTAPI_OPS,
                     "backend/app/auth.py": FASTAPI_AUTH})
        (repo / "phase1_output.md").write_text("no table", encoding="utf-8")
        res = resolve_partitions(repo / "phase1_output.md", repo=repo,
                                 repartition_fn=lambda t, h: "still no json")
        self.assertEqual(res.source, "deterministic")
        self.assertTrue(res.fallback)
        self.assertFalse(res.collapsed)
        self.assertGreater(len(res.partitions), 1)

    def test_collapse_only_when_no_structure(self):
        repo = _repo({"readme.md": "nothing here"})
        (repo / "phase1_output.md").write_text("no table", encoding="utf-8")
        res = resolve_partitions(repo / "phase1_output.md", repo=repo)
        self.assertTrue(res.collapsed)
        self.assertEqual(res.source, "single_fallback")

    def test_retry_exception_does_not_crash(self):
        repo = _repo({"backend/app/auth.py": FASTAPI_AUTH,
                     "backend/app/ops.py": FASTAPI_OPS})
        (repo / "phase1_output.md").write_text("no table", encoding="utf-8")

        def boom(_t, _h):
            raise RuntimeError("model down")

        res = resolve_partitions(repo / "phase1_output.md", repo=repo,
                                 repartition_fn=boom)
        self.assertEqual(res.source, "deterministic")


class TestCoverageLedger(unittest.TestCase):
    def setUp(self):
        self.repo = _repo({"backend/app/ops.py": FASTAPI_OPS,
                          "backend/app/auth.py": FASTAPI_AUTH})
        self.results = Path(tempfile.mkdtemp())

    def test_unreferenced_routes_are_not_reviewed(self):
        # An artifact that only mentions ops.py; auth routes go unreviewed.
        (self.results / "results").mkdir()
        (self.results / "results" / "sg1_inj.md").write_text(
            "Looked at backend/app/ops.py — pickle sink at line 5.",
            encoding="utf-8")
        led = build_coverage_ledger(self.results, self.repo)
        self.assertEqual(led.total, 5)          # 2 ops + 3 auth (POST/PUT split)
        self.assertGreater(led.not_reviewed, 0)
        self.assertFalse(led.complete)
        auth_disp = {e.path: e.disposition for e in led.entries
                     if e.file.endswith("auth.py")}
        self.assertTrue(all(d == "not_reviewed" for d in auth_disp.values()))

    def test_finding_file_marked_emitted(self):
        led = build_coverage_ledger(self.results, self.repo,
                                    finding_files=["backend/app/ops.py"])
        ops = [e for e in led.entries if e.file.endswith("ops.py")]
        self.assertTrue(all(e.disposition == "finding_emitted" for e in ops))

    def test_full_coverage_is_complete(self):
        (self.results / "phase2b_output.md").write_text(
            "Reviewed backend/app/ops.py and backend/app/auth.py thoroughly.",
            encoding="utf-8")
        led = build_coverage_ledger(self.results, self.repo)
        self.assertEqual(led.not_reviewed, 0)
        self.assertTrue(led.complete)

    def test_empty_denominator_is_not_complete(self):
        empty_repo = _repo({"notes.txt": "no routes"})
        led = build_coverage_ledger(self.results, empty_repo)
        self.assertEqual(led.total, 0)
        self.assertFalse(led.complete)   # unknown, never asserted complete


class TestCoverageAugmentation(unittest.TestCase):
    def setUp(self):
        # ops covers dispatch, auth covers auth; io_csv (filedata) is omitted.
        self.repo = _repo({
            "backend/app/ops.py": FASTAPI_OPS,
            "backend/app/auth.py": FASTAPI_AUTH,
            "backend/app/io_csv.py":
                "from fastapi import APIRouter\n"
                "router = APIRouter(prefix='/csv')\n"
                "@router.post('/import')\n"
                "def imp(): ...\n"
                "@router.get('/export')\n"
                "def exp(): ...\n",
        })

    def test_omitted_file_gets_coverage_partition(self):
        # Model plan names ops.py and auth.py but never io_csv.py.
        model = [Partition("SG-1", "ops backend/app/ops.py"),
                 Partition("SG-2", "auth backend/app/auth.py")]
        aug = augment_partitions_for_coverage(model, self.repo, max_partitions=8)
        self.assertTrue(aug.added)
        self.assertIn("backend/app/io_csv.py", aug.added_files)
        joined = " ".join(p.description for p in aug.partitions)
        self.assertIn("io_csv.py", joined)
        self.assertIn("HARNESS-ENFORCED COVERAGE", joined)
        self.assertEqual(aug.uncovered_remaining, [])

    def test_full_coverage_adds_nothing(self):
        model = [Partition("SG-1", "ops backend/app/ops.py"),
                 Partition("SG-2", "auth backend/app/auth.py"),
                 Partition("SG-3", "csv backend/app/io_csv.py")]
        aug = augment_partitions_for_coverage(model, self.repo, max_partitions=8)
        self.assertEqual(aug.added, [])
        self.assertEqual(len(aug.partitions), 3)

    def test_coverage_partition_ids_do_not_collide(self):
        model = [Partition("SG-1", "ops backend/app/ops.py")]
        aug = augment_partitions_for_coverage(model, self.repo, max_partitions=8)
        idents = [p.ident for p in aug.partitions]
        self.assertEqual(len(idents), len(set(idents)))

    def test_no_routes_no_augmentation(self):
        repo = _repo({"notes.txt": "no code"})
        model = [Partition("SG-1", "whatever")]
        aug = augment_partitions_for_coverage(model, repo, max_partitions=8)
        self.assertEqual(aug.added, [])


class TestRouteSeed(unittest.TestCase):
    def test_seed_lists_every_route(self):
        repo = _repo({"backend/app/ops.py": FASTAPI_OPS,
                     "backend/app/auth.py": FASTAPI_AUTH})
        md = route_inventory_markdown(repo)
        self.assertIn("/ops/trace", md)
        self.assertIn("/login", md)
        self.assertIn("MUST account for", md)

    def test_seed_empty_when_no_routes(self):
        repo = _repo({"notes.txt": "nothing"})
        self.assertEqual(route_inventory_markdown(repo), "")


class TestPartitionJson(unittest.TestCase):
    def test_parses_fenced_json(self):
        parts = parse_partition_json('```json\n[{"id":"SG-3","description":"x"}]\n```')
        self.assertEqual(parts[0].ident, "SG-3")

    def test_rejects_non_array(self):
        self.assertEqual(parse_partition_json('{"id":"SG-1"}'), [])

    def test_empty_on_garbage(self):
        self.assertEqual(parse_partition_json("not json at all"), [])


if __name__ == "__main__":
    unittest.main()
