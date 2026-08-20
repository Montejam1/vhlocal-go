"""Tests for the Phase 2b -> Phase 3 compact handoff."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.handoff import HANDOFF_FILE, parse_confirmed, write_handoff  # noqa: E402

# A 2b output with the real-world shape: a summary verdict table (with explicit
# duplicate rows to drop) followed by a detail table that must NOT be re-parsed.
TWO_B = """# Phase 2b Verification

## Confirmed findings

| # | Source File | Finding ID | CWE | Endpoint | Severity |
|---|---|---|---|---|---|
| 1 | sink_driven.md | VULN-001 | CWE-601 | GET /ops/after/lane-021?lane=... | Medium |
| 2 | sink_driven.md | VULN-002 | CWE-94 | GET /ops/formula/cast-254?expr=... | High+ |
| 3 | sg-1_log.md | VULN-001 | CWE-338 | GET /ops/nonce/roll-405?length=... | High |
| 4 | sg-1_nav.md | VULN-003 | CWE-22 | POST /ops/dock/shelf-393?name=... | High |
| 5 | sg-1_nav.md | VULN-001 | CWE-601 | (Duplicate of #1 - Open Redirect) | - |

## Detailed verification

| Finding | Gate 1 | Gate 2 | Verdict |
|---|---|---|---|
| VULN-001 | yes | no sanitisation | CONFIRMED |
| VULN-002 | yes | no escaping | CONFIRMED |
"""


class TestParse(unittest.TestCase):
    def test_only_first_table_parsed(self):
        items = parse_confirmed(TWO_B)
        # 5 summary rows, 1 duplicate dropped -> 4; detail table ignored
        self.assertEqual(len(items), 4)

    def test_duplicate_rows_dropped(self):
        entries = parse_confirmed(TWO_B)
        self.assertTrue(all("601" != e.cwe or "after" in e.entry for e in entries))
        # the dup was CWE-601 with "(Duplicate of #1)"; the kept CWE-601 is #1
        cwe601 = [e for e in entries if e.cwe == "CWE-601"]
        self.assertEqual(len(cwe601), 1)

    def test_sequential_global_ids(self):
        ids = [e.vuln for e in parse_confirmed(TWO_B)]
        self.assertEqual(ids, ["VULN-001", "VULN-002", "VULN-003", "VULN-004"])

    def test_fields_extracted(self):
        first = parse_confirmed(TWO_B)[0]
        self.assertEqual(first.cwe, "CWE-601")
        self.assertEqual(first.severity, "Medium")
        self.assertEqual(first.source, "sink_driven.md")
        self.assertEqual(first.source_id, "VULN-001")
        self.assertIn("/ops/after", first.entry)

    def test_empty_on_no_table(self):
        self.assertEqual(parse_confirmed("no findings here"), [])


# The regression from run 155237: 2b emits a Candidate Manifest FIRST (all
# candidates, pre-verification), eliminates most of them in prose, and confirms
# only a couple in a verdict table. The manifest rows carry no "eliminated" text,
# so the old "first VULN table" parser shipped them as confirmed (21 rows for a
# 2-confirmed run).
MANIFEST_FIRST = """# Phase 2b: Adversarial Verification Report

## Candidate Manifest

### SG-1 (dispatch_operations.py - /ops/* routes)
| ID | CWE | Entry point | Class |
|---|---|---|---|
| VULN-001 | CWE-94 | GET /ops/formula/cast-254 | INJ (eval) |
| VULN-002 | CWE-502 | POST /ops/bundle/thaw-172 | INJ (pickle) |
| VULN-003 | CWE-611 | POST /ops/xml/fold-450 | INJ (XXE) |

### SG-4 (/api/auth*)
| ID | CWE | Description | Class |
|---|---|---|---|
| VULN-001 | CWE-321 | Hardcoded secret_key in config.py:9 | LOG |
| VULN-002 | CWE-532 | Password reset token logged | LOG |

## Verification Results

### SG-1 /ops/* Routes - ALL ELIMINATED
All `/ops/*` routes are behind `_wrk_gate`; treated as not attacker-controlled.

## Final Verdict Summary

| Finding | CWE | Verdict |
|---|---|---|
| VULN-001 | CWE-321 | CONFIRMED |
| VULN-002 | CWE-532 | CONFIRMED |
"""


class TestManifestNotShipped(unittest.TestCase):
    def test_only_confirmed_survive_not_manifest(self):
        items = parse_confirmed(MANIFEST_FIRST)
        self.assertEqual(len(items), 2)
        self.assertEqual({i.cwe for i in items}, {"CWE-321", "CWE-532"})

    def test_eliminated_ops_candidates_excluded(self):
        items = parse_confirmed(MANIFEST_FIRST)
        cwes = {i.cwe for i in items}
        for gone in ("CWE-94", "CWE-502", "CWE-611"):
            self.assertNotIn(gone, cwes)


class TestWrite(unittest.TestCase):
    def test_writes_compact_file(self):
        d = Path(tempfile.mkdtemp())
        (d / "phase2b_output.md").write_text(TWO_B, encoding="utf-8")
        out = write_handoff(d)
        self.assertIsNotNone(out)
        self.assertEqual(out.name, HANDOFF_FILE)
        text = out.read_text(encoding="utf-8")
        self.assertIn("VULN-001", text)
        self.assertIn("do NOT re-read", text)
        # The point is stripping the transcript: the detail verification table
        # must not survive into the handoff.
        self.assertNotIn("Gate 1", text)
        self.assertNotIn("Detailed verification", text)

    def test_scales_down_on_realistic_transcript(self):
        # The fixed instruction header dominates on a trivial fixture; the
        # compaction shows on realistically-sized 2b output (13% on real runs).
        big = TWO_B + ("\n\n## Verification notes\n" +
                       "Detailed gate-by-gate reasoning. " * 400)
        d = Path(tempfile.mkdtemp())
        (d / "phase2b_output.md").write_text(big, encoding="utf-8")
        out = write_handoff(d)
        self.assertLess(len(out.read_text(encoding="utf-8")), len(big) // 2)

    def test_missing_source_returns_none(self):
        self.assertIsNone(write_handoff(Path(tempfile.mkdtemp())))

    def test_unparseable_returns_none(self):
        d = Path(tempfile.mkdtemp())
        (d / "phase2b_output.md").write_text("no findings", encoding="utf-8")
        self.assertIsNone(write_handoff(d))


class TestEngineWiring(unittest.TestCase):
    def test_phase3_reads_handoff(self):
        from vhlocal.phases import PHASES_BY_KEY
        self.assertEqual(PHASES_BY_KEY["3"].reads, ["phase2b_handoff.md"])

    def test_read_fallback_to_raw_when_handoff_absent(self):
        from vhlocal.engine import _resolve_reads
        d = Path(tempfile.mkdtemp())
        # handoff not written -> falls back to raw 2b output
        self.assertEqual(_resolve_reads(["phase2b_handoff.md"], d),
                         ["phase2b_output.md"])

    def test_read_uses_handoff_when_present(self):
        from vhlocal.engine import _resolve_reads
        d = Path(tempfile.mkdtemp())
        (d / HANDOFF_FILE).write_text("x", encoding="utf-8")
        self.assertEqual(_resolve_reads(["phase2b_handoff.md"], d),
                         ["phase2b_handoff.md"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestHandoffGeneratedInScan(unittest.TestCase):
    """After a successful 2b, the engine writes the handoff and emits an event."""

    def test_engine_emits_handoff_after_2b(self):
        from unittest import mock
        from vhlocal import engine
        repo = Path(tempfile.mkdtemp()) / "app"
        (repo / "app").mkdir(parents=True)
        (repo / "app" / "main.py").write_text("x=1\n", encoding="utf-8")
        out = Path(tempfile.mkdtemp()) / "res"
        skill = Path(__file__).resolve().parent.parent.parent / "vulnhunt"
        if not (skill / "phases").is_dir():
            self.skipTest("vulnhunt skill dir not present")

        # A stub agent that writes a valid 2b table when phase 2b runs, so the
        # handoff has something to parse; other phases just write a stub.
        calls = {"n": 0}

        def fake_run_agent(client, sandbox, system, task, **kw):
            from vhlocal.agent import AgentResult
            from vhlocal.client import Usage
            for f in (kw.get("expect_files") or []):
                Path(f).parent.mkdir(parents=True, exist_ok=True)
                if Path(f).name == "phase2b_output.md":
                    Path(f).write_text(TWO_B, encoding="utf-8")
                else:
                    Path(f).write_text("# stub\n| ID | x |\n| VULN-001 | y |\n",
                                       encoding="utf-8")
            return AgentResult(final_text="", turns=1, usage=Usage(),
                               stopped_reason="complete")

        events = []
        with mock.patch.object(engine, "make_client") as MC, \
             mock.patch.object(engine, "run_agent", side_effect=fake_run_agent), \
             mock.patch("vhlocal.engine._run_fan_out", return_value=None):
            inst = MC.return_value
            inst.model = "stub"; inst.num_ctx = 131072
            inst.preflight.return_value = None
            inst.usage = engine.Usage()
            spec = engine.ScanSpec(repo=repo, skill_dir=skill, out=out,
                                   phases="2b,3")
            engine.execute_scan(spec, on_event=events.append,
                                attach_log_handler=False)

        self.assertTrue((out / HANDOFF_FILE).exists(),
                        "handoff not generated after phase 2b")
        self.assertTrue(any(e.get("type") == "handoff" and e.get("written")
                            for e in events))
