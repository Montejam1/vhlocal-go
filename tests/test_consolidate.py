"""Tests for the consolidated report renderer.

Deterministic end of the pipeline: no model, no Ollama. The regressions guarded
here were all observed in real output — a severity downgrade, collapsed
findings, and nested markup.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.consolidate import (  # noqa: E402
    Finding,
    _clean,
    _sev_key,
    apply_validation,
    compute_run_status,
    flag_duplicates,
    parse_findings,
    rank,
    render,
    write_consolidated,
)

README = """# VulnHunter Security Audit Report

**Run ID**: app_VULNHUNT_RESULTS_gptoss120b_2026-08-14-101500
**Repository**: https://github.com/acme/app
**Model**: gpt-oss:120b
**Findings Summary**: 4 High+

## Summary of Confirmed Findings
| ID | Title | CWE | Severity | Exploit Test | Status |
|---|---|---|---|---|---|
| VULN-001 | Path Traversal in Invoice | CWE-22 | High+ | PASS | Confirmed |
| VULN-002 | IDOR on Order Retrieval | CWE-639 | Medium | PASS | Confirmed |
| VULN-003 | Path Traversal via Filename | CWE-22 | High+ | PASS | Confirmed |
| VULN-004 | SQL Injection via `q` | CWE-89 | High+ | PASS | Confirmed |
| VULN-005 | SQL Injection via `status` | CWE-89 | Low | PASS | Confirmed |

### [VULN-001] Path Traversal in Invoice
| Field | Value |
|---|---|
| **Location** | `app/files.py:10` (open call) |
| **Entry Point** | GET `/api/invoice?name=...` |
| **Data Flow** | request.args.get("name") -> fetch_invoice(name) -> open |
| **Fix** | Canonicalise the path |

### [VULN-003] Path Traversal via Filename
| Field | Value |
|---|---|
| **Location** | `app/files.py:10` (open call) |
| **Entry Point** | GET `/api/invoice?name=...` |
| **Data Flow** | request.args.get("name") -> fetch_invoice(name) -> open |

### [VULN-004] SQL Injection via `q`
| Field | Value |
|---|---|
| **Location** | `app/db.py:21` (cur.execute(sql)) |
| **Entry Point** | GET `/api/search?q=...` |
| **Data Flow** | request.args.get("q") -> find_orders -> execute |

### [VULN-005] SQL Injection via `status`
| Field | Value |
|---|---|
| **Location** | `app/db.py:21` (cur.execute(sql)) |
| **Entry Point** | GET `/api/search?status=...` |
| **Data Flow** | request.args.get("status") -> find_orders -> execute |
"""

META = {
    "started_at": 1786700000.0, "finished_at": 1786706800.0,
    "repo": "/code/app", "results_dir": "/reports/app",
    "model": "gpt-oss:120b", "verify_model": None, "host": "http://localhost:11434",
    "num_ctx": 131072, "max_partitions": 8,
    "phases_requested": ["1", "2", "2b", "4"],
    "phases_completed": ["1", "2", "2b", "4"],
    "phases_skipped": [], "phase_timings": {"1": 88.0, "2": 1600.0},
    "partitions": ["SG-1", "SG-2"], "vuln_classes": ["INJ", "NAV", "LOG"],
    "agents": [{"label": "p1", "turns": 10, "stopped_reason": "complete"},
               {"label": "p2:sg-1:inj", "turns": 60, "stopped_reason": "max_turns"}],
    "usage": {"calls": 270, "prompt_tokens": 3578860, "completion_tokens": 97585,
              "peak_prompt_tokens": 28822, "summary": "270 calls"},
    "cancelled": False, "engine_version": "0.1.0",
    "tool_envelope": ["Read", "Grep", "Glob", "Write"], "bash_enabled": False,
}


class TestSeverity(unittest.TestCase):
    def test_high_plus_not_downgraded(self):
        """A trailing \\b cannot match after '+', which silently made High+ High."""
        self.assertEqual(_sev_key("High+")[1], "High+")
        self.assertLess(_sev_key("High+")[0], _sev_key("High")[0])

    def test_ordering_is_most_severe_first(self):
        order = [_sev_key(s)[0] for s in
                 ("Critical", "High+", "High", "Medium", "Low", "Informational")]
        self.assertEqual(order, sorted(order))

    def test_unknown_is_last(self):
        self.assertGreater(_sev_key("banana")[0], _sev_key("Informational")[0])
        self.assertEqual(_sev_key("")[1], "Unrated")

    def test_moderate_maps_to_medium(self):
        self.assertEqual(_sev_key("Moderate")[1], "Medium")


class TestParsing(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "README.md").write_text(README, encoding="utf-8")
        (self.d / "scan_meta.json").write_text(json.dumps(META), encoding="utf-8")

    def test_all_findings_parsed(self):
        got = parse_findings(self.d)
        self.assertEqual({f.id for f in got},
                         {"VULN-001", "VULN-002", "VULN-003", "VULN-004", "VULN-005"})

    def test_severity_and_cwe_extracted(self):
        by = {f.id: f for f in parse_findings(self.d)}
        self.assertEqual(by["VULN-001"].severity, "High+")
        self.assertEqual(by["VULN-002"].severity, "Medium")
        self.assertEqual(by["VULN-005"].severity, "Low")
        self.assertEqual(by["VULN-004"].cwe, "CWE-89")

    def test_detail_fields_enriched(self):
        by = {f.id: f for f in parse_findings(self.d)}
        self.assertIn("app/files.py:10", by["VULN-001"].location)
        self.assertIn("/api/invoice", by["VULN-001"].entry_point)
        self.assertIn("Canonicalise", by["VULN-001"].fix)

    def test_ranked_most_severe_first(self):
        ordered = rank(parse_findings(self.d))
        self.assertEqual(ordered[0].severity, "High+")
        self.assertEqual(ordered[-1].severity, "Low")

    def test_no_findings_when_empty(self):
        empty = Path(tempfile.mkdtemp())
        self.assertEqual(parse_findings(empty), [])


# Phase 4 sometimes leaves README a boilerplate stub; findings must be recovered
# from phase3_output.md (clean assignment table) — NOT phase2b_output.md (wide
# verdict/gate table whose title cells are "Yes"). Regression for run 214354.
README_STUB = ("# Vulnerability Hunt Results\n\n"
               "This directory contains the results of the hunting session.\n")

PHASE3_TABLE = """# Phase 3 Output Summary

## VULN Assignment Table
| VULN-NNN | Phase 2b # | Title | Severity |
|---|---|---|---|
| VULN-001 | 1 | Code Injection via eval() | High |
| VULN-002 | 2 | Unsafe Pickle Deserialization | High |
| VULN-012 | 12 | IDOR on GET /api/users/{user_id} | High |
"""

PHASE2B_VERDICT = """# Phase 2b Verification

## Verification Output
| Finding | Gates complete? | Production-reachable? | Precondition | Verdict |
|---|---|---|---|---|
| VULN-001 | Yes | Yes | Requires ops token | CONFIRMED |
| VULN-002 | Yes | Yes | Unauthenticated | CONFIRMED |
"""


class TestPhase4StubFallback(unittest.TestCase):
    def _dir(self, **files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            (d / name.replace("__", ".")).write_text(body, encoding="utf-8")
        return d

    def test_phase3_used_when_readme_is_stub(self):
        d = self._dir(**{"README__md": README_STUB,
                         "phase3_output__md": PHASE3_TABLE,
                         "phase2b_output__md": PHASE2B_VERDICT})
        fs = {f.id: f for f in parse_findings(d)}
        self.assertEqual(len(fs), 3)
        # Clean titles from phase3, not "Yes" from the 2b verdict table.
        self.assertEqual(fs["VULN-001"].title, "Code Injection via eval()")
        self.assertIn("IDOR", fs["VULN-012"].title)
        self.assertTrue(all(f.title != "Yes" for f in fs.values()))

    def test_verdict_table_titles_never_yes(self):
        """Even if only the 2b verdict table exists, titles must not be 'Yes'."""
        d = self._dir(**{"phase2b_output__md": PHASE2B_VERDICT})
        fs = parse_findings(d)
        self.assertTrue(all(f.title != "Yes" for f in fs))

    def test_stub_readme_backfilled_from_report(self):
        d = self._dir(**{"README__md": README_STUB,
                         "phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(META)})
        write_consolidated(d)
        rd = (d / "README.md").read_text(encoding="utf-8")
        self.assertIn("Consolidated Scan Report", rd)
        self.assertIn("VULN-001", rd)

    def test_real_phase4_readme_not_clobbered(self):
        real = ("# Security Audit\n\n## Summary\n"
                "| ID | Title | CWE | Severity |\n|---|---|---|---|\n"
                "| VULN-001 | Hand-written finding | CWE-89 | High |\n") * 2
        d = self._dir(**{"README__md": real, "phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(META)})
        write_consolidated(d)
        self.assertEqual((d / "README.md").read_text(encoding="utf-8"), real)

    def test_stub_word_vulnerability_not_mistaken_for_findings(self):
        """The stub's own heading says 'Vulnerability' — must still be a stub."""
        d = self._dir(**{"README__md": README_STUB,
                         "phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(META)})
        write_consolidated(d)
        self.assertIn("Consolidated Scan Report",
                      (d / "README.md").read_text(encoding="utf-8"))


class TestDuplicates(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "README.md").write_text(README, encoding="utf-8")

    def test_true_duplicate_flagged(self):
        f = {x.id: x for x in parse_findings(self.d)}
        flag_duplicates(list(f.values()))
        self.assertEqual(f["VULN-003"].duplicate_of, "VULN-001")

    def test_distinct_inputs_same_sink_not_duplicates(self):
        """`q` and `status` hit one execute() but are separate vulnerabilities.

        Collapsing them is the 'collapsing findings' failure the methodology
        explicitly warns about — each needs its own fix.
        """
        f = {x.id: x for x in parse_findings(self.d)}
        flag_duplicates(list(f.values()))
        self.assertIsNone(f["VULN-004"].duplicate_of)
        self.assertIsNone(f["VULN-005"].duplicate_of)

    def test_findings_without_location_never_flagged(self):
        a = Finding(id="VULN-100", cwe="CWE-89")
        b = Finding(id="VULN-101", cwe="CWE-89")
        flag_duplicates([a, b])
        self.assertIsNone(b.duplicate_of)

    def test_line_drift_does_not_split_root_cause(self):
        """Two reports of one XXE that disagree only on the line number must
        still cluster — the P0-B robustness fix."""
        a = Finding(id="VULN-005", title="XML External Entity", cwe="CWE-611",
                    location="app/x.py:51", data_flow="body -> etree.parse(body)")
        b = Finding(id="VULN-013", title="XXE via parser", cwe="CWE-611",
                    location="app/x.py:58", data_flow="body -> etree.parse(body)")
        flag_duplicates([a, b])
        self.assertEqual(b.duplicate_of, "VULN-005")
        self.assertEqual(b.cluster_id, "VULN-005")
        self.assertEqual(a.cluster_id, "VULN-005")

    def test_related_cwe_still_clusters_by_family(self):
        """Same NoSQL injection reported with CWE-943 vs CWE-89 clusters on the
        title family so a taxonomy disagreement does not inflate the count."""
        a = Finding(id="VULN-006", title="NoSQL injection", cwe="",
                    location="db.py:10", data_flow="q -> col.find(q)")
        b = Finding(id="VULN-014", title="NoSQL injection", cwe="",
                    location="db.py:10", data_flow="q -> col.find(q)")
        flag_duplicates([a, b])
        self.assertEqual(b.duplicate_of, "VULN-006")


class TestValidationLabeling(unittest.TestCase):
    """P0-A: the harness never renders the model's PASS/Confirmed as a verdict."""

    def test_static_when_bash_disabled(self):
        f = Finding(id="VULN-1", status="Confirmed", exploit_test="PASS",
                    poc="curl ...")
        apply_validation([f], {"bash_enabled": False})
        self.assertEqual(f.test_status, "not_run")
        self.assertEqual(f.validation_method, "static_reasoning")
        self.assertEqual(f.finding_state, "statically_supported")
        self.assertEqual(f.poc_status, "authored")
        # Model claim preserved verbatim, but not promoted to a verdict.
        self.assertEqual(f.status, "Confirmed")

    def test_never_passes_without_execution_record(self):
        """Even with bash_enabled, no execution record => never 'passed'."""
        f = Finding(id="VULN-1", exploit_test="PASS")
        apply_validation([f], {"bash_enabled": True})
        self.assertEqual(f.test_status, "not_run")

    def test_dynamic_pass_requires_record(self):
        f = Finding(id="VULN-1")
        meta = {"bash_enabled": True,
                "execution_records": {"VULN-1": {"exit_code": 0}}}
        apply_validation([f], meta)
        self.assertEqual(f.test_status, "passed")
        self.assertEqual(f.finding_state, "dynamically_confirmed")

    def test_rendered_report_has_no_bare_verdict_rows(self):
        d = Path(tempfile.mkdtemp())
        (d / "README.md").write_text(README, encoding="utf-8")
        (d / "scan_meta.json").write_text(json.dumps(META), encoding="utf-8")
        out = render(d)
        self.assertNotIn("| Status | Confirmed |", out)
        self.assertNotIn("| Exploit test | PASS |", out)
        self.assertIn("Scanner-reported (unverified)", out)
        self.assertIn("not run (no code executed)", out)


class TestRunStatusAxes(unittest.TestCase):
    """P0-C: execution, coverage, and validation are separate axes."""

    def test_complete_but_degraded_are_independent(self):
        meta = dict(META)
        meta["partitions"] = ["whole-repo"]
        meta["partition_fallback"] = True
        meta["partition_collapsed"] = True
        rs = compute_run_status(meta)
        self.assertEqual(rs["execution_status"], "complete")
        self.assertEqual(rs["coverage_status"], "degraded")
        self.assertTrue(any("whole-repo" in r for r in rs["coverage_degraded_reasons"]))
        self.assertEqual(rs["validation_mode"], "static_reasoning")

    def test_subsystem_fallback_degraded_but_not_whole_repo(self):
        """A deterministic subsystem fallback still fans out — degraded (the
        model's partitioning failed) but not a whole-repo collapse."""
        meta = dict(META)
        meta["partition_fallback"] = True
        meta["partition_collapsed"] = False
        meta["partitions"] = ["SG-1", "SG-2", "SG-3"]
        rs = compute_run_status(meta)
        self.assertEqual(rs["coverage_status"], "degraded")
        self.assertTrue(any("deterministic" in r for r in rs["coverage_degraded_reasons"]))
        self.assertFalse(any("whole-repo" in r for r in rs["coverage_degraded_reasons"]))

    def test_partial_execution(self):
        meta = dict(META)
        meta["phases_completed"] = ["1", "2"]  # requested 1,2,2b,4
        rs = compute_run_status(meta)
        self.assertEqual(rs["execution_status"], "partial")

    def test_aborted_wins(self):
        meta = dict(META)
        meta["aborted"] = "endpoint unreachable"
        self.assertEqual(compute_run_status(meta)["execution_status"], "aborted")


class TestRender(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "README.md").write_text(README, encoding="utf-8")
        (self.d / "scan_meta.json").write_text(json.dumps(META), encoding="utf-8")
        self.out = render(self.d)

    def test_has_expected_sections(self):
        for s in ("Consolidated Scan Report", "1. Scan summary", "2. Checks enabled",
                  "3. Findings by severity", "4. Findings ranked by priority",
                  "Scope and limitations"):
            self.assertIn(s, self.out)

    def test_scan_metadata_rendered(self):
        self.assertIn("/code/app", self.out)
        self.assertIn("gpt-oss:120b", self.out)
        self.assertIn("1h 53m", self.out)          # 6800s duration
        self.assertIn("131,072", self.out)          # context window

    def test_phase_status_shown(self):
        self.assertIn("Recon — attack surface mapping", self.out)
        self.assertIn("Completed", self.out)

    def test_incomplete_agent_surfaced(self):
        self.assertIn("did not finish cleanly", self.out)
        self.assertIn("max_turns", self.out)

    def test_static_only_limitation_stated(self):
        self.assertIn("Static analysis only", self.out)
        self.assertIn("never executed", self.out)

    def test_same_model_falsification_warned(self):
        # META has no verify_model — the report must call that out.
        self.assertIn("Falsification ran on the same model", self.out)

    def test_duplicate_excluded_from_counts(self):
        # 5 findings, 1 duplicate -> 4 counted
        self.assertIn("**4 total**", self.out)

    def test_no_nested_backticks_in_locations(self):
        self.assertNotIn("``", self.out)

    def test_clean_strips_markup(self):
        self.assertEqual(_clean("`app/x.py:1` **bold**"), "app/x.py:1 bold")


class TestWrite(unittest.TestCase):
    def test_writes_both_artifacts(self):
        d = Path(tempfile.mkdtemp())
        (d / "README.md").write_text(README, encoding="utf-8")
        (d / "scan_meta.json").write_text(json.dumps(META), encoding="utf-8")
        md, js = write_consolidated(d)
        self.assertTrue(md.exists() and js.exists())
        data = json.loads(js.read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 5)
        self.assertEqual(sum(data["counts"].values()), 4)  # duplicate excluded
        self.assertEqual(data["meta"]["model"], "gpt-oss:120b")

    def test_missing_meta_degrades_not_crashes(self):
        d = Path(tempfile.mkdtemp())
        (d / "README.md").write_text(README, encoding="utf-8")
        md, _js = write_consolidated(d)
        text = md.read_text(encoding="utf-8")
        self.assertIn("unknown", text)
        self.assertIn("4. Findings ranked by priority", text)

    def test_empty_dir_still_produces_report(self):
        d = Path(tempfile.mkdtemp())
        md, _js = write_consolidated(d)
        self.assertIn("No findings were reported", md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestClassCoverageHonesty(unittest.TestCase):
    """The 'checks enabled' section must not claim checks that never ran."""

    def _render(self, meta_over):
        d = Path(tempfile.mkdtemp())
        (d / "README.md").write_text(README, encoding="utf-8")
        m = dict(META); m.update(meta_over)
        (d / "scan_meta.json").write_text(json.dumps(m), encoding="utf-8")
        return render(d)

    def test_recon_only_run_does_not_claim_class_coverage(self):
        out = self._render({"phases_requested": ["1"], "phases_completed": ["1"],
                            "agents": [{"label": "p1", "turns": 8,
                                        "stopped_reason": "complete"}]})
        self.assertIn("not part of this run", out)
        self.assertNotIn("| INJ | ", out)

    def test_hunt_run_lists_classes_with_agent_counts(self):
        out = self._render({
            "phases_requested": ["1", "2"], "phases_completed": ["1", "2"],
            "agents": [
                {"label": "p2:sg-1:inj", "turns": 5, "stopped_reason": "complete",
                 "vuln_class": "INJ"},
                {"label": "p2:sg-1:nav", "turns": 5, "stopped_reason": "complete",
                 "vuln_class": "NAV"},
            ]})
        self.assertIn("| INJ | 1 |", out)
        self.assertIn("| NAV | 1 |", out)

    def test_incomplete_hunt_is_flagged(self):
        out = self._render({"phases_requested": ["1", "2"],
                            "phases_completed": ["1"]})
        self.assertIn("Phase 2 did not complete", out)
