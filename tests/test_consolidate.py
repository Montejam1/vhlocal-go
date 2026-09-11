"""Tests for the consolidated report renderer.

Deterministic end of the pipeline: no model, no Ollama. The regressions guarded
here were all observed in real output — a severity downgrade, collapsed
findings, and nested markup.
"""

import json
import os
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


class TestHuntIdentityIntegrity(unittest.TestCase):
    """A hunt file frequently reuses local VULN-NNN ids across rewrite passes for
    DIFFERENT candidates. Each observation must keep its own title/cwe/location/
    data_flow — never take a title from one block and a data flow from another
    (regression: strict run 2026-09-10, VULN-023/025/026/027)."""

    def _parse(self, body):
        d = Path(tempfile.mkdtemp())
        (d / "results").mkdir()
        (d / "results" / "sg-1_inj.md").write_text(body, encoding="utf-8")
        from vhlocal.consolidate import _hunt_evidence_findings
        return _hunt_evidence_findings(d)

    def test_reused_id_does_not_weld_title_to_a_foreign_flow(self):
        # The same file writes VULN-001 twice: once an open redirect, once a path
        # traversal. The old merge-by-id took the title from the first and the
        # data flow from the last, producing a path-traversal titled record with
        # an open-redirect flow. Each must stay whole.
        body = (
            "#### [VULN-001] Open Redirect via `lane`\n"
            "- **Class**: CWE-601\n- **Location**: `app/ops.py:39`\n"
            "- **Data Flow**: `lane` -> `RedirectResponse(lane)` line 39\n\n"
            "#### [VULN-001] Path Traversal via `ref`\n"
            "- **Class**: CWE-22\n- **Location**: `app/ops.py:69`\n"
            "- **Data Flow**: `ref` -> `open(target)` line 69\n")
        fs = self._parse(body)
        by_cwe = {f.cwe: f for f in fs}
        self.assertIn("CWE-601", by_cwe)
        self.assertIn("CWE-22", by_cwe)
        # Each observation's flow belongs to its own CWE — no welding.
        self.assertIn("RedirectResponse", by_cwe["CWE-601"].data_flow)
        self.assertIn("open(target)", by_cwe["CWE-22"].data_flow)
        self.assertNotIn("RedirectResponse", by_cwe["CWE-22"].data_flow)


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

    def test_model_readme_is_replaced_with_canonical(self):
        # The published README must be canonical (harness-rendered), never the
        # model's own file — a model README has been observed inventing a commit,
        # the wrong model name, and PASS tests the harness never ran. Even a
        # plausible-looking Phase-4 README is overwritten.
        real = ("# Security Audit\n\n**Branch**: main [abcdef1]\n**Model**: made-up\n\n"
                "| ID | Title | CWE | Severity | Exploit Test |\n|---|---|---|---|---|\n"
                "| VULN-001 | Hand-written finding | CWE-89 | High | PASS |\n") * 2
        d = self._dir(**{"README__md": real, "phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(META)})
        write_consolidated(d)
        rd = (d / "README.md").read_text(encoding="utf-8")
        self.assertIn("Consolidated Scan Report", rd)     # canonical, not the model file
        self.assertNotIn("# Security Audit", rd)
        self.assertNotIn("[abcdef1]", rd)                 # invented commit gone

    def test_stub_word_vulnerability_not_mistaken_for_findings(self):
        """The stub's own heading says 'Vulnerability' — must still be a stub."""
        d = self._dir(**{"README__md": README_STUB,
                         "phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(META)})
        write_consolidated(d)
        self.assertIn("Consolidated Scan Report",
                      (d / "README.md").read_text(encoding="utf-8"))


class TestTranche1Artifacts(unittest.TestCase):
    """write_consolidated emits SARIF + run_manifest, a Scan Health section, and
    (when opted in) redacts secrets across the artifacts."""

    def _dir(self, **files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            (d / name.replace("__", ".")).write_text(body, encoding="utf-8")
        return d

    def test_sarif_and_manifest_always_written(self):
        d = self._dir(**{"phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(META)})
        write_consolidated(d)
        sarif = json.loads((d / "findings.sarif").read_text("utf-8"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "vhlocal")
        man = json.loads((d / "run_manifest.json").read_text("utf-8"))
        self.assertEqual(man["tool"]["name"], "vhlocal")
        self.assertIn("hash", man["config"])

    def test_scan_health_section_present(self):
        d = self._dir(**{"phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(META)})
        write_consolidated(d)
        self.assertIn("## Scan Health", (d / "SCAN_REPORT.md").read_text("utf-8"))

    def test_findings_json_has_chains_key(self):
        d = self._dir(**{"phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(META)})
        _, js = write_consolidated(d)
        data = json.loads(js.read_text("utf-8"))
        self.assertIn("chains", data)
        self.assertIsInstance(data["chains"], list)

    def test_remediation_dtos_only_when_opted_in(self):
        off = self._dir(**{"phase3_output__md": PHASE3_TABLE,
                           "scan_meta__json": json.dumps(META)})
        _, js = write_consolidated(off)
        self.assertIsNone(json.loads(js.read_text("utf-8"))["remediation"])
        self.assertFalse((off / "remediation").exists())

        on = self._dir(**{"phase3_output__md": PHASE3_TABLE,
                          "scan_meta__json": json.dumps(dict(META, remediate=True))})
        _, js2 = write_consolidated(on)
        rem = json.loads(js2.read_text("utf-8"))["remediation"]
        self.assertIsNotNone(rem)
        self.assertGreaterEqual(rem["total"], 1)
        self.assertTrue((on / "remediation" / "index.json").exists())
        self.assertIn("## Remediation", (on / "SCAN_REPORT.md").read_text("utf-8"))

    def test_redaction_masks_secrets_when_opted_in(self):
        leaky = PHASE3_TABLE + "\n\nEvidence: card 4111 1111 1111 1111 leaked.\n"
        d = self._dir(**{"phase3_output__md": leaky,
                         "scan_meta__json": json.dumps(dict(META, redact=True))})
        write_consolidated(d)
        phase3 = (d / "phase3_output.md").read_text("utf-8")
        self.assertNotIn("4111 1111 1111 1111", phase3)
        self.assertIn("[REDACTED-CARD]", phase3)

    def test_no_redaction_by_default(self):
        leaky = PHASE3_TABLE + "\n\nEvidence: card 4111 1111 1111 1111 leaked.\n"
        d = self._dir(**{"phase3_output__md": leaky,
                         "scan_meta__json": json.dumps(META)})
        write_consolidated(d)
        self.assertIn("4111 1111 1111 1111",
                      (d / "phase3_output.md").read_text("utf-8"))


class TestVulnerabilityLedger(unittest.TestCase):
    """The opt-in ledger merges only when meta['ledger'] is set, and its recall
    summary must appear in findings.json + the markdown report."""

    def _dir(self, **files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            (d / name.replace("__", ".")).write_text(body, encoding="utf-8")
        return d

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._prev = os.environ.get("VHLOCAL_LEDGER_DIR")
        os.environ["VHLOCAL_LEDGER_DIR"] = self._tmp.name

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("VHLOCAL_LEDGER_DIR", None)
        else:
            os.environ["VHLOCAL_LEDGER_DIR"] = self._prev
        self._tmp.cleanup()

    def test_ledger_null_when_not_opted_in(self):
        d = self._dir(**{"phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(dict(META, ledger=False))})
        _, js = write_consolidated(d)
        data = json.loads(js.read_text("utf-8"))
        self.assertIsNone(data["vulnerability_ledger"])
        self.assertNotIn("### Vulnerability ledger",
                         (d / "SCAN_REPORT.md").read_text("utf-8"))
        # nothing persisted
        self.assertEqual(list(Path(self._tmp.name).glob("*.json")), [])

    def test_ledger_written_and_summarized_when_opted_in(self):
        # The ledger records substantiated findings, so the run needs at least one
        # well-formed candidate (CWE + concrete title + location) that clears the
        # static gate — a bare hypothesis is not a tracked vulnerability.
        d = self._dir(**{"scan_meta__json": json.dumps(dict(META, ledger=True))})
        (d / "results").mkdir()
        (d / "results" / "sg-1.md").write_text(
            "#### [VULN-001] Code Injection via eval()\n- **Class**: CWE-94\n"
            "- **Location**: app/ops.py:76\n- **Severity**: High\n"
            "- **Data Flow**: request.json body -> eval(code) executes attacker input\n"
            "- **Root Cause**: user input reaches eval.\n", encoding="utf-8")
        _, js = write_consolidated(d)
        data = json.loads(js.read_text("utf-8"))
        bank = data["vulnerability_ledger"]
        self.assertIsNotNone(bank)
        self.assertEqual(bank["runs_recorded"], 1)
        self.assertGreaterEqual(bank["total_known"], 1)
        self.assertIn("### Vulnerability ledger",
                      (d / "SCAN_REPORT.md").read_text("utf-8"))
        self.assertTrue(list(Path(self._tmp.name).glob("*.json")))

    def test_rerender_is_idempotent(self):
        meta = dict(META, ledger=True)
        d = self._dir(**{"phase3_output__md": PHASE3_TABLE,
                         "scan_meta__json": json.dumps(meta)})
        write_consolidated(d)
        _, js = write_consolidated(d)   # re-render the same run
        bank = json.loads(js.read_text("utf-8"))["vulnerability_ledger"]
        self.assertEqual(bank["runs_recorded"], 1)   # not double-counted


class TestBackfillLocations(unittest.TestCase):
    """The model abbreviates the report and drops file:line; backfill restores it
    from the raw hunt evidence so dedup/votes/chains work."""

    def _dir(self, hunt_md):
        d = Path(tempfile.mkdtemp())
        (d / "results").mkdir()
        (d / "results" / "sg-1.md").write_text(hunt_md, encoding="utf-8")
        return d

    def test_backfills_from_hunt_evidence_by_ident_and_cwe(self):
        from vhlocal.consolidate import backfill_locations
        d = self._dir(
            "## eval sink\nUnsafe eval of expr — CWE-94 at backend/app/ops.py:76\n\n"
            "## pickle\npickle.loads of untrusted bytes — CWE-502 at backend/app/ops.py:61\n")
        fs = [Finding(id="VULN-001", title="Unrestricted `eval()` of expression", cwe="CWE-94"),
              Finding(id="VULN-002", title="Insecure pickle deserialization", cwe="CWE-502")]
        n = backfill_locations(fs, d, "")
        self.assertEqual(n, 2)
        self.assertIn("ops.py:76", fs[0].location)
        self.assertIn("ops.py:61", fs[1].location)

    def test_no_fill_without_confident_match(self):
        from vhlocal.consolidate import backfill_locations
        d = self._dir("some code at x.py:5\n")
        fs = [Finding(id="V1", title="Totally unrelated thing", cwe="CWE-999")]
        self.assertEqual(backfill_locations(fs, d, ""), 0)
        self.assertEqual(fs[0].location, "")

    def test_existing_location_not_overwritten(self):
        from vhlocal.consolidate import backfill_locations
        d = self._dir("eval CWE-94 at other.py:9\n")
        fs = [Finding(id="V1", title="`eval()` sink", cwe="CWE-94", location="real.py:1")]
        backfill_locations(fs, d, "")
        self.assertEqual(fs[0].location, "real.py:1")

    def test_repo_prefix_trimmed_to_relative(self):
        from vhlocal.consolidate import backfill_locations
        d = self._dir("XML External Entity — CWE-611 at /home/u/myrepo/app/x.py:42\n")
        fs = [Finding(id="V1", title="XML External Entity injection", cwe="CWE-611")]
        backfill_locations(fs, d, "/home/u/myrepo")
        self.assertEqual(fs[0].location, "app/x.py:42")

    def test_cwe_restored_from_evidence(self):
        from vhlocal.consolidate import backfill_locations
        d = self._dir("## eval\nUnsafe eval of expr — CWE-94 at app/ops.py:76\n")
        fs = [Finding(id="V1", title="Unrestricted `eval()` of expression", cwe="")]
        backfill_locations(fs, d, "")
        self.assertEqual(fs[0].cwe, "CWE-94")
        self.assertIn("ops.py:76", fs[0].location)

    def test_md_scratch_files_never_used_as_location(self):
        # The 2b handoff references the hunt scratch files (sg-1_inj.md:214);
        # those must never become a finding location.
        from vhlocal.consolidate import backfill_locations
        d = self._dir("## IDOR\nSee sg-1_inj.md:214 — IDOR CWE-639\n")
        fs = [Finding(id="V1", title="IDOR in `get_customer`", cwe="")]
        backfill_locations(fs, d, "")
        self.assertNotIn(".md:", fs[0].location or "")

    def test_title_cwe_fallback_when_no_evidence_cwe(self):
        # No CWE in the evidence block, but the title names the class.
        from vhlocal.consolidate import backfill_locations
        d = self._dir("## xss\nReflected content at app/views.py:5\n")
        fs = [Finding(id="V1", title="Reflected XSS via unsafe template", cwe="")]
        backfill_locations(fs, d, "")
        self.assertEqual(fs[0].cwe, "CWE-79")

    def test_near_dup_same_sink_varying_flow_merges(self):
        # Same vuln across samples, same file, close lines, flow worded differently
        # (overlapping/empty params) — the second pass must collapse them.
        a = Finding(id="V1", cwe="CWE-22", location="app/ops.py:116",
                    title="Arbitrary File Write via `BASE_EXPORT / name`",
                    data_flow="request body -> target = BASE_EXPORT / name")
        b = Finding(id="V2", cwe="CWE-22", location="app/ops.py:117",
                    title="Arbitrary File Write via unvalidated `name`")
        flag_duplicates([a, b])
        self.assertEqual(b.duplicate_of, "V1")

    def test_near_dup_different_files_kept_separate(self):
        # Five races in five files must NOT be merged just for sharing a CWE.
        fs = [Finding(id="V%d" % i, cwe="CWE-362", location="app/r%d.py:10" % i,
                      title="TOCTOU race") for i in range(5)]
        flag_duplicates(fs)
        self.assertTrue(all(f.duplicate_of is None for f in fs))

    def test_restored_location_enables_precise_dedup(self):
        from vhlocal.consolidate import backfill_locations
        d = self._dir("eval CWE-94 at app/ops.py:76\n")
        fs = [Finding(id="V1", title="`eval()` of expr", cwe="CWE-94"),
              Finding(id="V2", title="Unsafe `eval()` of expr (duplicate)", cwe="CWE-94")]
        backfill_locations(fs, d, "")
        flag_duplicates(fs)
        self.assertEqual(fs[1].duplicate_of, "V1")   # same file:line -> collapsed


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

    def test_path_spelling_variants_collapse(self):
        # One defect cited with and without its package dir must be a single root
        # cause, not two findings (audit P1 #4: balanced published separate pickle
        # findings for dispatch_operations.py vs backend/app/dispatch_operations.py).
        a = Finding(id="V1", title="Insecure pickle deserialization", cwe="CWE-502",
                    location="dispatch_operations.py:61", data_flow="body -> pickle.loads(b)")
        b = Finding(id="V2", title="Pickle RCE", cwe="CWE-502",
                    location="backend/app/dispatch_operations.py:61",
                    data_flow="body -> pickle.loads(b)")
        flag_duplicates([a, b])
        self.assertEqual(b.duplicate_of, "V1")

    def test_duplicate_assessment_is_marked_inherited(self):
        from vhlocal.consolidate import assess_candidates
        d = Path(tempfile.mkdtemp())
        (d / "app").mkdir()
        (d / "app" / "db.py").write_text(
            "def q(u):\n    cur.execute('SELECT ' + u)\n", encoding="utf-8")
        canon = Finding(id="V1", title="SQL injection", cwe="CWE-89",
                        location="app/db.py:2", data_flow="u -> execute(sql)")
        dup = Finding(id="V2", title="SQLi dup", cwe="CWE-89",
                      location="app/db.py:2", data_flow="u -> execute(sql)",
                      duplicate_of="V1")
        assess_candidates([canon, dup], {"repo": str(d)})
        self.assertFalse(canon.assessment_inherited)
        self.assertTrue(dup.assessment_inherited)
        self.assertIn("inherited from canonical V1", dup.assessment_reason)

    def test_findings_without_location_or_title_never_flagged(self):
        # No location AND no title signature -> nothing to key on -> never merged.
        a = Finding(id="VULN-100", cwe="CWE-89")
        b = Finding(id="VULN-101", cwe="CWE-89")
        flag_duplicates([a, b])
        self.assertIsNone(b.duplicate_of)

    def test_locationless_same_identifier_collapses(self):
        # Multi-sample runs where the model reported by function name and omitted
        # file:line: same family + same identifier must still collapse, or
        # hunt_samples silently multiplies every finding (the 50-vs-16 bug).
        a = Finding(id="VULN-200", cwe="CWE-611",
                    title="XXE Injection in `dispatch_xml_fold_450`")
        b = Finding(id="VULN-201", cwe="CWE-611",
                    title="XXE Injection in `dispatch_xml_fold_450`")
        flag_duplicates([a, b])
        self.assertEqual(b.duplicate_of, "VULN-200")

    def test_locationless_distinct_identifiers_not_collapsed(self):
        # Same family, different function identifiers -> genuinely distinct.
        a = Finding(id="VULN-300", cwe="CWE-639", title="IDOR in `get_customer`")
        b = Finding(id="VULN-301", cwe="CWE-639", title="IDOR in `update_region`")
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
        self.assertEqual(f.finding_state, "unresolved")
        self.assertEqual(f.poc_status, "authored")
        # Model claim preserved verbatim, but not promoted to a verdict.
        self.assertEqual(f.status, "Confirmed")

    def test_never_passes_without_execution_record(self):
        """Even with bash_enabled, no execution record => never 'passed'."""
        f = Finding(id="VULN-1", exploit_test="PASS")
        apply_validation([f], {"bash_enabled": True})
        self.assertEqual(f.test_status, "not_run")

    def test_dynamic_pass_requires_record(self):
        f = Finding(id="VULN-1", assessment="supported", candidate_key="key")
        meta = {"bash_enabled": True, "git_commit": "rev",
                "execution_records": {"VULN-1": {"exit_code": 0,
                    "candidate_key": "key", "revision": "rev",
                    "security_property_violated": True}}}
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

    def test_phase2b_hand_waved_disposition_is_flagged(self):
        # 2b claims 148 reviewed but supplies a few verdict rows and an "…"
        # hand-wave (regression: strict run 2026-09-10).
        d = Path(tempfile.mkdtemp())
        (d / "phase2b_output.md").write_text(
            "# Phase 2b\n\n**Total candidate findings:** 148\n\nAll 148 confirmed.\n\n"
            "| # | VULN-ID | CWE | Verdict |\n|---|---|---|---|\n"
            "| 1 | VULN-001 | CWE-89 | CONFIRMED |\n"
            "| 2 | VULN-002 | CWE-22 | CONFIRMED |\n"
            "| … | … | … | … |\n", encoding="utf-8")
        gap = compute_run_status(dict(META), results_dir=d)
        self.assertTrue(any("Phase 2b claimed 148" in r
                            for r in gap["coverage_degraded_reasons"]))

    def test_phase2b_aggregate_claim_is_partial(self):
        # "All 215 confirmed" with one aggregate row and zero per-candidate
        # dispositions must fail validation: execution is partial, not complete
        # (regression: run 2026-09-10-165124).
        d = Path(tempfile.mkdtemp())
        (d / "phase1_output.md").write_text("recon\n", encoding="utf-8")
        (d / "phase2b_output.md").write_text(
            "# Phase 2b\n\n**Total candidates:** 215\n\n"
            "All candidates confirmed.\n\n"
            "| Finding | Verdict |\n|---|---|\n"
            "| All VULN-* (215) | CONFIRMED |\n\n"
            "*No individual rows are listed due to the large number of findings.*\n",
            encoding="utf-8")
        meta = dict(META, phases_requested=["1", "2b"],
                    phases_completed=["1", "2b"])
        rs = compute_run_status(meta, results_dir=d)
        self.assertEqual(rs["execution_status"], "partial")
        self.assertTrue(any("aggregate" in r.lower()
                            for r in rs["coverage_degraded_reasons"]))

    def test_phase2b_full_disposition_not_flagged(self):
        # Every claimed candidate has a row — no hand-wave, no flag.
        d = Path(tempfile.mkdtemp())
        (d / "phase2b_output.md").write_text(
            "**Total candidate findings:** 2\n\n"
            "| # | VULN-ID | Verdict |\n|---|---|---|\n"
            "| 1 | VULN-001 | CONFIRMED |\n| 2 | VULN-002 | ELIMINATED |\n",
            encoding="utf-8")
        rs = compute_run_status(dict(META), results_dir=d)
        self.assertFalse(any("Phase 2b claimed" in r
                             for r in rs["coverage_degraded_reasons"]))

    def test_empty_deliverable_is_not_complete(self):
        # A phase the engine recorded as completed but which left an empty (0-byte)
        # deliverable does not count as complete — publication depends on valid
        # content (regression: strict run 2026-09-10, 0-byte phase3_output.md while
        # execution read "complete").
        d = Path(tempfile.mkdtemp())
        (d / "phase1_output.md").write_text("recon\n", encoding="utf-8")
        (d / "phase2b_output.md").write_text("verify\n", encoding="utf-8")
        (d / "phase3_output.md").write_text("", encoding="utf-8")   # empty
        (d / "README.md").write_text("report\n", encoding="utf-8")
        meta = dict(META, phases_requested=["1", "2b", "3", "4"],
                    phases_completed=["1", "2b", "3", "4"])
        rs = compute_run_status(meta, results_dir=d)
        self.assertEqual(rs["execution_status"], "partial")
        self.assertTrue(any("empty or missing" in r for r in rs["coverage_degraded_reasons"]))
        # Without a results_dir (pure metadata) the check is inert.
        self.assertEqual(compute_run_status(meta)["execution_status"], "complete")


class TestRender(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "README.md").write_text(README, encoding="utf-8")
        (self.d / "scan_meta.json").write_text(json.dumps(META), encoding="utf-8")
        self.out = render(self.d)

    def test_has_expected_sections(self):
        for s in ("Consolidated Scan Report", "1. Scan summary", "2. Checks enabled",
                  "3. Hypotheses and substantiated vulnerabilities", "4. Investigation priorities",
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
        self.assertIn("Evidence levels are separate from severity", self.out)
        self.assertIn("do not prove execution", self.out)

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
        self.assertIn("4. Investigation priorities", text)

    def test_empty_dir_still_produces_report(self):
        d = Path(tempfile.mkdtemp())
        md, _js = write_consolidated(d)
        self.assertIn("No hypotheses or substantiated vulnerabilities were reported", md.read_text(encoding="utf-8"))


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
