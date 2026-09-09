"""Evidence publication contracts, including model claims that must not promote."""
import copy
import html as html_lib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vhlocal import consolidate as C
from vhlocal.evidence import candidate_key
from vhlocal.sarif import build_sarif


class EvidenceReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        (self.repo / "app.py").write_text('value = request.args["q"]\ncur.execute(value)\n')
        self.f = C.Finding(id="V1", title="Query injection", cwe="CWE-89",
                           location="app.py:2", status="Confirmed", exploit_test="PASS",
                           data_flow="q -> cur.execute(value)")
        self.meta = {"repo": str(self.repo), "git_commit": "revision-one"}
        self.key = candidate_key(self.f, "revision-one")
        self.record = {
            "verdict": "supported", "revision": "revision-one", "reviewer": "reviewer-1",
            "rationale": "The request's query value reaches execute without parameter binding.",
            "entry_point": "GET /search", "attacker_control": "query parameter q",
            "preconditions": "authenticated search access",
            "defenses_reviewed": "No binding or validation in this path.",
            "security_impact": "Caller can change query semantics.",
            "evidence": [{"path": "app.py", "start_line": 1, "end_line": 2,
                          "quote": 'value = request.args["q"]\ncur.execute(value)'}],
        }

    def assess(self, record=None):
        self.meta["verification_records"] = {self.key: record} if record is not None else {}
        C.assess_candidates([self.f], self.meta)
        C.apply_validation([self.f], self.meta)
        return self.f.classification

    def test_model_confirmation_and_pass_are_not_a_review(self):
        # A well-formed candidate is statically supported by default, but the
        # model's own "Confirmed"/"PASS" prose never earns the higher *reviewed*
        # tier — that requires a source-grounded review record.
        self.assertEqual(self.assess(), "statically_supported")
        self.assertIn("Statically supported", self.f.assessment_reason)
        self.assertEqual(self.f.test_status, "not_run")

    def test_source_grounded_review_has_an_explanation(self):
        self.assertEqual(self.assess(self.record), "reviewed")
        self.assertEqual(self.f.assessment_reason, self.record["rationale"])
        self.assertEqual(self.f.test_status, "not_run")

    def test_invalid_reviews_do_not_reach_reviewed(self):
        # An invalid review never earns the *reviewed* tier. The candidate is
        # well-formed, so it stays statically_supported rather than dropping to a
        # bare hypothesis — but it is not a source-grounded reviewed vulnerability.
        for field, value in (("verdict", "UNVERIFIED"), ("rationale", ""),
                             ("revision", "old"), ("defenses_reviewed", ""),
                             ("security_impact", ""), ("evidence", [])):
            with self.subTest(field=field):
                record = dict(self.record, **{field: value})
                self.assertNotEqual(self.assess(record), "reviewed")

    def test_invalid_or_unrelated_citations_do_not_reach_reviewed(self):
        for change in ({"end_line": 999999}, {"path": "../outside.py"},
                       {"quote": "invented evidence"}, {"path": "missing.py"},
                       {"start_line": 1, "end_line": 1, "quote": 'value = request.args["q"]'}):
            with self.subTest(change=change):
                record = copy.deepcopy(self.record)
                record["evidence"][0].update(change)
                self.assertNotEqual(self.assess(record), "reviewed")

    def test_changed_code_invalidates_review(self):
        (self.repo / "app.py").write_text("execute_bound(value)\n")
        # The review no longer matches source, so it cannot reach *reviewed*.
        self.assertNotEqual(self.assess(self.record), "reviewed")

    def test_no_location_is_a_hypothesis(self):
        # Without a source location nothing can be substantiated — not even the
        # static tier — so the candidate is a bare hypothesis.
        self.f.location = ""
        self.key = candidate_key(self.f, "revision-one")
        self.assertEqual(self.assess(self.record), "hypothesis")

    def test_missing_checkout_cannot_reach_reviewed(self):
        # An unavailable checkout cannot verify a review's source quotes, so the
        # *reviewed* tier is unreachable — but a well-formed candidate is still
        # statically supported (the static gate is lenient on a missing tree).
        self.meta["repo"] = ""
        self.assertEqual(self.assess(self.record), "statically_supported")

    def test_duplicate_inherits_canonical_assessment(self):
        # A duplicate inherits its canonical's tier and state, never assessed on
        # its own. The canonical here is statically supported.
        duplicate = C.Finding(id="V2", duplicate_of="V1")
        C.assess_candidates([duplicate, self.f], self.meta)
        C.apply_validation([duplicate, self.f], self.meta)
        self.assertEqual(duplicate.classification, "statically_supported")
        self.assertEqual(duplicate.finding_state, C.STATE_STATIC_SUPPORTED)

    def test_orphan_duplicate_is_a_hypothesis(self):
        # A duplicate whose canonical is absent cannot inherit and has no
        # evidence of its own, so it stays an unresolved hypothesis.
        orphan = C.Finding(id="V2", duplicate_of="GONE")
        C.assess_candidates([orphan], self.meta)
        C.apply_validation([orphan], self.meta)
        self.assertEqual(orphan.classification, "hypothesis")
        self.assertEqual(orphan.finding_state, C.STATE_UNRESOLVED)

    def test_exit_zero_is_not_a_reproduction(self):
        self.meta.update(bash_enabled=True, execution_records={"V1": {"exit_code": 0}})
        self.assess(self.record)
        self.assertNotEqual(self.f.finding_state, C.STATE_DYNAMIC_CONFIRMED)

    def test_sarif_maps_hypothesis_to_review_not_failure(self):
        # A candidate that clears no static gate (no CWE) is a hypothesis and must
        # publish as a SARIF review note, never a failure result.
        self.f.cwe = ""
        self.assess()
        self.assertEqual(self.f.classification, "hypothesis")
        result = build_sarif([self.f.to_dict()], self.meta)["runs"][0]["results"][0]
        self.assertEqual(result["kind"], "review")
        self.assertEqual(result["level"], "note")
        self.assertEqual(result["properties"]["classification"], "hypothesis")

    def test_sarif_maps_statically_supported_to_failure(self):
        # A statically-supported finding publishes as a SARIF failure result.
        self.assess()
        self.assertEqual(self.f.classification, "statically_supported")
        result = build_sarif([self.f.to_dict()], self.meta)["runs"][0]["results"][0]
        self.assertEqual(result["kind"], "fail")

    def test_hunt_reason_is_preserved_without_becoming_a_review(self):
        path = self.repo / "hunt.md"
        path.write_text('#### [VULN-001] Query injection\n- **Class**: CWE-89\n'
                        '- **Location**: app.py:2\n- **Root Cause**: Query text is unbound.\n'
                        '- **Data Flow**: q -> execute\n')
        finding = C._parse_hunt_file(path)[0]
        C.assess_candidates([finding], self.meta)
        self.assertEqual(finding.hypothesis_reason, "Query text is unbound.")
        # The root-cause prose is preserved but does not itself constitute a
        # review — the finding is statically supported, never *reviewed*.
        self.assertEqual(finding.classification, "statically_supported")

    def test_invalid_sidecar_fails_closed(self):
        (self.repo / "scan_meta.json").write_text(json.dumps(self.meta))
        (self.repo / "verification_records.json").write_text("not json")
        self.assertEqual(C.load_meta(self.repo)["verification_records"], {})

    def test_generated_reports_share_the_assessment_and_reason(self):
        from vhlocal.render_html import render_html
        results = self.repo / "results"
        results.mkdir()
        (results / "results").mkdir()
        # A well-formed hunt observation (CWE + concrete title + resolvable
        # location) is statically supported by default...
        (results / "results" / "sg-1_inj.md").write_text(
            '#### [VULN-001] Query injection\n- **Class**: CWE-89\n'
            '- **Location**: app.py:2\n- **Severity**: High\n'
            '- **Root Cause**: Query text is unbound.\n')
        # ...while a real claim with no weakness class fails the static gate and
        # stays a hypothesis (kept, but not published as a finding).
        (results / "results" / "sg-2_hyp.md").write_text(
            '#### [VULN-002] Unvalidated redirect in the login flow\n- **Class**: \n'
            '- **Location**: app.py:1\n- **Severity**: Low\n'
            '- **Root Cause**: Field is user-controlled.\n')
        (results / "scan_meta.json").write_text(json.dumps(self.meta))
        md = C.render(results)
        html = render_html(results)
        self.assertIn("1 substantiated findings", md)
        self.assertIn("statically-supported", md)
        self.assertIn("Why the scanner flagged this", md)
        self.assertIn("Query text is unbound.", md)
        self.assertIn("Statically-supported", html)
        self.assertNotIn("Every finding is confirmed", html)
        C.write_consolidated(results)
        payload = json.loads((results / "findings.json").read_text())
        self.assertEqual(payload["vulnerability_counts"], {"High": 1})
        self.assertEqual(payload["assessment"]["statically_supported"], 1)
        self.assertEqual(payload["assessment"]["reviewed"], 0)
        self.assertEqual(payload["assessment"]["hypotheses"], 1)
        from vhlocal.reports import parse_report
        indexed = parse_report(results)
        self.assertEqual(indexed.findings, 1)
        self.assertEqual(indexed.hypotheses, 1)
        # A review explicitly keyed to the supported candidate upgrades it to the
        # *reviewed* tier in both formats.
        supported = [f for f in C.parse_findings(results) if f.location == "app.py:2"][0]
        key = candidate_key(supported, self.meta["git_commit"])
        (results / "verification_records.json").write_text(json.dumps({key: self.record}))
        self.assertIn("(1 reviewed, 0 statically-supported)", C.render(results))
        self.assertIn(self.record["rationale"], html_lib.unescape(render_html(results)))
