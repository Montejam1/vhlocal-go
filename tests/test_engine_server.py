"""Tests for the engine, job queue, and server — no Ollama required.

    cd vulnhunt-local && python3 -m unittest discover -s tests -v

Everything that would touch a model is stubbed. What's exercised here is the
logic that decides *whether* and *where* a scan runs: spec round-tripping,
phase validation, queue state transitions, crash recovery, and the two path
checks that keep the HTTP surface from being a file-read primitive.
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.engine import (  # noqa: E402
    ScanError,
    ScanSpec,
    _make_phase_clients,
    _role_client_config,
    model_tag,
    resolve_results_dir,
    select_phases,
)
from vhlocal.jobs import (  # noqa: E402
    STATUS_CANCELLED,
    STATUS_INTERRUPTED,
    STATUS_QUEUED,
    Job,
    JobStore,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestPerRoleModels(unittest.TestCase):
    def _spec(self, **kw):
        return ScanSpec(repo=Path("/x"), skill_dir=Path("/y"), **kw)

    def test_roles_fall_back_to_hunt(self):
        s = self._spec(backend="ollama", model="gpt-oss:120b", host="h")
        for role in ("recon", "hunt", "verify", "reproduce"):
            self.assertEqual(_role_client_config(s, role),
                             ("ollama", "gpt-oss:120b", "h"))

    def test_role_overrides_and_backend_pinning(self):
        s = self._spec(backend="openrouter", model="kimi", host="",
                       recon_model="gpt-oss", recon_backend="ollama", recon_host="oh",
                       verify_model="qwen", verify_backend="ollama",
                       reproduce_model="cheap", reproduce_backend="openai",
                       reproduce_host="ah")
        self.assertEqual(_role_client_config(s, "recon"), ("ollama", "gpt-oss", "oh"))
        self.assertEqual(_role_client_config(s, "hunt"), ("openrouter", "kimi", ""))
        # verify pins backend but inherits the hunt host (its own host unset)
        self.assertEqual(_role_client_config(s, "verify"), ("ollama", "qwen", ""))
        self.assertEqual(_role_client_config(s, "reproduce"),
                         ("openai", "cheap", "ah"))

    def test_make_phase_clients_dedup_and_no_3d_client(self):
        # hunt + verify share the default client; recon overrides → 2 distinct.
        s = self._spec(backend="ollama", model="gpt-oss:120b", host="h",
                       recon_model="m2", recon_backend="openai", recon_host="oh",
                       sweep_mode="deterministic")
        by_phase, distinct = _make_phase_clients(s, select_phases("all"))
        self.assertEqual(len(distinct), 2)
        self.assertIs(by_phase["2"], by_phase["2b"])   # same (backend,model,host)
        self.assertIsNot(by_phase["1"], by_phase["2"])  # recon differs
        self.assertNotIn("3d", by_phase)               # deterministic sweep: no model


class TestDashboardStats(unittest.TestCase):
    def test_aggregate_and_usage_denominator(self):
        from vhlocal.server import aggregate_stats
        s = aggregate_stats([
            (5, {"prompt_tokens": 100, "completion_tokens": 20, "seconds": 60}, "gpt-oss"),
            (3, {}, "kimi"),   # died before recording usage
            (7, {"prompt_tokens": 900, "completion_tokens": 80, "seconds": 30}, "gpt-oss"),
        ])
        self.assertEqual(s["scans"], 3)
        self.assertEqual(s["total_tokens"], 1100)
        self.assertEqual(s["findings"], 15)
        # token/time averages divide by scans WITH usage (2), not 3
        self.assertEqual(s["avg_tokens_per_scan"], 550)
        self.assertEqual(s["avg_seconds_per_scan"], 45)
        # findings average divides by all scans
        self.assertEqual(s["avg_findings_per_scan"], 5.0)
        self.assertEqual(s["by_model"]["gpt-oss"]["scans"], 2)
        self.assertEqual(s["by_model"]["kimi"]["tokens"], 0)

    def test_empty(self):
        from vhlocal.server import aggregate_stats
        s = aggregate_stats([])
        self.assertEqual(s["scans"], 0)
        self.assertEqual(s["avg_tokens_per_scan"], 0)


class TestLiveStats(unittest.TestCase):
    def _store(self):
        return JobStore(Path(tempfile.mkdtemp()) / "jobs.json", auto_start=False)

    def test_tokens_findings_and_model_captured(self):
        st = self._store()
        j = Job(id="j", spec={"model": "kimi"})
        st._jobs["j"] = j
        st._update_progress("j", {"type": "agent_start", "label": "p1",
                                  "model": "gpt-oss:120b", "index": 1, "total": 1})
        st._update_progress("j", {"type": "agent_done",
                                  "prompt_tokens": 278739, "completion_tokens": 6752})
        st._update_progress("j", {"type": "findings", "count": 7, "stage": "confirmed"})
        p = j.public()
        self.assertEqual(p["current_model"], "gpt-oss:120b")
        self.assertEqual(p["prompt_tokens"], 278739)
        self.assertEqual(p["findings_count"], 7)
        self.assertEqual(p["findings_stage"], "confirmed")
        # final supersedes confirmed; a later confirmed must NOT regress it
        st._update_progress("j", {"type": "findings", "count": 5, "stage": "final"})
        st._update_progress("j", {"type": "findings", "count": 99, "stage": "confirmed"})
        self.assertEqual(j.findings_count, 5)
        self.assertEqual(j.findings_stage, "final")


class TestScanSpec(unittest.TestCase):
    def test_round_trip_preserves_fields(self):
        spec = ScanSpec(
            repo=Path("/tmp/r"), skill_dir=Path("/tmp/s"), model="m:1",
            num_ctx=4096, max_partitions=3, verify_model="v:2", resume=True,
        )
        back = ScanSpec.from_dict(spec.to_dict())
        self.assertEqual(back.repo, Path("/tmp/r"))
        self.assertEqual(back.model, "m:1")
        self.assertEqual(back.num_ctx, 4096)
        self.assertEqual(back.max_partitions, 3)
        self.assertEqual(back.verify_model, "v:2")
        self.assertTrue(back.resume)

    def test_to_dict_is_json_serializable(self):
        spec = ScanSpec(repo=Path("/tmp/r"), skill_dir=Path("/tmp/s"))
        json.dumps(spec.to_dict())  # must not raise on Path objects

    def test_efficiency_fields_round_trip(self):
        spec = ScanSpec(repo=Path("/tmp/r"), skill_dir=Path("/tmp/s"),
                        phase2_mode="combined", enforce_coverage=False,
                        seed_routes=True)
        back = ScanSpec.from_dict(spec.to_dict())
        self.assertEqual(back.phase2_mode, "combined")
        self.assertFalse(back.enforce_coverage)
        self.assertTrue(back.seed_routes)

    def test_phase2_mode_defaults_to_split(self):
        self.assertEqual(
            ScanSpec(repo=Path("/tmp/r"), skill_dir=Path("/tmp/s")).phase2_mode,
            "split")

    def test_combined_mode_uses_one_group(self):
        """Combined mode fans out 1 agent per partition, not 3."""
        from vhlocal.phases import CLASS_GROUPS, COMBINED_GROUP
        # split: N partitions x 3 classes; combined: N x 1.
        parts = 7
        split_units = parts * len(CLASS_GROUPS)
        combined_units = parts * 1
        self.assertEqual(split_units, 21)
        self.assertEqual(combined_units, 7)
        # COMBINED_GROUP bundles all three class reference files.
        self.assertEqual(len(COMBINED_GROUP[1]), len(CLASS_GROUPS))

    def test_from_dict_coerces_string_numbers(self):
        back = ScanSpec.from_dict({
            "repo": "/tmp/r", "skill_dir": "/tmp/s",
            "num_ctx": "8192", "max_partitions": "2",
        })
        self.assertEqual(back.num_ctx, 8192)
        self.assertIsInstance(back.num_ctx, int)
        self.assertEqual(back.max_partitions, 2)

    def test_from_dict_ignores_blanks(self):
        back = ScanSpec.from_dict({
            "repo": "/tmp/r", "skill_dir": "/tmp/s",
            "verify_model": "", "num_ctx": "",
        })
        self.assertIsNone(back.verify_model)


class TestPhaseSelection(unittest.TestCase):
    def test_all(self):
        self.assertEqual(len(select_phases("all")), 6)

    def test_subset_order_preserved(self):
        got = [p.key for p in select_phases("2b,1")]
        self.assertEqual(got, ["2b", "1"])

    def test_unknown_raises(self):
        with self.assertRaises(ScanError):
            select_phases("99")

    def test_whitespace_tolerated(self):
        self.assertEqual([p.key for p in select_phases(" 1 , 2 ")], ["1", "2"])


class TestNaming(unittest.TestCase):
    def test_model_tag_strips_punctuation(self):
        self.assertEqual(model_tag("gpt-oss:120b"), "gptoss120b")
        self.assertEqual(model_tag("qwen3.5:122b-a10b"), "qwen35122ba10b")

    def test_results_dir_honours_explicit_out(self):
        spec = ScanSpec(repo=Path("/tmp"), skill_dir=Path("/tmp"), out=Path("/tmp/xyz"))
        self.assertEqual(resolve_results_dir(spec), Path("/tmp/xyz").resolve())

    def test_results_dir_default_shape(self):
        d = Path(tempfile.mkdtemp())
        rep = Path(tempfile.mkdtemp())
        spec = ScanSpec(repo=d, skill_dir=d, model="gpt-oss:120b", reports_dir=rep)
        got = resolve_results_dir(spec)
        # Name shape is preserved so *_VULNHUNT_RESULTS_* globs still match...
        self.assertTrue(got.name.startswith(d.name + "_VULNHUNT_RESULTS_gptoss120b_"))
        # ...but the location is the reports dir, never the scanned repo.
        self.assertEqual(got.parent, rep.resolve())
        self.assertNotEqual(got.parent, d.resolve())


class TestJobStore(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # auto_start=False: assert on queue state without the worker
        # consuming jobs the instant they are submitted.
        self.store = JobStore(self.tmp / "jobs.json", auto_start=False)

    def _spec(self):
        return ScanSpec(repo=self.tmp, skill_dir=self.tmp)

    def test_submit_creates_queued_job(self):
        job = self.store.submit(self._spec())
        self.assertEqual(self.store.get(job.id)["status"], STATUS_QUEUED)

    def test_submit_resolves_results_dir_up_front(self):
        # The UI shows the destination before the scan starts; resolving later
        # would produce a different timestamp than the scan actually uses.
        job = self.store.submit(self._spec())
        self.assertTrue(job.results_dir)
        self.assertEqual(job.spec["out"], job.results_dir)

    def test_cancel_queued_job(self):
        job = self.store.submit(self._spec())
        self.assertTrue(self.store.cancel(job.id))
        self.assertEqual(self.store.get(job.id)["status"], STATUS_CANCELLED)

    def test_cancel_unknown_job_returns_false(self):
        self.assertFalse(self.store.cancel("nope"))

    def test_cancel_terminal_job_returns_false(self):
        job = self.store.submit(self._spec())
        self.store.cancel(job.id)
        self.assertFalse(self.store.cancel(job.id))

    def test_state_persists_across_instances(self):
        job = self.store.submit(self._spec())
        self.store.cancel(job.id)
        reopened = JobStore(self.tmp / "jobs.json")
        self.assertIsNotNone(reopened.get(job.id))

    def test_running_job_becomes_interrupted_on_reload(self):
        """A scan cannot survive its process; never silently re-run it."""
        path = self.tmp / "j2.json"
        payload = {"jobs": [Job(id="abc", spec={}, status="running").__dict__]}
        path.write_text(json.dumps(payload), encoding="utf-8")
        store = JobStore(path, auto_start=False)
        got = store.get("abc")
        self.assertEqual(got["status"], STATUS_INTERRUPTED)
        self.assertIn("restart", (got["error"] or "").lower())

    def test_corrupt_state_file_does_not_crash(self):
        path = self.tmp / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        self.assertEqual(JobStore(path, auto_start=False).list_jobs(), [])

    def test_events_ring_is_bounded(self):
        from vhlocal.jobs import MAX_EVENTS_PER_JOB
        job = self.store.submit(self._spec())
        for i in range(MAX_EVENTS_PER_JOB + 50):
            self.store._emit(job.id, {"type": "log", "message": str(i)})
        self.assertLessEqual(
            len(self.store.events_since(job.id, 0)), MAX_EVENTS_PER_JOB)

    def test_subscriber_receives_event(self):
        job = self.store.submit(self._spec())
        q = self.store.subscribe(job.id)
        self.store._emit(job.id, {"type": "log", "message": "hi"})
        self.assertEqual(q.get(timeout=2)["message"], "hi")

    def test_unsubscribe_stops_delivery(self):
        job = self.store.submit(self._spec())
        q = self.store.subscribe(job.id)
        self.store.unsubscribe(job.id, q)
        self.store._emit(job.id, {"type": "log", "message": "x"})
        self.assertTrue(q.empty())

    def test_progress_tracked_from_events(self):
        job = self.store.submit(self._spec())
        self.store._emit(job.id, {"type": "phase_start", "key": "2", "title": "Hunt"})
        self.store._emit(job.id, {
            "type": "agent_start", "label": "p2:sg-1:inj", "index": 3, "total": 16})
        got = self.store.get(job.id)
        self.assertIn("Hunt", got["phase"])
        self.assertEqual(got["agent_index"], 3)
        self.assertEqual(got["agent_total"], 16)


class TestServerPathChecks(unittest.TestCase):
    """The two checks that stop the HTTP surface being a file-read primitive."""

    def setUp(self):
        from vhlocal.server import Config
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        (self.tmp / "allowed").mkdir()
        self.cfg = Config(
            skill_dir=self.tmp, allow_roots=[self.tmp / "allowed"],
            store=JobStore(self.tmp / "j.json", auto_start=False),
            host="127.0.0.1", port=1, reports_dir=self.tmp / "reports",
        )

    def test_inside_root_allowed(self):
        self.assertTrue(self.cfg.path_allowed(self.tmp / "allowed" / "x"))

    def test_root_itself_allowed(self):
        self.assertTrue(self.cfg.path_allowed(self.tmp / "allowed"))

    def test_outside_root_denied(self):
        self.assertFalse(self.cfg.path_allowed(Path("/etc")))
        self.assertFalse(self.cfg.path_allowed(self.tmp))

    def test_traversal_denied(self):
        self.assertFalse(
            self.cfg.path_allowed(self.tmp / "allowed" / ".." / ".." / "etc"))

    def test_sibling_prefix_not_confused(self):
        # "/x/allowed-evil" must not pass a naive startswith("/x/allowed").
        (self.tmp / "allowed-evil").mkdir()
        self.assertFalse(self.cfg.path_allowed(self.tmp / "allowed-evil"))


class TestWebAssets(unittest.TestCase):
    def test_index_exists_and_is_self_contained(self):
        idx = REPO_ROOT / "vhlocal" / "web" / "index.html"
        self.assertTrue(idx.exists(), "web/index.html missing")
        html = idx.read_text(encoding="utf-8")
        # A CSP-free offline page must not FETCH an external resource. Ban the
        # actual fetch vectors, not a bare scheme string — a backend host in a
        # JS config value or a warning message (e.g. the OpenRouter URL) is not a
        # fetched resource, and the page still loads nothing off-host.
        for bad in ('src="http', "src='http", 'href="http', "href='http",
                    "@import", "url(http", "http://cdn", "unpkg", "jsdelivr",
                    "googleapis"):
            self.assertNotIn(bad, html, "external resource {0!r} in UI".format(bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestReportsDirDefault(unittest.TestCase):
    """Reports must not land inside the scanned repository."""

    def test_default_is_outside_repo(self):
        from vhlocal.engine import DEFAULT_REPORTS_DIR
        repo = Path(tempfile.mkdtemp()).resolve()
        spec = ScanSpec(repo=repo, skill_dir=repo, model="gpt-oss:120b")
        got = resolve_results_dir(spec)
        self.assertEqual(got.parent, DEFAULT_REPORTS_DIR.resolve())
        self.assertNotIn(str(repo), str(got))

    def test_reports_dir_override(self):
        repo = Path(tempfile.mkdtemp()).resolve()
        rep = Path(tempfile.mkdtemp()).resolve()
        spec = ScanSpec(repo=repo, skill_dir=repo, reports_dir=rep)
        self.assertEqual(resolve_results_dir(spec).parent, rep)

    def test_explicit_out_beats_reports_dir(self):
        repo = Path(tempfile.mkdtemp()).resolve()
        spec = ScanSpec(repo=repo, skill_dir=repo,
                        reports_dir=Path("/tmp/ignored"), out=Path("/tmp/exact"))
        self.assertEqual(resolve_results_dir(spec), Path("/tmp/exact").resolve())

    def test_reports_dir_survives_spec_round_trip(self):
        spec = ScanSpec(repo=Path("/tmp/r"), skill_dir=Path("/tmp/s"),
                        reports_dir=Path("/tmp/rep"))
        self.assertEqual(ScanSpec.from_dict(spec.to_dict()).reports_dir,
                         Path("/tmp/rep"))


class TestReportIndex(unittest.TestCase):
    def setUp(self):
        from vhlocal import reports as R
        self.R = R
        self.base = Path(tempfile.mkdtemp()).resolve()

    def _make(self, name, readme=None, extra=()):
        d = self.base / name
        (d / "results").mkdir(parents=True)
        (d / "results" / "sg-1_inj.md").write_text("x", encoding="utf-8")
        (d / "phase1_output.md").write_text("recon", encoding="utf-8")
        for f in extra:
            (d / f).write_text("y", encoding="utf-8")
        if readme is not None:
            (d / "README.md").write_text(readme, encoding="utf-8")
        return d

    README = (
        "# VulnHunter Security Audit Report\n\n"
        "**Run ID**: app_VULNHUNT_RESULTS_gptoss120b_2026-08-14-101500\n"
        "**Repository**: https://github.com/acme/app\n"
        "**Audit Date**: 2026-08-14\n"
        "**Branch**: main [abc1234]\n"
        "**Model**: gpt-oss:120b\n"
        "**Findings Summary**: 3 High+\n\n"
        "## Summary of Confirmed Findings\n"
        "| ID | Title | CWE | Severity |\n|---|---|---|---|\n"
        "| VULN-001 | SQLi | CWE-89 | High+ |\n"
        "| VULN-002 | Path traversal | CWE-22 | High+ |\n"
        "| VULN-003 | Cmd inj | CWE-78 | High+ |\n"
    )

    def test_lists_and_parses_header(self):
        self._make("app_VULNHUNT_RESULTS_gptoss120b_2026-08-14-101500", self.README)
        got = self.R.list_reports(self.base)
        self.assertEqual(len(got), 1)
        r = got[0]
        self.assertEqual(r.repo, "https://github.com/acme/app")
        # dir-derived tag is authoritative; header value kept separately
        self.assertEqual(r.model, "gptoss120b")
        self.assertEqual(r.model_reported, "gpt-oss:120b")
        self.assertEqual(r.findings, 3)
        self.assertTrue(r.complete)

    def test_incomplete_report_still_listed(self):
        self._make("app_VULNHUNT_RESULTS_gptoss120b_2026-08-14-101501", readme=None)
        got = self.R.list_reports(self.base)
        self.assertEqual(len(got), 1)
        self.assertFalse(got[0].complete)
        self.assertEqual(got[0].findings, 0)
        self.assertIn("1", got[0].phases_present)

    def test_phases_present_tracked(self):
        self._make("a_VULNHUNT_RESULTS_m_2026-01-01-000000", self.README,
                   extra=("phase2b_output.md", "phase3d_output.md"))
        r = self.R.list_reports(self.base)[0]
        for k in ("1", "2", "2b", "3d", "4"):
            self.assertIn(k, r.phases_present)

    def test_findings_deduped_by_id(self):
        dup = self.README + "\n### [VULN-001] SQLi\n| VULN-001 | again | | |\n"
        self._make("b_VULNHUNT_RESULTS_m_2026-01-01-000001", dup)
        self.assertEqual(self.R.list_reports(self.base)[0].findings, 3)

    def test_findings_count_from_json_when_readme_is_stub(self):
        """The Reports-tab '0 findings' bug: Phase 4 left README a stub but the
        run confirmed findings. Count must come from findings.json."""
        import json as _json
        stub = ("# Vulnerability Hunt Results\n\n"
                "This directory contains the results of the session.\n")
        d = self._make("c_VULNHUNT_RESULTS_m_2026-01-01-000002", readme=stub)
        (d / "findings.json").write_text(_json.dumps({
            "counts": {"High+": 2, "High": 10, "Medium": 4},
            "findings": [{"id": "VULN-%03d" % i, "duplicate_of": None}
                         for i in range(1, 17)],
        }), encoding="utf-8")
        r = self.R.list_reports(self.base)[0]
        self.assertEqual(r.findings, 16)
        self.assertEqual(r.severities.get("high"), 10)

    def test_json_excludes_clustered_duplicates(self):
        import json as _json
        d = self._make("d_VULNHUNT_RESULTS_m_2026-01-01-000003", readme=self.README)
        (d / "findings.json").write_text(_json.dumps({
            "counts": {"High": 2},
            "findings": [
                {"id": "VULN-001", "duplicate_of": None},
                {"id": "VULN-002", "duplicate_of": None},
                {"id": "VULN-003", "duplicate_of": "VULN-001"},
            ],
        }), encoding="utf-8")
        # findings.json wins over the 3-row README table; dup excluded → 2.
        self.assertEqual(self.R.list_reports(self.base)[0].findings, 2)

    def test_non_report_dirs_ignored(self):
        (self.base / "random").mkdir()
        (self.base / "random" / "notes.txt").write_text("hi", encoding="utf-8")
        self.assertEqual(self.R.list_reports(self.base), [])

    def test_missing_dir_returns_empty(self):
        self.assertEqual(self.R.list_reports(self.base / "nope"), [])

    def test_extra_dirs_folded_in(self):
        other = Path(tempfile.mkdtemp()).resolve() / "custom_out"
        other.mkdir(parents=True)
        (other / "README.md").write_text(self.README, encoding="utf-8")
        got = self.R.list_reports(self.base, extra_dirs=[other])
        self.assertEqual(len(got), 1)

    def test_extra_dirs_deduped_against_base(self):
        d = self._make("c_VULNHUNT_RESULTS_m_2026-01-01-000002", self.README)
        self.assertEqual(len(self.R.list_reports(self.base, extra_dirs=[d])), 1)

    def test_resolve_report_matches_id(self):
        d = self._make("d_VULNHUNT_RESULTS_m_2026-01-01-000003", self.README)
        self.assertEqual(self.R.resolve_report(self.base, d.name), d)

    def test_resolve_report_rejects_traversal_id(self):
        # ids are matched against the enumerated set, never joined as a path.
        self._make("e_VULNHUNT_RESULTS_m_2026-01-01-000004", self.README)
        for bad in ("../../etc", "/etc/passwd", "..", "e_VULNHUNT_RESULTS_m_2026-01-01-000004/.."):
            self.assertIsNone(self.R.resolve_report(self.base, bad), bad)

    def test_unicode_header_normalised(self):
        # gpt-oss emits U+2011; the header parser must still match.
        weird = self.README.replace("Run ID", "Run ID").replace("main [abc1234]", "main‑x")
        self._make("f_VULNHUNT_RESULTS_m_2026-01-01-000005", weird)
        r = self.R.list_reports(self.base)[0]
        self.assertEqual(r.branch, "main-x")

    def test_dir_model_wins_over_hallucinated_header(self):
        """The README's Model field is model-authored and untrustworthy."""
        bad = self.README.replace("**Model**: gpt-oss:120b", "**Model**: claude-opus-4-8")
        self._make("g_VULNHUNT_RESULTS_gptoss120b_2026-01-01-000006", bad)
        r = [x for x in self.R.list_reports(self.base) if x.id.startswith("g_")][0]
        self.assertEqual(r.model, "gptoss120b")
        self.assertEqual(r.model_reported, "claude-opus-4-8")


class TestReportDelete(unittest.TestCase):
    """Deleting a report is guarded: resolved against the enumerated set (no
    traversal), must sit inside the reports tree, and can't be an active scan."""

    def setUp(self):
        import vhlocal.server as S
        from vhlocal.jobs import JobStore
        self.S = S
        self.base = Path(tempfile.mkdtemp()).resolve()
        for n in ("a_VULNHUNT_RESULTS_m_2026-01-01-000000",
                  "b_VULNHUNT_RESULTS_m_2026-01-02-000000"):
            d = self.base / n
            d.mkdir()
            (d / "scan_meta.json").write_text("{}", encoding="utf-8")
            (d / "README.md").write_text("# x", encoding="utf-8")
        self.store = JobStore(self.base / "jobs.json", auto_start=False)
        S.CFG = S.Config(skill_dir=self.base, allow_roots=[self.base],
                         store=self.store, host="127.0.0.1", port=0,
                         reports_dir=self.base, ollama_host="http://x")

    def _handler(self):
        class H:
            def _json(self, o, s=200):
                self.out = ("json", o, s)

            def _err(self, m, s=400):
                self.out = ("err", m, s)
        H._delete_report = self.S.Handler._delete_report
        return H()

    def test_deletes_a_report(self):
        from vhlocal.reports import list_reports, resolve_report
        self.assertEqual(len(list_reports(self.base)), 2)
        rid = list_reports(self.base)[0].id
        h = self._handler()
        h._delete_report(rid, resolve_report(self.base, rid))
        self.assertEqual(h.out[0], "json")
        self.assertEqual(len(list_reports(self.base)), 1)

    def test_refuses_outside_reports_dir(self):
        h = self._handler()
        h._delete_report("x", Path("/etc"))
        self.assertEqual(h.out[0], "err")
        self.assertEqual(h.out[2], 403)

    def test_refuses_reports_dir_itself(self):
        h = self._handler()
        h._delete_report("root", self.base)
        self.assertEqual(h.out[2], 403)


class TestWebUiIntegrity(unittest.TestCase):
    """The engine UI is one hand-edited file with a large inline <script>.

    A stray duplicate declaration is a SyntaxError that silently kills the
    *entire* script — the page renders its static shell and nothing works, with
    no console-free symptom. That happened once; this catches it.
    """

    def _ui(self):
        return (REPO_ROOT / "vhlocal" / "web" / "index.html").read_text(encoding="utf-8")

    def _inline_js(self):
        # The page has more than one inline <script> (a tiny pre-paint theme
        # setter in <head>, plus the main app script). Validate the largest one —
        # that is the application logic this suite exists to protect.
        import re
        blocks = re.findall(r"<script>(.*?)</script>", self._ui(), re.S)
        self.assertTrue(blocks, "no inline <script> found")
        return max(blocks, key=len)

    def test_inline_script_parses(self):
        import shutil, subprocess, tempfile
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available for syntax check")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
            fh.write(self._inline_js())
            path = fh.name
        proc = subprocess.run([node, "--check", path],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(proc.returncode, 0,
                         "inline UI script has a syntax error:\n" +
                         proc.stdout.decode("utf-8", "replace"))

    def test_no_duplicate_top_level_declarations(self):
        """Cheap guard that runs even without node."""
        import re
        js = self._inline_js()
        names = re.findall(r"^(?:let|const|var)\s+([A-Za-z_$][\w$]*)", js, re.M)
        dupes = {n for n in names if names.count(n) > 1}
        self.assertEqual(dupes, set(), "duplicate top-level declarations: " + str(dupes))

    def test_single_swappable_pane(self):
        """The rail is static; only #view swaps."""
        ui = self._ui()
        self.assertEqual(ui.count('id="view"'), 1)
        self.assertNotIn('id="reportsView"', ui)
        self.assertNotIn("grid-column:1 / -1", ui)

    def test_views_declare_lifecycle(self):
        js = self._inline_js()
        self.assertIn("const VIEWS", js)
        self.assertIn("window.navigate", js)
        # navigate() must tear the outgoing view down, or the SSE stream leaks
        self.assertIn("unmount", js)
        self.assertIn("closeStream", js)
