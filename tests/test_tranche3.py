"""Tranche 3 — exploit-chain analysis, IaC lens gating, and the vote-count
propagation that carries multi-sample confidence to the final findings."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import votes, chains  # noqa: E402
from vhlocal.engine import _has_iac  # noqa: E402


class Votes(unittest.TestCase):
    def test_location_keys_and_lookup(self):
        vm = {}
        entry = {"keys": votes.location_keys("app/dispatch.py:61 and dispatch.py:70"),
                 "votes": 3, "samples": 3}
        votes.merge_votes(vm, [entry])
        # a finding at :65 is the same 20-line bucket as :61 -> matches
        self.assertEqual(votes.votes_for("app/dispatch.py:65", vm), (3, 3))
        self.assertEqual(votes.votes_for("other.py:5", vm), (0, 0))

    def test_merge_keeps_highest_vote(self):
        vm = {}
        votes.merge_votes(vm, [{"keys": {"a.py:@0"}, "votes": 1, "samples": 3}])
        votes.merge_votes(vm, [{"keys": {"a.py:@0"}, "votes": 3, "samples": 3}])
        votes.merge_votes(vm, [{"keys": {"a.py:@0"}, "votes": 2, "samples": 3}])
        self.assertEqual(vm["a.py:@0"]["votes"], 3)

    def test_write_load_roundtrip(self):
        d = Path(tempfile.mkdtemp())
        votes.write_votes(d, {"a.py:@1": {"votes": 2, "samples": 3}})
        self.assertEqual(votes.load_votes(d)["a.py:@1"]["votes"], 2)
        # empty map writes nothing
        d2 = Path(tempfile.mkdtemp())
        votes.write_votes(d2, {})
        self.assertEqual(votes.load_votes(d2), {})


def _F(fid, cwe, loc, entry="", sev="High", rank=3):
    return {"id": fid, "cwe": cwe, "normalized_cwe": cwe, "location": loc,
            "entry_point": entry, "severity": sev, "severity_rank": rank}


class Chains(unittest.TestCase):
    def test_authz_amplified_sink_groups_co_located_sinks(self):
        fs = [
            _F("VULN-1", "CWE-862", "app/ops.py:10"),          # missing authz
            _F("VULN-2", "CWE-502", "app/ops.py:40"),          # pickle sink
            _F("VULN-3", "CWE-94", "app/ops.py:55"),           # eval sink
            _F("VULN-9", "CWE-79", "other/x.py:3"),            # elsewhere
        ]
        out = chains.build_chains(fs)
        amp = [c for c in out if c["kind"] == "authz-amplified-sink"]
        self.assertEqual(len(amp), 1)                          # grouped, not 2 pairs
        self.assertIn("VULN-1", amp[0]["finding_ids"])
        self.assertIn("VULN-2", amp[0]["finding_ids"])
        self.assertIn("VULN-3", amp[0]["finding_ids"])
        self.assertNotIn("VULN-9", amp[0]["finding_ids"])      # different file
        self.assertTrue(amp[0]["id"].startswith("CHAIN-"))

    def test_shared_entry_point_chain(self):
        fs = [_F("VULN-1", "CWE-89", "a.py:1", entry="POST /api/x"),
              _F("VULN-2", "CWE-79", "b.py:2", entry="POST /api/x")]
        out = chains.build_chains(fs)
        self.assertTrue(any(c["kind"] == "shared-surface" for c in out))

    def test_no_chain_when_nothing_composes(self):
        fs = [_F("VULN-1", "CWE-89", "a.py:1", entry="GET /a"),
              _F("VULN-2", "CWE-79", "b.py:2", entry="GET /b")]
        self.assertEqual(chains.build_chains(fs), [])

    def test_duplicates_ignored(self):
        fs = [_F("VULN-1", "CWE-862", "app/ops.py:10"),
              _F("VULN-2", "CWE-502", "app/ops.py:40")]
        fs[1]["duplicate_of"] = "VULN-2b"
        self.assertEqual(chains.build_chains(fs), [])   # sink is a dup -> no chain

    def test_ranked_most_severe_first(self):
        fs = [
            _F("A", "CWE-862", "f.py:1", sev="Low", rank=1),
            _F("B", "CWE-502", "f.py:2", sev="High+", rank=5),
            _F("C", "CWE-306", "g.py:1", entry="POST /y", sev="Medium", rank=2),
            _F("D", "CWE-79", "g.py:2", entry="POST /y", sev="Medium", rank=2),
        ]
        out = chains.build_chains(fs)
        self.assertTrue(out)
        ranks = [c["_rank"] for c in out]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


class IaCGate(unittest.TestCase):
    def _repo(self, *files):
        d = Path(tempfile.mkdtemp())
        for f in files:
            p = d / f
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x", encoding="utf-8")
        return d

    def test_detects_common_iac(self):
        self.assertTrue(_has_iac(self._repo("infra/main.tf")))
        self.assertTrue(_has_iac(self._repo("Dockerfile")))
        self.assertTrue(_has_iac(self._repo(".github/workflows/ci.yml")))
        self.assertTrue(_has_iac(self._repo("k8s/deployment.yaml")))

    def test_ignores_plain_app_repo(self):
        self.assertFalse(_has_iac(self._repo("app.py", "config.yaml", "README.md")))


if __name__ == "__main__":
    unittest.main()
