"""A shallow run must never report coverage 'complete'. The gvisor failure: recon
enumerated 0 entry points over 2,400+ files and the run reported complete. These
tests lock in the deterministic shallowness signals in compute_run_status."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import consolidate as C  # noqa: E402


class _Ledger:
    def __init__(self, total, not_reviewed=0):
        self.total = total
        self.reviewed = max(0, total - not_reviewed)
        self.not_reviewed = not_reviewed


def _repo(n_files, ext=".go"):
    d = Path(tempfile.mkdtemp())
    for i in range(n_files):
        (d / "f{0}{1}".format(i, ext)).write_text("x\n", encoding="utf-8")
    return d


def _meta(repo, partitions, **kw):
    m = {
        "repo": str(repo),
        "phases_requested": ["1", "2", "2b", "3", "3d", "4"],
        "phases_completed": ["1", "2", "2b", "3", "3d", "4"],
        "partitions": partitions,
        "partition_fallback": False,
        "partition_collapsed": False,
        "max_partitions": kw.get("max_partitions", 8),
        "agents": [],
    }
    m.update({k: v for k, v in kw.items() if k != "max_partitions"})
    return m


class CoverageHonesty(unittest.TestCase):
    def test_zero_entry_points_large_repo_is_degraded(self):
        # The gvisor shape: 0 entry points, big repo, "complete" execution.
        repo = _repo(300)
        rs = C.compute_run_status(_meta(repo, ["SG-1"], max_partitions=1),
                                  ledger=_Ledger(total=0))
        self.assertEqual(rs["coverage_status"], "degraded")
        joined = " ".join(rs["coverage_degraded_reasons"])
        self.assertIn("no entry points", joined)
        self.assertIn("single partition", joined)

    def test_single_partition_over_large_repo_flagged_even_if_max_is_one(self):
        # max_partitions=1 does NOT excuse shallow coverage of a large tree.
        repo = _repo(300)
        rs = C.compute_run_status(_meta(repo, ["SG-1"], max_partitions=1),
                                  ledger=_Ledger(total=12))
        self.assertEqual(rs["coverage_status"], "degraded")
        self.assertTrue(any("single partition" in r
                            for r in rs["coverage_degraded_reasons"]))

    def test_small_repo_single_partition_stays_complete(self):
        # A deliberate single-partition pass over a tiny repo is fine.
        repo = _repo(5)
        rs = C.compute_run_status(_meta(repo, ["SG-1"], max_partitions=1),
                                  ledger=_Ledger(total=8))
        self.assertEqual(rs["coverage_status"], "complete")
        self.assertEqual(rs["coverage_degraded_reasons"], [])

    def test_healthy_multi_partition_run_is_complete(self):
        repo = _repo(300)
        rs = C.compute_run_status(
            _meta(repo, ["SG-1", "SG-2", "SG-3", "SG-4"]),
            ledger=_Ledger(total=40))
        self.assertEqual(rs["coverage_status"], "complete")

    def test_threat_model_partitions_suppress_single_partition_warning(self):
        # If the PASTA threat model added partitions, a small recon-partition count
        # is no longer the whole story — don't double-warn.
        repo = _repo(300)
        m = _meta(repo, ["SG-1"], max_partitions=1,
                  threat_model_partitions=["SG-2", "SG-3"])
        rs = C.compute_run_status(m, ledger=_Ledger(total=20))
        self.assertFalse(any("single partition" in r
                             for r in rs["coverage_degraded_reasons"]))

    def test_missing_repo_keeps_checks_inert(self):
        m = _meta(Path("/nonexistent/repo"), ["SG-1"], max_partitions=1)
        rs = C.compute_run_status(m, ledger=_Ledger(total=0))
        # repo_files == 0 → the >=40 / >=150 gates never trip on these signals.
        joined = " ".join(rs["coverage_degraded_reasons"])
        self.assertNotIn("source files", joined)


if __name__ == "__main__":
    unittest.main()
