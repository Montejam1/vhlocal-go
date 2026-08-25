"""Tranche 2 — beat the run-to-run variance: multi-sample hunt voting (union for
recall) and the max_budget_usd cap. The union recovers volatile access-control
findings a single hunt pass drops; the budget cap is the wallet backstop that
lets multi-sampling run without a $16 surprise."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal.engine import _merge_hunt_samples, ScanSpec  # noqa: E402
from vhlocal.pricing import Budget, cost_usd  # noqa: E402
from vhlocal.client import Usage  # noqa: E402


class MergeSamples(unittest.TestCase):
    def test_union_recovers_finding_seen_in_one_sample(self):
        s1 = "## A\nSQLi db.py:10\n\n## B\nXSS v.py:5\n"
        s2 = "## A\nSQLi db.py:10\n\n## C\nIDOR users.py:17\n"   # C only in s2
        out, entries = _merge_hunt_samples([s1, s2], "SG-1", "NAV", 2)
        self.assertIn("IDOR users.py:17", out)     # union keeps it
        self.assertIn("XSS v.py:5", out)
        self.assertIn("SQLi db.py:10", out)
        # vote entries carry location keys for downstream propagation
        self.assertTrue(any(e["votes"] == 2 for e in entries))

    def test_identical_block_deduped_with_vote_count(self):
        s = "## A\nSQLi db.py:10\n"
        out, entries = _merge_hunt_samples([s, s, s], "SG-1", "INJ", 3)
        self.assertEqual(out.count("SQLi db.py:10"), 1)   # collapsed
        self.assertIn("votes: 3/3", out)
        self.assertEqual(entries[0]["votes"], 3)

    def test_stub_samples_dropped(self):
        stub = "# SG / NAV\n\nAgent produced no output (error).\n"
        real = "## A\nreal finding at x.py:1\n"
        out, _ = _merge_hunt_samples([stub, real, stub], "SG-1", "NAV", 3)
        self.assertIn("real finding at x.py:1", out)
        self.assertNotIn("produced no output", out)

    def test_all_stubs_yields_no_output(self):
        stub = "Agent produced no output (error).\n"
        out, entries = _merge_hunt_samples([stub, stub], "SG-1", "LOG", 2)
        self.assertIn("no output across 2 samples", out)
        self.assertEqual(entries, [])

    def test_single_real_sample_passes_through(self):
        real = "## A\nfinding\n"
        out, entries = _merge_hunt_samples([real], "SG-1", "INJ", 1)
        self.assertEqual(out, real)
        self.assertEqual(entries, [])


class _Client:
    def __init__(self, pp=0.0, pc=0.0):
        self.usage = Usage()
        self.price_prompt = pp
        self.price_completion = pc


class BudgetCap(unittest.TestCase):
    def test_cost_and_exceeded(self):
        c = _Client(pp=1e-6, pc=2e-6)
        c.usage.add(1_000_000, 500_000, 1.0)   # $1.00 + $1.00 = $2.00
        b = Budget(2.0, [c])
        self.assertAlmostEqual(b.spent(), 2.0, places=6)
        self.assertTrue(b.exceeded())
        self.assertTrue(b.enabled())

    def test_under_cap_not_exceeded(self):
        c = _Client(pp=1e-6, pc=0)
        c.usage.add(500_000, 0, 1.0)           # $0.50
        self.assertFalse(Budget(2.0, [c]).exceeded())

    def test_zero_cap_disabled_even_with_spend(self):
        c = _Client(pp=1e-3, pc=0)
        c.usage.add(1_000_000, 0, 1.0)         # $1000, but no cap
        b = Budget(0, [c])
        self.assertFalse(b.enabled())
        self.assertFalse(b.exceeded())

    def test_local_free_client_costs_nothing(self):
        c = _Client()                          # prices 0 (local)
        c.usage.add(9_000_000, 9_000_000, 1.0)
        self.assertEqual(Budget(1.0, [c]).spent(), 0.0)

    def test_multi_client_sums_per_price(self):
        paid = _Client(pp=1e-6, pc=0); paid.usage.add(1_000_000, 0, 1.0)   # $1
        local = _Client(); local.usage.add(5_000_000, 0, 1.0)             # $0
        self.assertAlmostEqual(Budget(5, [paid, local]).spent(), 1.0, places=6)

    def test_non_numeric_usage_coerced_to_zero(self):
        class Bad:
            usage = object()
            price_prompt = object()
        self.assertEqual(Budget(1.0, [Bad()]).spent(), 0.0)   # never raises


class SpecFields(unittest.TestCase):
    def test_from_dict_clamps_samples_and_budget(self):
        s = ScanSpec.from_dict({"repo": "/x", "skill_dir": "/y",
                                "hunt_samples": 99, "max_budget_usd": -3})
        self.assertEqual(s.hunt_samples, 5)        # clamped to 5
        self.assertEqual(s.max_budget_usd, 0.0)    # negative -> 0
        s2 = ScanSpec.from_dict({"repo": "/x", "skill_dir": "/y",
                                 "hunt_samples": 3, "max_budget_usd": 4.5})
        self.assertEqual(s2.hunt_samples, 3)
        self.assertEqual(s2.max_budget_usd, 4.5)


if __name__ == "__main__":
    unittest.main()
