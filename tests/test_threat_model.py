"""Phase 1t — the PASTA threat model. Its value is the "Hunt targets" block that
ADDS partitions for archetype-specific surfaces recon's web/RPC entry-point
enumeration misses (the gvisor failure: a container sandbox whose real attack
surface is syscall handlers and packet parsers, none of which recon partitioned).
The parse must survive real model output, and augmentation must be purely additive,
existence-checked, priority-ordered, and bounded."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import phases as P  # noqa: E402


def _repo(files):
    d = Path(tempfile.mkdtemp())
    for rel in files:
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x\n", encoding="utf-8")
    return d


def _tm(repo, body):
    p = repo / "threat_model.md"
    p.write_text(body, encoding="utf-8")
    return p


_BLOCK = """# Threat model
## Hunt targets
```json
[{{"id":"TM-1","subsystem":"syscall handlers","paths":["pkg/sentry/syscalls"],"threat":"guest->host escape","cwe_class":"CWE-269","priority":"high"}},
 {{"id":"TM-2","subsystem":"packet parser","paths":["pkg/tcpip"],"threat":"memory corruption","cwe_class":"CWE-787","priority":"medium"}}]
```
"""


class ParseHuntTargets(unittest.TestCase):
    def test_fenced_json_with_nested_paths(self):
        repo = _repo(["pkg/sentry/syscalls/a.go", "pkg/tcpip/b.go"])
        got = P.parse_hunt_targets(_tm(repo, _BLOCK.format()))
        self.assertEqual(len(got), 2)
        self.assertEqual(got[0]["paths"], ["pkg/sentry/syscalls"])

    def test_json_amid_prose_and_other_brackets(self):
        repo = _repo(["a.go"])
        body = ("Some prose with a [markdown link](http://x) and a list [1, 2, 3].\n"
                "## Hunt targets\n```json\n"
                '[{"id":"TM-1","subsystem":"s","paths":["a.go"],"cwe_class":"CWE-1","priority":"low"}]\n'
                "```\nmore prose\n")
        got = P.parse_hunt_targets(_tm(repo, body))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["paths"], ["a.go"])

    def test_no_block_returns_empty(self):
        repo = _repo(["a.go"])
        self.assertEqual(P.parse_hunt_targets(_tm(repo, "# just prose, no targets")), [])

    def test_missing_file(self):
        self.assertEqual(P.parse_hunt_targets(Path("/nonexistent/threat_model.md")), [])


class Augment(unittest.TestCase):
    def setUp(self):
        self.repo = _repo(["website/main.go", "pkg/sentry/syscalls/a.go", "pkg/tcpip/b.go"])
        self.recon = [P.Partition("SG-1", "website HTTP server — website/main.go")]

    def test_adds_uncovered_skips_covered(self):
        tm = _tm(self.repo, _BLOCK.format())
        aug = P.augment_partitions_from_threat_model(self.recon, self.repo, tm)
        # website is covered by recon → not re-added; two new surfaces added.
        self.assertEqual(len(aug.added), 2)
        descs = " ".join(p.description for p in aug.partitions)
        self.assertIn("pkg/sentry/syscalls", descs)
        self.assertIn("pkg/tcpip", descs)

    def test_covered_target_not_duplicated(self):
        body = ('## Hunt targets\n```json\n'
                '[{"id":"TM-1","subsystem":"website","paths":["website/main.go"],'
                '"cwe_class":"CWE-601","priority":"low"}]\n```\n')
        aug = P.augment_partitions_from_threat_model(self.recon, self.repo, _tm(self.repo, body))
        self.assertEqual(aug.added, [])                 # recon already covers it

    def test_nonexistent_paths_dropped(self):
        body = ('## Hunt targets\n```json\n'
                '[{"id":"TM-1","subsystem":"ghost","paths":["does/not/exist"],'
                '"cwe_class":"CWE-1","priority":"high"}]\n```\n')
        aug = P.augment_partitions_from_threat_model(self.recon, self.repo, _tm(self.repo, body))
        self.assertEqual(aug.added, [])

    def test_partition_ids_continue_from_recon(self):
        # recon ends at SG-1 → first threat partition is SG-2.
        aug = P.augment_partitions_from_threat_model(self.recon, self.repo, _tm(self.repo, _BLOCK.format()))
        self.assertEqual(aug.added[0], "SG-2")

    def test_priority_order_and_cap(self):
        # 3 targets, cap=2 → the two 'high'/'medium' survive, 'low' dropped.
        repo = _repo(["a/x.go", "b/y.go", "c/z.go"])
        body = ('## Hunt targets\n```json\n'
                '[{"id":"L","subsystem":"low","paths":["c"],"cwe_class":"CWE-3","priority":"low"},'
                ' {"id":"H","subsystem":"high","paths":["a"],"cwe_class":"CWE-1","priority":"high"},'
                ' {"id":"M","subsystem":"med","paths":["b"],"cwe_class":"CWE-2","priority":"medium"}]\n```\n')
        aug = P.augment_partitions_from_threat_model([], repo, _tm(repo, body), max_extra=2)
        self.assertEqual(len(aug.added), 2)
        descs = " ".join(p.description for p in aug.partitions)
        self.assertIn("high", descs)      # high priority kept
        self.assertIn("med", descs)       # medium kept
        self.assertNotIn("[THREAT-MODEL TARGET] low", descs)  # low dropped by cap

    def test_empty_when_no_threat_model(self):
        aug = P.augment_partitions_from_threat_model(
            self.recon, self.repo, self.repo / "threat_model.md")
        self.assertEqual(aug.added, [])
        self.assertEqual([p.ident for p in aug.partitions], ["SG-1"])


class PhaseWiring(unittest.TestCase):
    def test_phase_1t_registered(self):
        self.assertIn("1t", P.PHASES_BY_KEY)
        p = P.PHASES_BY_KEY["1t"]
        self.assertEqual(p.output_file, "threat_model.md")
        self.assertEqual(p.prompt_file, "phase1t_threat_model.md")
        self.assertFalse(p.fan_out)

    def test_1t_ordered_between_recon_and_hunt(self):
        keys = [p.key for p in P.PHASES]
        self.assertEqual(keys.index("1t"), keys.index("1") + 1)
        self.assertLess(keys.index("1t"), keys.index("2"))

    def test_scanspec_flag(self):
        from vhlocal.engine import ScanSpec
        off = ScanSpec.from_dict({"repo": "/tmp/x", "skill_dir": "/tmp/s"})
        self.assertFalse(off.threat_model)
        on = ScanSpec.from_dict({"repo": "/tmp/x", "skill_dir": "/tmp/s", "threat_model": True})
        self.assertTrue(on.threat_model)


if __name__ == "__main__":
    unittest.main()
