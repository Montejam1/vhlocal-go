"""The SBOM builder must parse dependency manifests across ecosystems into a valid
CycloneDX 1.5 document — deterministically, stdlib-only, skipping vendored trees."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import sbom  # noqa: E402


def _repo(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


class SBOM(unittest.TestCase):
    def _names(self, cdx):
        return {c["name"]: c for c in cdx["components"]}

    def test_requirements_txt(self):
        d = _repo({"requirements.txt":
                   "flask==2.0.1\nrequests>=2.28\n# comment\ndjango~=4.1\n-e .\n"})
        cdx = sbom.build_sbom(d)
        names = self._names(cdx)
        self.assertEqual(names["flask"]["version"], "2.0.1")
        self.assertEqual(names["flask"]["purl"], "pkg:pypi/flask@2.0.1")
        self.assertIn("requests", names)   # non-== operator still captured
        self.assertIn("django", names)
        self.assertNotIn("-e", names)

    def test_pyproject_pep621_and_poetry(self):
        d = _repo({"pyproject.toml":
                   '[project]\ndependencies = ["flask>=2.0", "httpx==0.24.1"]\n'
                   '[tool.poetry.dependencies]\npython = "^3.9"\nboto3 = "^1.26"\n'})
        names = self._names(sbom.build_sbom(d))
        self.assertIn("flask", names)
        self.assertEqual(names["httpx"]["version"], "0.24.1")
        self.assertIn("boto3", names)
        self.assertNotIn("python", names)  # python constraint excluded

    def test_package_json(self):
        d = _repo({"package.json": json.dumps({
            "dependencies": {"express": "^4.18.0"},
            "devDependencies": {"jest": "~29.0.0"}})})
        names = self._names(sbom.build_sbom(d))
        self.assertEqual(names["express"]["version"], "4.18.0")
        self.assertEqual(names["express"]["purl"], "pkg:npm/express@4.18.0")
        self.assertIn("jest", names)

    def test_go_mod(self):
        d = _repo({"go.mod":
                   "module example.com/app\ngo 1.21\n"
                   "require (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n"})
        names = self._names(sbom.build_sbom(d))
        self.assertIn("github.com/gin-gonic/gin", names)
        self.assertEqual(names["github.com/gin-gonic/gin"]["version"], "v1.9.1")

    def test_pom_xml_group(self):
        d = _repo({"pom.xml":
                   '<project xmlns="http://maven.apache.org/POM/4.0.0">'
                   '<dependencies><dependency>'
                   '<groupId>org.springframework</groupId>'
                   '<artifactId>spring-core</artifactId>'
                   '<version>5.3.20</version>'
                   '</dependency></dependencies></project>'})
        names = self._names(sbom.build_sbom(d))
        c = names["spring-core"]
        self.assertEqual(c["group"], "org.springframework")
        self.assertEqual(c["purl"], "pkg:maven/org.springframework/spring-core@5.3.20")

    def test_skips_vendored_dirs(self):
        d = _repo({
            "package.json": json.dumps({"dependencies": {"real-dep": "1.0.0"}}),
            "node_modules/foo/package.json":
                json.dumps({"dependencies": {"should-not-appear": "9.9.9"}}),
        })
        names = self._names(sbom.build_sbom(d))
        self.assertIn("real-dep", names)
        self.assertNotIn("should-not-appear", names)

    def test_cyclonedx_shape(self):
        d = _repo({"requirements.txt": "flask==2.0.1\n"})
        cdx = sbom.build_sbom(d, timestamp="2026-01-01T00:00:00Z")
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["specVersion"], "1.5")
        self.assertEqual(cdx["metadata"]["timestamp"], "2026-01-01T00:00:00Z")
        self.assertEqual(cdx["metadata"]["component"]["type"], "application")

    def test_dedup_across_manifests(self):
        d = _repo({
            "requirements.txt": "flask==2.0.1\n",
            "sub/requirements.txt": "flask==2.0.1\n",
        })
        flasks = [c for c in sbom.build_sbom(d)["components"] if c["name"] == "flask"]
        self.assertEqual(len(flasks), 1)

    def test_deterministic_order(self):
        d = _repo({"requirements.txt": "zzz==1.0\naaa==2.0\nmmm==3.0\n"})
        a = sbom.build_sbom(d)["components"]
        b = sbom.build_sbom(d)["components"]
        self.assertEqual([c["name"] for c in a], [c["name"] for c in b])
        self.assertEqual([c["name"] for c in a], ["aaa", "mmm", "zzz"])

    def test_summary(self):
        d = _repo({"requirements.txt": "flask==2.0.1\n",
                   "package.json": json.dumps({"dependencies": {"express": "4.0.0"}})})
        s = sbom.summary(sbom.build_sbom(d))
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["by_ecosystem"], {"pypi": 1, "npm": 1})
        self.assertEqual(len(s["components"]), 2)

    def test_write_sbom(self):
        d = _repo({"requirements.txt": "flask==2.0.1\n"})
        out = Path(tempfile.mkdtemp())
        s = sbom.write_sbom(out, d)
        self.assertTrue((out / sbom.SBOM_FILE).exists())
        self.assertEqual(s["total"], 1)
        written = json.loads((out / sbom.SBOM_FILE).read_text())
        self.assertEqual(written["bomFormat"], "CycloneDX")

    def test_empty_repo_valid_sbom(self):
        d = Path(tempfile.mkdtemp())
        cdx = sbom.build_sbom(d)
        self.assertEqual(cdx["components"], [])
        self.assertEqual(cdx["bomFormat"], "CycloneDX")


if __name__ == "__main__":
    unittest.main()
