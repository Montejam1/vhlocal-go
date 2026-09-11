"""Authorization map — cross-endpoint discovery + authz/IDOR refutation evidence."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import authz, consolidate as C, quality  # noqa: E402


def _repo(files):
    d = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return d


_APP = {
    "workers.py":
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "v1 = APIRouter(prefix='/api/v1')\n"
        "@router.get('/workers/{id}/status')\n"
        "def status(id, _=Depends(require_owner)):\n"
        "    return get(id)\n"
        "@v1.get('/workers/{id}/status')\n"
        "def status_v1(id):\n"
        "    return get(id)\n",
}


class ResourceKey(unittest.TestCase):
    def test_strips_version_and_normalizes_params(self):
        self.assertEqual(authz.resource_key("/api/v1/workers/{id}/status"),
                         authz.resource_key("/workers/{wid}/status"))
        self.assertEqual(authz.resource_key("/api/v2/x/<pk>"), "/x/{}")


class Inconsistency(unittest.TestCase):
    def test_api_v1_bypass_is_flagged(self):
        repo = _repo(_APP)
        amap = authz.build_authz_map(repo)
        incs = amap["inconsistencies"]
        self.assertEqual(len(incs), 1)
        self.assertEqual(incs[0]["resource_key"], "/workers/{}/status")
        self.assertEqual(incs[0]["unguarded"][0]["function"], "status_v1")

    def test_consistent_resources_not_flagged(self):
        repo = _repo({"a.py":
                      "from fastapi import APIRouter, Depends\n"
                      "r = APIRouter()\n"
                      "@r.get('/a/{id}')\n"
                      "def a(id, _=Depends(require_owner)):\n    return 1\n"
                      "@r.get('/api/v1/a/{id}')\n"
                      "def a2(id, _=Depends(require_owner)):\n    return 1\n"})
        self.assertEqual(authz.build_authz_map(repo)["inconsistencies"], [])


class AuthnVsAuthz(unittest.TestCase):
    """Authentication is not authorization — only an authz guard may refute an IDOR."""

    def setUp(self):
        self.repo = _repo({"h.py":
            "from fastapi import APIRouter, Depends\n"
            "r = APIRouter()\n"
            "@r.get('/a/{id}')\n"
            "def authn_only(id, user=Depends(get_current_user)):\n"
            "    return get(id)\n"
            "@r.get('/b/{id}')\n"
            "def authz_ok(id, _=Depends(require_owner)):\n"
            "    return get(id)\n"})
        self.routes = authz.authz_routes(self.repo)

    def test_authenticated_handler_has_no_authz(self):
        r = authz.guard_for_location(self.routes, "h.py:5")
        self.assertEqual(r.function, "authn_only")
        self.assertTrue(r.guarded)       # authenticated
        self.assertFalse(r.has_authz)    # but NOT authorized -> a real IDOR survives

    def test_authorized_handler_has_authz(self):
        r = authz.guard_for_location(self.routes, "h.py:8")
        self.assertEqual(r.function, "authz_ok")
        self.assertTrue(r.has_authz)


class IdorRefutation(unittest.TestCase):
    def setUp(self):
        self.repo = _repo({"h.py":
            "from fastapi import APIRouter, Depends\n"
            "r = APIRouter()\n"
            "@r.get('/a/{id}')\n"
            "def authn_only(id, user=Depends(get_current_user)):\n"
            "    return db.get(id)\n"
            "@r.get('/b/{id}')\n"
            "def authz_ok(id, _=Depends(require_owner)):\n"
            "    return db.get(id)\n"})

    def _cls(self, loc):
        f = C.Finding(id="V1", title="IDOR on resource", cwe="CWE-639", location=loc,
                      data_flow="id -> db.get(id) without an ownership check",
                      from_confirmed=True, votes=3, vote_samples=3)
        return quality.evaluate(f, self.repo, quality.BALANCED)

    def test_idor_refuted_when_handler_is_authorized(self):
        q = self._cls("h.py:8")    # authz_ok enforces require_owner
        self.assertFalse(q.substantiated)
        ce = {c.name: c for c in q.checks}["class_evidence"]
        self.assertEqual(ce.status, quality.FAIL)

    def test_idor_survives_when_handler_is_only_authenticated(self):
        q = self._cls("h.py:5")    # authn_only: authenticated, no ownership check
        ce = {c.name: c for c in q.checks}["class_evidence"]
        self.assertNotEqual(ce.status, quality.FAIL)   # not refuted
        self.assertTrue(q.substantiated)               # real IDOR stands (logic path)


class Discovery(unittest.TestCase):
    def test_inconsistency_becomes_a_statically_supported_finding(self):
        repo = _repo(_APP)
        meta = {"repo": str(repo)}
        fs = C.authz_findings(meta)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].cwe, "CWE-862")
        self.assertIn("/api/v1/workers", fs[0].location + fs[0].entry_point)
        C.assess_candidates(fs, meta)
        self.assertEqual(fs[0].classification, "statically_supported")
        self.assertIn("Cross-endpoint authorization", fs[0].assessment_reason)

    def test_no_findings_when_repo_absent(self):
        self.assertEqual(C.authz_findings({"repo": ""}), [])


if __name__ == "__main__":
    unittest.main()
