"""Pre-report quality battery — corroborating a candidate against the real source.

These lock in the "happy medium": metadata completeness alone never publishes a
finding; a sink claim must be backed by a matching sink in the cited source (or,
for logic classes, by a described flow + a precise location + agreement), at a
strictness the operator sets."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vhlocal import quality  # noqa: E402
from vhlocal.consolidate import Finding  # noqa: E402


def _repo(files):
    d = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return d


# A file whose cited line genuinely executes a SQL query, and one that does not.
_REPO = {
    "app/db.py": "def q(u):\n    cur.execute('SELECT * FROM t WHERE u=' + u)\n    return cur\n",
    "app/util.py": "def helper(x):\n    return x + 1\n",
}


class SourceCorroboration(unittest.TestCase):
    def setUp(self):
        self.repo = _repo(_REPO)

    def _cls(self, f, level):
        q = quality.evaluate(f, self.repo, level)
        return q.substantiated

    def test_sink_present_is_substantiated_everywhere(self):
        f = Finding(id="V1", title="SQL injection in q", cwe="CWE-89",
                    location="app/db.py:2", data_flow="u -> execute(sql)")
        for level in quality.LEVELS:
            self.assertTrue(self._cls(f, level), level)

    def test_sink_absent_demotes_at_balanced_and_strict(self):
        # The cited line has no query — a checked-and-absent sink. Balanced/strict
        # demote to hypothesis; lenient still needs *some* signal.
        f = Finding(id="V1", title="SQL injection somewhere", cwe="CWE-89",
                    location="app/util.py:1")
        self.assertFalse(self._cls(f, quality.LENIENT))    # no flow/agreement either
        self.assertFalse(self._cls(f, quality.BALANCED))
        self.assertFalse(self._cls(f, quality.STRICT))

    def test_lenient_accepts_flow_when_source_absent(self):
        # Same absent-sink finding, but now with a described flow + agreement.
        # Lenient publishes on that alone; balanced/strict still demand the source.
        f = Finding(id="V1", title="SQL injection via search", cwe="CWE-89",
                    location="app/util.py:1", data_flow="req.q -> execute(query)",
                    from_confirmed=True)
        self.assertTrue(self._cls(f, quality.LENIENT))
        self.assertFalse(self._cls(f, quality.BALANCED))
        self.assertFalse(self._cls(f, quality.STRICT))

    def test_strict_needs_a_second_signal_beyond_the_sink(self):
        # Source sink present but no flow and no agreement: balanced accepts,
        # strict does not.
        f = Finding(id="V1", title="SQL injection in q", cwe="CWE-89",
                    location="app/db.py:2")
        self.assertTrue(self._cls(f, quality.BALANCED))
        self.assertFalse(self._cls(f, quality.STRICT))


class LogicClasses(unittest.TestCase):
    """IDOR/authz/TOCTOU have no syntactic sink — corroborated by flow + a precise
    location + agreement, never by a source pattern."""

    def setUp(self):
        self.repo = _repo(_REPO)

    def test_idor_with_flow_precise_and_agreement_is_supported(self):
        f = Finding(id="V1", title="IDOR on GET /users/{id}", cwe="CWE-639",
                    location="app/db.py:2", data_flow="id -> record without owner check",
                    from_confirmed=True)
        for level in quality.LEVELS:
            self.assertTrue(quality.evaluate(f, self.repo, level).substantiated, level)

    def test_idor_without_agreement_is_hypothesis_at_balanced(self):
        f = Finding(id="V1", title="IDOR on GET /users/{id}", cwe="CWE-639",
                    location="app/db.py:2", data_flow="id -> record without owner check")
        # No votes, not confirmed: lenient still accepts (flow is a signal), but
        # balanced/strict require agreement for a logic class.
        self.assertTrue(quality.evaluate(f, self.repo, quality.LENIENT).substantiated)
        self.assertFalse(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)

    def test_idor_without_precise_location_is_hypothesis(self):
        f = Finding(id="V1", title="IDOR somewhere in users", cwe="CWE-639",
                    location="app/db.py", data_flow="id -> record without owner check",
                    from_confirmed=True)
        self.assertFalse(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)

    def test_votes_satisfy_agreement(self):
        f = Finding(id="V1", title="IDOR on GET /users/{id}", cwe="CWE-639",
                    location="app/db.py:2", data_flow="id -> record without owner check",
                    votes=3, vote_samples=5)
        self.assertTrue(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)


class StructuralFloor(unittest.TestCase):
    def setUp(self):
        self.repo = _repo(_REPO)

    def test_missing_cwe_is_hypothesis_at_every_level(self):
        f = Finding(id="V1", title="Something bad in db", cwe="",
                    location="app/db.py:2", data_flow="u -> execute(sql)",
                    from_confirmed=True, votes=5, vote_samples=5)
        for level in quality.LEVELS:
            self.assertFalse(quality.evaluate(f, self.repo, level).substantiated, level)

    def test_placeholder_title_is_hypothesis(self):
        # A padding row (Phase 3 emits "Placeholder for additional finding") never
        # clears the concrete-claim floor, even with a CWE + a real sink location.
        f = Finding(id="V1", title="Placeholder for additional finding", cwe="CWE-89",
                    location="app/db.py:2", data_flow="u -> execute(sql)")
        self.assertFalse(quality.evaluate(f, self.repo, quality.LENIENT).substantiated)

    def test_unresolvable_location_is_hypothesis(self):
        f = Finding(id="V1", title="SQL injection", cwe="CWE-89",
                    location="app/ghost.py:2", data_flow="u -> execute(sql)")
        self.assertFalse(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)


class EvidenceProvenance(unittest.TestCase):
    """A sink pattern for corroboration must come from the authoritative CWE table,
    never from call tokens the model wrote into its own data flow — otherwise a
    Mongo call can 'corroborate' an SSRF label (regression: strict run 2026-09-10,
    VULN-027)."""

    def setUp(self):
        self.repo = _repo({"backend/app/ops.py":
                           "def r(payload):\n" + "\n" * 130 +
                           "    q = payload.get('filter', payload)\n"
                           "    return MongoClient().ops.records.find_one(q)\n"})

    def test_mongo_source_does_not_corroborate_an_ssrf_label(self):
        # SSRF (CWE-918) cited at a line whose only call is a Mongo find_one, with
        # the model's flow naming find_one. Authoritative SSRF sinks are HTTP
        # clients, so this must NOT corroborate — at any strictness.
        f = Finding(id="V1", title="SSRF via webhook url", cwe="CWE-918",
                    location="backend/app/ops.py:131",
                    data_flow="payload -> find_one(query)", from_confirmed=True)
        c = {x.name: x for x in quality.evaluate(f, self.repo, quality.STRICT).checks}
        self.assertEqual(c["source_corroborated"].status, quality.FAIL)
        self.assertFalse(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)

    def test_genuine_nosql_at_the_same_line_is_corroborated(self):
        f = Finding(id="V1", title="NoSQL injection via Mongo query", cwe="CWE-943",
                    location="backend/app/ops.py:132", data_flow="payload -> find_one(q)")
        c = {x.name: x for x in quality.evaluate(f, self.repo, quality.BALANCED).checks}
        self.assertEqual(c["source_corroborated"].status, quality.PASS)


class FlowIsTraced(unittest.TestCase):
    def test_prose_without_a_connective_is_not_a_flow(self):
        f = Finding(id="V1", cwe="CWE-918",
                    data_flow="This endpoint appears vulnerable to request forgery in some cases")
        self.assertEqual(quality.check_flow_described(f).status, quality.FAIL)

    def test_traced_flow_passes(self):
        for df in ("hook.url reaches urllib.request.urlopen",
                   "payload -> find_one(query)",
                   "user input is passed to cursor.execute"):
            f = Finding(id="V1", cwe="CWE-918", data_flow=df)
            self.assertEqual(quality.check_flow_described(f).status, quality.PASS, df)


class ClassSpecificEvidence(unittest.TestCase):
    """Agreement is not proof — class-specific evidence can veto (audit P1 #5)."""

    def setUp(self):
        self.repo = _repo({
            "models.py": "class User(Base):\n    email = Column(String, unique=True)\n",
            # A real security consumer: the random value is stored into reset_token.
            "tok.py": "import random\ndef reset(u):\n"
                      "    u.reset_token = ''.join(random.choice(A) for _ in range(6))\n",
            # No consumer — the random value is just returned; 'nonce' is only in the
            # route name (audit-2 #3: a name is not a consumer).
            "code.py": "import random\n@app.get('/ops/nonce/dispatch-fan-304')\n"
                       "def gen(length):\n"
                       "    return ''.join(random.choice(A) for _ in range(length))\n",
        })

    def test_route_name_keyword_is_not_a_consumer(self):
        f = Finding(id="V1", title="Weak PRNG in nonce endpoint", cwe="CWE-330",
                    location="code.py:4", data_flow="length -> random.choice -> returned code")
        self.assertFalse(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)

    def test_weak_random_reaching_a_real_consumer_is_substantiated(self):
        tok = Finding(id="V1", title="Weak PRNG for reset token", cwe="CWE-330",
                      location="tok.py:3", data_flow="random.choice -> u.reset_token")
        self.assertTrue(quality.evaluate(tok, self.repo, quality.BALANCED).substantiated)

    def test_declared_unique_constraint_vetoes_a_uniqueness_race(self):
        # 3/3 agreement must NOT override a declared uniqueness constraint (VULN-164).
        race = Finding(id="V1", title="Race: missing uniqueness on User.email",
                       cwe="CWE-362", location="models.py:2",
                       data_flow="two requests -> duplicate User.email insert",
                       from_confirmed=True, votes=3, vote_samples=3)
        q = quality.evaluate(race, self.repo, quality.BALANCED)
        self.assertFalse(q.substantiated)
        ce = {c.name: c for c in q.checks}["class_evidence"]
        self.assertEqual(ce.status, quality.FAIL)


class DetectorCoverage(unittest.TestCase):
    """Cover the operations actually used; a missing rule = 'cannot assess', not
    'no vulnerability' (audit-2 #2, #4)."""

    def test_ssti_labeled_code_injection_corroborates(self):
        # SSTI via Template().render(), the model labels it CWE-94 (code injection).
        repo = _repo({"app.py": "def r(frag):\n    return Template('R:'+frag).render()\n"})
        f = Finding(id="V1", title="SSTI", cwe="CWE-94", location="app.py:2",
                    data_flow="frag -> Template(...).render()")
        c = {x.name: x for x in quality.evaluate(f, repo, quality.BALANCED).checks}
        self.assertEqual(c["source_corroborated"].status, quality.PASS)

    def test_binary_file_traversal_corroborates(self):
        repo = _repo({"app.py": "def w(name, body):\n    (BASE/name).write_bytes(body)\n"})
        f = Finding(id="V1", title="Path traversal (binary)", cwe="CWE-22",
                    location="app.py:2", data_flow="name -> write_bytes(body)")
        c = {x.name: x for x in quality.evaluate(f, repo, quality.BALANCED).checks}
        self.assertEqual(c["source_corroborated"].status, quality.PASS)

    def test_sibling_cwe_label_shares_the_family_detector(self):
        # CWE-95 (a code-injection sibling of 94) must pick the eval detector.
        repo = _repo({"app.py": "def r(e):\n    return eval(e)\n"})
        f = Finding(id="V1", title="eval", cwe="CWE-95", location="app.py:2",
                    data_flow="e -> eval(e)")
        c = {x.name: x for x in quality.evaluate(f, repo, quality.BALANCED).checks}
        self.assertEqual(c["source_corroborated"].status, quality.PASS)

    def test_uncovered_class_is_not_substantiated_by_prose(self):
        # CWE-20 (no authoritative sink rule) with a described flow must NOT be
        # promoted on prose — the checker cannot assess it (VULN-091).
        repo = _repo({"app.py": "def h(payload):\n    q = payload.get('filter')\n"})
        f = Finding(id="V1", title="Improper input validation", cwe="CWE-20",
                    location="app.py:2", data_flow="request JSON -> query = payload.get(filter)",
                    from_confirmed=True)
        for level in quality.LEVELS:
            q = quality.evaluate(f, repo, level)
            self.assertFalse(q.substantiated, level)
            c = {x.name: x for x in q.checks}["source_corroborated"]
            self.assertEqual((c.status, c.kind), (quality.NA, "uncovered"))

    def test_hardcoded_secret_forgery_claim_not_supported_on_prose(self):
        # CWE-798 has no syntactic sink; a "token forgery / auth bypass" narrative
        # cannot substantiate it (VULN-082).
        repo = _repo({"config.py": "secret_key = 'dev-default'\n"})
        f = Finding(id="V1", title="Hardcoded secret enables token forgery",
                    cwe="CWE-798", location="config.py:1",
                    data_flow="config.secret_key -> injected into settings")
        self.assertFalse(quality.evaluate(f, repo, quality.BALANCED).substantiated)

    def test_uncovered_with_a_real_sink_still_fails_not_uncovered(self):
        # Sanity: a covered class whose sink is genuinely absent stays FAIL (checked
        # and absent), distinct from uncovered.
        repo = _repo({"app.py": "def h():\n    return 1\n"})
        f = Finding(id="V1", title="SQLi", cwe="CWE-89", location="app.py:2")
        c = {x.name: x for x in quality.evaluate(f, repo, quality.BALANCED).checks}["source_corroborated"]
        self.assertEqual(c.status, quality.FAIL)


class XssContext(unittest.TestCase):
    """XSS needs an HTML context; a value reflected into JSON is not XSS."""

    def setUp(self):
        self.repo = _repo({"app.py":
            "from fastapi.responses import HTMLResponse\n"
            "def html(q):\n    return HTMLResponse(f'<div>{q}</div>')\n"
            "def js(q):\n    return {'echo': q}\n"})

    def test_reflected_into_html_is_xss(self):
        f = Finding(id="V", title="Reflected XSS", cwe="CWE-79", location="app.py:3",
                    data_flow="q -> HTMLResponse")
        self.assertTrue(quality.evaluate(f, self.repo, quality.BALANCED).substantiated)

    def test_reflected_into_json_is_not_xss(self):
        # The window must not bleed into the neighbouring HTML handler.
        f = Finding(id="V", title="Reflected XSS", cwe="CWE-79", location="app.py:5",
                    data_flow="q -> response")
        q = quality.evaluate(f, self.repo, quality.BALANCED)
        self.assertFalse(q.substantiated)
        self.assertEqual({c.name: c for c in q.checks}["class_evidence"].status, quality.FAIL)


class CorsConfig(unittest.TestCase):
    """CORS is exploitable only with credentials + a wildcard/reflected origin."""

    def test_credentialed_wildcard_is_substantiated(self):
        repo = _repo({"main.py":
            "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n"})
        f = Finding(id="V", title="CORS misconfig", cwe="CWE-942", location="main.py:1",
                    data_flow="CORS reflects any origin with credentials")
        self.assertTrue(quality.evaluate(f, repo, quality.BALANCED).substantiated)

    def test_restrictive_cors_is_hypothesis(self):
        repo = _repo({"main.py":
            "app.add_middleware(CORSMiddleware, allow_origins=['https://ok'], allow_credentials=True)\n"})
        f = Finding(id="V", title="CORS misconfig", cwe="CWE-942", location="main.py:1",
                    data_flow="CORS config")
        self.assertFalse(quality.evaluate(f, repo, quality.BALANCED).substantiated)

    def test_no_cors_config_is_hypothesis(self):
        repo = _repo({"main.py": "x = 1\n"})
        f = Finding(id="V", title="CORS misconfig", cwe="CWE-942", location="main.py:1",
                    data_flow="claimed CORS issue")
        self.assertFalse(quality.evaluate(f, repo, quality.BALANCED).substantiated)


class BrittleChecks(unittest.TestCase):
    """Checks must not suppress real findings (audit P1 #6)."""

    def test_source_window_scans_the_whole_cited_range(self):
        # pickle.loads sits at ~line 61 but the finding cites the range 50-62. A
        # window around the START line alone misses it; the full range must scan.
        repo = _repo({"ops.py": "\n" * 49 + "def load(b):\n" + "    x = 1\n" * 10 +
                      "    return pickle.loads(b)\n"})
        f = Finding(id="V1", title="Insecure deserialization", cwe="CWE-502",
                    location="ops.py:50-62", data_flow="body -> pickle.loads(b)")
        c = {x.name: x for x in quality.evaluate(f, repo, quality.BALANCED).checks}
        self.assertEqual(c["source_corroborated"].status, quality.PASS)

    def test_precise_endpoint_title_is_not_too_generic(self):
        # A precise endpoint slug (dispatch-fan-304) is SPECIFIC; a concrete claim
        # with a CWE + a data flow must not be demoted on title wording.
        f = Finding(id="V1", cwe="CWE-400", location="ops.py:60",
                    title="Unbounded allocation in POST /ops/spool/dispatch-fan-304",
                    data_flow="size param -> bytearray(n) allocates unboundedly")
        self.assertEqual(quality.check_concrete_claim(f).status, quality.PASS)

    def test_verdict_fragment_without_a_flow_is_not_a_claim(self):
        f = Finding(id="V3", title="Yes", cwe="CWE-89", location="ops.py:1")
        self.assertEqual(quality.check_concrete_claim(f).status, quality.FAIL)


class LevelAndRepoRobustness(unittest.TestCase):
    def test_unknown_level_defaults_to_balanced(self):
        self.assertEqual(quality.normalize_level("whatever"), quality.BALANCED)
        self.assertEqual(quality.normalize_level(None), quality.BALANCED)
        self.assertEqual(quality.normalize_level("strict"), quality.STRICT)

    def test_no_checkout_gives_benefit_of_doubt_for_sink(self):
        # Source can't be checked (repo None). A well-formed sink candidate is not
        # demoted just because we couldn't read the tree — it leans on other
        # signals (a re-render must not degrade a finding's tier).
        f = Finding(id="V1", title="SQL injection in q", cwe="CWE-89",
                    location="app/db.py:2", data_flow="u -> execute(sql)",
                    from_confirmed=True)
        self.assertTrue(quality.evaluate(f, None, quality.BALANCED).substantiated)

    def test_checks_are_recorded(self):
        f = Finding(id="V1", title="SQL injection in q", cwe="CWE-89",
                    location="app/db.py:2")
        q = quality.evaluate(f, _repo(_REPO), quality.BALANCED)
        names = {c.name for c in q.checks}
        self.assertIn("source_corroborated", names)
        self.assertIn("agreement", names)
        self.assertTrue(all(c.status in (quality.PASS, quality.FAIL, quality.NA)
                            for c in q.checks))


if __name__ == "__main__":
    unittest.main()
