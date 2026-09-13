import json
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vhlocal import verification as V, consolidate as C, authz, quality
from vhlocal.handoff import parse_confirmed, write_handoff
from vhlocal.tools import Sandbox, ToolError


class VerificationContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.source = 'def handle(value):\n    return eval(value)\n'
        (self.repo / 'app.py').write_text(self.source)
        self.out = self.root / 'out'
        self.out.mkdir()
        self.f = C.Finding(id='CAND-one', title='User input evaluated', cwe='CWE-94',
                           location='app.py:2', entry_point='GET /eval',
                           data_flow='value -> eval(value)', source='sg-1_inj.md')
        self.manifest = {'schema_version': 1, 'revision': 'abc', 'repo': str(self.repo),
                         'candidates': [{'id': self.f.id, 'finding': asdict(self.f), 'provenance': []}]}
        self.decision = {'candidate_id': self.f.id, 'verdict': 'supported', 'reviewer': 'phase2b-model',
                         'revision': 'abc', 'rationale': 'Attacker expression reaches eval',
                         'entry_point': 'GET /eval', 'attacker_control': 'value',
                         'preconditions': 'reachable endpoint', 'defenses_reviewed': 'no filtering in handle',
                         'security_impact': 'expression execution', 'unresolved_questions': [],
                         'evidence': [{'path': 'app.py', 'start_line': 1, 'end_line': 2,
                                       'quote': self.source.strip()}]}

    def save(self, decisions=None):
        V.write_json(self.out / V.MANIFEST, self.manifest)
        V.write_json(self.out / V.DECISIONS, [self.decision] if decisions is None else decisions)

    def test_missing_all_57_remain_unresolved(self):
        self.manifest['candidates'] = [dict(self.manifest['candidates'][0], id='CAND-' + str(i)) for i in range(57)]
        result = V.reconcile(self.manifest, [], self.repo)
        self.assertEqual(result['counts'], {'supported': 0, 'rejected': 0, 'unresolved': 57})
        self.assertFalse(result['complete'])
        markdown = '| ID | Verdict |\n|---|---|\n' + '\n'.join('| VULN-%03d | UNVERIFIED |' % i for i in range(57))
        self.assertEqual(parse_confirmed(markdown), [])

    def test_complete_decision_retains_identity_through_report(self):
        self.save()
        V.render(self.out)
        fs = C.parse_findings(self.out)
        C.assess_candidates(fs, {'repo': str(self.repo), 'git_commit': 'abc'})
        self.assertEqual(fs[0].id, 'CAND-one')
        self.assertEqual(fs[0].assessment, 'supported')
        self.assertIn('CAND-one', (self.out / 'phase2b_handoff.md').read_text())
        self.assertEqual(V.refresh(self.out)['counts']['supported'], 1)

    def test_bad_verdict_duplicate_unknown_and_missing_citations(self):
        for decisions in [[dict(self.decision, verdict='CONFIRMED')],
                          [self.decision, self.decision],
                          [dict(self.decision, candidate_id='unknown')],
                          [dict(self.decision, evidence=[])],
                          [dict(self.decision, unresolved_questions=['permission unclear'])],
                          [dict(self.decision, revision='stale')]]:
            with self.subTest(decisions=decisions):
                result = V.reconcile(self.manifest, decisions, self.repo)
                self.assertFalse(result['complete'])
                self.assertEqual(result['counts']['supported'], 0)

    def test_isolated_sink_quote_is_not_complete_function_evidence(self):
        d = dict(self.decision, evidence=[{'path':'app.py', 'start_line':2, 'end_line':2,
                                         'quote':'    return eval(value)'}])
        result = V.reconcile(self.manifest, [d], self.repo)
        self.assertEqual(result['counts']['supported'], 0)
        self.assertIn('complete containing function', ' '.join(result['errors']))

    def test_missing_source_is_quality_failure(self):
        (self.repo / 'app.py').unlink()
        result = V.reconcile(self.manifest, [self.decision], self.repo)
        self.assertFalse(result['complete'])
        self.assertEqual(result['counts']['supported'], 0)

    def test_constant_template_data_is_not_ssti(self):
        (self.repo / 'app.py').write_text('def card(value):\n    return Template("{{ value|safe }}").render(value=value)\n')
        f = C.Finding(id='x', title='Jinja2 Template Injection', cwe='CWE-79', location='app.py:2')
        check = quality.check_class_evidence(f, self.repo)
        self.assertEqual(check.status, quality.FAIL)
        self.assertIn('template source is constant', check.reason)

    def test_quotes_rechecked_after_source_changes(self):
        self.save()
        (self.repo / 'app.py').write_text('def handle(value):\n    return value\n')
        self.assertEqual(V.load_findings(self.out)[0].verification_status, 'unresolved')

    def test_explicit_unresolved_is_accounted_for(self):
        result = V.reconcile(self.manifest, [{'candidate_id': self.f.id, 'verdict': 'unresolved',
                                            'rationale': 'policy not available'}], self.repo)
        self.assertTrue(result['complete'])
        self.assertEqual(result['counts']['unresolved'], 1)

    def test_corrupt_manifest_never_falls_back_to_markdown(self):
        (self.out / V.MANIFEST).write_text('{broken json')
        (self.out / 'README.md').write_text('| ID | Title | CWE | Severity |\n|---|---|---|---|\n| VULN-001 | eval | CWE-94 | High |')
        self.assertEqual(C.parse_findings(self.out), [])
        self.assertFalse(V.refresh(self.out)['complete'])

    def test_no_markdown_fallback_or_renumbering(self):
        (self.out / 'phase2b_output.md').write_text('# Confirmed\n| VULN-001 | confirmed |')
        path = write_handoff(self.out)
        self.assertIn('Total confirmed findings: 0', path.read_text())

    def test_artifact_registration_validates_identity_and_assertions(self):
        self.save()
        (self.out / 'exploit_tests').mkdir()
        path = self.out / 'exploit_tests' / 'test_example.py'
        path.write_text('# CAND-one app.py:2\ndef test_case():\n    print(200)\n')
        entry = {'candidate_id': 'CAND-one', 'path': 'exploit_tests/test_example.py', 'kind': 'test', 'status': 'authored'}
        V.write_json(self.out / 'artifact_manifest.json', [entry])
        self.assertTrue(any('no assertion' in e for e in V.validate_artifacts(self.out)))
        path.write_text('# CAND-one app.py:2\ndef test_case():\n    assert 1 == 1\n')
        self.assertEqual(V.validate_artifacts(self.out), [])
        V.write_json(self.out / 'artifact_manifest.json', [dict(entry, candidate_id='VULN-002')])
        self.assertTrue(V.validate_artifacts(self.out))
        V.write_json(self.out / 'artifact_manifest.json', [dict(entry, status='passed')])
        self.assertTrue(V.validate_artifacts(self.out))

    def test_missing_file_and_unaccounted_candidate_fail(self):
        self.save()
        V.write_json(self.out / 'artifact_manifest.json', [])
        self.assertTrue(V.validate_artifacts(self.out))
        V.write_json(self.out / 'artifact_manifest.json', [{'candidate_id':'CAND-one', 'kind':'deferred', 'reason':'need fixture'}])
        self.assertEqual(V.validate_artifacts(self.out), [])

    def test_partial_status_on_missing_decisions(self):
        self.save([])
        V.render(self.out)
        status = C.compute_run_status({'phases_requested':['2b'], 'phases_completed':['2b']}, results_dir=self.out)
        self.assertNotEqual(status['execution_status'], 'complete')
        self.assertTrue(any('missing decision' in r for r in status['coverage_degraded_reasons']))

    def test_bounded_batches_and_cross_batch_rejection(self):
        self.manifest['candidates'] = [dict(self.manifest['candidates'][0], id='CAND-' + str(i)) for i in range(17)]
        V.write_json(self.out / V.MANIFEST, self.manifest)
        calls = []
        def run(task, path, batch, session):
            calls.append(batch)
            self.assertEqual(len(session.manifest['candidates']), 1)
            self.assertFalse(path.exists())
            payload = {k:'' for k in ['entry_point','attacker_control','preconditions','defenses_reviewed','security_impact']}
            payload.update(verdict='unresolved', rationale='needs policy review',
                           evidence_ids=[], unresolved_questions=['permission unknown'])
            self.assertNotIn('ERROR', session.call('submit_verification', payload))
        V.run_batches(self.out, self.manifest, run, lambda: False)
        self.assertEqual(calls, list(range(1,18)))
        self.assertTrue(V.refresh(self.out)['complete'])
        self.assertEqual(V.read_json(self.out / 'verification_metrics.json')['accepted_decisions'],17)

    def test_identity_ignores_title_and_line_shift(self):
        old = V.source_identity(self.f, self.repo)
        self.f.title = 'A completely different title'
        (self.repo / 'app.py').write_text('\n\n' + self.source)
        self.f.location = 'app.py:4'
        self.assertEqual(V.source_identity(self.f, self.repo), old)

    def test_harness_files_are_not_model_writable(self):
        sandbox = Sandbox([self.repo, self.out], self.out)
        for name in [V.MANIFEST, V.DECISIONS, V.RECONCILIATION, 'phase2b_handoff.md', 'phase3_output.md']:
            with self.assertRaises(ToolError):
                sandbox.write_path(name)
        self.assertEqual(sandbox.write_path('verification_batch_001.json'), (self.out / 'verification_batch_001.json').resolve())


class AuthorizationRegression(unittest.TestCase):
    def test_decorator_and_gap_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'routes.py').write_text("r = APIRouter()\n@r.get('/a')\ndef first(u=Depends(require_roles)):\n    return 1\n\n@r.get('/b')\ndef second():\n    return 2\n\nx=1\n")
            routes = authz.authz_routes(p)
            self.assertEqual(authz.guard_for_location(routes, 'routes.py:6').function, 'second')
            self.assertIsNone(authz.guard_for_location(routes, 'routes.py:5'))
            self.assertIsNone(authz.guard_for_location(routes, 'routes.py:10'))
            (p / 'other').mkdir()
            (p / 'other/routes.py').write_text((p/'routes.py').read_text())
            routes = authz.authz_routes(p)
            self.assertEqual(authz.guard_for_location(routes, 'other/routes.py:6').function, 'second')

    def test_role_guard_and_votes_neither_prove_nor_refute_object_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'app.py').write_text("r = APIRouter()\n@r.get('/a')\ndef f(u=Depends(require_roles)):\n    return db.get(id)\n")
            f = C.Finding(id='x', title='IDOR', cwe='CWE-639', location='app.py:4',
                          data_flow='id -> db.get(id)', votes=3, vote_samples=3)
            for level in quality.LEVELS:
                result = quality.evaluate(f, p, level)
                self.assertFalse(result.substantiated)
                self.assertEqual(next(c for c in result.checks if c.name=='class_evidence').status, quality.NA)


class EngineContract(unittest.TestCase):
    setUp = VerificationContract.setUp

    def test_engine_batches_then_renders_canonical_report(self):
        from vhlocal import engine
        from vhlocal.agent import AgentResult
        from vhlocal.client import Usage
        self.out.joinpath('results').mkdir()
        self.out.joinpath('results/sg-1_inj.md').write_text('''## VULN-001 Arbitrary expression evaluation
- **Class**: CWE-94
- **Location**: `app.py:2`
- **Severity**: High
- **Entry Point**: GET /eval
- **Data Flow**: value -> eval(value)
''')
        calls = []
        def run(client, sandbox, system, task, **kw):
            calls.append(kw['label'])
            if kw['label'].startswith('p2b:'):
                session = kw['task_tools']
                payload = {k:v for k,v in self.decision.items() if k in session.schemas[1]['function']['parameters']['properties']}
                payload['evidence_ids'] = list(session.evidence)
                self.assertNotIn('ERROR', session.call('submit_verification', payload))
            elif kw['label'] == 'p3':
                output = Path(kw['expect_files'][0])
                manifest = V.read_json(self.out / V.MANIFEST)
                V.write_json(output, [{'candidate_id':c['id'], 'kind':'deferred',
                                       'reason':'Needs isolated HTTP fixture'} for c in manifest['candidates']])
            else:
                self.fail('Unexpected model phase: ' + kw['label'])
            return AgentResult(final_text='', turns=1, usage=Usage(), stopped_reason='complete')
        skill = Path(__file__).resolve().parents[2] / 'vulnhunt'
        with patch.object(engine, 'make_client') as factory, patch.object(engine, 'run_agent', side_effect=run):
            client = factory.return_value
            client.model = 'stub'
            client.num_ctx = 131072
            client.preflight.return_value = None
            client.usage = Usage()
            engine.execute_scan(engine.ScanSpec(repo=self.repo, out=self.out, skill_dir=skill,
                                                phases='2b,3,4'), attach_log_handler=False)
        data = V.read_json(self.out / 'findings.json')
        self.assertIsNotNone(data)
        self.assertEqual(data['assessment']['supported'], 1)
        self.assertEqual(data['assessment']['reproduced'], 0)
        self.assertEqual(data['run_status']['execution_status'], 'complete')
        self.assertEqual(calls, ['p2b:batch-1', 'p3'])
        self.assertEqual(data['findings'][0]['id'], V.read_json(self.out / V.MANIFEST)['candidates'][0]['id'])
        self.assertTrue(data['verification']['complete'])
