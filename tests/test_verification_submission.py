import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import test_verification_contract as contract
from vhlocal.verification_session import VerificationSession
from vhlocal import verification as V
from vhlocal.agent import run_agent
from vhlocal.client import ChatResult
from vhlocal.tools import Sandbox


class Submission(unittest.TestCase):
    setUp = contract.VerificationContract.setUp

    def session(self):
        return VerificationSession(self.manifest, self.manifest['candidates'][0])

    def payload(self, session):
        args = {k:v for k,v in self.decision.items() if k in session.schemas[1]['function']['parameters']['properties']}
        return dict(args, evidence_ids=list(session.evidence))

    def agent(self, session, responses, **kwargs):
        class Client:
            num_ctx = 131072
            def chat(inner, messages, tools, repair_hint):
                names = [s['function']['name'] for s in tools]
                self.assertIn('submit_verification', names)
                self.assertNotIn('Write', names)
                return responses.pop(0)
        return run_agent(Client(), Sandbox([self.repo,self.out],self.out), 'system', 'verify',
                         task_tools=session, max_turns=10, **kwargs)

    def call(self, args):
        return ChatResult(content='', thinking='', tool_calls=[{'function':{'name':'submit_verification','arguments':args}}])

    def test_invalid_then_corrected_submission_completes(self):
        session = self.session()
        good = self.payload(session)
        result = self.agent(session,[self.call(dict(good,evidence_ids=['forged'])),self.call(good)])
        self.assertEqual(result.stopped_reason,'complete')
        self.assertEqual(result.turns,2)
        self.assertEqual(len(session.failures),1)
        self.assertIn('ERROR',result.transcript[3]['content'])

    def test_null_file_does_not_satisfy_completion(self):
        session = self.session()
        output = self.out/'legacy.json'
        output.write_text('null')
        result = self.agent(session,[ChatResult('done','') for _ in range(3)],expect_files=[output])
        self.assertEqual(result.stopped_reason,'verification_incomplete')
        self.assertFalse(session.accepted)

    def test_validation_retries_are_bounded(self):
        session = self.session()
        result = self.agent(session,[self.call({}) for _ in range(3)])
        self.assertEqual(result.turns,3)
        self.assertEqual(result.stopped_reason,'verification_incomplete')

    def test_harness_preserves_byte_literals_and_indentation(self):
        source = 'def handle(value):\n    marker = b"\\x80\\x04"\n    return eval(value)\n'
        (self.repo/'app.py').write_text(source)
        session = self.session()
        result = session.call('submit_verification',self.payload(session))
        self.assertNotIn('ERROR',result)
        quote = session.decision['evidence'][0]['quote']
        self.assertEqual(quote,source.rstrip('\n'))
        self.assertEqual(json.loads(json.dumps(session.decision))['evidence'][0]['quote'],quote)

    def test_stale_evidence_does_not_pass(self):
        session = self.session()
        (self.repo/'app.py').write_text('def handle(value):\n    return value\n')
        self.assertIn('ERROR',session.call('submit_verification',self.payload(session)))
        self.assertFalse(session.accepted)

    def test_capture_rejects_outside_repo_and_invalid_ranges(self):
        session = self.session()
        for args in [{'path':'../outside','start_line':1,'end_line':2},
                     {'path':'app.py','start_line':0,'end_line':2}]:
            self.assertIn('ERROR',session.call('capture_evidence',args))
        extra = json.loads(session.call('capture_evidence',{'path':'app.py','start_line':1,'end_line':2}))
        self.assertIn(extra['evidence_id'],session.evidence)

    def test_arbitrary_output_file_is_never_a_decision(self):
        V.write_json(self.out/V.MANIFEST,self.manifest)
        def run(task,path,index,session):
            V.write_json(path,[self.decision])
            return SimpleNamespace(stopped_reason='complete')
        V.run_batches(self.out,self.manifest,run,lambda:False)
        self.assertEqual(V.read_json(self.out/V.DECISIONS),[])
        metrics = V.read_json(self.out/'verification_metrics.json')
        self.assertEqual(metrics['incomplete'],1)
        self.assertEqual(metrics['attempts'][0]['stopped_reason'],'verification_incomplete')

    def test_cancellation_preserves_explicit_missing_decision(self):
        V.write_json(self.out/V.MANIFEST,self.manifest)
        V.run_batches(self.out,self.manifest,lambda *args:self.fail('must not run'),lambda:True)
        self.assertFalse(V.refresh(self.out)['complete'])
        self.assertEqual(V.read_json(self.out/'verification_metrics.json')['attempted'],0)

    def test_session_cannot_submit_for_another_candidate(self):
        session = self.session()
        args = dict(self.payload(session),candidate_id='someone-else')
        self.assertIn('ERROR',session.call('submit_verification',args))
