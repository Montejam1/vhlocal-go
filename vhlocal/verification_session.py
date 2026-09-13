"""Candidate-bound verification tools. Models reference evidence; the harness copies it."""
import ast
import hashlib
import json
import re
from pathlib import Path

from .verification import reconcile


def schema(name, description, properties, required):
    return {'type': 'function', 'function': {'name': name, 'description': description,
            'parameters': {'type': 'object', 'properties': properties, 'required': required,
                           'additionalProperties': False}}}


class VerificationSession:
    max_failures = 3

    def __init__(self, manifest, candidate):
        self.manifest = dict(manifest, candidates=[candidate])
        self.candidate = candidate
        self.repo = Path(manifest['repo']).resolve()
        self.evidence = {}
        self.decision = None
        self.failures = []
        self.initial_context = self._initial_context()

    @property
    def accepted(self):
        return self.decision is not None

    @property
    def exhausted(self):
        return len(self.failures) >= self.max_failures

    @property
    def schemas(self):
        text = {'type': 'string'}
        return [
            schema('capture_evidence', 'Read source lines and register immutable evidence. Returns evidence_id and exact source text. Use for helpers, policy, and defenses.',
                   {'path': text, 'start_line': {'type': 'integer'}, 'end_line': {'type': 'integer'}},
                   ['path', 'start_line', 'end_line']),
            schema('submit_verification', 'Submit the decision for this candidate. Errors explain what to correct. Do not write JSON files or copy source quotations.',
                   dict({k: text for k in ['rationale', 'entry_point', 'attacker_control', 'preconditions',
                                          'defenses_reviewed', 'security_impact']},
                        verdict={'type':'string', 'enum':['supported','rejected','unresolved']},
                        evidence_ids={'type':'array','items':text},
                        unresolved_questions={'type':'array','items':text}),
                   ['verdict', 'rationale', 'entry_point', 'attacker_control', 'preconditions',
                    'defenses_reviewed', 'security_impact', 'evidence_ids', 'unresolved_questions'])]

    def _capture(self, path, start, end):
        if not isinstance(path, str) or Path(path).is_absolute():
            raise ValueError('path must be repo-relative')
        source = (self.repo / path).resolve()
        source.relative_to(self.repo)
        if type(start) is not int or type(end) is not int:
            raise ValueError('line numbers must be integers')
        lines = source.read_text(encoding='utf-8').splitlines()
        if not 1 <= start <= end <= len(lines) or end - start >= 2000:
            raise ValueError('invalid line range (maximum 2000 lines per capture)')
        evidence = {'path':str(source.relative_to(self.repo)), 'start_line':start,
                    'end_line':end, 'quote':'\n'.join(lines[start-1:end])}
        ident = 'EV-' + hashlib.sha256(json.dumps(evidence).encode()).hexdigest()[:24]
        self.evidence[ident] = evidence
        return dict(evidence_id=ident, **evidence)

    def _initial_context(self):
        location = self.candidate['finding'].get('location', '')
        match = re.fullmatch(r'(.+?):(\d+)(?:[-–](\d+))?', location)
        if not match:
            return 'No resolvable primary citation; investigate or explicitly submit unresolved.'
        try:
            path, start, end = match[1], int(match[2]), int(match[3] or match[2])
            if Path(path).suffix == '.py':
                source = (self.repo / path).resolve()
                source.relative_to(self.repo)
                tree = ast.parse(source.read_text())
                funcs = [n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
                         and min([n.lineno]+[d.lineno for d in n.decorator_list]) <= start <= end <= n.end_lineno]
                if funcs:
                    fn = min(funcs, key=lambda n:n.end_lineno-n.lineno)
                    start = min([fn.lineno]+[d.lineno for d in fn.decorator_list])
                    end = fn.end_lineno
            return json.dumps(self._capture(path,start,end), ensure_ascii=False)
        except (ValueError, OSError, SyntaxError, UnicodeError) as exc:
            return 'Primary context unavailable: ' + str(exc)

    def handles(self, name):
        return name.lower() in ('capture_evidence', 'submit_verification')

    def call(self, name, args):
        submitting = name.lower() == 'submit_verification'
        try:
            if self.accepted or self.exhausted:
                raise ValueError('verification session is closed')
            if not isinstance(args, dict):
                raise ValueError('arguments must be an object')
            if not submitting:
                return json.dumps(self._capture(args.get('path'), args.get('start_line'), args.get('end_line')))
            allowed = set(self.schemas[1]['function']['parameters']['properties'])
            if set(args) != allowed:
                raise ValueError('provide exactly these fields: ' + ', '.join(sorted(allowed)))
            for key in ('rationale','entry_point','attacker_control','preconditions','defenses_reviewed','security_impact'):
                if not isinstance(args[key], str):
                    raise ValueError(key + ' must be a string')
            if not isinstance(args['unresolved_questions'], list) or any(
                    not isinstance(q,str) for q in args['unresolved_questions']):
                raise ValueError('unresolved_questions must be a string array')
            ids = args['evidence_ids']
            if not isinstance(ids, list) or any(not isinstance(i,str) or i not in self.evidence for i in ids):
                raise ValueError('evidence_ids must reference evidence captured in this session')
            decision = {k:v for k,v in args.items() if k != 'evidence_ids'}
            decision.update(candidate_id=self.candidate['id'], reviewer='phase2b-model',
                            revision=self.manifest['revision'], evidence=[self.evidence[i] for i in ids])
            result = reconcile(self.manifest, [decision], self.repo)
            if not result['complete']:
                raise ValueError('; '.join(result['errors']))
            self.decision = decision
            return json.dumps({'accepted': True, 'candidate_id': self.candidate['id'], 'verdict': decision['verdict']})
        except (ValueError, OSError, TypeError, UnicodeError) as exc:
            if submitting:
                self.failures.append(str(exc))
            return 'ERROR: ' + str(exc) + '. Correct the submission or use unresolved with an explicit reason.'
