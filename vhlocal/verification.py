"""Harness-owned candidate identity and fail-closed verification reconciliation.

JSON validates provenance and completeness, not the truth of a model's reasoning.
Only executor-owned results may establish runtime reproduction.
"""
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

MANIFEST = 'candidate_manifest.json'
DECISIONS = 'verification_decisions.json'
RECONCILIATION = 'verification_reconciliation.json'
BATCH_SIZE = 8


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def write_json(path, data):
    import tempfile
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     prefix='.vhlocal-', delete=False) as stream:
        stream.write(json.dumps(data, indent=2) + '\n')
        temporary = Path(stream.name)
    temporary.replace(path)


def target_repo(manifest, fallback):
    raw = manifest.get('repo') if isinstance(manifest, dict) else None
    return Path(raw) if isinstance(raw, str) and raw else Path(fallback)


def manifest_problem(manifest):
    if not isinstance(manifest, dict) or manifest.get('schema_version') != 1:
        return 'missing or unsupported candidate manifest schema'
    if not isinstance(manifest.get('repo'), str) or not isinstance(manifest.get('revision'), str):
        return 'candidate manifest lacks target/revision'
    rows = manifest.get('candidates')
    if not isinstance(rows, list):
        return 'candidate manifest lacks candidate array'
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not isinstance(row.get('finding'), dict):
            return 'invalid candidate manifest row'
        if row['id'] in seen:
            return 'duplicate candidate ID in manifest'
        seen.add(row['id'])
    return ''



def source_identity(finding, repo):
    """Conservative source identity: exact AST statement + function + CWE + full path.

    Ignores prose and line shifts. Does not merge merely nearby sites or sibling
    CWE classes; ambiguous citations remain separate provenance-bound candidates.
    """
    import ast
    import re
    from .quality import _resolve_source
    location = finding.location
    source = _resolve_source(location, repo)
    m = re.fullmatch(r"(.+?):(\d+)(?:[-–](\d+))?", location)
    anchor = None
    if source and m and source.suffix == '.py':
        try:
            tree = ast.parse(source.read_text())
            start, end = int(m[2]), int(m[3] or m[2])
            nodes = [n for n in ast.walk(tree) if isinstance(n, ast.stmt)
                     and n.lineno <= start <= end <= n.end_lineno]
            if nodes:
                node = min(nodes, key=lambda n: n.end_lineno - n.lineno)
                functions = [n for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
                owners = [n.name for n in sorted(functions, key=lambda n: n.lineno)]
                dump = ast.dump(node, include_attributes=False)
                scope = min(functions, key=lambda n: n.end_lineno - n.lineno) if functions else tree
                equivalents = sorted((n for n in ast.walk(scope) if isinstance(n, ast.stmt)
                                      and ast.dump(n, include_attributes=False) == dump), key=lambda n: n.lineno)
                occurrence = next(i for i, n in enumerate(equivalents) if n is node)
                anchor = [str(source.relative_to(Path(repo).resolve())), owners, dump, occurrence]
        except (OSError, SyntaxError, ValueError):
            pass
    identity = [finding.cwe, anchor] if anchor else [finding.cwe, location, finding.source, finding.source_id]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()


def build_manifest(root, repo, revision):
    from .consolidate import _hunt_evidence_findings, _parse_hunt_file, authz_findings
    from .quality import _resolve_source
    root, repo = Path(root), Path(repo)
    candidates = _hunt_evidence_findings(root) + authz_findings({"repo": str(repo)})
    sink = root / 'results' / 'sink_driven.md'
    if sink.exists():
        extras = _parse_hunt_file(sink)
        for f in extras:
            f.source_id = f.id
        candidates.extend(extras)
    from .authz import authz_routes, guard_for_location
    routes = authz_routes(repo)
    # Normalize unambiguous paths before clustering; preserve original provenance.
    for f in candidates:
        import re
        m = re.fullmatch(r'(.+?):(\d+)(?:[-–](\d+))?', f.location)
        if m:
            source = _resolve_source(f.location, repo)
            if source:
                try:
                    f.location = str(source.resolve().relative_to(repo.resolve())) + ':' + m[2] + ('-' + m[3] if m[3] else '')
                except ValueError:
                    pass
            route = guard_for_location(routes, f.location)
            if route:
                f.entry_point = route.method + ' ' + route.path
    groups = {}
    for f in candidates:
        digest = source_identity(f, repo)
        groups.setdefault(digest, []).append(f)
    records = []
    for digest, group in groups.items():
        canonical = group[0]
        candidate_id = 'CAND-' + digest[:24]
        data = asdict(canonical)
        data.update(id=candidate_id, stable_identity=digest, duplicate_of=None,
                    cluster_id=candidate_id, from_confirmed=False,
                    verification_status='unresolved')
        records.append({'id': candidate_id, 'finding': data,
                        'provenance': [{'source': f.source, 'source_agent': f.source.removesuffix('.md'),
                                        'source_id': f.source_id,
                                        'title': f.title, 'location': f.location,
                                        'root_cause': f.hypothesis_reason,
                                        'entry_point': f.entry_point} for f in group]})
    if not revision:
        # Non-git targets still need an explicit evidence revision.
        from .inventory import _iter_source_files
        digest = hashlib.sha256()
        for path in sorted(_iter_source_files(repo)):
            digest.update(str(path.relative_to(repo)).encode())
            digest.update(path.read_bytes())
        revision = 'tree-sha256:' + digest.hexdigest()
    manifest = {'schema_version': 1, 'revision': revision, 'repo': str(repo),
                'raw_count': len(candidates), 'candidates': records}
    write_json(root / MANIFEST, manifest)
    return manifest


def require_function_evidence(finding, decision, repo):
    """Require cited complete handler context, not just an isolated dangerous line."""
    import ast
    import re
    from .quality import _resolve_source
    source = _resolve_source(finding.location, repo)
    m = re.fullmatch(r"(.+?):(\d+)(?:[-–](\d+))?", finding.location)
    if not source or source.suffix != '.py' or not m:
        return ''
    try:
        tree = ast.parse(source.read_text())
    except (OSError, SyntaxError):
        return 'cannot validate containing function context'
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and min([n.lineno] + [d.lineno for d in n.decorator_list]) <= int(m[2]) <= n.end_lineno]
    if not funcs:
        return ''
    fn = min(funcs, key=lambda n: n.end_lineno - n.lineno)
    start = min([fn.lineno] + [d.lineno for d in fn.decorator_list])
    cited = set()
    for e in decision['evidence']:
        if (repo / e['path']).resolve() == source.resolve():
            cited.update(range(e['start_line'], e['end_line'] + 1))
    if not all(line in cited for line in range(start, fn.end_lineno + 1)):
        return 'evidence must cover the complete containing function, including decorators and defenses'
    return ''


def reconcile(manifest, decisions, repo):
    problem = manifest_problem(manifest)
    if problem:
        return {'schema_version': 1, 'complete': False, 'errors': [problem],
                'counts': {'supported': 0, 'rejected': 0, 'unresolved': 0}, 'results': []}
    from .consolidate import Finding
    from .evidence import candidate_key, review_support
    from .authz import _ROUTE_CACHE
    _ROUTE_CACHE.pop(str(Path(repo).resolve()), None)
    candidates = {r['id']: r for r in manifest['candidates']}
    errors, grouped, results = [], {}, []
    if not isinstance(decisions, list):
        decisions = []
        errors.append('verification decisions must be a JSON array')
    for d in decisions:
        if not isinstance(d, dict) or not isinstance(d.get('candidate_id'), str):
            errors.append('decision has no valid candidate_id')
            continue
        cid = d['candidate_id']
        if cid not in candidates:
            errors.append('unknown candidate_id: ' + cid)
            continue
        grouped.setdefault(cid, []).append(d)
    for cid, candidate in candidates.items():
        rows = grouped.get(cid, [])
        status, reason, record = 'unresolved', 'No verification decision supplied', None
        if len(rows) != 1:
            errors.append(cid + (': missing decision' if not rows else ': duplicate decisions'))
        else:
            d = rows[0]
            verdict = d.get('verdict')
            rationale = d.get('rationale')
            if verdict not in ('supported', 'rejected', 'unresolved') or not isinstance(rationale, str) or not rationale.strip():
                reason = 'Unknown verdict or missing rationale'
                errors.append(cid + ': ' + reason)
            elif verdict == 'unresolved':
                reason = rationale
            else:
                # Rejections also need cited source evidence, never a bare assertion.
                f = Finding(**{k: v for k, v in candidate['finding'].items()
                               if k in Finding.__dataclass_fields__})
                f.candidate_key = candidate_key(f, manifest['revision'])
                checked = dict(d, verdict='supported')
                valid, why = review_support(f, {'repo': str(repo), 'git_commit': manifest['revision'],
                    'verification_records': {f.candidate_key: checked}})
                questions = d.get('unresolved_questions')
                if not isinstance(questions, list) or any(not isinstance(q, str) for q in questions):
                    valid, why = False, 'unresolved_questions must be an explicit string array'
                if verdict == 'supported' and questions:
                    valid, why = False, 'Supported decision still has unresolved questions'
                if valid and verdict == 'supported':
                    from . import quality
                    checks = quality.evaluate(f, Path(repo), quality.STRICT).checks
                    from .authz import authz_routes_cached, guard_for_location
                    route = guard_for_location(authz_routes_cached(Path(repo)), f.location)
                    if route and d['entry_point'].strip() != route.method + ' ' + route.path:
                        valid, why = False, 'review entry point does not match the cited source handler'
                    context_error = require_function_evidence(f, d, Path(repo))
                    if context_error:
                        valid, why = False, context_error
                    blockers = [c.reason for c in checks if c.status == quality.FAIL and c.name in
                                ('weakness_class', 'concrete_claim', 'location_resolves',
                                 'location_precise', 'source_corroborated', 'class_evidence')]
                    if blockers:
                        valid, why = False, '; '.join(blockers)
                if valid:
                    status, reason, record = verdict, rationale, d
                else:
                    reason = why
                    errors.append(cid + ': ' + why)
        results.append({'candidate_id': cid, 'status': status, 'reason': reason, 'record': record})
    return {'schema_version': 1, 'complete': not errors, 'errors': errors,
            'counts': {s: sum(r['status'] == s for r in results)
                       for s in ('supported', 'rejected', 'unresolved')}, 'results': results}


def refresh(root):
    root = Path(root)
    manifest = read_json(root / MANIFEST)
    if not (root / MANIFEST).exists():
        return None
    result = reconcile(manifest, read_json(root / DECISIONS),
                       target_repo(manifest, root))
    write_json(root / RECONCILIATION, result)
    return result


def load_findings(root, include_artifacts=True):
    from .consolidate import Finding
    root = Path(root)
    manifest = read_json(root / MANIFEST)
    if not (root / MANIFEST).exists():
        return None
    if manifest_problem(manifest):
        return []
    reconciled = reconcile(manifest, read_json(root / DECISIONS), Path(manifest['repo']))
    by_id = {r['candidate_id']: r for r in reconciled['results']}
    out = []
    for c in manifest['candidates']:
        f = Finding(**{k: v for k, v in c['finding'].items() if k in Finding.__dataclass_fields__})
        f.id = c['id']
        r = by_id[c['id']]
        f.verification_status, f.verification_reason = r['status'], r['reason']
        f.verification_record = r['record'] or {}
        f.from_confirmed = r['status'] == 'supported'
        out.append(f)
    if include_artifacts and (root / 'artifact_manifest.json').exists() and not validate_artifacts(root, out):
        by_id = {f.id: f for f in out}
        for artifact in read_json(root / 'artifact_manifest.json'):
            f = by_id[artifact['candidate_id']]
            if artifact['kind'] == 'poc':
                f.poc = artifact['path']
            elif artifact['kind'] == 'test':
                f.exploit_test = artifact['path']
    return out


def render(root):
    root = Path(root)
    fs = load_findings(root) or []
    lines = ['# Candidate verification', '', '| Candidate | Decision | Explanation |', '|---|---|---|']
    for f in fs:
        lines.append('| {} | {} | {} |'.format(f.id, f.verification_status,
                                              f.verification_reason.replace('|', '/').replace('\n', ' ')))
    (root / 'phase2b_output.md').write_text('\n'.join(lines) + '\n')
    supported = [f for f in fs if f.verification_status == 'supported']
    lines = ['# Verified candidate handoff', '',
             'Preserve candidate IDs exactly. These are source-grounded model reviews, not runtime reproductions.', '',
             '| Candidate | Title | CWE | Location | Entry point |', '|---|---|---|---|---|']
    for f in supported:
        lines.append('| {} | {} | {} | {} | {} |'.format(
            f.id, f.title.replace('|', '/'), f.cwe, f.location, f.entry_point.replace('|', '/')))
    lines += ['', 'Total confirmed findings: {}'.format(len(supported)), '']
    (root / 'phase2b_handoff.md').write_text('\n'.join(lines))
    refresh(root)


CONTRACT = '''Review only the supplied candidates against the actual checkout. Preserve candidate_id exactly.
Read each complete relevant function, dependencies, called defenses, and database constraints.
Evidence must quote the COMPLETE containing function, including decorators, not just a sink line.
Where the manifest supplies a registered endpoint, entry_point must match its exact METHOD /path.
For authorization, identify actor, action, object/tenant/region, intended policy, and every effective predicate;
a role guard alone neither proves nor refutes object authorization. For races identify an achievable
interleaving and security impact despite constraints. For XSS distinguish template data from template source,
check CSP and victim delivery. Agreement between hunters is not evidence. Do not execute exploits.
Write a JSON array (no Markdown), exactly one decision per supplied candidate. Each decision:
{"candidate_id":"CAND-...", "verdict":"supported|rejected|unresolved", "reviewer":"phase2b-model",
 "revision":"COPY PROVIDED REVISION", "rationale":"finding-specific explanation",
 "entry_point":"method and endpoint", "attacker_control":"...", "preconditions":"...",
 "defenses_reviewed":"...", "security_impact":"...", "unresolved_questions":[],
 "evidence":[{"path":"exact repo-relative path", "start_line":1, "end_line":10,
 "quote":"exact complete source lines"}]}
Supported and rejected decisions require source evidence covering the candidate location and all reasoning fields.
Supported decisions must have no unresolved questions. Use unresolved when evidence or policy is missing.
'''


def run_batches(root, manifest, run, should_stop):
    """One fresh bounded agent per batch. `run` owns usage, cancellation and transport errors."""
    root = Path(root)
    decisions = []
    write_json(root / DECISIONS, decisions)
    candidates = manifest['candidates']
    for offset in range(0, len(candidates), BATCH_SIZE):
        if should_stop():
            break
        batch = candidates[offset:offset + BATCH_SIZE]
        path = root / ('verification_batch_%03d.json' % (offset // BATCH_SIZE + 1))
        # A retry/resume must not ingest a stale result from a previous invocation.
        path.write_text('null\n')
        task = CONTRACT + '\nRevision: ' + manifest['revision'] + '\nTarget checkout: ' + manifest['repo']
        task += '\nWrite your JSON to: ' + str(path) + '\nCandidates:\n' + json.dumps(batch)
        run(task, path, offset // BATCH_SIZE + 1)
        result = read_json(path)
        if isinstance(result, list):
            # Cross-batch decisions cannot impersonate a candidate assigned elsewhere.
            allowed = {c['id'] for c in batch}
            if all(isinstance(d, dict) and d.get('candidate_id') in allowed for d in result):
                decisions.extend(result)
        write_json(root / DECISIONS, decisions)
        render(root)
    render(root)


def validate_artifacts(root, findings=None):
    """Validate authored artifacts and identity. This never claims tests executed."""
    root = Path(root).resolve()
    findings = load_findings(root, include_artifacts=False) if findings is None else findings
    if findings is None:
        return []
    supported = {f.id: f for f in findings if f.verification_status == 'supported'}
    data = read_json(root / 'artifact_manifest.json')
    errors, registered, accounted = [], set(), set()
    if not isinstance(data, list):
        return ['Phase 3 artifact_manifest.json is missing or malformed']
    for entry in data:
        try:
            if not isinstance(entry, dict):
                raise ValueError('artifact record must be an object')
            f = supported.get(entry.get('candidate_id'))
            if f is None:
                raise ValueError('artifact references an unknown or unverified candidate')
            if entry.get('kind') == 'deferred':
                if not isinstance(entry.get('reason'), str) or not entry['reason'].strip():
                    raise ValueError('deferred reproduction requires a reason')
                accounted.add(f.id)
                continue
            relative = entry['path']
            if not isinstance(relative, str) or Path(relative).is_absolute():
                raise ValueError('artifact path must be relative')
            path = (root / relative).resolve()
            path.relative_to(root)
            if entry.get('kind') not in ('poc', 'test'):
                raise ValueError('artifact kind must be poc or test')
            expected = 'poc' if entry['kind'] == 'poc' else 'exploit_tests'
            path.relative_to(root / expected)
            if path in registered:
                raise ValueError('duplicate artifact path')
            text = path.read_text(encoding='utf-8')
            if not text.strip() or f.id not in text or f.location not in text:
                raise ValueError('artifact lacks canonical candidate ID or source location')
            if entry.get('status') != 'authored':
                raise ValueError('model artifact status must be authored; execution requires executor evidence')
            if entry['kind'] == 'test' and path.suffix == '.py':
                import ast
                try:
                    tree = ast.parse(text)
                except SyntaxError:
                    raise ValueError('authored test is not valid Python')
                if not any(isinstance(n, ast.Assert) or
                           (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                            and n.func.attr.startswith('assert')) for n in ast.walk(tree)):
                    raise ValueError('authored test has no assertion; printing output is not a test')
            registered.add(path)
            accounted.add(f.id)
        except (KeyError, ValueError, OSError, TypeError) as exc:
            errors.append(str(exc))
    errors.extend('no reproduction disposition for ' + cid for cid in sorted(set(supported) - accounted))
    for dirname in ('poc', 'exploit_tests'):
        for path in (root / dirname).rglob('*'):
            if path.is_file() and path.resolve() not in registered:
                errors.append('unregistered artifact: ' + str(path.relative_to(root)))
    return errors


ARTIFACT_CONTRACT = '''Author reproduction material only for candidates in phase2b_handoff.md.
Read verification_decisions.json for their evidence and preconditions, and inspect the target source.
Keep each CAND-... ID unchanged in every artifact. Include the exact candidate ID and canonical source
location in a header/comment. Use the actual authentication scheme. Tests must assert the claimed security
impact and include a negative control, not merely print responses or accept any HTTP 200.
Write PoCs under poc/ and tests under exploit_tests/. Do not execute exploits, tests, or modify target code.
Write artifact_manifest.json as a JSON array of {"candidate_id":"CAND-...", "path":"poc/...",
"kind":"poc|test", "status":"authored"}. Register every authored file exactly once.
For every candidate without reliable reproduction material include
{"candidate_id":"CAND-...", "kind":"deferred", "reason":"specific limitation"}. Do not invent PASS, execution results, locations, findings, or renumber candidates.
The harness renders the assignment table; do not write phase3_output.md.
'''


def render_assignments(root):
    root = Path(root)
    fs = load_findings(root) or []
    lines = ['# Reproduction assignments', '',
             'Artifact status is authored only. No execution is implied.', '',
             '| Candidate | Title | Source location |', '|---|---|---|']
    for f in fs:
        if f.verification_status == 'supported':
            lines.append('| {} | {} | {} |'.format(f.id, f.title.replace('|', '/'), f.location))
    (root / 'phase3_output.md').write_text('\n'.join(lines) + '\n')
