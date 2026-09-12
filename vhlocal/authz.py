"""AST inventory of declared route dependencies and possible protection differences.

Guard names describe declarations only. They do not establish intended policy,
prove object-level authorization, or prove a route is public. Custom helpers,
router inclusion, and checks in function bodies require source-grounded review.
Route ownership uses exact function spans including decorators; path matching
rejects ambiguous shortened paths.
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .inventory import (
    _iter_source_files,
    _methods_from_decorator,
    _router_prefixes,
    _str_arg,
    _ROUTE_ATTRS,
)

# Two tiers, because authentication is not authorization. An IDOR / missing-authz
# bug is precisely "authenticated but no per-object check", so only an AUTHORIZATION
# guard may refute one — a mere authentication dependency (get_current_user) must
# not. Discovery treats either tier as "guarded" (an open sibling of even an
# authenticated route is a bypass); the evidence check requires the authz tier.
_AUTHZ_NAME = re.compile(
    r"(?i)\b("
    r"require_(owner|role|permission|scope|admin|access|tenant)\w*|"
    r"owner_required|role_required|permission_required|admin_required|"
    r"has_(permission|role|scope|access)\w*|"
    r"check_(owner|permission|role|access|tenant)\w*|"
    r"ensure_(owner|role|permission|access|tenant)\w*|"
    r"authoriz\w*|permission_required|rbac\w*|acl\b|security_scopes?|"
    r"enforce_(owner|role|permission|access|tenant|policy)\w*"
    r")\b")
_AUTHN_NAME = re.compile(
    r"(?i)\b("
    r"get_current_(user|active_user|admin|principal)\w*|current_user|current_active_user|"
    r"authenticate\w*|is_authenticated|login_required|requires?_(auth|login)\w*|"
    r"verify_(token|jwt|session)\w*"
    r")\b")


def _is_guard(name: str) -> bool:
    return bool(_AUTHZ_NAME.search(name) or _AUTHN_NAME.search(name))


def _is_authz(name: str) -> bool:
    return bool(_AUTHZ_NAME.search(name))


@dataclass
class RouteAuthz:
    method: str
    path: str
    file: str
    line: int
    function: str
    resource_key: str
    guards: List[str] = field(default_factory=list)   # names of declared guards

    start_line: int = 0
    end_line: int = 0

    @property
    def guarded(self) -> bool:
        return bool(self.guards)

    @property
    def authz_guards(self) -> List[str]:
        """Guards that make an ACCESS decision (ownership/role/permission), not
        merely authentication — the only ones that may refute an IDOR/authz claim."""
        return [g for g in self.guards if _is_authz(g)]

    @property
    def has_authz(self) -> bool:
        return bool(self.authz_guards)

    def to_dict(self) -> Dict[str, object]:
        return {"method": self.method, "path": self.path, "file": self.file,
                "line": self.line, "start_line": self.start_line, "end_line": self.end_line,
                "function": self.function,
                "resource_key": self.resource_key, "guards": self.guards,
                "guarded": self.guarded, "authz_guards": self.authz_guards}


# Leading path segments that are version/API envelopes, not the resource itself —
# stripped so ``/api/v1/workers`` and ``/workers`` map to one resource.
_VERSION_SEG = re.compile(r"^(api|rest|v\d+)$", re.I)
_PARAM_SEG = ("{", ":", "<", "$")


def resource_key(path: str) -> str:
    """Normalize a URL path to a resource identity: strip a leading version/api
    envelope and collapse path parameters, so sibling routes for one resource map
    together regardless of version prefix or parameter name."""
    segs = [s for s in (path or "").strip("/").split("/") if s]
    i = 0
    while i < len(segs) and _VERSION_SEG.match(segs[i]):
        i += 1
    out = []
    for s in segs[i:]:
        out.append("{}" if s[:1] in _PARAM_SEG else s.lower())
    return "/" + "/".join(out)


def _guard_names(nodes) -> List[str]:
    """Auth-looking callee names referenced anywhere in the given AST node(s) —
    used for Depends(...)/Security(...)/decorator guard detection."""
    names: List[str] = []
    for root in nodes:
        if root is None:
            continue
        for n in ast.walk(root):
            nm = getattr(n, "id", None) or getattr(n, "attr", None)
            if nm and _is_guard(nm):
                names.append(nm)
    return names


def _dependency_args(call: ast.Call):
    """The ``dependencies=[...]`` elements of a route decorator call, if any."""
    for kw in call.keywords:
        if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
            return list(kw.value.elts)
    return []


def _signature_guard_names(fn) -> List[str]:
    """Guard names from the handler signature: a parameter defaulted to
    Depends(require_*) / Security(...), or a ``current_user``-style parameter."""
    names: List[str] = []
    args = fn.args
    for a, d in zip(args.args[-len(args.defaults):] if args.defaults else [],
                    args.defaults):
        names += _guard_names([d])
        if _is_guard(a.arg):
            names.append(a.arg)
    for a, d in zip(args.kwonlyargs, args.kw_defaults):
        if d is not None:
            names += _guard_names([d])
        if _is_guard(a.arg):
            names.append(a.arg)
    return names


def _router_guard_names(tree: ast.AST) -> Dict[str, List[str]]:
    """Router var name -> guard names from ``APIRouter(dependencies=[...])`` — a
    router-level dependency guards every route registered on it."""
    out: Dict[str, List[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        callee = node.value.func
        name = getattr(callee, "id", None) or getattr(callee, "attr", None)
        if name not in ("APIRouter", "Blueprint", "Router"):
            continue
        guards = _guard_names(_dependency_args(node.value))
        if guards:
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    out[tgt.id] = guards
    return out


_ROUTE_CACHE: Dict[str, List["RouteAuthz"]] = {}


def authz_routes_cached(repo) -> List["RouteAuthz"]:
    """``authz_routes`` memoized per repo path — the evidence check runs per
    finding but every finding in an assess pass shares one repo, so the tree is
    walked once."""
    key = str(repo)
    if key not in _ROUTE_CACHE:
        _ROUTE_CACHE[key] = authz_routes(repo) if repo and Path(repo).is_dir() else []
    return _ROUTE_CACHE[key]


def authz_routes(repo) -> List[RouteAuthz]:
    """Every HTTP route with its declared authorization guards, from the AST."""
    repo = Path(repo)
    found: List[RouteAuthz] = []
    seen = set()
    for src in _iter_source_files(repo):
        try:
            tree = ast.parse(src.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue
        prefixes = _router_prefixes(tree)
        router_guards = _router_guard_names(tree)
        rel = str(src.relative_to(repo))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                    continue
                attr = dec.func.attr.lower()
                if attr not in _ROUTE_ATTRS:
                    continue
                obj = getattr(dec.func.value, "id", "")
                path = (_str_arg(dec.args[0]) if dec.args else "") or ""
                path = (prefixes.get(obj, "") + path) or path or "/"
                guards = []
                guards += _guard_names(_dependency_args(dec))   # decorator dependencies=
                guards += _signature_guard_names(node)          # signature Depends/params
                guards += router_guards.get(obj, [])            # router-level deps
                # Auth decorators stacked on the handler (e.g. @login_required).
                for other in node.decorator_list:
                    if other is dec:
                        continue
                    nm = (getattr(getattr(other, "func", other), "id", None)
                          or getattr(getattr(other, "func", other), "attr", None))
                    if nm and _is_guard(nm):
                        guards.append(nm)
                guards = sorted(set(guards))
                for method in _methods_from_decorator(dec, attr):
                    ra = RouteAuthz(method=method, path=path, file=rel, line=node.lineno,
                                    function=node.name, resource_key=resource_key(path),
                                    guards=guards,
                                    start_line=min([node.lineno] + [d.lineno for d in node.decorator_list]),
                                    end_line=node.end_lineno)
                    k = (ra.method, ra.path, ra.file, ra.line)
                    if k in seen:
                        continue
                    seen.add(k)
                    found.append(ra)
    found.sort(key=lambda r: (r.resource_key, r.method, r.file, r.line))
    return found


@dataclass
class AuthzInconsistency:
    resource_key: str
    method: str
    guarded: List[RouteAuthz]
    unguarded: List[RouteAuthz]


def inconsistencies(routes: List[RouteAuthz]) -> List[AuthzInconsistency]:
    """Resources where, for one method, some routes declare a guard and a sibling
    does not — a cross-endpoint access-control bypass candidate. A resource whose
    routes are ALL guarded or ALL unguarded is not flagged (consistent)."""
    groups: Dict[tuple, List[RouteAuthz]] = {}
    for r in routes:
        groups.setdefault((r.resource_key, r.method), []).append(r)
    out: List[AuthzInconsistency] = []
    for (rk, method), rs in sorted(groups.items()):
        guarded = [r for r in rs if r.guarded]
        unguarded = [r for r in rs if not r.guarded]
        if guarded and unguarded:
            out.append(AuthzInconsistency(rk, method, guarded, unguarded))
    return out


def guard_for_location(routes: List[RouteAuthz], location: str):
    """Resolve an exact handler span, including decorators; reject ambiguous paths."""
    m = re.fullmatch(r"([\w./+\-]+\.py):(\d+)(?:[-–](\d+))?", location.strip())
    if not m:
        return None
    path, start, end = m[1], int(m[2]), int(m[3] or m[2])
    files = {r.file for r in routes if r.file == path}
    if not files:
        files = {r.file for r in routes if r.file.endswith("/" + path)}
    if len(files) != 1:
        return None
    matches = [r for r in routes if r.file in files
               and (r.start_line or r.line) <= start <= end <= (r.end_line or r.line)]
    return matches[0] if matches else None


def build_authz_map(repo) -> Dict[str, object]:
    """The full authorization map for a repo: routes, the resource×method matrix,
    and the cross-endpoint inconsistencies. None-safe for a missing repo."""
    routes = authz_routes(repo) if repo and Path(repo).is_dir() else []
    matrix: Dict[str, Dict[str, List[dict]]] = {}
    for r in routes:
        matrix.setdefault(r.resource_key, {}).setdefault(r.method, []).append(r.to_dict())
    incs = inconsistencies(routes)
    return {
        "routes": [r.to_dict() for r in routes],
        "matrix": matrix,
        "inconsistencies": [
            {"resource_key": i.resource_key, "method": i.method,
             "guarded": [r.to_dict() for r in i.guarded],
             "unguarded": [r.to_dict() for r in i.unguarded]}
            for i in incs],
    }


def render_map(amap: Dict[str, object]) -> str:
    routes = amap.get("routes") or []
    incs = amap.get("inconsistencies") or []
    L = ["# Authorization map", "",
         "{0} routes; {1} with a declared guard. Cross-endpoint inconsistencies "
         "below are resources a guard protects on one route but not on a sibling "
         "(a broken-access-control bypass candidate).".format(
             len(routes), sum(1 for r in routes if r.get("guarded"))),
         ""]
    if incs:
        L += ["## Inconsistent protection (bypass candidates)", "",
              "| Resource | Method | Guarded route | Unguarded sibling |",
              "|---|---|---|---|"]
        for i in incs:
            g = i["guarded"][0]
            for u in i["unguarded"]:
                L.append("| `{0}` | {1} | `{2}` ({3}) | `{4}` ({5}:{6}) |".format(
                    i["resource_key"], i["method"], g["path"],
                    ", ".join(g["guards"])[:40] or "guard", u["path"], u["file"], u["line"]))
        L.append("")
    else:
        L += ["_No cross-endpoint authorization inconsistencies found._", ""]
    return "\n".join(L)


def main(argv=None) -> int:
    import sys
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m vhlocal.authz <repo>")
        return 2
    print(render_map(build_authz_map(argv[0])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
