"""Standalone HTML scan report — the presentation layer over `consolidate`.

Self-contained: one file, no CDN, no fonts, no scripts fetched. Open it from
disk, mail it, or serve it. Works offline because the whole tool does.

Design decisions worth stating, since they were measured rather than chosen:

* **Severity is a *status* encoding, not a categorical series**, so it uses the
  reserved status palette (`critical` / `serious` / `warning`) rather than
  series hues, and every badge ships colour **plus an icon plus a text label**.
  The status palette validates at ΔE 13.6 between `#fab219` (Medium) and
  `#ec835a` (High) — below the 15 floor, i.e. hard to separate *even with full
  colour vision*. Colour alone would therefore be an accessibility failure
  here; the glyph and the word carry the distinction and the colour reinforces.
* **Low / Informational get no status colour at all.** Green would read as
  "good", which a finding never is. They wear muted ink, which also correctly
  signals lower priority.
* On the light surface `warning` (1.79:1) and `serious` (2.57:1) sit below
  3:1 by design. The relief is visible labels, which are mandatory anyway.
* Counts are a KPI row of stat tiles, not a bar chart — a handful of headline
  numbers is a tile job. The severity mix gets one stacked meter with 2px
  surface gaps and 4px rounded data-ends.
* Dark mode is *selected*, not an automatic inversion: both the OS media query
  and an explicit `data-theme` toggle are handled, and the toggle wins.
"""

import base64
import datetime as _dt
import html
import json
import re as _re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .knowledge import apply_knowledge
from .lifecycle import reconcile as reconcile_lifecycle
from .consolidate import (
    SEVERITY_ORDER,
    VALIDATION_DYNAMIC,
    Finding,
    _assessment_label,
    _clean,
    _format_quality_checks,
    _is_substantiated,
    apply_normalized_severity,
    apply_validation,
    assess_candidates,
    assessment_totals,
    backfill_locations,
    compute_run_status,
    coverage_ledger,
    flag_duplicates,
    load_meta,
    parse_findings,
    rank,
)

SCAN_REPORT_HTML = "SCAN_REPORT.html"

# Bump whenever the rendered output changes in a way existing reports should
# pick up. SCAN_REPORT.html is a generated snapshot, so without a stamp an
# improvement silently applies only to *new* scans and every older report keeps
# rendering with whatever version wrote it.
RENDERER_VERSION = "11"
_STAMP = '<meta name="generator" content="vhlocal-report/{0}">'.format(RENDERER_VERSION)

# Status palette — fixed, never themed. Same hexes in both modes.
SEV_STYLE: Dict[str, Tuple[str, str]] = {
    # label:        (colour,     glyph)
    "Critical":     ("#d03b3b", "◆"),   # filled diamond
    "High+":        ("#d03b3b", "▲"),   # filled triangle
    "High":         ("#ec835a", "△"),   # hollow triangle
    "Medium":       ("#fab219", "■"),   # filled square
    "Low":          ("",        "●"),   # dot, muted ink
    "Informational": ("",       "○"),   # hollow dot, muted ink
    "Unrated":      ("",        "—"),
}
SEV_LABELS = [lbl for _k, lbl in SEVERITY_ORDER]
_SEEN: List[str] = []
for _l in SEV_LABELS:
    if _l not in _SEEN:
        _SEEN.append(_l)
SEV_LABELS = _SEEN + ["Unrated"]

CSS = """
:root{
  color-scheme: light;
  --surface-1:#fcfcfb; --surface-2:#f4f4f1; --surface-3:#eceae5;
  --line:#dedbd3;
  --text-primary:#0b0b0b; --text-secondary:#52514e; --text-muted:#7b7a75;
  --crit:#d03b3b; --serious:#ec835a; --warn:#fab219; --good:#0ca30c;
  --accent:#2a78d6;
}
@media (prefers-color-scheme: dark){
  :root:where(:not([data-theme="light"])){
    color-scheme: dark;
    --surface-1:#1a1a19; --surface-2:#232322; --surface-3:#2d2d2b;
    --line:#3a3a37;
    --text-primary:#ffffff; --text-secondary:#c3c2b7; --text-muted:#94938b;
    --accent:#3987e5;
  }
}
:root[data-theme="dark"]{
  color-scheme: dark;
  --surface-1:#1a1a19; --surface-2:#232322; --surface-3:#2d2d2b;
  --line:#3a3a37;
  --text-primary:#ffffff; --text-secondary:#c3c2b7; --text-muted:#94938b;
  --accent:#3987e5;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--surface-1); color:var(--text-primary);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 80px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:.88em}

/* ---------- header ---------- */
.rhead{display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap;
  padding-bottom:20px;border-bottom:1px solid var(--line)}
.rhead h1{margin:0;font-size:22px;letter-spacing:-.01em}
.rhead .sub{color:var(--text-secondary);font-size:13.5px;margin-top:3px}
.rhead .spacer{flex:1}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:12px;
  padding:4px 10px;border-radius:999px;border:1px solid var(--line);
  background:var(--surface-2);color:var(--text-secondary);white-space:nowrap}
.chip.ok{border-color:var(--good);color:var(--good)}
.chip.warnc{border-color:var(--warn)}
button.tgl{cursor:pointer;font:inherit;font-size:12px;padding:4px 10px;
  border-radius:999px;border:1px solid var(--line);background:var(--surface-2);
  color:var(--text-secondary)}

/* ---------- hero + KPI ---------- */
.lead{display:flex;gap:28px;align-items:flex-end;flex-wrap:wrap;margin:28px 0 8px}
.hero{line-height:1}
.hero .n{font-size:56px;font-weight:650;letter-spacing:-.03em}
.hero .l{font-size:13px;color:var(--text-secondary);margin-top:6px}
.kpis{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  margin:22px 0 30px}
.tile{background:var(--surface-2);border:1px solid var(--line);border-radius:10px;
  padding:12px 14px}
.tile .k{font-size:11.5px;color:var(--text-muted);text-transform:uppercase;
  letter-spacing:.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tile .v{font-size:20px;font-weight:600;margin-top:4px;letter-spacing:-.01em}
.tile .s{font-size:11.5px;color:var(--text-secondary);margin-top:2px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ---------- severity meter ---------- */
h2{font-size:12.5px;text-transform:uppercase;letter-spacing:.08em;
  color:var(--text-muted);margin:34px 0 12px;font-weight:600}
.meter{display:flex;gap:2px;height:22px;margin:4px 0 14px}  /* 2px surface gap */
.meter i{display:block;height:100%;border-radius:0}
.meter i:first-child{border-radius:4px 0 0 4px}
.meter i:last-child{border-radius:0 4px 4px 0}              /* 4px data-end */
.meter i:only-child{border-radius:4px}
.sevrows{display:grid;gap:6px;margin-bottom:6px}
.sevrow{display:flex;align-items:center;gap:10px;font-size:13.5px}
.sevrow .nm{min-width:118px;display:flex;align-items:center;gap:7px;font-weight:600}
.sevrow .ct{color:var(--text-secondary);font-variant-numeric:tabular-nums}
.glyph{font-size:11px;line-height:1}

/* ---------- controls ---------- */
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0 14px}
.controls input{font:inherit;font-size:13px;padding:6px 10px;border-radius:8px;
  border:1px solid var(--line);background:var(--surface-2);
  color:var(--text-primary);min-width:220px}
.fbtn{cursor:pointer;font:inherit;font-size:12.5px;padding:5px 11px;
  border-radius:999px;border:1px solid var(--line);background:var(--surface-2);
  color:var(--text-secondary);display:inline-flex;align-items:center;gap:6px}
.fbtn[aria-pressed="true"]{background:var(--surface-3);color:var(--text-primary);
  border-color:var(--text-muted)}

/* ---------- findings ---------- */
.finding{border:1px solid var(--line);border-radius:10px;margin-bottom:10px;
  background:var(--surface-2);overflow:hidden}
.finding > summary{cursor:pointer;list-style:none;padding:13px 16px;
  display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}
.finding > summary::-webkit-details-marker{display:none}
.finding > summary:hover{background:var(--surface-3)}
.rank{font-variant-numeric:tabular-nums;color:var(--text-muted);
  min-width:22px;font-size:13px}
.sevtag{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;
  font-weight:700;letter-spacing:.03em;text-transform:uppercase;
  padding:3px 9px;border-radius:6px;border:1px solid var(--line);
  background:var(--surface-1);white-space:nowrap}
.ftitle{font-weight:600;flex:1;min-width:200px}
.fcwe{font-size:12px;color:var(--text-secondary)}
/* Lifecycle chips — state encoded by label + colour (never colour alone). */
.flc{font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;
  border:1px solid var(--line);white-space:nowrap}
.flc-new{color:var(--accent);border-color:var(--accent)}
.flc-persisting{color:var(--text-secondary)}
.flc-regressed{color:var(--crit);border-color:var(--crit)}
.floc{font-size:12px;color:var(--text-muted)}
.fbody{padding:2px 16px 16px;border-top:1px solid var(--line)}
.fbody dl{display:grid;grid-template-columns:150px 1fr;gap:8px 16px;margin:14px 0 0}
.fbody dt{color:var(--text-muted);font-size:12px;text-transform:uppercase;
  letter-spacing:.05em;padding-top:2px}
.fbody dd{margin:0;font-size:14px;overflow-wrap:anywhere}
.dupnote{font-size:12.5px;color:var(--text-secondary);
  background:var(--surface-3);border-radius:6px;padding:8px 11px;margin-top:12px}

/* ---------- generic ---------- */
table.kv{width:100%;border-collapse:collapse;font-size:13.5px}
table.kv td,table.kv th{text-align:left;padding:7px 10px;
  border-bottom:1px solid var(--line);vertical-align:top}
table.kv th{color:var(--text-muted);font-weight:500;width:210px}
details.sec{border:1px solid var(--line);border-radius:10px;
  background:var(--surface-2);margin-bottom:12px}
details.sec > summary{cursor:pointer;padding:12px 16px;font-weight:600;
  font-size:13.5px;list-style:none}
details.sec > summary::-webkit-details-marker{display:none}
details.sec > summary::before{content:"\\25b8";display:inline-block;
  margin-right:9px;color:var(--text-muted);transition:transform .15s}
details.sec[open] > summary::before{transform:rotate(90deg)}
details.sec .in{padding:0 16px 14px}
.note{border-left:3px solid var(--warn);background:var(--surface-2);
  padding:11px 14px;border-radius:0 8px 8px 0;font-size:13.5px;margin:10px 0}
.note.crit{border-left-color:var(--crit)}
ul.lim{margin:8px 0 0;padding-left:20px;font-size:13.5px;
  color:var(--text-secondary)}
ul.lim li{margin-bottom:7px}
.empty{text-align:center;color:var(--text-muted);padding:44px 0;
  border:1px dashed var(--line);border-radius:10px}
footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--line);
  font-size:12px;color:var(--text-muted)}

/* ---------- print / PDF ---------- */
@page{ margin:14mm 12mm; }
@media print{
  /* Force the light palette regardless of theme. `:root[data-theme]` matches
     the specificity of the dark-mode rule above, and this block comes later in
     source order, so it wins in both directions. */
  :root, :root[data-theme]{
    color-scheme: light;
    --surface-1:#ffffff; --surface-2:#ffffff; --surface-3:#f4f4f1;
    --line:#c9c6be;
    --text-primary:#000000; --text-secondary:#333333; --text-muted:#555555;
  }
  html,body{background:#fff}
  .wrap{max-width:none;padding:0}

  /* Interactive chrome has no meaning on paper. */
  .controls, button.tgl, button.pdf, #expandBtn{display:none}

  /* Everything expanded — a collapsed <details> would print as a bare heading.
     The beforeprint handler also sets .open, this is the belt to that braces. */
  details.sec > .in, .fbody{display:block}
  details.sec > summary::before{content:""}

  /* Browsers drop background colours when printing. The severity meter and
     badges ARE the encoding, so opt them back in explicitly. */
  .meter i, .sevtag, .glyph, .chip, .note{
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }

  .finding, details.sec, .tile, .sevrow{break-inside:avoid; page-break-inside:avoid}
  h2{break-after:avoid} .rhead{break-after:avoid}
  .fbody dl{break-inside:auto}
  a{text-decoration:none; color:inherit}
  .kpis{grid-template-columns:repeat(3,1fr)}
  footer{break-before:avoid}

  /* A filtered PDF that looks complete is dangerous in a security report. */
  .printnote{display:block}
}
.printnote{display:none;border:1px solid var(--warn);border-radius:6px;
  padding:9px 12px;margin:0 0 14px;font-size:12.5px;
  -webkit-print-color-adjust:exact; print-color-adjust:exact}
"""

JS = """
(function(){
  var root=document.documentElement;
  var btn=document.getElementById('themeBtn');
  if(btn){btn.addEventListener('click',function(){
    var cur=root.getAttribute('data-theme');
    if(!cur){cur=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}
    root.setAttribute('data-theme',cur==='dark'?'light':'dark');
  });}

  var q=document.getElementById('q');
  var chips=Array.prototype.slice.call(document.querySelectorAll('.fbtn[data-sev]'));
  var items=Array.prototype.slice.call(document.querySelectorAll('.finding'));
  var count=document.getElementById('shown');
  var active={};

  function apply(){
    var term=(q&&q.value||'').toLowerCase();
    var anyActive=Object.keys(active).some(function(k){return active[k];});
    var n=0;
    items.forEach(function(el){
      var sev=el.getAttribute('data-sev');
      var hay=(el.getAttribute('data-search')||'').toLowerCase();
      var okSev=!anyActive||active[sev];
      var okTerm=!term||hay.indexOf(term)>=0;
      var show=okSev&&okTerm;
      el.style.display=show?'':'none';
      if(show)n++;
    });
    if(count)count.textContent=n;
  }
  chips.forEach(function(c){
    c.addEventListener('click',function(){
      var s=c.getAttribute('data-sev');
      active[s]=!active[s];
      c.setAttribute('aria-pressed',active[s]?'true':'false');
      apply();
    });
  });
  if(q)q.addEventListener('input',apply);

  // ---- PDF ----
  // No bundled PDF library: inlining one would add ~500KB to every report and
  // break the self-contained/offline guarantee. The browser's own print engine
  // renders the tuned @media print stylesheet to PDF and works everywhere,
  // including on this file opened straight from disk.
  var pdfBtn=document.getElementById('pdfBtn');
  if(pdfBtn){pdfBtn.addEventListener('click',function(){window.print();});}

  // ---- Markdown ----
  // The source is embedded as base64 in #mdSource; decode it (UTF-8 safe) and
  // hand the browser a Blob so no server round-trip is needed.
  var mdBtn=document.getElementById('mdBtn');
  var mdEl=document.getElementById('mdSource');
  if(mdBtn&&mdEl){mdBtn.addEventListener('click',function(){
    var txt='';
    try{
      var bin=atob((mdEl.textContent||'').replace(/\\s+/g,''));
      txt=decodeURIComponent(Array.prototype.map.call(bin,function(c){
        return '%'+('00'+c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
    }catch(e){txt='';}
    if(!txt){return;}
    var blob=new Blob([txt],{type:'text/markdown;charset=utf-8'});
    var url=URL.createObjectURL(blob);
    var a=document.createElement('a');
    a.href=url; a.download=mdBtn.getAttribute('data-fn')||'scan-report.md';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function(){URL.revokeObjectURL(url);},1000);
  });}

  var _reopen=[];
  window.addEventListener('beforeprint',function(){
    // A collapsed <details> prints as a bare heading — expand everything, then
    // put it back exactly as the reader had it.
    _reopen=[];
    Array.prototype.forEach.call(document.querySelectorAll('details'),function(d){
      _reopen.push([d,d.open]); d.open=true;
    });
    // Print what is on screen (respect an active filter), but say so — a
    // filtered PDF that looks complete would understate the findings.
    var note=document.getElementById('printNote');
    if(note){
      var total=items.length;
      var shown=items.filter(function(el){return el.style.display!=='none';}).length;
      var term=(q&&q.value||'').trim();
      var sevs=Object.keys(active).filter(function(k){return active[k];});
      if(shown<total){
        note.textContent='Filtered view — showing '+shown+' of '+total+
          ' findings'+
          (sevs.length?' (severity: '+sevs.join(', ')+')':'')+
          (term?' (search: "'+term+'")':'')+
          '. Clear the filters and re-export for the complete report.';
        note.style.display='block';
      } else { note.style.display='none'; note.textContent=''; }
    }
  });
  window.addEventListener('afterprint',function(){
    _reopen.forEach(function(pair){pair[0].open=pair[1];});
    _reopen=[];
  });

  var ex=document.getElementById('expandBtn');
  if(ex)ex.addEventListener('click',function(){
    var open=ex.getAttribute('data-open')==='1';
    items.forEach(function(el){if(el.style.display!=='none')el.open=!open;});
    ex.setAttribute('data-open',open?'0':'1');
    ex.textContent=open?'Expand all':'Collapse all';
  });
  apply();
})();
"""


def _e(v: Any) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def _fmt_dur(seconds: float) -> str:
    s = int(max(0, seconds or 0))
    if s < 60:
        return "{0}s".format(s)
    if s < 3600:
        return "{0}m {1}s".format(s // 60, s % 60)
    return "{0}h {1}m".format(s // 3600, (s % 3600) // 60)


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "unknown"
    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def _sev_color(label: str) -> str:
    return SEV_STYLE.get(label, ("", "●"))[0]


def _sev_glyph(label: str) -> str:
    return SEV_STYLE.get(label, ("", "●"))[1]


def _sev_badge(label: str) -> str:
    """Colour + glyph + word. Never colour alone — Medium/High measure ΔE 13.6."""
    col = _sev_color(label)
    style = ' style="color:{0}"'.format(col) if col else ' style="color:var(--text-muted)"'
    return ('<span class="sevtag"><span class="glyph"{0}>{1}</span>{2}</span>'
            .format(style, _sev_glyph(label), _e(label)))


def _tile(key: str, value: str, sub: str = "") -> str:
    return ('<div class="tile"><div class="k">{0}</div><div class="v">{1}</div>'
            '{2}</div>').format(
        _e(key), _e(value),
        '<div class="s">{0}</div>'.format(_e(sub)) if sub else "")


def _counts(findings: List[Finding]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        if f.duplicate_of:
            continue
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _markdown_source(results_dir: Path) -> str:
    """The report's Markdown for the 'Save as Markdown' button.

    Prefer the already-written SCAN_REPORT.md so the download is byte-identical
    to the on-disk artifact; regenerate it in memory only if the file is absent
    (e.g. render_html invoked standalone before consolidate wrote it).
    """
    md_path = results_dir / "SCAN_REPORT.md"
    if md_path.exists():
        try:
            return md_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    try:
        from .consolidate import render as _render_md
        return _render_md(results_dir)
    except Exception:
        return ""


def _download_name(target: str, started_at: float) -> str:
    """Filesystem-safe basename for the Markdown download, e.g.
    scan-report-myapp-2026-08-17.md."""
    base = Path(target).name or "scan"
    date = _fmt_ts(started_at or _dt.datetime.now().timestamp()).split()[0]
    raw = "scan-report-{0}-{1}".format(base, date)
    safe = _re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-") or "scan-report"
    return safe + ".md"


def render_html(results_dir: Path) -> str:
    results_dir = Path(results_dir)
    meta = load_meta(results_dir)
    findings = parse_findings(results_dir)
    backfill_locations(findings, results_dir, meta.get("repo", ""))
    flag_duplicates(findings)
    assess_candidates(findings, meta)
    apply_validation(findings, meta)
    apply_knowledge(findings)
    apply_normalized_severity(findings)
    findings = rank(findings)
    lifecycle = reconcile_lifecycle(findings, results_dir, meta)
    ledger = coverage_ledger(results_dir, meta, findings)
    rs = compute_run_status(meta, ledger=ledger)

    unique = [f for f in findings if not f.duplicate_of]
    dupes = [f for f in findings if f.duplicate_of]
    counts = _counts(findings)
    total = len(unique)

    req = meta.get("phases_requested") or []
    done = set(meta.get("phases_completed") or [])
    skipped = set(meta.get("phases_skipped") or [])
    timings = meta.get("phase_timings") or {}
    agents = meta.get("agents") or []
    parts = meta.get("partitions") or []
    usage = meta.get("usage") or {}
    duration = (meta.get("finished_at", 0) or 0) - (meta.get("started_at", 0) or 0)
    target = meta.get("repo") or "unknown target"
    incomplete = [a for a in agents
                  if a.get("stopped_reason") not in ("complete", None, "")]

    H: List[str] = []
    A = H.append

    A("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    A("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
    A(_STAMP)
    # The browser uses <title> as the default PDF filename, so include the
    # target and the scan date rather than a bare "Scan report".
    A("<title>Scan report \u2014 {0} \u2014 {1}</title>".format(
        _e(Path(target).name or "scan"),
        _fmt_ts(meta.get("started_at") or _dt.datetime.now().timestamp()).split()[0]))
    A("<style>{0}</style></head><body><div class=\"wrap\">".format(CSS))

    # ---------------- header ----------------
    # Absent metadata means *unknown*, not zero/incomplete. Asserting
    # "Incomplete" or "0 agents" for a run we simply have no record of would be
    # a false claim about the scan.
    has_meta = bool(meta)
    # Execution and coverage are separate axes: a run can finish every phase
    # (execution complete) yet only reach one whole-repo partition (coverage
    # degraded). Show both, never a single conflated "Partial".
    if not has_meta:
        exec_status = "unknown"
    else:
        exec_status = rs["execution_status"]
    exec_label = exec_status.capitalize()
    cov_status = rs["coverage_status"] if has_meta else "unknown"
    exec_cls = "chip ok" if exec_status == "complete" else "chip warnc"
    cov_cls = "chip ok" if cov_status == "complete" else "chip warnc"
    hunt = meta.get("model") or "unknown model"
    fals = meta.get("verify_model") or meta.get("model") or "—"
    orch = "vhlocal " + meta.get("engine_version") if meta.get("engine_version") else "vhlocal"
    A('<div class="rhead"><div>')
    A('<h1>Security scan report</h1>')
    A('<div class="sub"><span class="mono">{0}</span></div>'.format(_e(target)))
    A('<div class="sub">{0} &middot; hunt <span class="mono">{1}</span> '
      '&middot; falsification <span class="mono">{2}</span> &middot; {3}</div>'.format(
          _fmt_ts(meta.get("started_at", 0)), _e(hunt), _e(fals), _e(orch)))
    A('</div><div class="spacer"></div>')
    A('<span class="{0}" title="Did the requested phases run to completion?">'
      'exec: {1}</span>'.format(exec_cls, _e(exec_label)))
    A('<span class="{0}" title="Did the run reach the whole attack surface?">'
      'coverage: {1}</span>'.format(cov_cls, _e(cov_status.capitalize())))
    A('<button class="tgl pdf" id="pdfBtn" title="Open the print dialog and '
      'choose \u201cSave as PDF\u201d">Save as PDF</button>')
    md_source = _markdown_source(results_dir)
    if md_source:
        A('<button class="tgl pdf" id="mdBtn" data-fn="{0}" '
          'title="Download this report as a Markdown file">'
          'Save as Markdown</button>'.format(
              _e(_download_name(target, meta.get("started_at") or 0))))
    A('<button class="tgl" id="themeBtn">Theme</button>')
    A('</div>')

    # ---------------- hero + KPI row ----------------
    A('<div class="lead"><div class="hero">')
    A('<div class="n">{0}</div>'.format(total))
    A('<div class="l">{0} reported</div>'.format(
        "candidate" if total == 1 else "candidates"))
    at = assessment_totals(unique)
    A('<div>{0} substantiated vulnerabilities · {1} hypotheses worth investigating</div>'.format(
        at["supported"], at["unresolved"]))
    A('</div></div>')

    A('<div class="kpis">')
    if has_meta:
        A(_tile("Duration", _fmt_dur(duration),
                "{0:,} model calls".format(usage.get("calls", 0))
                if usage.get("calls") else ""))
        A(_tile("Phases completed", "{0} / {1}".format(len(done), len(req) or len(done)),
                "of those requested" if req else ""))
        A(_tile("Agents", str(len(agents)),
                "{0} did not finish".format(len(incomplete)) if incomplete
                else "all completed"))
        A(_tile("Partitions", str(len(parts)) if parts else "—",
                ", ".join(parts[:3]) + ("…" if len(parts) > 3 else "")
                if parts else "none recorded"))
        if usage:
            A(_tile("Tokens processed",
                    "{0:,}".format(usage.get("prompt_tokens", 0) +
                                   usage.get("completion_tokens", 0)),
                    "peak ctx {0:,}".format(usage.get("peak_prompt_tokens", 0))))
        A(_tile("Code execution", "Disabled", "static analysis only"))
    else:
        A(_tile("Scan metadata", "Unavailable",
                "run predates metadata capture"))
        A(_tile("Duration", "Unknown"))
        A(_tile("Agents", "Unknown"))
        A(_tile("Code execution", "Disabled", "static analysis only"))
    A('</div>')

    # Coverage degradation is louder than a chip: a narrow run must not read as
    # thorough. State exactly why coverage is provisional.
    if rs["coverage_degraded_reasons"]:
        A('<div class="note crit"><strong>Coverage is degraded — '
          'coverage-dependent numbers are provisional.</strong><ul>')
        for reason in rs["coverage_degraded_reasons"]:
            A('<li>{0}</li>'.format(_e(reason)))
        A('</ul></div>')

    # ---------------- severity ----------------
    if total:
        A('<h2>Severity breakdown</h2>')
        A('<div class="meter" role="img" aria-label="Severity distribution">')
        for lbl in SEV_LABELS:
            n = counts.get(lbl, 0)
            if not n:
                continue
            col = _sev_color(lbl) or "var(--text-muted)"
            A('<i style="width:{0:.4f}%;background:{1}" title="{2}: {3}"></i>'.format(
                100.0 * n / total, col, _e(lbl), n))
        A('</div>')
        A('<div class="sevrows">')
        for lbl in SEV_LABELS:
            n = counts.get(lbl, 0)
            if not n:
                continue
            col = _sev_color(lbl)
            style = ' style="color:{0}"'.format(col) if col else \
                    ' style="color:var(--text-muted)"'
            A('<div class="sevrow"><span class="nm">'
              '<span class="glyph"{0}>{1}</span>{2}</span>'
              '<span class="ct">{3}</span></div>'.format(
                  style, _sev_glyph(lbl), _e(lbl), n))
        A('</div>')

    # ---------------- change since last scan (Mode A) ----------------
    if lifecycle.get("has_prior"):
        prior_c = lifecycle.get("prior_commit") or ""
        A('<h2>Change since last scan</h2>')
        A('<div class="kpis">')
        for k, lbl in (("new", "New this scan"), ("persisting", "Persisting"),
                       ("regressed", "Regressed"), ("fixed", "Fixed")):
            A('<div class="tile"><div class="k">{0}</div>'
              '<div class="v">{1}</div></div>'.format(_e(lbl), lifecycle.get(k, 0)))
        A('</div>')
        A('<div class="printnote">Compared against <span class="mono">{0}</span>{1}.'
          '</div>'.format(
              _e(lifecycle.get("prior_report", "the prior report")),
              " (commit <span class=\"mono\">{0}</span>)".format(_e(prior_c[:12]))
              if prior_c else ""))
        fixed = lifecycle.get("fixed_findings") or []
        if fixed:
            A('<details class="finding"><summary><span class="ftitle">'
              'No longer observed since previous scan ({0}) — not evidence of a fix'
              '</span></summary>'
              '<div class="fbody"><dl>'.format(len(fixed)))
            for ff in fixed:
                A('<dt class="mono">{0}</dt><dd>{1} <span style="color:'
                  'var(--text-muted)">{2}</span></dd>'.format(
                      _e(ff.get("id") or "—"), _e(ff.get("title") or "—"),
                      _e(ff.get("cwe") or "")))
            A('</dl></div></details>')

    # ---------------- findings ----------------
    A('<h2>Hypotheses and substantiated vulnerabilities <span style="text-transform:none;letter-spacing:0">'
      '(<span id="shown">{0}</span> shown)</span></h2>'.format(total))

    if not total:
        A('<div class="empty">No hypotheses or substantiated vulnerabilities were reported.')
        if not (results_dir / "README.md").exists():
            A('<br><br>The scanner\'s final report is absent, so this may be an '
              'incomplete scan rather than a clean result.')
        A('</div>')
    else:
        A('<div class="controls">')
        A('<input id="q" type="search" placeholder="Filter candidates…" '
          'aria-label="Filter candidates">')
        for lbl in SEV_LABELS:
            if not counts.get(lbl):
                continue
            col = _sev_color(lbl)
            style = ' style="color:{0}"'.format(col) if col else ''
            A('<button class="fbtn" data-sev="{0}" aria-pressed="false">'
              '<span class="glyph"{1}>{2}</span>{0} ({3})</button>'.format(
                  _e(lbl), style, _sev_glyph(lbl), counts[lbl]))
        A('<button class="fbtn" id="expandBtn" data-open="0">Expand all</button>')
        A('</div>')
        A('<div class="printnote" id="printNote"></div>')

        for i, f in enumerate(unique, start=1):
            hay = " ".join([f.id, f.title, f.cwe, _clean(f.location),
                            _clean(f.entry_point), f.severity])
            A('<details class="finding" data-sev="{0}" data-search="{1}">'.format(
                _e(f.severity), _e(hay)))
            A('<summary><span class="rank">{0}</span>{1}'.format(i, _sev_badge(f.severity)))
            A('<span class="fcwe">{0}</span>'.format(
                {"reviewed": "Reviewed vulnerability",
                 "statically_supported": "Statically-supported"}.get(
                     f.classification, "Hypothesis")))
            A('<span class="ftitle">{0}</span>'.format(_e(f.title or f.id)))
            chip_cwe = f.normalized_cwe or f.cwe
            if chip_cwe:
                A('<span class="fcwe">{0}</span>'.format(_e(chip_cwe)))
            lc_chip = {"new": ("🆕 new", "new"),
                       "persisting": ("➡️ persisting", "persisting"),
                       "regressed": ("🔁 regressed", "regressed")}.get(
                           f.finding_lifecycle)
            if lc_chip:
                A('<span class="flc flc-{1}">{0}</span>'.format(
                    lc_chip[0], lc_chip[1]))
            A('</summary><div class="fbody"><dl>')
            A('<dt>Finding ID</dt><dd class="mono">{0}</dd>'.format(_e(f.id)))
            # Deterministic family severity is what the badge shows; surface the
            # model's own tier when it differed, so nothing is hidden.
            if f.reported_severity and f.reported_severity != f.severity:
                A('<dt>Severity</dt><dd>{0} <span style="color:var(--text-muted)">'
                  '(scanner-assessed: {1})</span></dd>'.format(
                      _e(f.severity), _e(f.reported_severity)))
            # CWE: model-reported, plus the canonical family roll-up used for
            # cross-run comparison when it differs.
            if f.cwe or f.normalized_cwe:
                A('<dt>CWE</dt><dd>{0}</dd>'.format(_e(f.cwe or "—")))
                if f.normalized_cwe and f.normalized_cwe != f.cwe:
                    fam = " ({0})".format(f.canonical_name) if f.canonical_name else ""
                    A('<dt>Normalized CWE</dt><dd>{0}{1}</dd>'.format(
                        _e(f.normalized_cwe), _e(fam)))
                elif f.canonical_name:
                    A('<dt>Family</dt><dd>{0}</dd>'.format(_e(f.canonical_name)))
            if f.description:
                A('<dt>Description</dt><dd>{0}</dd>'.format(_e(f.description)))
            if f.exploitability and _is_substantiated(f.classification):
                basis = ("statically confirmed (source→sink); not runtime-tested"
                         if f.validation_method != VALIDATION_DYNAMIC
                         else "runtime-verified")
                A('<dt>Exploitability</dt><dd>{0}<br><span style="color:'
                  'var(--text-muted)">Basis: {1}</span></dd>'.format(
                      _e(f.exploitability), _e(basis)))
            for label, val, mono in (
                ("Assessment", _assessment_label(f.classification), False),
                ("Why the scanner flagged this", f.hypothesis_reason or f.data_flow or "No candidate-specific explanation was provided.", False),
                ("Evidence assessment", f.assessment_reason, False),
                ("Quality checks", _format_quality_checks(f.quality_checks) if f.quality_checks else "", False),
                ("Potential severity", f.severity if f.classification == "hypothesis" else "", False),
                ("Location", _clean(f.location), True),
                ("Entry point", f.entry_point, False),
                ("Data flow", f.data_flow, False),
                ("Proposed fix", f.fix, False),
                ("Proof of concept", _clean(f.poc), False),
            ):
                if val:
                    A('<dt>{0}</dt><dd{1}>{2}</dd>'.format(
                        _e(label), ' class="mono"' if mono else "", _e(val)))
            # Harness-owned validation — never the model's PASS/Confirmed claim.
            test_txt = {"not_run": "not run (no code executed)",
                        "passed": "passed (execution record)",
                        "failed": "failed (execution record)"}.get(
                            f.test_status, f.test_status or "not run")
            A('<dt>Test status</dt><dd>{0}</dd>'.format(_e(test_txt)))
            A('<dt>Validation</dt><dd>{0}</dd>'.format(_e(
                "dynamic execution" if f.validation_method == VALIDATION_DYNAMIC
                else "static reasoning")))
            A('<dt>Finding state</dt><dd>{0}</dd>'.format(_e(
                (f.finding_state or "hypothesis").replace("_", " "))))
            if f.finding_lifecycle:
                A('<dt>Lifecycle</dt><dd>{0}</dd>'.format(_e({
                    "new": "new this scan",
                    "persisting": "persisting since last scan",
                    "regressed": "reappeared (not observed last scan, present now)",
                }.get(f.finding_lifecycle, f.finding_lifecycle))))
            reported = " / ".join(
                x for x in (_clean(f.status), _clean(f.exploit_test))
                if x and x.lower() not in ("—", "n/a"))
            if reported:
                A('<dt>Scanner-reported (unverified)</dt>'
                  '<dd>{0}</dd>'.format(_e(reported)))
            if f.reference:
                # Linkify the reference URL — a clickable anchor is navigation,
                # not a fetched resource, so it keeps the report self-contained.
                m = _re.search(r'https?://[^\s]+', f.reference)
                if m:
                    url = m.group(0)
                    label = f.reference[:m.start()].rstrip(" —-")
                    # Short anchor text (not the raw URL) so the URL lives only in
                    # href — keeps the page free of loose external URLs.
                    ref_html = '{0} — <a href="{1}" target="_blank" rel="noopener">MITRE ↗</a>'.format(
                        _e(label), _e(url))
                else:
                    ref_html = _e(f.reference)
                A('<dt>Reference</dt><dd>{0}</dd>'.format(ref_html))
            # CVE deliberately N/A for first-party code findings (see knowledge.py).
            A('<dt>CVE</dt><dd>{0}</dd>'.format(_e(f.cve or "—")))
            A('</dl></div></details>')

    if dupes:
        A('<h2>Duplicate findings (clustered)</h2>')
        A('<div class="note">Each shares a root cause — family, file, sink '
          'function <em>and</em> data-flow signature — with a canonical finding '
          'above. Clustered rather than deleted (duplicate reporting is itself a '
          'signal about scan quality) and <strong>excluded from the counts and '
          'severity totals</strong>, which reflect unique root causes only.'
          '</div>')
        A('<table class="kv"><tr><th>Finding</th><td>Clustered under</td>'
          '<td>Location</td></tr>')
        for f in dupes:
            A('<tr><th class="mono">{0}</th><td class="mono">{1}</td>'
              '<td class="mono">{2}</td></tr>'.format(
                  _e(f.id), _e(f.cluster_id or f.duplicate_of),
                  _e(_clean(f.location) or "—")))
        A('</table>')

    # ---------------- coverage ledger ----------------
    if ledger is not None and ledger.total:
        A('<h2>Entry-point coverage ledger</h2>')
        A('<div class="note">The attack surface is enumerated by the harness '
          'from source — the model cannot shrink the denominator by overlooking '
          'a route. {0} of {1} entry points were reached by the analysis.'
          '</div>'.format(ledger.reviewed, ledger.total))
        not_reviewed = [e for e in ledger.entries
                        if e.disposition == "not_reviewed"]
        if not_reviewed:
            A('<div class="note crit"><strong>{0} of {1} entry points were '
              'never referenced by any produced artifact</strong> — a run cannot '
              'be complete-coverage while these remain.</div>'.format(
                  len(not_reviewed), ledger.total))
            A('<table class="kv"><tr><th>Method</th><td>Path</td>'
              '<td>Location</td></tr>')
            for e in not_reviewed:
                A('<tr><th class="mono">{0}</th><td class="mono">{1}</td>'
                  '<td class="mono">{2}:{3}</td></tr>'.format(
                      _e(e.method), _e(e.path), _e(e.file), e.line))
            A('</table>')

    # ---------------- checks enabled ----------------
    A('<h2>Checks enabled</h2>')
    if meta.get("aborted"):
        A('<div class="note crit"><strong>Scan aborted early.</strong> The '
          'inference endpoint became unreachable, so remaining phases did not '
          'run. Findings below are partial. <span class="mono">{0}</span></div>'
          .format(_e(meta.get("aborted"))))
    if incomplete:
        A('<div class="note crit"><strong>{0} of {1} agents did not finish '
          'cleanly.</strong> Coverage for the affected areas is reduced.</div>'
          .format(len(incomplete), len(agents)))

    A('<details class="sec" open><summary>Phases</summary><div class="in">')
    if req:
        A('<table class="kv"><tr><th>Phase</th><td>Check</td><td>Status</td>'
          '<td>Duration</td></tr>')
        from .consolidate import PHASE_TITLES
        for k in req:
            st = "Completed" if k in done else (
                "Skipped (resume)" if k in skipped else "Not completed")
            A('<tr><th>{0}</th><td>{1}</td><td>{2}</td><td>{3}</td></tr>'.format(
                _e(k), _e(PHASE_TITLES.get(k, k)), _e(st),
                _fmt_dur(timings.get(k, 0)) if timings.get(k) else "—"))
        A('</table>')
    else:
        A('<p style="color:var(--text-muted);font-size:13.5px">'
          'No phase record — this scan predates metadata capture.</p>')
    A('</div></details>')

    from .consolidate import CLASS_TITLES
    classes = meta.get("vuln_classes") or []
    if classes and "2" in req:
        by_class: Dict[str, int] = {}
        for a in agents:
            vc = a.get("vuln_class")
            if vc:
                by_class[vc] = by_class.get(vc, 0) + 1
        A('<details class="sec"><summary>Vulnerability classes</summary>'
          '<div class="in">')
        if "2" not in done:
            A('<div class="note">Phase 2 did not complete — the coverage below '
              'was requested but not fully exercised.</div>')
        A('<table class="kv"><tr><th>Class</th><td>Agents</td><td>Coverage</td></tr>')
        for c in list(classes) + ["SINK"]:
            A('<tr><th>{0}</th><td>{1}</td><td>{2}</td></tr>'.format(
                _e(c), by_class.get(c, 0), _e(CLASS_TITLES.get(c, c))))
        A('</table></div></details>')
    elif classes:
        A('<details class="sec"><summary>Vulnerability classes</summary>'
          '<div class="in"><p style="color:var(--text-muted);font-size:13.5px">'
          'Phase 2 (hunt) was not part of this run, so no vulnerability-class '
          'checks were performed.</p></div></details>')

    A('<details class="sec"><summary>Scan configuration</summary><div class="in">')
    A('<table class="kv">')
    for k, v in (
        ("Target", meta.get("repo") or "unknown"),
        ("Hunt model", meta.get("model") or "—"),
        ("Falsification model", meta.get("verify_model") or meta.get("model") or "—"),
        ("Inference host", meta.get("host") or "—"),
        ("Context window", "{0:,} tokens".format(meta.get("num_ctx") or 0)),
        ("Max partitions", meta.get("max_partitions") or "—"),
        ("Tool envelope", ", ".join(meta.get("tool_envelope") or []) or "—"),
        ("Code execution", "Enabled" if meta.get("bash_enabled")
         else "Disabled — static analysis only"),
        ("Scan engine", "vhlocal {0}".format(meta.get("engine_version") or "—")),
        ("Started", _fmt_ts(meta.get("started_at", 0))),
        ("Finished", _fmt_ts(meta.get("finished_at", 0))),
        ("Results directory", meta.get("results_dir") or str(results_dir)),
    ):
        A('<tr><th>{0}</th><td class="mono">{1}</td></tr>'.format(_e(k), _e(v)))
    if usage:
        A('<tr><th>Tokens (prompt / completion)</th><td class="mono">'
          '{0:,} / {1:,}</td></tr>'.format(
              usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)))
    A('</table></div></details>')

    if incomplete:
        A('<details class="sec"><summary>Agents that did not finish '
          '({0})</summary><div class="in"><table class="kv">'.format(len(incomplete)))
        A('<tr><th>Agent</th><td>Reason</td><td>Turns</td></tr>')
        for a in incomplete:
            A('<tr><th class="mono">{0}</th><td>{1}</td><td>{2}</td></tr>'.format(
                _e(a.get("label")), _e(a.get("stopped_reason")), _e(a.get("turns"))))
        A('</table></div></details>')

    # ---------------- limitations ----------------
    A('<h2>Scope and limitations</h2><ul class="lim">')
    A('<li><strong>Evidence levels are separate from severity.</strong> '
      'Hypotheses are potential vulnerabilities requiring further investigation. '
      'Substantiated vulnerabilities require an explicit review with matching source evidence. '
      'Authored tests and model-written PASS claims do not prove execution or impact.</li>')
    A('<li><strong>Excluded by design:</strong> test code, build scripts, '
      'vendored and third-party directories, generated code, and documentation.</li>')
    if not meta.get("verify_model") and meta.get("model"):
        A('<li><strong>Falsification ran on the same model as the hunt phase.</strong> '
          'Phase 2b exists to disprove weak candidates; running it on the model '
          'that produced them tends to rubber-stamp rather than refute. Re-run '
          'with a stronger verify model to raise precision.</li>')
    if skipped or (req and not set(req) <= done):
        A('<li><strong>Not every requested phase completed.</strong> Findings may '
          'be partial — see Checks enabled.</li>')
    if meta.get("seeded_from_prior"):
        A('<li><strong>Seeded run (Mode B).</strong> Phase 1 was seeded with the '
          'findings of <span class="mono">{0}</span> as hot spots to re-verify, '
          'so this run is correlated with that prior scan and is <em>not</em> an '
          'independent sample — exclude it from union-recall benchmarking.</li>'
          .format(_e(meta["seeded_from_prior"])))
    A('<li>Severities are the deterministic per-family baseline (adjusted one tier '
      'down when exploitation requires a precondition such as authentication), '
      'chosen for stable cross-run comparison — not CVSS scores. The scanner\'s '
      'own tier is shown beside a finding when it differed.</li>')
    A('</ul>')

    A('<footer>Generated {0} by vhlocal{1} &middot; scan metadata is recorded by '
      'the engine, not authored by the model. Raw artifacts are alongside this '
      'file; <span class="mono">results/</span> is pre-falsification and '
      'intentionally noisy.</footer>'.format(
          _fmt_ts(_dt.datetime.now().timestamp()),
          " " + _e(meta["engine_version"]) if meta.get("engine_version") else ""))

    A('</div>')  # close .wrap
    # Embed the Markdown as base64 so the report stays fully self-contained and
    # the download works even when the .html is opened straight from disk (no
    # server to fetch SCAN_REPORT.md from). base64 is inert HTML, so there is no
    # "</script>"-injection risk regardless of report content.
    if md_source:
        A('<script type="application/x-vh-markdown" id="mdSource">{0}</script>'.format(
            base64.b64encode(md_source.encode("utf-8")).decode("ascii")))
    A('<script>{0}</script></body></html>'.format(JS))
    return "\n".join(H)


def is_stale(results_dir: Path) -> bool:
    """True when SCAN_REPORT.html is missing or was written by an older renderer."""
    out = Path(results_dir) / SCAN_REPORT_HTML
    if not out.exists():
        return True
    try:
        head = out.read_text(encoding="utf-8", errors="replace")[:2048]
    except OSError:
        return True
    return _STAMP not in head


def ensure_fresh(results_dir: Path) -> bool:
    """Re-render if stale. Returns True when it rewrote the file.

    Cheap enough to call on every serve: rendering is string building over
    already-parsed artifacts, and the stamp check short-circuits the common
    case to a 2KB read.
    """
    if not is_stale(results_dir):
        return False
    write_html(results_dir)
    return True


def write_html(results_dir: Path) -> Path:
    results_dir = Path(results_dir)
    out = results_dir / SCAN_REPORT_HTML
    out.write_text(render_html(results_dir), encoding="utf-8")
    return out
