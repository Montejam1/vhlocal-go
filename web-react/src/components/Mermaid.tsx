import { useCallback, useEffect, useRef, useState } from "react";
import mermaid from "mermaid";
import { fixMermaid } from "@/lib/mermaid-fix";

let _seq = 0;

// Feature 015 (FR-011..013): a diagram is rendered ON ITS OWN, parse-first, with
// explicit states. Failure keeps the surrounding narrative, shows a node/flow
// table, the exact error (line + message), Retry and View-source; state is reset
// whenever the chart changes and on theme change; labels render in strict mode;
// SVG export is a click. One diagram's failure never affects a sibling.
type State =
  | { kind: "rendering" }
  | { kind: "valid"; svg: string; repaired: boolean }
  | { kind: "error"; line?: number; message: string };

function themeName(): "dark" | "default" {
  const explicit = document.documentElement.getAttribute("data-theme");
  const dark = explicit ? explicit !== "light" : !window.matchMedia?.("(prefers-color-scheme: light)").matches;
  return dark ? "dark" : "default";
}

/** Structure for the fallback table (mirrors the Go subset parser: nodes, edges, subgraphs). */
export function diagramStructure(src: string) {
  const nodes = new Map<string, string>();
  const edges: [string, string][] = [];
  const boundaries: { id: string; label: string; nodes: Set<string> }[] = [];
  const stack: { id: string; label: string; nodes: Set<string> }[] = [];
  const declare = (id: string, label: string) => {
    if (!nodes.has(id)) nodes.set(id, label || id);
    else if (label && nodes.get(id) === id) nodes.set(id, label);
    if (stack.length) stack[stack.length - 1].nodes.add(id);
  };
  const nodeRe = /^([A-Za-z_][A-Za-z0-9_-]*)(?:\[\(|\(\(|\[|\(|\{|>)?(?:"([^"]*)"|([^\]\)\}|]*))?/;
  src.split("\n").slice(1).forEach((raw) => {
    const line = raw.replace(/%%.*$/, "").trim();
    if (!line) return;
    if (line === "end") { if (stack.length) boundaries.push(stack.pop()!); return; }
    const sg = line.match(/^subgraph\s+([A-Za-z_][\w-]*)(?:\["([^"]*)"\])?/);
    if (sg) { stack.push({ id: sg[1], label: sg[2] || sg[1], nodes: new Set() }); return; }
    if (/^(style|classDef|class|click|linkStyle)\b/.test(line)) return;
    const parts = line.split(/\s*(-->|-\.->|==>|---|-\.-|===)\s*(?:\|[^|]*\|)?\s*/);
    let prev: string | null = null;
    parts.forEach((p) => {
      const nm = p.trim().match(nodeRe);
      if (!nm) return;
      declare(nm[1], (nm[2] || nm[3] || "").trim());
      if (prev) edges.push([prev, nm[1]]);
      prev = nm[1];
    });
  });
  while (stack.length) boundaries.push(stack.pop()!);
  return { nodes, edges, boundaries };
}

function DiagramTable({ src }: { src: string }) {
  const s = diagramStructure(src);
  return (
    <div className="mt-2 text-[12px]" data-testid="diagram-table">
      <b>Diagram as a table</b> <span className="text-text-3">(the structure that could be read from the source)</span>
      {s.boundaries.length > 0 && (
        <table className="mt-1 w-full border border-line"><thead><tr className="bg-surface-2"><th className="px-2 text-left">Trust boundary</th><th className="px-2 text-left">Label</th><th className="px-2 text-left">Nodes</th></tr></thead>
          <tbody>{s.boundaries.map((b) => <tr key={b.id} className="border-t border-line"><td className="px-2 font-mono">{b.id}</td><td className="px-2">{b.label}</td><td className="px-2 font-mono">{[...b.nodes].join(", ")}</td></tr>)}</tbody></table>
      )}
      <table className="mt-1 w-full border border-line"><thead><tr className="bg-surface-2"><th className="px-2 text-left">Node</th><th className="px-2 text-left">Label</th></tr></thead>
        <tbody>{[...s.nodes].map(([id, l]) => <tr key={id} className="border-t border-line"><td className="px-2 font-mono">{id}</td><td className="px-2">{l}</td></tr>)}</tbody></table>
      <table className="mt-1 w-full border border-line"><thead><tr className="bg-surface-2"><th className="px-2 text-left">From</th><th></th><th className="px-2 text-left">To</th></tr></thead>
        <tbody>{s.edges.map(([a, b], i) => <tr key={i} className="border-t border-line"><td className="px-2 font-mono">{a}</td><td>→</td><td className="px-2 font-mono">{b}</td></tr>)}</tbody></table>
    </div>
  );
}

/** Render a Mermaid diagram from (possibly model-broken) source. */
export function Mermaid({ chart }: { chart: string }) {
  const src = fixMermaid(chart);
  const repaired = src !== chart.trim();
  const [state, setState] = useState<State>({ kind: "rendering" });
  const [open, setOpen] = useState(false);
  const [showSrc, setShowSrc] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [theme, setTheme] = useState(themeName());
  const box = useRef<HTMLDivElement>(null);

  // Theme changes re-render (state is per diagram, reset here and on chart change).
  useEffect(() => {
    const obs = new MutationObserver(() => setTheme(themeName()));
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const mq = window.matchMedia?.("(prefers-color-scheme: light)");
    const onMq = () => setTheme(themeName());
    mq?.addEventListener?.("change", onMq);
    return () => { obs.disconnect(); mq?.removeEventListener?.("change", onMq); };
  }, []);

  useEffect(() => {
    let alive = true;
    setState({ kind: "rendering" }); // reset: a previous failure never sticks to a new chart
    mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme });
    const id = "mmd-" + ++_seq;
    (async () => {
      try {
        const ok = await mermaid.parse(src, { suppressErrors: true });
        if (ok === false) throw new Error("syntax error in diagram source");
        const { svg } = await mermaid.render(id, src);
        if (alive) setState({ kind: "valid", svg, repaired });
      } catch (e) {
        if (!alive) return;
        const err = e as { hash?: { line?: number }; str?: string; message?: string };
        setState({ kind: "error", line: err?.hash?.line, message: String(err?.str || err?.message || e).split("\n")[0] });
      }
    })();
    return () => { alive = false; };
  }, [src, repaired, attempt, theme]);

  const exportSvg = useCallback(() => {
    if (state.kind !== "valid") return;
    const blob = new Blob([state.svg], { type: "image/svg+xml" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "diagram.svg";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }, [state]);

  if (state.kind === "rendering") return <div className="p-4 text-sm text-text-3">Rendering diagram…</div>;
  if (state.kind === "error") {
    return (
      <div className="my-2 rounded-md border border-err/40 bg-err-weak p-3 text-sm" data-testid="diagram-error">
        <div className="text-err">
          <b>Diagram did not render</b>{state.line ? ` — line ${state.line}` : ""}: <code>{state.message}</code>
        </div>
        <div className="mt-2 flex gap-2">
          <button className="rounded border border-line px-2 py-0.5 text-[12px]" onClick={() => setAttempt((n) => n + 1)}>Retry</button>
          <button className="rounded border border-line px-2 py-0.5 text-[12px]" onClick={() => setShowSrc((s) => !s)}>View source</button>
        </div>
        {showSrc && <pre className="md mt-2 whitespace-pre-wrap text-[11px]">{src}</pre>}
        <DiagramTable src={src} />
      </div>
    );
  }
  return (
    <>
      <div ref={box} className="mermaid-box" title="Click to enlarge" onClick={() => setOpen(true)} dangerouslySetInnerHTML={{ __html: state.svg }} />
      <div className="mt-1 flex items-center gap-2 text-[11px] text-text-3">
        {state.repaired && <span>repaired (bounded formatting rules)</span>}
        <button className="rounded border border-line px-2 py-0.5" onClick={exportSvg}>Export SVG</button>
        <button className="rounded border border-line px-2 py-0.5" onClick={() => setShowSrc((s) => !s)}>View source</button>
      </div>
      {showSrc && <pre className="md mt-2 whitespace-pre-wrap text-[11px]">{src}</pre>}
      {open && <DiagramLightbox svg={state.svg} onClose={() => setOpen(false)} />}
    </>
  );
}

function DiagramLightbox({ svg, onClose }: { svg: string; onClose: () => void }) {
  const [zoom, setZoom] = useState(1);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-black/80" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="flex items-center gap-1.5 p-2.5 text-text-2">
        <button className="h-8 w-9 rounded-md border border-line bg-surface-2 hover:border-accent" onClick={() => setZoom((z) => Math.max(0.2, z / 1.2))}>−</button>
        <button className="h-8 w-9 rounded-md border border-line bg-surface-2 hover:border-accent" onClick={() => setZoom((z) => Math.min(6, z * 1.2))}>+</button>
        <button className="h-8 w-9 rounded-md border border-line bg-surface-2 hover:border-accent" onClick={() => setZoom(1)}>⤢</button>
        <span className="flex-1" />
        <button className="h-8 w-9 rounded-md border border-line bg-surface-2 hover:border-accent" onClick={onClose}>✕</button>
      </div>
      <div className="flex-1 overflow-auto p-5">
        <div style={{ transform: `scale(${zoom})`, transformOrigin: "top left", display: "inline-block" }} dangerouslySetInnerHTML={{ __html: svg }} />
      </div>
    </div>
  );
}
