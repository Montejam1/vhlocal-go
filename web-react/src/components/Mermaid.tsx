import { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";
import { fixMermaid } from "@/lib/mermaid-fix";

let _seq = 0;

/** Render a Mermaid diagram from (possibly model-broken) source. Repairs common
 *  syntax errors first; on a hard parse failure shows the source instead of an
 *  error box. Click to enlarge in a zoom/pan lightbox. */
export function Mermaid({ chart }: { chart: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let alive = true;
    const dark =
      document.documentElement.getAttribute("data-theme") !== "light" &&
      !(
        !document.documentElement.getAttribute("data-theme") &&
        window.matchMedia?.("(prefers-color-scheme: light)").matches
      );
    mermaid.initialize({ startOnLoad: false, securityLevel: "loose", theme: dark ? "dark" : "default" });
    const id = "mmd-" + ++_seq;
    mermaid
      .render(id, fixMermaid(chart))
      .then(({ svg }) => alive && setSvg(svg))
      .catch(() => alive && setFailed(true));
    return () => {
      alive = false;
    };
  }, [chart]);

  if (failed) {
    // Hard parse failure even after repair — show the (repaired) source so the
    // diagram content is never lost behind an error box.
    return <pre className="md">{fixMermaid(chart)}</pre>;
  }
  if (svg === null) {
    return <div className="text-text-3 text-sm p-4">Rendering diagram…</div>;
  }
  return (
    <>
      <div
        ref={ref}
        className="mermaid-box"
        title="Click to enlarge"
        onClick={() => setOpen(true)}
        dangerouslySetInnerHTML={{ __html: svg }}
      />
      {open && <DiagramLightbox svg={svg} onClose={() => setOpen(false)} />}
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
    <div
      className="fixed inset-0 z-50 flex flex-col bg-black/80"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="flex items-center gap-1.5 p-2.5 text-text-2">
        <button className="h-8 w-9 rounded-md border border-line bg-surface-2 hover:border-accent" onClick={() => setZoom((z) => Math.max(0.2, z / 1.2))}>−</button>
        <button className="h-8 w-9 rounded-md border border-line bg-surface-2 hover:border-accent" onClick={() => setZoom((z) => Math.min(6, z * 1.2))}>+</button>
        <button className="h-8 w-9 rounded-md border border-line bg-surface-2 hover:border-accent" onClick={() => setZoom(1)}>⤢</button>
        <span className="flex-1" />
        <button className="h-8 w-9 rounded-md border border-line bg-surface-2 hover:border-accent" onClick={onClose}>✕</button>
      </div>
      <div className="flex-1 overflow-auto p-5">
        <div
          style={{ transform: `scale(${zoom})`, transformOrigin: "top left", display: "inline-block" }}
          dangerouslySetInnerHTML={{ __html: svg }}
        />
      </div>
    </div>
  );
}
