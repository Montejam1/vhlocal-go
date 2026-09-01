import { useEffect, useRef, useState } from "react";

export interface FeedLine {
  text: string;
  kind: string;
}

// Subscribe to a scan's Server-Sent Events (/api/scans/<id>/events) for the live
// feed. Reconnects on the same id; closes when id changes or the scan ends.
export function useEvents(id: string | null, live: boolean): FeedLine[] {
  const [lines, setLines] = useState<FeedLine[]>([]);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    setLines([]);
    esRef.current?.close();
    if (!id || !live) return;

    const es = new EventSource(`/api/scans/${encodeURIComponent(id)}/events`);
    esRef.current = es;
    es.onmessage = (ev) => {
      let obj: Record<string, unknown> = {};
      try {
        obj = JSON.parse(ev.data);
      } catch {
        return;
      }
      const t = String(obj.type || "");
      let text = "";
      if (t === "phase_start") text = `▸ ${obj.title || obj.key}`;
      else if (t === "phase_skip") text = `· skipped ${obj.key} (${obj.reason})`;
      else if (t === "agent_start") text = `  ${obj.label}${obj.total ? ` (${obj.index}/${obj.total})` : ""} → ${obj.model}`;
      else if (t === "agent_done") text = `  ✓ ${obj.label} (${obj.turns} turns)`;
      else if (t === "log") text = String(obj.message || "");
      else if (t === "error") text = `✗ ${obj.message}`;
      else if (t === "budget_halted") text = `‼ ${obj.message}`;
      else if (t) text = t;
      if (text) setLines((prev) => [...prev.slice(-400), { text, kind: t }]);
    };
    es.onerror = () => {}; // browser auto-retries; scan-end closes the stream server-side
    return () => es.close();
  }, [id, live]);

  return lines;
}
