import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import type { ActivityEvent } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/tabs";
import { cn, fmtDateTime } from "@/lib/utils";

// type → { label, badge variant }
const TYPE_META: Record<string, { variant: "default" | "ok" | "warn" | "err" | "accent" }> = {
  "scan.started": { variant: "accent" },
  "scan.completed": { variant: "ok" },
  "scan.cancelled": { variant: "warn" },
  "scan.failed": { variant: "err" },
  "scan.interrupted": { variant: "err" },
  "threat_model.built": { variant: "accent" },
  "app.named": { variant: "default" },
  "app.renamed": { variant: "default" },
  "app.forgotten": { variant: "warn" },
  "report.deleted": { variant: "warn" },
};

export function Activity() {
  const [tab, setTab] = useState<"feed" | "log">("feed");
  const [logScan, setLogScan] = useState("");

  return (
    <div>
      <h1 className="text-xl font-semibold text-text-1">Activity</h1>
      <p className="mt-1 mb-4 text-[13px] text-text-2">
        A centralized record of what the engine did — a structured audit feed and the raw central log.
      </p>
      <Tabs
        value={tab}
        onChange={(t) => setTab(t as typeof tab)}
        tabs={[
          { key: "feed", label: "Activity feed" },
          { key: "log", label: "Log" },
        ]}
      />
      <div className="mt-4">
        {tab === "feed" ? (
          <Feed
            onOpenLog={(scan) => {
              setLogScan(scan);
              setTab("log");
            }}
          />
        ) : (
          <LogView scan={logScan} setScan={setLogScan} />
        )}
      </div>
    </div>
  );
}

function Feed({ onOpenLog }: { onOpenLog: (scan: string) => void }) {
  const [type, setType] = useState("");
  const { data, refresh } = usePoll<ActivityEvent[]>(() => api.activity({ limit: 300, type }), 5000);

  // refetch when the filter changes
  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type]);

  const events = data || [];
  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        <select
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="rounded-[var(--radius-sm,8px)] border border-line bg-surface-2 px-2.5 py-1.5 text-[12.5px] text-text-1 outline-none focus:border-accent"
        >
          <option value="">All events</option>
          <option value="scan">Scans</option>
          <option value="app">Applications</option>
          <option value="report">Reports</option>
          <option value="threat_model">Threat models</option>
        </select>
        <span className="flex-1" />
        <Button variant="secondary" size="sm" onClick={refresh}>
          Refresh
        </Button>
      </div>

      {!data && <div className="py-8 text-center text-text-3">Loading…</div>}
      {data && events.length === 0 && (
        <div className="py-8 text-center text-text-3">No activity yet. Run a scan and it appears here.</div>
      )}

      <div className="flex flex-col gap-1.5">
        {events.map((e, i) => (
          <div key={i} className="flex items-center gap-3 rounded-lg border border-line bg-surface-1 px-3 py-2">
            <span className="w-36 shrink-0 font-mono text-[11px] text-text-3">{fmtDateTime(e.ts)}</span>
            <Badge variant={TYPE_META[e.type]?.variant || "default"}>{e.type}</Badge>
            <span className="min-w-0 flex-1 truncate text-[13px] text-text-1" title={e.message}>
              {e.message}
            </span>
            {e.scan && (
              <button
                className="shrink-0 text-[11px] text-accent hover:underline"
                title="View this scan's log slice"
                onClick={() => onOpenLog(e.scan!)}
              >
                log ↗
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function LogView({ scan, setScan }: { scan: string; setScan: (s: string) => void }) {
  const [level, setLevel] = useState("");
  const [tail, setTail] = useState(500);
  const [text, setText] = useState<string | null>(null);
  const preRef = useRef<HTMLPreElement>(null);

  const load = () =>
    api
      .log({ tail, scan: scan || undefined, level: level || undefined })
      .then((t) => setText(t))
      .catch((e) => setText(`error: ${e.message || e}`));

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan, level, tail]);

  useEffect(() => {
    if (preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight;
  }, [text]);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2 text-[12.5px]">
        {scan ? (
          <span className="flex items-center gap-1.5 rounded-full bg-accent-weak px-2.5 py-1 text-accent">
            scan {scan}
            <button className="font-bold" title="clear scan filter" onClick={() => setScan("")}>
              ✕
            </button>
          </span>
        ) : (
          <span className="text-text-3">all scans</span>
        )}
        <select
          value={level}
          onChange={(e) => setLevel(e.target.value)}
          className="rounded-[var(--radius-sm,8px)] border border-line bg-surface-2 px-2.5 py-1.5 text-text-1 outline-none focus:border-accent"
        >
          <option value="">All levels</option>
          <option value="INFO">INFO+</option>
          <option value="WARNING">WARNING+</option>
          <option value="ERROR">ERROR+</option>
        </select>
        <select
          value={tail}
          onChange={(e) => setTail(+e.target.value)}
          className="rounded-[var(--radius-sm,8px)] border border-line bg-surface-2 px-2.5 py-1.5 text-text-1 outline-none focus:border-accent"
        >
          {[200, 500, 1000, 5000].map((n) => (
            <option key={n} value={n}>
              last {n}
            </option>
          ))}
        </select>
        <span className="flex-1" />
        <Button variant="secondary" size="sm" onClick={load}>
          Refresh
        </Button>
      </div>
      <pre
        ref={preRef}
        className="h-[70vh] overflow-auto rounded-[var(--radius-sm,8px)] border border-line bg-surface-1 p-3 font-mono text-[11.5px] leading-relaxed text-text-2"
      >
        {text === null ? "Loading…" : text || "(no matching log lines)"}
      </pre>
    </div>
  );
}
