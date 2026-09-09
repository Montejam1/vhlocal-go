import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { ConfigResp, ModelInfo } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const inputCls =
  "w-full rounded-[var(--radius-sm,8px)] border border-line bg-surface-2 px-3 py-2 text-[13px] text-text-1 outline-none focus:border-accent";

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="mb-1 text-[12px] font-medium text-text-2">{label}</div>
      {children}
      {hint && <div className="mt-1 text-[11px] text-text-3">{hint}</div>}
    </label>
  );
}

function Toggle({
  checked,
  onChange,
  title,
  sub,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  title: string;
  sub: string;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-3 rounded-[var(--radius-sm,8px)] border border-line bg-surface-2 px-3 py-2.5">
      <input type="checkbox" className="h-4 w-4 accent-[var(--accent)]" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="flex flex-col">
        <b className="text-[12.5px] font-medium text-text-1">{title}</b>
        <span className="text-[11px] text-text-3">{sub}</span>
      </span>
    </label>
  );
}

export function NewScan({ onLaunched }: { onLaunched: (id: string) => void }) {
  const [cfg, setCfg] = useState<ConfigResp | null>(null);
  const [repo, setRepo] = useState("");
  const [appName, setAppName] = useState("");
  const [appHint, setAppHint] = useState("optional");
  const [backend, setBackend] = useState("ollama");
  const [host, setHost] = useState("");
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [modelErr, setModelErr] = useState<string | null>(null);
  const [model, setModel] = useState("");
  const [phases, setPhases] = useState("all");
  const [maxPart, setMaxPart] = useState(8);
  const [samples, setSamples] = useState(1);
  const [quality, setQuality] = useState("balanced");
  const [flags, setFlags] = useState({
    threat_model: false,
    iac_lens: true,
    ledger: false,
    redact: false,
    remediate: false,
  });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.config().then((c) => {
      setCfg(c);
      setHost(c.defaults.ollama_host);
      setModel(c.defaults.model);
    });
  }, []);

  const defaultHost = (b: string, c: ConfigResp) =>
    b === "openai" ? c.defaults.openai_host : b === "openrouter" ? c.defaults.openrouter_host : c.defaults.ollama_host;

  // Load the model list whenever backend/host settles.
  const loadModels = (b = backend, h = host) => {
    setModelErr(null);
    api
      .models(b, h)
      .then((m) => {
        setModels(m);
        if (m.length && !m.some((x) => x.name === model)) setModel(m[0].name);
      })
      .catch((e) => {
        setModels([]);
        setModelErr(String(e.message || e));
      });
  };
  useEffect(() => {
    if (cfg) loadModels();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cfg]);

  const onBackend = (b: string) => {
    setBackend(b);
    if (cfg) {
      const h = defaultHost(b, cfg);
      setHost(h);
      loadModels(b, h);
    }
  };

  const lookupApp = () => {
    const r = repo.trim();
    if (!r) return setAppHint("optional");
    api
      .lookupApp(r)
      .then((d) => {
        if (d.application?.name) {
          if (!appName) setAppName(d.application.name);
          setAppHint("known application");
        } else setAppHint("optional — new folder");
      })
      .catch(() => {});
  };

  const start = async () => {
    setErr(null);
    if (!repo.trim()) return setErr("Repository path is required.");
    if (!model.trim()) return setErr("Pick or enter a model.");
    setBusy(true);
    try {
      const job = await api.createScan({
        repo: repo.trim(),
        app_name: appName.trim(),
        model: model.trim(),
        backend,
        host: host.trim() || null,
        phases: phases.trim() || "all",
        max_partitions: maxPart,
        hunt_samples: samples,
        quality_strictness: quality,
        ...flags,
      });
      onLaunched(job.id);
    } catch (e) {
      setErr(String((e as Error).message || e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-3xl">
      <p className="mb-4 text-[13px] text-text-2">Point the engine at a repository and launch a scan. Scans run one at a time.</p>
      {err && <div className="mb-3 rounded-md border border-err/40 bg-err-weak px-3 py-2 text-sm text-err">{err}</div>}

      <div className="flex flex-col gap-3">
        <Field label="Repository path" hint={cfg ? `Allowed under: ${cfg.allow_roots.join(", ")}` : undefined}>
          <input
            className={inputCls}
            placeholder="/path/to/your/repo"
            value={repo}
            onChange={(e) => setRepo(e.target.value)}
            onBlur={lookupApp}
            spellCheck={false}
          />
        </Field>

        <Field label={`Application (${appHint})`} hint="Optional label tying this scan's ledger, threat model & SBOM to a named app. Blank = folder name.">
          <input className={inputCls} placeholder="optional — defaults to the folder name" value={appName} onChange={(e) => setAppName(e.target.value)} spellCheck={false} />
        </Field>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label="Backend">
            <select className={inputCls} value={backend} onChange={(e) => onBackend(e.target.value)}>
              <option value="ollama">Ollama (local)</option>
              <option value="openai">OpenAI-compatible</option>
              <option value="openrouter">OpenRouter (paid)</option>
            </select>
          </Field>
          <Field label="Host">
            <input className={inputCls} value={host} onChange={(e) => setHost(e.target.value)} onBlur={() => loadModels()} spellCheck={false} />
          </Field>
          <Field label="Model" hint={modelErr ? `couldn't list models — type one` : `${models.length} available`}>
            {models.length > 0 ? (
              <select className={inputCls} value={model} onChange={(e) => setModel(e.target.value)}>
                {!models.some((m) => m.name === model) && <option value={model}>{model}</option>}
                {models.map((m) => (
                  <option key={m.name} value={m.name}>
                    {m.name}
                  </option>
                ))}
              </select>
            ) : (
              <input className={inputCls} value={model} onChange={(e) => setModel(e.target.value)} placeholder="model name" spellCheck={false} />
            )}
          </Field>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label="Phases">
            <input className={inputCls} value={phases} onChange={(e) => setPhases(e.target.value)} spellCheck={false} />
          </Field>
          <Field label="Max partitions">
            <input type="number" min={1} className={inputCls} value={maxPart} onChange={(e) => setMaxPart(+e.target.value || 8)} />
          </Field>
          <Field label="Hunt samples" hint="1–5; unions repeated passes">
            <input type="number" min={1} max={5} className={inputCls} value={samples} onChange={(e) => setSamples(Math.max(1, Math.min(5, +e.target.value || 1)))} />
          </Field>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label="Quality bar" hint="corroboration needed to report a finding vs a hypothesis">
            <select className={inputCls} value={quality} onChange={(e) => setQuality(e.target.value)}>
              <option value="lenient">Lenient — any one signal</option>
              <option value="balanced">Balanced — source match (default)</option>
              <option value="strict">Strict — source + a second signal</option>
            </select>
          </Field>
        </div>

        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <Toggle checked={flags.threat_model} onChange={(v) => setFlags({ ...flags, threat_model: v })} title="Build threat model (PASTA)" sub="characterize the app + SBOM + DFD; focuses the hunt" />
          <Toggle checked={flags.iac_lens} onChange={(v) => setFlags({ ...flags, iac_lens: v })} title="IaC / CI-CD lens" sub="audit Terraform · Docker · K8s · Actions (auto-skips if none)" />
          <Toggle checked={flags.ledger} onChange={(v) => setFlags({ ...flags, ledger: v })} title="Include in Vulnerability Ledger" sub="accumulate findings across runs & score recall" />
          <Toggle checked={flags.remediate} onChange={(v) => setFlags({ ...flags, remediate: v })} title="Write remediation DTOs" sub="per-finding proposed-fix records (report-only)" />
          <Toggle checked={flags.redact} onChange={(v) => setFlags({ ...flags, redact: v })} title="Redact secrets & PII" sub="mask cards / SSNs / credentials in the artifacts" />
        </div>

        <div>
          <Button className={cn("mt-1", busy && "opacity-70")} disabled={busy} onClick={start}>
            {busy ? "Launching…" : "▶  Start scan"}
          </Button>
        </div>
      </div>
    </div>
  );
}
