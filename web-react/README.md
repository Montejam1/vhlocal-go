# vhlocal — React / TypeScript UI

A React + TypeScript front-end for the vhlocal engine, mirroring the vanilla
single-file UI with a modern component-based look. It is a **client only** — it
talks to the existing Python engine's JSON API (`/api/*`); the backend is
unchanged.

- **Stack:** Vite + React 19 + TypeScript, Tailwind CSS v4, shadcn-style
  components (hand-written, owned in `src/components/ui/`), Mermaid for the
  data-flow diagrams, react-markdown for report/threat-model bodies.
- **Served at `/app`** by the Python engine (`vite build` → `../vhlocal/web/app/`).
  The vanilla UI remains at `/`.

## Develop

```bash
cd web-react
npm install
npm run dev        # Vite dev server on :5173, proxies /api + /static → :8420
```

Run the Python engine (`python3 -m vhlocal.server`) alongside, on :8420.

## Build (what the engine serves)

```bash
npm run build      # → ../vhlocal/web/app/ ; open http://127.0.0.1:8420/app
npm run typecheck  # tsc --noEmit
```

The build output (`vhlocal/web/app/`) is git-ignored — regenerate it with
`npm run build`. `node_modules/` is git-ignored too.

## Status

Vertical slices ported so far:

- [x] App shell — layout, nav rail, theme (dark/light), routing, typed API client
- [x] **Applications** — list + detail with History / Threat model / SBOM tabs,
      SBOM table, threat-model markdown + rendered DFD (click-to-zoom)
- [x] **Dashboard** — metric tiles (colored), findings-per-scan chart, by-model
      bars, latest-scan step tracker
- [x] **Scans** — job list + detail: stat tiles, pulsing step tracker, and a live
      feed over SSE (`/api/scans/<id>/events`)
- [x] **Reports** — table with checkbox multi-select + bulk delete; in-place
      detail (health, downloads, report body, threat model + DFD, SBOM,
      artifacts); deep-linked from Apps via `?open=<id>`
- [x] **Ledger** — per-application cards + findings table (status / seen /
      confidence, cross-family marker)
- [x] **Docs** — the pipeline, step by step, + "beyond the steps"
- [ ] Settings, New Scan form
