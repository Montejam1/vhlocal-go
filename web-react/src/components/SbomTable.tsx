import { api, sbomRows } from "@/lib/api";
import type { Cdx } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

/** Render a CycloneDX SBOM as a component table + ecosystem summary + download. */
export function SbomTable({ cdx, id }: { cdx: Cdx; id: string }) {
  const { rows, byEco } = sbomRows(cdx);
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-3 text-[13px] text-text-2">
        <span>
          <b>{rows.length}</b> direct dependencies ·{" "}
          {Object.entries(byEco)
            .map(([k, v]) => `${v} ${k}`)
            .join(", ")}
        </span>
        <a className="ml-auto" href={api.reportFileUrl(id, "sbom.cdx.json")} download="sbom.cdx.json">
          <Button variant="secondary" size="sm">
            CycloneDX ↓
          </Button>
        </a>
      </div>
      <div className="overflow-x-auto rounded-[var(--radius-sm,8px)] border border-line">
        <table className="w-full text-[12.5px]">
          <thead>
            <tr className="bg-surface-2 text-text-2">
              {["Component", "Version", "Ecosystem", "License"].map((h) => (
                <th key={h} className="px-3 py-2 text-left font-semibold">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((c, i) => (
              <tr key={i} className="border-t border-line">
                <td className="px-3 py-2 font-mono">{c.group ? `${c.group}/${c.name}` : c.name}</td>
                <td className="px-3 py-2 font-mono text-text-2">{c.version || "—"}</td>
                <td className="px-3 py-2">
                  <Badge>{c.ecosystem}</Badge>
                </td>
                <td className="px-3 py-2 text-text-2">{c.license || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
