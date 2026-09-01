/** Shell stub for views not yet ported from the vanilla UI. */
export function Placeholder({ title, note }: { title: string; note?: string }) {
  return (
    <div>
      <h1 className="text-xl font-semibold text-text-1">{title}</h1>
      <div className="mt-8 rounded-[var(--radius,12px)] border border-dashed border-line bg-surface-1 p-10 text-center text-text-3">
        <p className="text-sm">
          {note || `${title} is not ported to the React UI yet.`}
        </p>
        <p className="mt-2 text-xs">
          The vanilla interface remains available at <code>/</code> on the engine.
        </p>
      </div>
    </div>
  );
}
