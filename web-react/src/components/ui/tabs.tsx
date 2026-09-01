import * as React from "react";
import { cn } from "@/lib/utils";

/** Minimal controlled tab strip — no external primitive needed. */
export function Tabs({
  tabs,
  value,
  onChange,
  className,
}: {
  tabs: { key: string; label: React.ReactNode }[];
  value: string;
  onChange: (key: string) => void;
  className?: string;
}) {
  return (
    <div className={cn("flex gap-1 border-b border-line", className)} role="tablist">
      {tabs.map((t) => {
        const on = t.key === value;
        return (
          <button
            key={t.key}
            role="tab"
            aria-selected={on}
            onClick={() => onChange(t.key)}
            className={cn(
              "-mb-px border-b-2 px-3.5 py-2 text-[13px] font-medium transition-colors",
              on
                ? "border-accent text-accent"
                : "border-transparent text-text-3 hover:text-text-1",
            )}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}
