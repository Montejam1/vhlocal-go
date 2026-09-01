import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10.5px] font-semibold whitespace-nowrap",
  {
    variants: {
      variant: {
        default: "border-line bg-surface-2 text-text-2",
        ok: "border-transparent bg-ok-weak text-ok",
        warn: "border-transparent bg-warn-weak text-warn",
        err: "border-transparent bg-err-weak text-err",
        accent: "border-transparent bg-accent-weak text-accent",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

/** Small severity-colored chip: Critical/High → err, Medium → warn, Low → accent. */
export function SeverityStrip({ severities }: { severities?: Record<string, number> }) {
  const order = ["Critical", "High+", "High", "Medium", "Moderate", "Low", "Informational", "Info"];
  const entries = Object.entries(severities || {}).sort(
    (a, b) => (order.indexOf(a[0]) + 99) % 100 - ((order.indexOf(b[0]) + 99) % 100),
  );
  if (!entries.length) return <span className="text-text-3">—</span>;
  const variantFor = (s: string): BadgeProps["variant"] => {
    const l = s.toLowerCase();
    if (l.startsWith("crit") || l === "high+") return "err";
    if (l.startsWith("high")) return "err";
    if (l.startsWith("med") || l.startsWith("mod")) return "warn";
    if (l.startsWith("low")) return "accent";
    return "default";
  };
  return (
    <span className="flex flex-wrap gap-1.5">
      {entries.map(([sev, n]) => (
        <Badge key={sev} variant={variantFor(sev)}>
          {n} {sev}
        </Badge>
      ))}
    </span>
  );
}
