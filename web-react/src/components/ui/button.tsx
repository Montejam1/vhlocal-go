import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 rounded-[var(--radius-sm,8px)] text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 disabled:opacity-45 disabled:pointer-events-none whitespace-nowrap",
  {
    variants: {
      variant: {
        default: "bg-accent text-accent-ink hover:bg-accent-strong",
        secondary:
          "bg-surface-2 text-text-1 border border-line hover:border-accent hover:bg-surface-3",
        ghost: "text-text-2 hover:text-text-1 hover:bg-surface-2",
        danger:
          "bg-err-weak text-err border border-transparent hover:bg-err hover:text-white",
      },
      size: {
        default: "h-9 px-4",
        sm: "h-8 px-3 text-[13px]",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />
  ),
);
Button.displayName = "Button";
