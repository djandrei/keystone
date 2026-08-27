import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

const badge = cva(
  "inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset",
  {
    variants: {
      variant: {
        default: "bg-panel-2 text-fg-muted ring-border",
        amber: "bg-amber/15 text-amber-bright ring-amber/30",
        good: "bg-good/15 text-good ring-good/30",
        warn: "bg-warn/15 text-warn ring-warn/30",
        critical: "bg-critical/15 text-critical ring-critical/30",
        info: "bg-info/15 text-info ring-info/30",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badge> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badge({ variant }), className)} {...props} />;
}
