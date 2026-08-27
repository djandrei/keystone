import { cn } from "@/lib/cn";
import { Logo } from "./Logo";

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <Logo className="h-7 w-7" />
      <span className="font-display text-lg font-extrabold tracking-tight text-fg">
        KEY<span className="text-amber">STONE</span>
      </span>
    </span>
  );
}
