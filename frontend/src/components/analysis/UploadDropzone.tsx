import { useRef, useState } from "react";
import { UploadCloud } from "lucide-react";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/button";

export function UploadDropzone({
  onFile,
  disabled,
}: {
  onFile: (file: File) => void;
  disabled?: boolean;
}) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        if (disabled) return;
        const file = e.dataTransfer.files?.[0];
        if (file) onFile(file);
      }}
      className={cn(
        "flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed p-8 text-center transition-colors",
        dragging ? "border-amber bg-amber/5" : "border-border bg-panel-2",
        disabled && "opacity-50",
      )}
    >
      <UploadCloud className="h-8 w-8 text-stone-light" />
      <div className="text-sm text-fg-muted">
        Drag a binary here, or
        <Button
          variant="ghost"
          size="sm"
          className="ml-1"
          disabled={disabled}
          onClick={() => inputRef.current?.click()}
        >
          browse
        </Button>
      </div>
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        aria-label="Upload binary"
        disabled={disabled}
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFile(file);
          e.target.value = "";
        }}
      />
    </div>
  );
}
