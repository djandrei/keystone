import { Copy, Link2, Download } from "lucide-react";
import { analysesApi } from "@/lib/analysisApi";
import { downloadBlob } from "@/lib/download";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ui/toast";

export function ExportBar({ analysisId, markdown }: { analysisId: number; markdown?: string }) {
  const toast = useToast();

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast({ title: `${what} copied` });
    } catch {
      toast({ title: `Could not copy ${what.toLowerCase()}`, variant: "error" });
    }
  }

  async function download(format: "md" | "json" | "pdf") {
    try {
      const blob = await analysesApi.export(analysisId, format);
      downloadBlob(`analysis-${analysisId}.${format}`, blob);
    } catch {
      toast({ title: "Export failed", variant: "error" });
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      {markdown && (
        <Button variant="ghost" size="sm" onClick={() => copy(markdown, "Report")}>
          <Copy className="h-4 w-4" /> Copy
        </Button>
      )}
      <Button variant="ghost" size="sm" onClick={() => copy(window.location.href, "Link")}>
        <Link2 className="h-4 w-4" /> Permalink
      </Button>
      {(["md", "json", "pdf"] as const).map((fmt) => (
        <Button key={fmt} variant="secondary" size="sm" onClick={() => download(fmt)}>
          <Download className="h-4 w-4" /> {fmt.toUpperCase()}
        </Button>
      ))}
    </div>
  );
}
