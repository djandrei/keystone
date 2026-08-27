import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "@/components/ui/toast";
import { analysesApi } from "@/lib/analysisApi";
import { ExportBar } from "./ExportBar";

describe("ExportBar", () => {
  afterEach(() => vi.restoreAllMocks());

  function setup(markdown?: string) {
    // jsdom lacks these
    vi.stubGlobal("URL", { ...URL, createObjectURL: vi.fn(() => "blob:x"), revokeObjectURL: vi.fn() });
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    render(
      <ToastProvider>
        <ExportBar analysisId={5} markdown={markdown} />
      </ToastProvider>,
    );
    return { writeText };
  }

  it("downloads each format via the export API", async () => {
    const exp = vi.spyOn(analysesApi, "export").mockResolvedValue(new Blob(["x"]));
    setup();
    await userEvent.click(screen.getByRole("button", { name: "MD" }));
    await userEvent.click(screen.getByRole("button", { name: "JSON" }));
    await userEvent.click(screen.getByRole("button", { name: "PDF" }));
    await waitFor(() => expect(exp).toHaveBeenCalledTimes(3));
    expect(exp.mock.calls.map((c) => c[1])).toEqual(["md", "json", "pdf"]);
  });

  it("copies the markdown report and the permalink", async () => {
    const { writeText } = setup("# report body");
    await userEvent.click(screen.getByRole("button", { name: /copy/i }));
    expect(writeText).toHaveBeenCalledWith("# report body");
    await userEvent.click(screen.getByRole("button", { name: /permalink/i }));
    expect(writeText).toHaveBeenCalledTimes(2);
  });
});
