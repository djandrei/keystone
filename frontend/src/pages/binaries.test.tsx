import { afterAll, afterEach, beforeAll, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ToastProvider } from "@/components/ui/toast";
import { setAccess } from "@/auth/tokenStore";
import { server } from "@/tests/msw/server";
import { api } from "@/lib/api";
import { binariesApi } from "@/lib/analysisApi";
import { BinariesPage } from "./BinariesPage";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const BINARY = {
  id: 1, team_id: 1, sha256: "a".repeat(64), filename: "ls", size: 16120,
  format: "ELF", arch: "x86-64", platform: "linux", ghidra_program_name: "ls",
  uploaded_by: 1, created_at: null,
};

it("uploads a binary as multipart FormData (team_id + file)", async () => {
  // axios+FormData+MSW hangs in jsdom, so assert the request the client builds.
  const post = vi.spyOn(api, "post").mockResolvedValue({ data: BINARY });
  const file = new File([new Uint8Array([0x7f, 0x45, 0x4c, 0x46])], "ls");
  const result = await binariesApi.upload(1, file);
  expect(result.filename).toBe("ls");
  expect(post).toHaveBeenCalledWith("/binaries", expect.any(FormData));
  const form = post.mock.calls[0][1] as FormData;
  expect(form.get("team_id")).toBe("1");
  expect(form.get("file")).toBeInstanceOf(File);
  post.mockRestore();
});

it("lists binaries and starts an RE analysis from Run RE", async () => {
  setAccess("access-1");
  let started: { binaryId: number } | null = null;
  server.use(
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/binaries", () => HttpResponse.json([BINARY])),
    http.post("/api/binaries/1/analyses", () => {
      started = { binaryId: 1 };
      return HttpResponse.json({
        id: 77, team_id: 1, binary_id: 1, mode: "re", status: "queued", model: "m",
        params: null, created_by: 1, created_at: null, started_at: null, finished_at: null,
        error: null, progress: null,
      }, { status: 201 });
    }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <ToastProvider>
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/binaries"]}>
          <Routes>
            <Route path="/binaries" element={<BinariesPage />} />
            <Route path="/analyses/:id" element={<div>analysis view 77</div>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </ToastProvider>,
  );
  // the seeded binary is listed, with its human-readable size
  expect(await screen.findByRole("cell", { name: "ls" })).toBeInTheDocument();
  expect(screen.getByRole("cell", { name: "15.7 KB" })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /run re/i }));
  // starts the analysis and navigates to its view
  await waitFor(() => expect(started).toEqual({ binaryId: 1 }));
  expect(await screen.findByText("analysis view 77")).toBeInTheDocument();
});
