import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";
import { useAnalysisStream } from "./useAnalysisStream";
import { setAccess } from "@/auth/tokenStore";
import { MockWebSocket } from "@/tests/mockWebSocket";

describe("useAnalysisStream", () => {
  beforeEach(() => {
    MockWebSocket.reset();
    vi.stubGlobal("WebSocket", MockWebSocket);
    setAccess("access-1");
  });
  afterEach(() => vi.unstubAllGlobals());

  it("connects with the token and accumulates streamed events", async () => {
    const { result } = renderHook(() => useAnalysisStream(7, true));
    await waitFor(() => expect(result.current.status).toBe("open"));
    expect(MockWebSocket.last().url).toContain("/api/analyses/7/stream?token=access-1");

    act(() => {
      MockWebSocket.last().emit({ type: "step_start", step: "overview" });
      MockWebSocket.last().emit({ type: "done" });
    });
    await waitFor(() => expect(result.current.events).toHaveLength(2));
    expect(result.current.events[1].type).toBe("done");
  });

  it("does not connect when disabled", () => {
    renderHook(() => useAnalysisStream(7, false));
    expect(MockWebSocket.instances).toHaveLength(0);
  });
});
