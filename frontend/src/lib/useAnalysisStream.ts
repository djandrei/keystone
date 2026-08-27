import { useEffect, useRef, useState } from "react";
import { getAccess } from "@/auth/tokenStore";
import type { StreamEvent } from "./analysisApi";

type StreamStatus = "idle" | "connecting" | "open" | "closed";

/** Subscribe to WS /api/analyses/:id/stream. Seeds from a snapshot (the analysis's
 *  persisted progress) so a late subscriber still sees earlier steps. */
export function useAnalysisStream(
  analysisId: number | null,
  enabled: boolean,
  seed: StreamEvent[] = [],
): { events: StreamEvent[]; status: StreamStatus } {
  const [events, setEvents] = useState<StreamEvent[]>(seed);
  const [status, setStatus] = useState<StreamStatus>("idle");
  const seededFor = useRef<number | null>(null);

  // reset when the analysis changes
  if (analysisId !== seededFor.current) {
    seededFor.current = analysisId;
  }

  useEffect(() => {
    if (!enabled || analysisId == null) return;
    setEvents(seed.length ? seed : []);
    setStatus("connecting");
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const token = getAccess() ?? "";
    const ws = new WebSocket(
      `${proto}://${window.location.host}/api/analyses/${analysisId}/stream?token=${encodeURIComponent(token)}`,
    );
    ws.onopen = () => setStatus("open");
    ws.onmessage = (e) => {
      try {
        setEvents((prev) => [...prev, JSON.parse(e.data) as StreamEvent]);
      } catch {
        /* ignore malformed frame */
      }
    };
    ws.onclose = () => setStatus("closed");
    ws.onerror = () => setStatus("closed");
    return () => ws.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId, enabled]);

  return { events, status };
}
