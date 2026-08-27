import { useEffect, useState } from "react";

type Status = "checking" | "ok" | "error";

/** Minimal liveness probe against the API's /healthz (wired through nginx). */
export function HealthCheck() {
  const [status, setStatus] = useState<Status>("checking");

  useEffect(() => {
    let active = true;
    fetch("/api/healthz")
      .then((r) => (r.ok ? setStatus("ok") : setStatus("error")))
      .catch(() => active && setStatus("error"));
    return () => {
      active = false;
    };
  }, []);

  return <p data-testid="health">API: {status}</p>;
}
