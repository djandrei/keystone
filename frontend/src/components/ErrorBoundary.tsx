import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/** App-level boundary: a render error anywhere below shows a recoverable fallback
 *  instead of a blank white screen. componentDidCatch logs it; a deployment with
 *  Sentry wired forwards it from there. */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Uncaught UI error:", error, info.componentStack);
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <div
        role="alert"
        className="mx-auto mt-24 flex max-w-md flex-col items-center gap-4 rounded-lg border border-border bg-panel p-8 text-center"
      >
        <h1 className="text-xl font-bold text-fg">Something went wrong</h1>
        <p className="text-sm text-fg-muted">
          The page hit an unexpected error. Reloading usually clears it. If it keeps happening,
          contact an administrator.
        </p>
        {import.meta.env.DEV && (
          <pre className="max-h-48 w-full overflow-auto whitespace-pre-wrap rounded bg-bg p-3 text-left font-mono text-xs text-critical">
            {this.state.error.message}
          </pre>
        )}
        <Button onClick={() => window.location.reload()}>Reload</Button>
      </div>
    );
  }
}
