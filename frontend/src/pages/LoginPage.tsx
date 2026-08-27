import { useState } from "react";
import { useNavigate, useLocation, Navigate } from "react-router-dom";
import { z } from "zod";
import { isAxiosError } from "axios";
import { useAuth } from "@/auth/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Wordmark } from "@/components/brand/Wordmark";

const schema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (user) return <Navigate to={from} replace />;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    const parsed = schema.safeParse({ username, password });
    if (!parsed.success) {
      const errs: Record<string, string> = {};
      for (const issue of parsed.error.issues) errs[String(issue.path[0])] = issue.message;
      setFieldErrors(errs);
      return;
    }
    setFieldErrors({});
    setSubmitting(true);
    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (err) {
      setFormError(
        isAxiosError(err) && err.response?.status === 401
          ? "Invalid username or password."
          : "Something went wrong. Please try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <Wordmark className="scale-125" />
          <p className="text-sm text-fg-muted">
            AI-assisted reverse engineering &amp; vulnerability research.
          </p>
        </div>
        <form
          onSubmit={onSubmit}
          noValidate
          aria-label="Sign in"
          className="flex flex-col gap-4 rounded-2xl border border-border bg-panel p-6 shadow-panel"
        >
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              value={username}
              autoComplete="username"
              onChange={(e) => setUsername(e.target.value)}
              aria-invalid={!!fieldErrors.username}
            />
            {fieldErrors.username && (
              <span className="text-xs text-critical">{fieldErrors.username}</span>
            )}
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              value={password}
              autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)}
              aria-invalid={!!fieldErrors.password}
            />
            {fieldErrors.password && (
              <span className="text-xs text-critical">{fieldErrors.password}</span>
            )}
          </div>
          {formError && (
            <p role="alert" className="rounded-lg bg-critical/10 px-3 py-2 text-sm text-critical">
              {formError}
            </p>
          )}
          <Button type="submit" disabled={submitting} className="mt-2 w-full">
            {submitting ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </div>
    </div>
  );
}
