import { useCurrentUser } from "@/auth/AuthContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function DashboardPage() {
  const user = useCurrentUser();
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-fg">Welcome back, {user.username}</h1>
        <p className="mt-1 text-fg-muted">Your team's analyses will appear here.</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>No analyses yet</CardTitle>
          <CardDescription>
            Upload a binary and run an RE or VR analysis to get started. (Coming in M2.)
          </CardDescription>
        </CardHeader>
        <CardContent />
      </Card>
    </div>
  );
}
