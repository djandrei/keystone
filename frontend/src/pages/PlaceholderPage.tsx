import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function PlaceholderPage({ title, note }: { title: string; note: string }) {
  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-2xl font-bold text-fg">{title}</h1>
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{note}</CardDescription>
        </CardHeader>
        <CardContent />
      </Card>
    </div>
  );
}
