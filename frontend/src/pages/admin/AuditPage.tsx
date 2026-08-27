import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { auditApi, type AuditRow } from "@/lib/adminApi";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Modal, ModalContent, ModalHeader, ModalTitle } from "@/components/ui/modal";

export function AuditPage() {
  const [action, setAction] = useState("");
  const [selected, setSelected] = useState<AuditRow | null>(null);
  const { data, isLoading } = useQuery({
    queryKey: ["audit", action],
    queryFn: () => auditApi.list(action ? { action } : undefined),
  });

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-fg">Audit log</h1>
        <p className="mt-1 text-fg-muted">Every privileged action, most recent first.</p>
      </div>

      <div className="flex max-w-xs flex-col gap-1.5">
        <Label htmlFor="audit-action">Filter by action</Label>
        <Input
          id="audit-action"
          value={action}
          placeholder="e.g. user.create"
          onChange={(e) => setAction(e.target.value)}
        />
      </div>

      {isLoading ? (
        <Skeleton className="h-64 w-full" />
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Time</TH>
              <TH>User</TH>
              <TH>Action</TH>
              <TH>Target</TH>
              <TH className="text-right">Detail</TH>
            </TR>
          </THead>
          <TBody>
            {data?.items.map((row) => (
              <TR key={row.id}>
                <TD className="text-fg-muted">{row.created_at?.slice(0, 19).replace("T", " ")}</TD>
                <TD>{row.username ?? "—"}</TD>
                <TD>
                  <Badge variant="amber">{row.action}</Badge>
                </TD>
                <TD className="text-fg-muted">
                  {row.target_type}
                  {row.target_id ? ` #${row.target_id}` : ""}
                </TD>
                <TD>
                  <div className="flex justify-end">
                    <Button size="sm" variant="ghost" disabled={!row.detail} onClick={() => setSelected(row)}>
                      View
                    </Button>
                  </div>
                </TD>
              </TR>
            ))}
            {data?.items.length === 0 && (
              <TR>
                <TD colSpan={5} className="text-center text-fg-muted">
                  No audit entries match.
                </TD>
              </TR>
            )}
          </TBody>
        </Table>
      )}

      <Modal open={!!selected} onOpenChange={(v) => !v && setSelected(null)}>
        {selected && (
          <ModalContent>
            <ModalHeader>
              <ModalTitle>{selected.action}</ModalTitle>
            </ModalHeader>
            <pre className="overflow-x-auto rounded-lg bg-panel-2 p-3 font-mono text-xs text-fg">
              {JSON.stringify(selected.detail, null, 2)}
            </pre>
          </ModalContent>
        )}
      </Modal>
    </div>
  );
}
