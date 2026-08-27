import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { usersApi, type AdminUser } from "@/lib/adminApi";
import type { Role } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Modal,
  ModalContent,
  ModalDescription,
  ModalHeader,
  ModalTitle,
} from "@/components/ui/modal";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/components/ui/toast";

const ROLES: Role[] = ["admin", "analyst", "viewer"];

function roleBadge(role: Role) {
  const variant = role === "admin" ? "amber" : role === "analyst" ? "info" : "default";
  return <Badge variant={variant}>{role}</Badge>;
}

export function UsersAdminPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const { data: users, isLoading } = useQuery({ queryKey: ["users"], queryFn: usersApi.list });
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<AdminUser | null>(null);

  const deactivate = useMutation({
    mutationFn: (id: number) => usersApi.deactivate(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      toast({ title: "User deactivated" });
    },
  });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-fg">Users</h1>
          <p className="mt-1 text-fg-muted">Manage accounts, roles and access.</p>
        </div>
        <Button onClick={() => setCreating(true)}>New user</Button>
      </div>

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Username</TH>
              <TH>Email</TH>
              <TH>Role</TH>
              <TH>Status</TH>
              <TH className="text-right">Actions</TH>
            </TR>
          </THead>
          <TBody>
            {users?.map((u) => (
              <TR key={u.id}>
                <TD className="font-medium">{u.username}</TD>
                <TD className="text-fg-muted">{u.email}</TD>
                <TD>{roleBadge(u.role)}</TD>
                <TD>
                  {u.is_active ? (
                    <Badge variant="good">active</Badge>
                  ) : (
                    <Badge variant="critical">inactive</Badge>
                  )}
                </TD>
                <TD>
                  <div className="flex justify-end gap-2">
                    <Button size="sm" variant="secondary" onClick={() => setEditing(u)}>
                      Edit
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={!u.is_active}
                      onClick={() => deactivate.mutate(u.id)}
                    >
                      Deactivate
                    </Button>
                  </div>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      <CreateUserModal open={creating} onOpenChange={setCreating} />
      <EditUserModal user={editing} onClose={() => setEditing(null)} />
    </div>
  );
}

function CreateUserModal({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const toast = useToast();
  const qc = useQueryClient();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => usersApi.create({ username, email, role }),
    onSuccess: (u) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      onOpenChange(false);
      setUsername("");
      setEmail("");
      setRole("analyst");
      toast({
        title: `User ${u.username} created`,
        description: u.temp_password ? `Temporary password: ${u.temp_password}` : undefined,
        variant: "success",
      });
    },
    onError: (err) => {
      const code = isAxiosError(err) ? err.response?.data?.error : null;
      setError(
        code === "username_taken"
          ? "That username is taken."
          : code === "email_taken"
            ? "That email is already in use."
            : "Could not create the user.",
      );
    },
  });

  return (
    <Modal open={open} onOpenChange={onOpenChange}>
      <ModalContent>
        <ModalHeader>
          <ModalTitle>New user</ModalTitle>
          <ModalDescription>They'll receive a one-time temporary password.</ModalDescription>
        </ModalHeader>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            create.mutate();
          }}
        >
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="cu-username">Username</Label>
            <Input id="cu-username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="cu-email">Email</Label>
            <Input id="cu-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>Role</Label>
            <Select value={role} onValueChange={(v) => setRole(v as Role)}>
              <SelectTrigger aria-label="Role">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ROLES.map((r) => (
                  <SelectItem key={r} value={r}>
                    {r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {error && <p role="alert" className="text-sm text-critical">{error}</p>}
          <div className="mt-2 flex justify-end gap-2">
            <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "Creating…" : "Create user"}
            </Button>
          </div>
        </form>
      </ModalContent>
    </Modal>
  );
}

function EditUserModal({ user, onClose }: { user: AdminUser | null; onClose: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const [role, setRole] = useState<Role>("analyst");
  const [active, setActive] = useState(true);
  const [password, setPassword] = useState("");

  const update = useMutation({
    mutationFn: () =>
      usersApi.update(user!.id, {
        role,
        is_active: active,
        password: password || undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      onClose();
      setPassword("");
      toast({ title: "User updated", variant: "success" });
    },
  });

  return (
    <Modal
      open={!!user}
      onOpenChange={(v) => {
        if (!v) onClose();
      }}
    >
      {user && (
        <ModalContent
          onOpenAutoFocus={() => {
            setRole(user.role);
            setActive(user.is_active);
            setPassword("");
          }}
        >
          <ModalHeader>
            <ModalTitle>Edit {user.username}</ModalTitle>
            <ModalDescription>Change role, status, or reset the password.</ModalDescription>
          </ModalHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              update.mutate();
            }}
          >
            <div className="flex flex-col gap-1.5">
              <Label>Role</Label>
              <Select value={role} onValueChange={(v) => setRole(v as Role)}>
                <SelectTrigger aria-label="Role">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {r}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <label className="flex items-center gap-2 text-sm text-fg">
              <input
                type="checkbox"
                checked={active}
                onChange={(e) => setActive(e.target.checked)}
                className="h-4 w-4 accent-amber"
              />
              Active
            </label>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="eu-password">Reset password (optional)</Label>
              <Input
                id="eu-password"
                type="password"
                value={password}
                placeholder="Leave blank to keep current"
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <div className="mt-2 flex justify-end gap-2">
              <Button type="button" variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={update.isPending}>
                Save
              </Button>
            </div>
          </form>
        </ModalContent>
      )}
    </Modal>
  );
}
