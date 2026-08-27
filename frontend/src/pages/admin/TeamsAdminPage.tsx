import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { Trash2 } from "lucide-react";
import { teamsApi, usersApi } from "@/lib/adminApi";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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

export function TeamsAdminPage() {
  const qc = useQueryClient();
  const { data: teams, isLoading } = useQuery({ queryKey: ["teams"], queryFn: teamsApi.list });
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-fg">Teams</h1>
          <p className="mt-1 text-fg-muted">Groups that share analyses.</p>
        </div>
        <Button onClick={() => setCreating(true)}>New team</Button>
      </div>

      {isLoading ? (
        <Skeleton className="h-32 w-full" />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {teams?.map((t) => (
            <Card key={t.id}>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  {t.name}
                  <Badge>#{t.id}</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Button variant="secondary" size="sm" onClick={() => setSelected(t.id)}>
                  Manage members
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <CreateTeamModal open={creating} onOpenChange={setCreating} />
      <ManageMembersModal
        teamId={selected}
        onClose={() => {
          setSelected(null);
          qc.invalidateQueries({ queryKey: ["teams"] });
        }}
      />
    </div>
  );
}

function CreateTeamModal({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => teamsApi.create(name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["teams"] });
      onOpenChange(false);
      setName("");
      toast({ title: "Team created", variant: "success" });
    },
    onError: (err) =>
      setError(
        isAxiosError(err) && err.response?.data?.error === "name_taken"
          ? "A team with that name already exists."
          : "Could not create the team.",
      ),
  });

  return (
    <Modal open={open} onOpenChange={onOpenChange}>
      <ModalContent>
        <ModalHeader>
          <ModalTitle>New team</ModalTitle>
          <ModalDescription>Members will see each other's analyses.</ModalDescription>
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
            <Label htmlFor="ct-name">Team name</Label>
            <Input id="ct-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          {error && <p role="alert" className="text-sm text-critical">{error}</p>}
          <div className="mt-2 flex justify-end gap-2">
            <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={create.isPending}>
              Create team
            </Button>
          </div>
        </form>
      </ModalContent>
    </Modal>
  );
}

function ManageMembersModal({ teamId, onClose }: { teamId: number | null; onClose: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const { data: team } = useQuery({
    queryKey: ["team", teamId],
    queryFn: () => teamsApi.get(teamId!),
    enabled: teamId != null,
  });
  const { data: allUsers } = useQuery({
    queryKey: ["users"],
    queryFn: usersApi.list,
    enabled: teamId != null,
  });
  const [addUserId, setAddUserId] = useState<string>("");

  const invalidate = () => qc.invalidateQueries({ queryKey: ["team", teamId] });

  const addMember = useMutation({
    mutationFn: () => teamsApi.addMember(teamId!, Number(addUserId)),
    onSuccess: () => {
      invalidate();
      setAddUserId("");
      toast({ title: "Member added", variant: "success" });
    },
  });
  const removeMember = useMutation({
    mutationFn: (uid: number) => teamsApi.removeMember(teamId!, uid),
    onSuccess: () => {
      invalidate();
      toast({ title: "Member removed" });
    },
  });

  const memberIds = new Set(team?.members.map((m) => m.user_id));
  const candidates = allUsers?.filter((u) => !memberIds.has(u.id) && u.is_active) ?? [];

  return (
    <Modal open={teamId != null} onOpenChange={(v) => !v && onClose()}>
      <ModalContent>
        <ModalHeader>
          <ModalTitle>{team ? `Members of ${team.name}` : "Members"}</ModalTitle>
          <ModalDescription>Add or remove people from this team.</ModalDescription>
        </ModalHeader>

        <ul className="mb-4 flex flex-col gap-2">
          {team?.members.map((m) => (
            <li
              key={m.user_id}
              className="flex items-center justify-between rounded-lg border border-border bg-panel-2 px-3 py-2"
            >
              <span className="flex items-center gap-2 text-sm text-fg">
                {m.username}
                <Badge variant={m.team_role === "lead" ? "amber" : "default"}>{m.team_role}</Badge>
              </span>
              <Button
                size="icon"
                variant="ghost"
                aria-label={`Remove ${m.username}`}
                onClick={() => removeMember.mutate(m.user_id)}
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </li>
          ))}
          {team?.members.length === 0 && <li className="text-sm text-fg-muted">No members yet.</li>}
        </ul>

        <div className="flex items-end gap-2">
          <div className="flex flex-1 flex-col gap-1.5">
            <Label>Add member</Label>
            <Select value={addUserId} onValueChange={setAddUserId}>
              <SelectTrigger aria-label="Add member">
                <SelectValue placeholder="Select a user…" />
              </SelectTrigger>
              <SelectContent>
                {candidates.map((u) => (
                  <SelectItem key={u.id} value={String(u.id)}>
                    {u.username}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button disabled={!addUserId || addMember.isPending} onClick={() => addMember.mutate()}>
            Add
          </Button>
        </div>
      </ModalContent>
    </Modal>
  );
}
