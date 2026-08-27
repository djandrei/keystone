import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  Badge,
  Button,
  Card,
  CardTitle,
  Input,
  Skeleton,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  ToastProvider,
  useToast,
} from "./index";

describe("Button", () => {
  it("renders variants and fires onClick", async () => {
    const onClick = vi.fn();
    render(<Button variant="primary" onClick={onClick}>Run</Button>);
    const btn = screen.getByRole("button", { name: "Run" });
    await userEvent.click(btn);
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("is disabled and does not fire when disabled", async () => {
    const onClick = vi.fn();
    render(<Button disabled onClick={onClick}>Nope</Button>);
    const btn = screen.getByRole("button", { name: "Nope" });
    expect(btn).toBeDisabled();
    await userEvent.click(btn);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("renders as child element with asChild", () => {
    render(<Button asChild><a href="/x">Link</a></Button>);
    expect(screen.getByRole("link", { name: "Link" })).toHaveAttribute("href", "/x");
  });
});

describe("Input", () => {
  it("accepts typed text", async () => {
    render(<Input aria-label="name" />);
    const input = screen.getByLabelText("name");
    await userEvent.type(input, "keystone");
    expect(input).toHaveValue("keystone");
  });
});

describe("Badge", () => {
  it("renders each semantic variant", () => {
    const { rerender } = render(<Badge variant="critical">crit</Badge>);
    expect(screen.getByText("crit")).toBeInTheDocument();
    rerender(<Badge variant="good">ok</Badge>);
    expect(screen.getByText("ok")).toBeInTheDocument();
  });
});

describe("Card / Table / Skeleton", () => {
  it("renders card title", () => {
    render(<Card><CardTitle>Panel</CardTitle></Card>);
    expect(screen.getByRole("heading", { name: "Panel" })).toBeInTheDocument();
  });

  it("renders a table with rows", () => {
    render(
      <Table>
        <THead><TR><TH>User</TH></TR></THead>
        <TBody><TR><TD>neo</TD></TR></TBody>
      </Table>,
    );
    expect(screen.getByRole("columnheader", { name: "User" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "neo" })).toBeInTheDocument();
  });

  it("renders skeleton placeholder", () => {
    render(<Skeleton className="h-4 w-20" />);
    expect(screen.getByTestId("skeleton")).toBeInTheDocument();
  });
});

describe("Toast", () => {
  function Trigger() {
    const toast = useToast();
    return <Button onClick={() => toast({ title: "Saved", variant: "success" })}>fire</Button>;
  }
  it("shows a toast when triggered", async () => {
    render(<ToastProvider><Trigger /></ToastProvider>);
    await userEvent.click(screen.getByRole("button", { name: "fire" }));
    expect(await screen.findByText("Saved")).toBeInTheDocument();
  });
});
