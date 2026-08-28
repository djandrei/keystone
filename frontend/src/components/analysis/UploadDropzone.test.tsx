import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { UploadDropzone } from "./UploadDropzone";

const file = () => new File([new Uint8Array([0x7f, 0x45])], "b.elf");

describe("UploadDropzone", () => {
  it("calls onFile when a file is dropped", () => {
    const onFile = vi.fn();
    render(<UploadDropzone onFile={onFile} />);
    const zone = screen.getByText(/drag a binary/i).closest("div")!.parentElement!;
    fireEvent.dragOver(zone);
    fireEvent.drop(zone, { dataTransfer: { files: [file()] } });
    expect(onFile).toHaveBeenCalledOnce();
  });

  it("calls onFile when a file is chosen via the input", async () => {
    const onFile = vi.fn();
    render(<UploadDropzone onFile={onFile} />);
    await userEvent.upload(screen.getByLabelText("Upload binary"), file());
    expect(onFile).toHaveBeenCalledOnce();
  });

  it("ignores a drop while disabled", () => {
    const onFile = vi.fn();
    render(<UploadDropzone onFile={onFile} disabled />);
    const zone = screen.getByText(/drag a binary/i).closest("div")!.parentElement!;
    fireEvent.drop(zone, { dataTransfer: { files: [file()] } });
    expect(onFile).not.toHaveBeenCalled();
  });
});
