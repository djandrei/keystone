import { describe, expect, it } from "vitest";
import { formatBytes } from "./formatBytes";

describe("formatBytes", () => {
  it("formats bytes with no decimals", () => {
    expect(formatBytes(820)).toBe("820 B");
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("formats KB/MB/GB with one decimal (1024-based)", () => {
    expect(formatBytes(16120)).toBe("15.7 KB");
    expect(formatBytes(3_566_789)).toBe("3.4 MB");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(5 * 1024 * 1024 * 1024)).toBe("5.0 GB");
  });

  it("falls back to em dash on bad input", () => {
    expect(formatBytes(-1)).toBe("—");
    expect(formatBytes(NaN)).toBe("—");
    expect(formatBytes(Infinity)).toBe("—");
  });
});
