import { expect, test } from "@playwright/test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = { username: "admin", password: "change-me" };

/** A minimal, unique ELF so the sniffer labels it and dedup doesn't collide. */
function makeElf(): string {
  const buf = Buffer.alloc(64);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0); // ELF64 LE
  buf.writeUInt16LE(0x3e, 18); // x86-64
  buf.writeBigUInt64LE(BigInt(Date.now()), 32); // unique tail
  const dir = mkdtempSync(join(tmpdir(), "kst-e2e-"));
  const path = join(dir, "ls");
  writeFileSync(path, buf);
  return path;
}

async function login(page: import("@playwright/test").Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN.username);
  await page.getByLabel("Password").fill(ADMIN.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: /welcome back/i })).toBeVisible();
}

test("M2 end-to-end: upload -> run RE -> watch steps -> report -> history", async ({ page }) => {
  await login(page);

  // upload a binary
  await page.getByRole("link", { name: /Binaries/ }).click();
  await page.locator('input[aria-label="Upload binary"]').setInputFiles(makeElf());
  await expect(page.getByRole("cell", { name: "ls" }).first()).toBeVisible();

  // run RE -> analysis view
  await page.getByRole("button", { name: /run re/i }).first().click();
  await expect(page.getByRole("heading", { name: /Analysis #/ })).toBeVisible();

  // the analysis completes (fake engine) and the report shows Language / runtime = C
  await expect(page.getByText("succeeded")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Language / runtime").first()).toBeVisible();
  await expect(page.getByText("RE Report")).toBeVisible();

  // the run appears in history
  await page.getByRole("link", { name: /Dashboard/ }).click();
  await expect(page.getByRole("cell", { name: /^#\d+$/ }).first()).toBeVisible();
  await expect(page.getByText("succeeded").first()).toBeVisible();
});
