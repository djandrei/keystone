import { expect, test } from "@playwright/test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = { username: "admin", password: "change-me" };

function elf(name: string): string {
  const buf = Buffer.alloc(512);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0);
  buf.writeUInt16LE(0x3e, 18);
  buf.writeBigUInt64LE(BigInt(Date.now()), 40);
  const dir = mkdtempSync(join(tmpdir(), "kst-sec-"));
  const path = join(dir, name);
  writeFileSync(path, buf);
  return path;
}

test("SEC: an injection-flagged sample surfaces the ⚠ banner + history marker", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN.username);
  await page.getByLabel("Password").fill(ADMIN.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: /welcome back/i })).toBeVisible();

  // a sample whose name signals an embedded injection (fake-engine demo hook)
  await page.getByRole("link", { name: /Binaries/ }).click();
  const name = `inject_${Date.now()}.bin`;
  await page.locator('input[aria-label="Upload binary"]').setInputFiles(elf(name));
  const row = page.getByRole("row").filter({ hasText: name });
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: /run re/i }).click();

  // the analysis flags the sample and warns the reviewer (the banner appears as
  // soon as the security signal is persisted mid-run)
  await expect(page.getByRole("alert")).toContainText(/possible prompt injection/i, { timeout: 30_000 });

  // history marks the flagged run
  await page.getByRole("link", { name: /Dashboard/ }).click();
  await expect(page.getByLabel("injection flagged").first()).toBeVisible();
});
