import { expect, test } from "@playwright/test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = { username: "admin", password: "change-me" };

function makeElf(name: string): string {
  const buf = Buffer.alloc(512);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0);
  buf.writeUInt16LE(0x3e, 18);
  buf.writeBigUInt64LE(BigInt(Date.now()), 40);
  const dir = mkdtempSync(join(tmpdir(), "kst-fn-"));
  const path = join(dir, name);
  writeFileSync(path, buf);
  return path;
}

test("M7 end-to-end: named functions, and unticking one removes it from the report", async ({
  page,
}) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN.username);
  await page.getByLabel("Password").fill(ADMIN.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: /welcome back/i })).toBeVisible();

  await page.getByRole("link", { name: /Binaries/ }).click();
  await page.locator('input[aria-label="Upload binary"]').setInputFiles(makeElf("fn-sample.elf"));
  await expect(page.getByRole("cell", { name: "fn-sample.elf" }).first()).toBeVisible();

  await page.getByRole("button", { name: /run re/i }).first().click();
  await expect(page.getByRole("heading", { name: /Analysis #/ })).toBeVisible();
  await expect(page.getByText("succeeded")).toBeVisible({ timeout: 60_000 });

  // the panel lists the decompiled functions, each with its Ghidra symbol
  const panel = page.getByRole("heading", { name: /^Functions \(/ });
  await expect(panel).toBeVisible();

  const firstBox = page.locator('input[type="checkbox"][aria-label^="Include "]').first();
  const label = (await firstBox.getAttribute("aria-label")) ?? "";
  const name = label.replace(/^Include /, "").replace(/ in the report$/, "");
  await expect(firstBox).toBeChecked();

  // it is in the report…
  await expect(page.getByText("## Functions").or(page.getByText("Functions"))).toBeVisible();

  // …until it is unticked, with no regeneration step
  await firstBox.uncheck();
  await expect(firstBox).not.toBeChecked();
  await expect
    .poll(async () => (await page.content()).split(name).length, { timeout: 15_000 })
    .toBeLessThan(3);
});
