import { expect, test } from "@playwright/test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = { username: "admin", password: "change-me" };

function makeElf(): string {
  const buf = Buffer.alloc(512);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0);
  buf.writeUInt16LE(0x3e, 18);
  buf.writeBigUInt64LE(BigInt(Date.now()), 40);
  const dir = mkdtempSync(join(tmpdir(), "kst-m3-"));
  const path = join(dir, "ksthunk.sys");
  writeFileSync(path, buf);
  return path;
}

test("M3 end-to-end: VR run with the interactive rule pick -> findings", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN.username);
  await page.getByLabel("Password").fill(ADMIN.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: /welcome back/i })).toBeVisible();

  await page.getByRole("link", { name: /Binaries/ }).click();
  await page.locator('input[aria-label="Upload binary"]').setInputFiles(makeElf());
  await expect(page.getByRole("cell", { name: "ksthunk.sys" }).first()).toBeVisible();

  // start VR -> analysis view, which pauses on the rule picker
  await page.getByRole("button", { name: /run vr/i }).first().click();
  await expect(page.getByRole("heading", { name: /Analysis #/ })).toBeVisible();
  await expect(page.getByText(/choose a rule class/i)).toBeVisible({ timeout: 20_000 });

  // pick the kernel integer wraparound class
  await page.getByRole("button", { name: /kernel-integer-wraparound/ }).click();

  // the run completes and the vulnerability findings render
  await expect(page.getByText("succeeded")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/vulnerability findings/i)).toBeVisible();
  await expect(page.getByText("CWE-190")).toBeVisible();
  await expect(page.getByText(/reachable: yes/i)).toBeVisible();
});
