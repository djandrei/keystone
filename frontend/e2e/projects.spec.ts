import { expect, test } from "@playwright/test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = { username: "admin", password: "change-me" };

/** A unique, >256-byte ELF so the sniffer labels it, the analyzability guard
 *  accepts it, and dedup doesn't collide across runs. */
function makeElf(): string {
  const buf = Buffer.alloc(512);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0);
  buf.writeUInt16LE(0x3e, 18); // x86-64
  buf.writeBigUInt64LE(BigInt(Date.now()) ^ BigInt(Math.floor(Math.random() * 1e9)), 24);
  const dir = mkdtempSync(join(tmpdir(), "kst-proj-"));
  const path = join(dir, "fw.bin");
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

test("projects: create, upload into it, group, move, and delete", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Binaries", exact: true }).click();

  // the sharing surface is present
  await expect(page.getByText(/shared with .* of /i).first()).toBeVisible();

  // create a uniquely-named project
  const project = `e2e-proj-${Date.now()}`;
  await page.getByLabel("New project").fill(project);
  await page.getByRole("button", { name: /create/i }).click();
  await expect(page.getByRole("button", { name: new RegExp(`toggle ${project}`, "i") })).toBeVisible();

  // upload a binary into it (pick the project in the upload form)
  await page.getByLabel("Project", { exact: true }).click();
  await page.getByRole("option", { name: project }).click();
  await page.locator('input[aria-label="Upload binary"]').setInputFiles(makeElf());

  // it lands in that project's section, with a human-readable size
  const cell = page.getByRole("cell", { name: "fw.bin" }).first();
  await expect(cell).toBeVisible();
  await expect(page.getByRole("cell", { name: /512 B/ }).first()).toBeVisible();

  // deleting the non-empty project is refused with a helpful message
  await page.getByRole("button", { name: new RegExp(`delete ${project}`, "i") }).click();
  // The refusal arrives as a toast. Radix also mirrors each toast into a hidden
  // aria-live announcer outside the toast region, so scope to the region.
  const toasts = page.getByRole("region", { name: /notifications/i });
  await expect(toasts.getByText(/move them out first/i)).toBeVisible();

  // move the binary out to Unassigned, then the (now empty) project deletes.
  // Every fw.bin row has a "Move fw.bin" combobox; this test's shows its project.
  await page.getByRole("combobox", { name: /move fw.bin/i }).filter({ hasText: project }).click();
  await page.getByRole("option", { name: "Unassigned" }).click();
  await expect(toasts.getByText(/moved to unassigned/i)).toBeVisible();
  await page.getByRole("button", { name: new RegExp(`delete ${project}`, "i") }).click();
  await expect(page.getByRole("button", { name: new RegExp(`toggle ${project}`, "i") })).toBeHidden();
});
