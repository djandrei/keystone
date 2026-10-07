import { expect, test, type Page } from "@playwright/test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = { username: "admin", password: "change-me" };

const RULES = `rules:
  - id: e2e-dangerous-copy
    languages: [c]
    severity: ERROR
    message: Unbounded copy into a fixed buffer.
    patterns:
      - pattern-either:
          - pattern: memcpy(...)
`;

function makeElf(name: string): string {
  const buf = Buffer.alloc(512);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0);
  buf.writeUInt16LE(0x3e, 18);
  buf.writeBigUInt64LE(BigInt(Date.now()), 40);
  const dir = mkdtempSync(join(tmpdir(), "kst-rs-"));
  const path = join(dir, name);
  writeFileSync(path, buf);
  return path;
}

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN.username);
  await page.getByLabel("Password").fill(ADMIN.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: /welcome back/i })).toBeVisible();
}

test("M6 end-to-end: author a rule set, run VR with it, see the pinned version", async ({ page }) => {
  const name = `e2e rules ${Date.now()}`;
  await login(page);

  // --- the library: the built-in is there, and a team rule set can be authored
  await page.getByRole("link", { name: /Rule sets/ }).click();
  await expect(page.getByText(/Decompiled C/).first()).toBeVisible();

  await page.getByRole("button", { name: /new rule set/i }).click();
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Rules (YAML)").fill(RULES);

  // validation runs before it is stored
  await page.getByRole("button", { name: /^validate$/i }).click();
  await expect(page.getByText(/e2e-dangerous-copy/)).toBeVisible();

  await page.getByRole("button", { name: /^create$/i }).click();
  await expect(page.getByRole("cell", { name: new RegExp(name) })).toBeVisible();

  // --- run VR against it
  await page.getByRole("link", { name: "Binaries", exact: true }).click();
  await page.locator('input[aria-label="Upload binary"]').setInputFiles(makeElf("rs-sample.elf"));
  await expect(page.getByRole("cell", { name: "rs-sample.elf" }).first()).toBeVisible();

  await page.getByRole("button", { name: /run vr/i }).first().click();
  await expect(page.getByRole("heading", { name: /run vr analysis/i })).toBeVisible();
  await page.getByLabel(name).check();
  await page.getByRole("button", { name: /start analysis/i }).click();

  // --- the analysis names the exact version it ran
  await expect(page.getByRole("heading", { name: /Analysis #/ })).toBeVisible();
  await expect(page.getByText("Rule sets:")).toBeVisible();
  await expect(page.getByRole("link", { name: new RegExp(`${name} v1`) })).toBeVisible();
});

test("editing a rule set appends a version and leaves the old one readable", async ({ page }) => {
  const name = `e2e versioned ${Date.now()}`;
  await login(page);
  await page.getByRole("link", { name: /Rule sets/ }).click();

  await page.getByRole("button", { name: /new rule set/i }).click();
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Rules (YAML)").fill(RULES);
  await page.getByRole("button", { name: /^create$/i }).click();
  await expect(page.getByRole("cell", { name: new RegExp(name) })).toBeVisible();

  // edit -> new version
  await page
    .getByRole("row", { name: new RegExp(name) })
    .getByRole("button", { name: /edit/i })
    .click();
  await page.getByLabel("Rules (YAML)").fill(RULES.replace("memcpy", "strcpy"));
  await page.getByLabel("What changed?").fill("switch to strcpy");
  await page.getByRole("button", { name: /save new version/i }).click();

  await expect(page.getByRole("row", { name: new RegExp(name) }).getByText("v2")).toBeVisible();

  // v1 is still there, unrewritten
  await page
    .getByRole("row", { name: new RegExp(name) })
    .getByRole("button", { name: /edit/i })
    .click();
  await page.getByText(/version history \(2\)/i).click();
  await expect(page.getByText(/switch to strcpy/)).toBeVisible();
});
