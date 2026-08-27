import { expect, test, type APIRequestContext } from "@playwright/test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = { username: "admin", password: "change-me" };
const BASE = process.env.E2E_BASE_URL ?? "http://localhost:8080";

function makeElf(name: string): string {
  const buf = Buffer.alloc(64);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0);
  buf.writeUInt16LE(0x3e, 18);
  buf.writeBigUInt64LE(BigInt(Date.now()), 40);
  const dir = mkdtempSync(join(tmpdir(), "kst-m4-"));
  const path = join(dir, name);
  writeFileSync(path, buf);
  return path;
}

async function api(request: APIRequestContext, token: string, method: "post" | "delete", path: string, data?: unknown) {
  const res = await request[method](`${BASE}/api${path}`, {
    headers: { Authorization: `Bearer ${token}` },
    data: data as object,
  });
  expect(res.ok(), `${method} ${path} -> ${res.status()}`).toBeTruthy();
  return res.json().catch(() => ({}));
}

async function uiLogin(page: import("@playwright/test").Page, username: string, password: string) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: /welcome back/i })).toBeVisible();
}

test("M4: collaboration, search, export and audit", async ({ page, request }) => {
  const ts = Date.now();
  const analyst = `collab_${ts}`;
  const teamName = `Squad ${ts}`;
  const filename = `collab_${ts}.bin`;

  // --- setup via API (robust) ---
  const login = await request.post(`${BASE}/api/auth/login`, { data: ADMIN });
  const adminToken = (await login.json()).access_token;
  const adminId = (await (await request.get(`${BASE}/api/auth/me`, { headers: { Authorization: `Bearer ${adminToken}` } })).json()).id;

  const team = await api(request, adminToken, "post", "/teams", { name: teamName });
  const user = await api(request, adminToken, "post", "/users", { username: analyst, email: `${analyst}@x.io`, password: "analyst-pw-123" });
  await api(request, adminToken, "post", `/teams/${team.id}/members`, { user_id: adminId });
  await api(request, adminToken, "post", `/teams/${team.id}/members`, { user_id: user.id });

  // --- admin: upload + run RE in the new team ---
  await uiLogin(page, ADMIN.username, ADMIN.password);
  await page.getByRole("link", { name: /Binaries/ }).click();
  // pick the new team for the upload
  await page.getByLabel("Team", { exact: true }).click();
  await page.getByRole("option", { name: teamName }).click();
  await page.locator('input[aria-label="Upload binary"]').setInputFiles(makeElf(filename));
  await expect(page.getByRole("cell", { name: filename }).first()).toBeVisible();
  await page.getByRole("button", { name: /run re/i }).first().click();
  await expect(page.getByText("succeeded")).toBeVisible({ timeout: 30_000 });

  // --- search on the dashboard, then export the report ---
  await page.getByRole("link", { name: /Dashboard/ }).click();
  await page.getByLabel("Active team").click();
  await page.getByRole("option", { name: teamName }).click();
  await page.getByLabel("Search analyses").fill(`collab_${ts}`);
  await expect(page.getByRole("cell", { name: "admin" })).toBeVisible(); // the run, by admin, matches the filename search
  await page.getByRole("link", { name: /view/i }).first().click();
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "MD" }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/\.md$/);

  // --- admin views the audit trail ---
  await page.getByRole("link", { name: /Audit/ }).click();
  await page.getByLabel(/filter by action/i).fill("analysis.start");
  await expect(page.getByText("analysis.start").first()).toBeVisible();

  // --- analyst sees the admin's run (team-scoped collaboration) ---
  await page.getByRole("button", { name: /account menu/i }).click();
  await page.getByRole("menuitem", { name: /sign out/i }).click();
  await uiLogin(page, analyst, "analyst-pw-123");
  // the analyst belongs to just this team, so the dashboard is already scoped to it
  await expect(page.getByRole("cell", { name: "admin" })).toBeVisible(); // teammate run visible
});
