import { expect, test, type APIRequestContext } from "@playwright/test";

const ADMIN = { username: "admin", password: "change-me" };
const BASE = process.env.E2E_BASE_URL ?? "http://localhost:8080";

function elf(): Buffer {
  const buf = Buffer.alloc(512);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0);
  buf.writeUInt16LE(0x3e, 18);
  buf.writeBigUInt64LE(BigInt(Date.now()), 40);
  return buf;
}

async function json(res: import("@playwright/test").APIResponse) {
  expect(res.ok(), `${res.url()} -> ${res.status()}`).toBeTruthy();
  return res.json();
}

async function post(request: APIRequestContext, token: string, path: string, data: unknown) {
  return json(await request.post(`${BASE}/api${path}`, { headers: { Authorization: `Bearer ${token}` }, data: data as object }));
}

test("M4: collaboration, search, export and audit", async ({ page, request }) => {
  const ts = Date.now();
  const analyst = `collab_${ts}`;
  const filename = `collab_${ts}.bin`;

  // --- setup + upload + run RE, all via the API (robust against accumulated data) ---
  const adminToken = (await json(await request.post(`${BASE}/api/auth/login`, { data: ADMIN }))).access_token;
  const adminId = (await json(await request.get(`${BASE}/api/auth/me`, { headers: { Authorization: `Bearer ${adminToken}` } }))).id;

  const team = await post(request, adminToken, "/teams", { name: `Squad ${ts}` });
  const user = await post(request, adminToken, "/users", { username: analyst, email: `${analyst}@x.io`, password: "analyst-pw-123" });
  await post(request, adminToken, `/teams/${team.id}/members`, { user_id: adminId });
  await post(request, adminToken, `/teams/${team.id}/members`, { user_id: user.id });

  const binary = await json(
    await request.post(`${BASE}/api/binaries`, {
      headers: { Authorization: `Bearer ${adminToken}` },
      multipart: { team_id: String(team.id), file: { name: filename, mimeType: "application/octet-stream", buffer: elf() } },
    }),
  );
  const started = await post(request, adminToken, `/binaries/${binary.id}/analyses`, { mode: "re" });

  // wait for the fake engine to finish
  await expect
    .poll(async () => (await json(await request.get(`${BASE}/api/analyses/${started.id}`, { headers: { Authorization: `Bearer ${adminToken}` } }))).status, { timeout: 30_000 })
    .toBe("succeeded");

  // --- analyst (single team -> dashboard auto-scoped) sees the teammate's run ---
  await page.goto("/login");
  await page.getByLabel("Username").fill(analyst);
  await page.getByLabel("Password").fill("analyst-pw-123");
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: /welcome back/i })).toBeVisible();

  await page.getByLabel("Search analyses").fill(`collab_${ts}`);
  await expect(page.getByRole("cell", { name: "admin" })).toBeVisible(); // teammate's run, matched by filename search

  // open it and export the markdown report
  await page.getByRole("link", { name: /view/i }).first().click();
  await expect(page.getByText("succeeded", { exact: true })).toBeVisible();
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "MD" }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/\.md$/);

  // --- admin reviews the audit trail ---
  await page.getByRole("button", { name: /account menu/i }).click();
  await page.getByRole("menuitem", { name: /sign out/i }).click();
  await page.getByLabel("Username").fill(ADMIN.username);
  await page.getByLabel("Password").fill(ADMIN.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.getByRole("link", { name: /Audit/ }).click();
  await page.getByLabel(/filter by action/i).fill("analysis.start");
  await expect(page.getByText("analysis.start").first()).toBeVisible();
});
