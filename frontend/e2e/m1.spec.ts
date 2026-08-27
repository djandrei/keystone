import { expect, test } from "@playwright/test";

const ADMIN = { username: "admin", password: "change-me" };

async function login(page: import("@playwright/test").Page, username: string, password: string) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
}

async function logout(page: import("@playwright/test").Page) {
  await page.getByRole("button", { name: /account menu/i }).click();
  await page.getByRole("menuitem", { name: /sign out/i }).click();
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
}

test("M1 end-to-end: admin provisions an analyst who then logs in", async ({ page }) => {
  const stamp = Date.now();
  const analyst = `analyst_${stamp}`;
  const team = `Team ${stamp}`;

  // 1. unauthenticated visitor is bounced to login
  await page.goto("/");
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();

  // 2. admin logs in -> dashboard
  await login(page, ADMIN.username, ADMIN.password);
  await expect(page.getByRole("heading", { name: /welcome back, admin/i })).toBeVisible();

  // 3. create an analyst, capture the one-time temp password from the toast
  await page.getByRole("link", { name: /Users/ }).click();
  await page.getByRole("button", { name: /new user/i }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Username").fill(analyst);
  await dialog.getByLabel("Email").fill(`${analyst}@keystone.local`);
  await dialog.getByRole("button", { name: /create user/i }).click();

  const toast = page.getByText(/Temporary password:/i).first();
  await expect(toast).toBeVisible();
  const tempPassword = (await toast.textContent())!.split("Temporary password:")[1].trim();
  expect(tempPassword.length).toBeGreaterThan(6);
  await expect(page.getByRole("cell", { name: analyst, exact: true })).toBeVisible();

  // 4. create a team and add the analyst to it
  await page.getByRole("link", { name: /Teams/ }).click();
  await page.getByRole("button", { name: /new team/i }).click();
  await page.getByRole("dialog").getByLabel(/team name/i).fill(team);
  await page.getByRole("dialog").getByRole("button", { name: /create team/i }).click();

  await page.getByRole("button", { name: /manage members/i }).last().click();
  const members = page.getByRole("dialog");
  await members.getByLabel(/add member/i).click();
  await page.getByRole("option", { name: analyst }).click();
  await members.getByRole("button", { name: /^add$/i }).click();
  await expect(members.getByText(analyst)).toBeVisible();
  await page.keyboard.press("Escape");

  // 5. set system settings
  await page.getByRole("link", { name: /Settings/ }).click();
  await page.getByLabel(/llm endpoint url/i).fill("https://llm.example.com/api");
  await page.getByLabel(/default model/i).fill("qwen/qwen3-8b");
  await page.getByRole("button", { name: /save settings/i }).click();
  await expect(page.getByText(/settings saved/i)).toBeVisible();

  // 6. admin logs out; analyst logs in with the temp password -> empty dashboard
  await logout(page);
  await login(page, analyst, tempPassword);
  await expect(page.getByRole("heading", { name: new RegExp(`welcome back, ${analyst}`, "i") })).toBeVisible();
  await expect(page.getByText(/no analyses yet/i)).toBeVisible();
});
