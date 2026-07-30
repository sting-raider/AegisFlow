import { expect, test } from "@playwright/test";

test("shows seeded operations data and opens detection evidence", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByText("Demo traffic")).toBeVisible();
  await expect(page.getByText("Live stream linked")).toBeVisible({ timeout: 15_000 });

  if (process.env.UPDATE_SCREENSHOTS === "1") {
    await page.screenshot({ path: "../../docs/images/dashboard.png", fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: "../../docs/images/dashboard-mobile.png", fullPage: true });
    await page.setViewportSize({ width: 1440, height: 900 });
  }

  await page.getByRole("button", { name: "Live alerts" }).click();
  const rows = page.locator("tbody tr");
  await expect(rows.first()).toBeVisible();
  await rows.first().click();
  await expect(page.getByRole("complementary", { name: "Alert detail" })).toBeVisible();
  await expect(page.getByText("Detection evidence")).toBeVisible();
  await page.getByLabel("Note").fill("Automated demo acceptance check");
  await page.getByRole("button", { name: "Record feedback" }).click();
  await expect(
    page.getByText("Feedback recorded without changing the detection.")
  ).toBeVisible();
});
