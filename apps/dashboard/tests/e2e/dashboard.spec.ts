import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("shows seeded operations data and opens detection evidence", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to intelligence brief" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Overview/ })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("Demo traffic")).toBeVisible();
  await expect(page.getByText("Live stream linked")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("Signal edition")).toBeVisible();
  await expect(page.locator(".flowline__mark").first()).toBeVisible();
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);

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
  await expect(page.getByRole("dialog", { name: /known attack/i })).toBeVisible();
  await expect(page.getByText("Detection evidence")).toBeVisible();
  const dialogAccessibility = await new AxeBuilder({ page }).include(".drawer").analyze();
  expect(dialogAccessibility.violations).toEqual([]);
  await page.getByLabel("Note").fill("Automated demo acceptance check");
  await page.getByRole("button", { name: "Record feedback" }).click();
  await expect(
    page.getByText("Feedback recorded without changing the detection.")
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: /known attack/i })).toBeHidden();
});

test("has no automated accessibility violations across all analyst views", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Signal edition")).toBeVisible();
  const viewNames = [
    "Overview",
    "Live alerts",
    "Incidents",
    "Flow explorer",
    "Hosts",
    "Models & drift",
    "System health"
  ];
  for (const viewName of viewNames) {
    if (viewName !== "Overview") {
      await page.getByRole("button", { name: new RegExp(viewName.replace("&", "\\&"), "i") }).click();
    }
    await expect(page.getByRole("heading", { name: viewName })).toBeVisible();
    const accessibility = await new AxeBuilder({ page }).include("#main-content").analyze();
    expect(accessibility.violations, `${viewName} accessibility violations`).toEqual([]);
  }
});
