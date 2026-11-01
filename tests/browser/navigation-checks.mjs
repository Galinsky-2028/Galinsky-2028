import assert from "node:assert/strict";

// Exercise real rendered routes with the site's styles and JavaScript. Each
// browser caller records success only after all scripting and viewport cases.
export async function checkNavigation(browser, origin, screenshotPrefix) {
  const routes = ["/", "/issues/", "/notices/"];
  for (const javaScriptEnabled of [false, true]) {
    const context = await browser.newContext({ javaScriptEnabled });
    try {
      const page = await context.newPage();
      for (const width of [320, 390, 780, 781, 1280]) {
        await page.setViewportSize({ width, height: 900 });
        for (const route of routes) {
          await page.goto(origin + route);
          const nav = page.getByRole("navigation", { name: "Main navigation" });
          const menu = page.locator("#menu-toggle");
          const links = nav.locator("a");
          const mobile = width <= 780;
          assert.equal(await links.count(), 6);
          assert.equal(await menu.isVisible(), javaScriptEnabled && mobile);
          if (javaScriptEnabled && mobile) {
            assert.equal(await menu.getAttribute("aria-expanded"), "false");
            assert.equal(await nav.isVisible(), false);
            await menu.focus();
            await page.keyboard.press("Enter");
            assert.equal(await menu.getAttribute("aria-expanded"), "true");
            await page.keyboard.press("Tab");
            assert.equal(
              await links
                .first()
                .evaluate((el) => el === document.activeElement),
              true,
            );
            await page.keyboard.press("Escape");
            assert.equal(await nav.isVisible(), false);
            assert.equal(await menu.getAttribute("aria-expanded"), "false");
            assert.equal(
              await menu.evaluate((el) => el === document.activeElement),
              true,
            );
            await page.keyboard.press("Space");
          }
          assert.equal(await nav.isVisible(), true);
          if (!javaScriptEnabled && mobile) {
            const navBox = await nav.boundingBox();
            const headerBox = await page.locator(".header").boundingBox();
            assert(
              navBox.y + navBox.height <= headerBox.y + headerBox.height + 1,
              "Fallback navigation must expand the header instead of covering page content",
            );
          }
          for (const link of await links.all()) {
            await link.focus();
            assert.equal(
              await link.evaluate((el) => el === document.activeElement),
              true,
            );
            const box = await link.boundingBox();
            assert(
              box &&
                box.width > 0 &&
                box.height > 0 &&
                box.x >= 0 &&
                box.x + box.width <= width + 1,
            );
          }
          assert.equal(
            await page.evaluate(
              () => document.documentElement.scrollWidth <= innerWidth,
            ),
            true,
          );
          if (route === "/" && width === 390) {
            await page.screenshot({
              path: `${screenshotPrefix}-${javaScriptEnabled ? "js" : "nojs"}-navigation.png`,
            });
          }
        }
      }
    } finally {
      await context.close();
    }
  }
  return {
    noJavaScriptNavigation: true,
    keyboardMenuAndFocusRestoration: true,
    navigationWidths: [320, 390, 780, 781, 1280],
  };
}
