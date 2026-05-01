import {expect, test} from '@playwright/test';
import {goToNewPad} from 'ep_etherpad-lite/tests/frontend-new/helper/padHelper';

// A full login → logout flow needs a hash-authed user fixture written to
// disk and `settings.ep_hash_auth.hash_dir` pointed at it before the server
// starts. That setup is brittle in CI, so this spec asserts the UI surface
// only — the server-side endpoint behavior is covered by the backend tests
// in static/tests/backend/specs/logout.js.

test.describe('ep_hash_auth logout button', () => {
  test.beforeEach(async ({page}) => {
    await goToNewPad(page);
  });

  test('logout button is rendered in the userlist', async ({page}) => {
    // Open the userlist popup so the button is in the visible DOM tree.
    await page.locator('[data-key="showusers"] > a').click();
    const btn = page.locator('#ep_hash_auth_logout_btn');
    await expect(btn).toBeVisible();
    await expect(btn).toHaveAttribute('aria-label', /log out/i);
    await expect(btn).toHaveAttribute('data-l10n-id', 'ep_hash_auth.logout');
  });

  test('clicking logout navigates to /', async ({page}) => {
    await page.locator('[data-key="showusers"] > a').click();
    // The poison fetch returns 401 but our handler redirects unconditionally.
    await Promise.all([
      page.waitForURL((url) => url.pathname === '/'),
      page.locator('#ep_hash_auth_logout_btn').click(),
    ]);
    expect(new URL(page.url()).pathname).toBe('/');
  });
});
