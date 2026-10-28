import { test, expect } from '@playwright/test';

for (const width of [390, 1280]) {
for (const area of ['platform', 'organizer', 'gate'] as const) {
  test(`${area} at ${width}px has visible sign-out and revokes the correct server session`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await page.route('**/ready', route => route.fulfill({ json: { status: 'ready' } }));
    await page.route('**/api/v1/platform/auth/session', route => route.fulfill({ json: { email: 'admin@example.test' } }));
    await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'staff@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
    await page.route('**/api/v1/gate/session', route => route.fulfill({ json: { role: 'gate_scanner', assignments: [] } }));
    await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [] } }));
    await page.route('**/api/v1/**/csrf', route => route.fulfill({ json: { csrf_token: 'synthetic-csrf' } }));
    const logout = area === 'platform' ? '/api/v1/platform/auth/logout' : '/api/v1/auth/logout';
    let calls = 0;
    await page.route(`**${logout}`, async route => {
      expect(route.request().method()).toBe('POST');
      expect(route.request().headers()['x-csrf-token']).toBe('synthetic-csrf');
      calls++;
      await route.fulfill({ json: {} });
    });
    await page.goto(area === 'platform' ? '/platform-console.html#settings' : area === 'organizer' ? '/workspace.html' : '/gate.html');
    await page.evaluate(() => sessionStorage.setItem('staff_session_seen', '1'));
    const signOut = page.getByRole('button', { name: 'Sign out', exact: true });
    await expect(signOut).toBeVisible();
    const bounds = await signOut.boundingBox();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
    await signOut.click();
    await expect(page).toHaveURL('/');
    expect(calls).toBe(1);
    expect(await page.evaluate(() => sessionStorage.getItem('staff_session_seen'))).toBeNull();
  });
}

}

test('failed logout stays on dashboard and offers retry', async ({ page }) => {
  await page.route('**/ready', route => route.fulfill({ json: { status: 'ready' } }));
  await page.route('**/api/v1/platform/auth/session', route => route.fulfill({ json: { email: 'admin@example.test' } }));
  await page.route('**/api/v1/platform/auth/csrf', route => route.fulfill({ json: { csrf_token: 'synthetic-csrf' } }));
  await page.route('**/api/v1/platform/auth/logout', route => route.fulfill({ status: 503, json: {} }));
  await page.goto('/platform-console.html#settings');
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('Could not sign out. Check your connection and try again.');
  await expect(page).toHaveURL(/platform-console.html#settings/);
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeEnabled();
});
