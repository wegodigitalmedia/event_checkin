import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const event = {
  slug: 'demo', name: 'Àjọ Lagos', location: 'Victoria Island',
  starts_at: '2026-11-03T08:00:00Z', ends_at: '2026-11-03T16:00:00Z',
  timezone: 'Africa/Lagos', available: true, form_version: 3,
  form_schema: { fields: [{ key: 'meal', label: 'Meal preference', type: 'select', required: true,
    options: ['Vegan', 'Other'] }] },
  privacy_notice: { version: 2, body: 'Synthetic test privacy notice.' },
};

test('public registration has safe confirmation, consent separation and accessible mobile form', async ({ page }) => {
  await page.route('**/api/v1/public/events/demo', (route) => route.fulfill({ json: event }));
  await page.route('**/api/v1/branding/public', (route) => route.fulfill({ json: {
    display_name: 'Àjọ Events', logo_url: null, primary_color: '#205b4a', accent_color: '#205b4a',
    action_text_color: '#ffffff', sender_name: null, revision: 1,
  } }));
  let sent = false;
  await page.route('**/api/v1/public/events/demo/registrations', (route) => {
    const body = route.request().postDataJSON();
    expect(body).toMatchObject({ full_name: 'Ada Lovelace', email: 'ada@example.test',
      form_version: 3, notice_version: 2, notice_acknowledged: true,
      marketing_opt_in: false, custom_answers: { meal: 'Vegan' } });
    expect(body).not.toHaveProperty('tenant_id');
    sent = true;
    return route.fulfill({ status: 202, json: { message: 'Check your email.' } });
  });
  await page.goto('/register.html?event=demo');
  await expect(page.getByRole('heading', { name: 'Àjọ Lagos' })).toBeVisible();
  await expect(page.getByText('Àjọ Events')).toBeVisible();
  await page.getByRole('textbox', { name: 'Full name' }).fill('Ada Lovelace');
  await page.getByRole('textbox', { name: 'Email address' }).fill('ada@example.test');
  await page.getByRole('textbox', { name: 'Phone number' }).fill('+234 801 234 5678');
  await page.getByLabel('Meal preference').selectOption('Vegan');
  await page.getByLabel('I have read the privacy notice.').check();
  await page.setViewportSize({ width: 320, height: 740 });
  await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag22aa']).analyze();
  expect(result.violations).toEqual([]);
  await page.getByRole('button', { name: 'Submit registration' }).click();
  await expect(page.getByRole('status')).toContainText('Request received');
  expect(sent).toBe(true);
});

test('closed public registration has no form and retains theme control', async ({ page }) => {
  await page.route('**/api/v1/public/events/demo', (route) => route.fulfill({
    json: { ...event, available: false },
  }));
  await page.route('**/api/v1/branding/public', (route) => route.fulfill({ status: 404 }));
  await page.goto('/register.html?event=demo');
  await expect(page.getByRole('status')).toContainText('Registration unavailable');
  await expect(page.getByRole('button', { name: 'Submit registration' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Use dark theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});

test('registration works with privacy notice management unavailable', async ({ page }) => {
  await page.route('**/api/v1/public/events/demo', route => route.fulfill({ json: { ...event, privacy_notice: null } }));
  await page.route('**/api/v1/branding/public', route => route.fulfill({ status: 404 }));
  await page.route('**/api/v1/public/events/demo/registrations', route => {
    const body = route.request().postDataJSON();
    expect(body).not.toHaveProperty('notice_version');
    expect(body.notice_acknowledged).toBe(false);
    expect(body.marketing_opt_in).toBe(false);
    return route.fulfill({ status: 202, json: { message: 'Check your email.' } });
  });
  await page.goto('/register.html?event=demo');
  await expect(page.getByLabel('I have read the privacy notice.')).toHaveCount(0);
  await page.getByRole('textbox', { name: 'Full name' }).fill('Demo Attendee');
  await page.getByRole('textbox', { name: 'Email address' }).fill('demo@example.test');
  await page.getByRole('textbox', { name: 'Phone number' }).fill('+2348012345699');
  await page.getByLabel('Meal preference').selectOption('Vegan');
  await page.getByRole('button', { name: 'Submit registration' }).click();
  await expect(page.getByRole('status')).toContainText('Request received');
});
