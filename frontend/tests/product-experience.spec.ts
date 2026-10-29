import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('organizer workspace exposes every destination with honest capability labels', async ({ page }) => {
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [{ id: 'event-1', slug: 'summit', name: 'Innovation Summit 2026', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1 }] } }));
  await page.route('**/api/v1/events/event-1/registrations**', route => route.fulfill({ json: { registrations: [] } }));
  await page.route('**/api/v1/events/event-1/gates', route => route.fulfill({ json: { gates: [] } }));
  await page.route('**/api/v1/events/event-1/attendance', route => route.fulfill({ json: { event_id: 'event-1', registered: 0, checked_in: 0, remaining: 0, attendance_percent: 0, duplicate_scans: 0, invalid_scans: 0, refreshed_at: '2026-10-26T10:00:00Z', gates: [], recent: [] } }));
  await page.goto('/workspace.html');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  const routes: Array<[string, string]> = [
    ['Events', 'Events'], ['Participants', 'Participants'], ['Tickets', 'Tickets'],
    ['Check-in', 'Live attendance'], ['Communications', 'Communications'],
    ['Reports', 'Attendance export'], ['Gate staff', 'Gate staff'], ['Branding', 'Branding'], ['Settings', 'Settings'],
  ];
  for (const [link, heading] of routes) {
    await page.getByRole('link', { name: new RegExp(`^${link}`) }).click();
    await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible();
  }
  await page.getByRole('link', { name: /^Check-in/ }).click();
  await expect(page.getByText('Server-confirmed admissions')).toBeVisible();
});

test('selected event is validated in the URL and persists across workspace routes and refresh', async ({ page }) => {
  const events = [
    { id: 'event-1', slug: 'summit', name: 'Innovation Summit 2026', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1 },
    { id: 'event-2', slug: 'forum', name: 'Operations Forum', status: 'published', starts_at: '2026-12-01T08:00:00Z', ends_at: '2026-12-01T18:00:00Z', revision: 1 },
  ];
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events } }));
  await page.route('**/api/v1/events/event-2/registrations**', route => route.fulfill({ json: { registrations: [], next_cursor: null } }));
  await page.route('**/api/v1/events/event-2/tickets/bulk', route => route.fulfill({ json: { registered: 0, issued: 0, queued: 0, sent: 0, delivered: 0, failed: 0 } }));
  await page.goto('/workspace.html#participants?event=event-2');
  await expect(page.getByRole('combobox', { name: 'Event' }).locator('option:checked')).toHaveText('Operations Forum');
  await page.getByRole('link', { name: /^Tickets/ }).click();
  await expect(page).toHaveURL(/#tickets\?event=event-2/);
  await expect(page.getByRole('heading', { name: 'Tickets', exact: true })).toBeVisible();
  await expect(page.getByText('Operations Forum', { exact: true }).first()).toBeVisible();
  await page.reload();
  await expect(page.getByRole('combobox', { name: 'Event' }).first().locator('option:checked')).toHaveText('Operations Forum');
});

test('ticket operations use participant context and shared confirmation dialogs', async ({ page }) => {
  const event = { id: 'event-1', slug: 'summit', name: 'Innovation Summit 2026', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1 };
  const participant = { id: 'registration-1', full_name: 'Ada Okafor', email: 'ada@example.test', phone: null, status: 'registered', source: 'import', registered_at: '2026-10-26T10:00:00Z', ticket_status: 'active', delivery_status: 'sent' };
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [event] } }));
  await page.route('**/api/v1/events/event-1/registrations**', route => route.fulfill({ json: { registrations: [participant], next_cursor: null } }));
  await page.route('**/api/v1/events/event-1/tickets/bulk', route => route.fulfill({ json: { registered: 1, issued: 1, queued: 0, sent: 1, delivered: 0, failed: 0 } }));
  await page.route('**/api/v1/events/event-1/registrations/registration-1/ticket', route => route.fulfill({ json: { ticket_status: 'active', delivery_status: 'sent' } }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/events/event-1/registrations/registration-1/ticket/revoke', route => route.fulfill({ json: { ticket_status: 'revoked', delivery_status: 'sent' } }));
  await page.goto('/workspace.html#tickets?event=event-1');
  await page.getByRole('button', { name: 'Manage' }).click();
  await expect(page.getByRole('heading', { name: "Ada Okafor's ticket" })).toBeVisible();
  await page.getByRole('button', { name: 'Revoke', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Revoke this ticket?' });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Revoke ticket' }).click();
  await expect(page.getByText('Revoked', { exact: true })).toBeVisible();
  await expect(page.getByText('registration-1')).not.toBeVisible();
  await page.getByText('Support identifiers').click();
  await expect(page.getByText('registration-1')).toBeVisible();
});

test('gate staff assignment changes use the shared accessible dialog', async ({ page }) => {
  const event = { id: 'event-1', slug: 'summit', name: 'Innovation Summit 2026', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1 };
  const staff = { user_id: 'staff-1', email: 'scanner@example.test', role: 'gate_scanner', status: 'active', assignments: [{ event_id: 'event-1', gate_id: 'gate-1' }] };
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [event] } }));
  await page.route('**/api/v1/events/event-1/gates', route => route.fulfill({ json: { gates: [{ id: 'gate-1', event_id: 'event-1', name: 'Main hall', enabled: true }] } }));
  await page.route('**/api/v1/auth/gate-staff', route => route.fulfill({ json: { staff: [staff] } }));
  await page.goto('/workspace.html#gate-staff?event=event-1');
  const move = page.getByRole('button', { name: 'Move', exact: true });
  await move.click();
  await expect(page.getByRole('dialog', { name: 'Move gate assignment?' })).toContainText('Innovation Summit 2026');
  await page.keyboard.press('Escape');
  await expect(move).toBeFocused();
});

test('core organizer workflows reflow at 320px and pass automated accessibility checks', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium');
  test.setTimeout(90_000);
  const event = { id: 'event-1', slug: 'summit', name: 'Innovation Summit 2026', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1 };
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [event] } }));
  await page.route('**/api/v1/events/event-1/registrations**', route => route.fulfill({ json: { registrations: [], next_cursor: null } }));
  await page.route('**/api/v1/events/event-1/tickets/bulk', route => route.fulfill({ json: { registered: 0, issued: 0, queued: 0, sent: 0, delivered: 0, failed: 0 } }));
  await page.route('**/api/v1/events/event-1/attendance', route => route.fulfill({ json: { event_id: 'event-1', registered: 0, checked_in: 0, remaining: 0, attendance_percent: 0, duplicate_scans: 0, invalid_scans: 0, refreshed_at: '2026-10-26T10:00:00Z', gates: [], recent: [] } }));
  await page.route('**/api/v1/events/event-1/gates', route => route.fulfill({ json: { gates: [] } }));
  await page.route('**/api/v1/auth/gate-staff', route => route.fulfill({ json: { staff: [] } }));
  await page.setViewportSize({ width: 320, height: 760 });
  for (const path of ['participants', 'tickets', 'check-in', 'gate-staff']) {
    await page.goto(`/workspace.html#${path}?event=event-1`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth), path).toBeLessThanOrEqual(320);
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag22aa']).analyze();
    expect(results.violations, path).toEqual([]);
  }
});

test('gate staff are directed away from the organizer workspace', async ({ page }) => {
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'scanner@example.test', role: 'gate_scanner', tenant_id: 'tenant-1' } }));
  await page.goto('/workspace.html');
  await expect(page.getByRole('heading', { name: 'Organizer access required' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open scanner' })).toHaveAttribute('href', '/gate.html');
  await expect(page.getByRole('link', { name: /^Participants/ })).toHaveCount(0);
});

test('platform console has a coherent control-plane route map', async ({ page }) => {
  await page.goto('/platform-console.html');
  for (const [link, heading] of [['Organizations','Organizations'],['Privacy notices','Privacy notices'],['Domains','Domains'],['Subscriptions','Subscriptions'],['Operations','Operations'],['Settings','Platform settings']] as const) {
    await page.getByRole('link', { name: new RegExp(`^${link}`) }).click();
    await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible();
  }
  await page.getByRole('link', { name: 'Overview' }).click();
  await expect(page.getByText('Platform activity is unavailable')).toBeVisible();
  await expect(page.getByText('Demo aggregate')).toHaveCount(0);
  await expect(page.getByText('Synthetic platform registration activity')).toHaveCount(0);
});

test('platform creation takes only organization and organizer details', async ({ page }) => {
  await page.route('**/api/v1/platform/auth/session', route => route.fulfill({ json: { email: 'admin@example.test' } }));
  await page.route('**/api/v1/platform/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/platform/organizations?*', route => route.fulfill({ json: { organizations: [], total: 0, limit: 25, offset: 0, has_more: false } }));
  await page.route('**/api/v1/platform/organizations', async route => {
    const body = route.request().postDataJSON();
    expect(body.name).toBe('Summit Operations');
    expect(body.organizer_email).toBe('organizer@example.test');
    expect(body.slug).toBeUndefined();
    expect(body.tenant_id).toBeUndefined();
    expect(body.idempotency_key).toBeTruthy();
    await route.fulfill({ status: 201, json: { organization_id: 'org-1', organizer_email: body.organizer_email, invitation_delivery_status: 'accepted_by_transport', event_setup_name: '' } });
  });
  await page.goto('/platform-console.html#organizations');
  await page.getByLabel('Organization name').fill('Summit Operations');
  await page.getByLabel('Organizer email').fill('organizer@example.test');
  await page.getByRole('button', { name: 'Create and invite organizer' }).click();
  await expect(page.getByText('accepted by transport')).toBeVisible();
  await expect(page.getByText('Provider acceptance does not prove inbox delivery.')).toBeVisible();
});

test('platform organization directory searches and shows details without notice setup links', async ({ page }) => {
  const organization = 'c1526557-cdf0-49b8-89a0-3516ab47ab41';
  const item = { id: organization, name: 'Summit Operations', status: 'active', created_at: '2026-10-27T09:00:00Z', primary_organizer: 'organizer@example.test', invitation_delivery_status: 'accepted_by_transport' };
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.route('**/api/v1/platform/auth/session', route => route.fulfill({ json: { email: 'admin@example.test' } }));
  await page.route('**/api/v1/platform/organizations?*', route => {
    const q = new URL(route.request().url()).searchParams.get('q');
    return route.fulfill({ json: { organizations: q === 'Summit' ? [item] : [], total: q === 'Summit' ? 1 : 0, limit: 25, offset: 0, has_more: false } });
  });
  await page.route(`**/api/v1/platform/organizations/${organization}`, route => route.fulfill({ json: item }));
  await page.route(`**/api/v1/platform/organizations/${organization}/privacy-notices`, route => route.fulfill({ json: { organization_id: organization, organization_name: item.name, notices: [] } }));
  await page.goto('/platform-console.html#organizations');
  await expect(page.getByText('No organizations found')).toBeVisible();
  await page.getByLabel('Find organization').fill('Summit');
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByText('organizer@example.test')).toBeVisible();
  await page.getByRole('button', { name: 'View Summit Operations' }).click();
  await expect(page.getByText(organization)).toBeVisible();
  await page.setViewportSize({ width: 320, height: 740 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
  await page.getByRole('button', { name: 'Copy UUID' }).click();
  await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(organization);
  await expect(page.getByRole('link', { name: 'Manage privacy notices' })).toHaveCount(0);
});

test('platform organization directory reports errors and recovers to an empty state', async ({ page }) => {
  let requests = 0;
  await page.route('**/api/v1/platform/auth/session', route => route.fulfill({ json: { email: 'admin@example.test' } }));
  await page.route('**/api/v1/platform/organizations?*', route => {
    requests += 1;
    return route.fulfill(requests < 3
      ? { status: 503, json: { detail: { message: 'Directory temporarily unavailable' } } }
      : { json: { organizations: [], total: 0, limit: 25, offset: 0, has_more: false } });
  });
  await page.goto('/platform-console.html#organizations');
  await expect(page.getByRole('alert').filter({ hasText: 'The service is temporarily unavailable' })).toBeVisible();
  requests = 2;
  await page.getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByText('No organizations found')).toBeVisible();
});

test('privacy notice page is coming soon and makes no notice API requests', async ({ page }) => {
  let requests = 0;
  await page.route('**/api/v1/platform/organizations/**/privacy-notices**', route => {
    requests++;
    return route.fulfill({ status: 503, json: {} });
  });
  await page.goto('/platform-console.html#privacy?organization=old-bookmark');
  await expect(page.getByRole('heading', { name: 'Privacy notices are coming soon' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create draft' })).toHaveCount(0);
  expect(requests).toBe(0);
});

test('shared sign-in chooses a server-authorized workspace after password verification', async ({ page }) => {
  await page.route('**/api/v1/shared/context', route => route.fulfill({ json: { shared: true } }));
  await page.route('**/api/v1/auth/session', route => route.fulfill({ status: 421, json: {} }));
  await page.route('**/api/v1/platform/auth/session', route => route.fulfill({ status: 401, json: {} }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/shared/login', async route => {
    const body = route.request().postDataJSON();
    if (!body.context) await route.fulfill({ json: { state: 'select_context', contexts: [{ id: 'platform', name: 'Platform Console', role: 'platform_admin' }, { id: 'tenant-1', name: 'Summit Operations', role: 'tenant_owner' }] } });
    else { expect(body.context).toBe('tenant-1'); await route.fulfill({ json: { state: 'mfa', destination: 'tenant', role: 'tenant_owner' } }); }
  });
  await page.goto('/');
  await page.getByLabel('Email address').fill('organizer@example.test');
  await page.getByLabel('Password', { exact: true }).fill('synthetic-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Choose your workspace' })).toBeVisible();
  await page.getByRole('button', { name: 'Summit Operations · tenant owner' }).click();
  await expect(page.getByRole('heading', { name: 'Verify your identity' })).toBeVisible();
});

test('shared password recovery keeps the tenant hint in the reset request', async ({ page }) => {
  await page.route('**/api/v1/shared/context', route => route.fulfill({ json: { shared: true } }));
  await page.route('**/api/v1/auth/session', route => route.fulfill({ status: 421, json: {} }));
  await page.route('**/api/v1/platform/auth/session', route => route.fulfill({ status: 401, json: {} }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/shared/password-reset/request', async route => {
    expect(route.request().postDataJSON()).toEqual({ email: 'organizer@example.test' });
    await route.fulfill({ json: { message: 'If the account is eligible, a reset link will be sent' } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Forgot password?' }).click();
  await page.getByLabel('Email address').fill('organizer@example.test');
  await page.getByRole('button', { name: 'Send reset link' }).click();
  await expect(page.getByText('If the account is eligible, a reset link will be sent')).toBeVisible();
  await page.route('**/api/v1/auth/password-reset/complete', async route => {
    expect(route.request().postDataJSON()).toEqual({ token: 'synthetic-reset', password: 'synthetic-password-123', tenant_id: 'tenant-1' });
    await route.fulfill({ json: { state: 'password_changed' } });
  });
  await page.goto('/reset#token=synthetic-reset&tenant=tenant-1');
  await page.getByLabel('Password', { exact: true }).fill('synthetic-password-123');
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByText('Password updated. Sign in again.')).toBeVisible();
});

test('gate experience shows admission only after server-confirmed redemption', async ({ page }) => {
  await page.route('**/api/v1/gate/session', route => route.fulfill({ json: { role: 'gate_scanner', assignments: [{ event_id: 'event-1', event_name: 'Innovation Summit 2026', gate_id: 'gate-1', gate_name: 'Main hall' }] } }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/gate/redeem', async route => {
    expect((await route.request().postDataJSON()).credential).toBe('secure-test-credential');
    await route.fulfill({ json: { outcome: 'accepted', reason_code: 'ACCEPTED', confirmed_at: '2026-11-01T09:10:00Z' } });
  });
  await page.goto('/gate.html');
  await expect(page.getByRole('heading', { name: 'Ready to scan' })).toBeVisible();
  await page.getByLabel('Secure manual credential').fill('secure-test-credential');
  await page.getByRole('button', { name: 'Verify with server' }).click();
  await expect(page.getByText('Server-confirmed result')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Admission confirmed' })).toBeVisible();
  await expect(page.getByText('No participant identity is shown')).toBeVisible();
});

test('gate session shows a useful error when the server returns non-JSON', async ({ page }) => {
  await page.route('**/api/v1/gate/session', route => route.fulfill({
    status: 500, contentType: 'text/plain', body: 'Internal Server Error',
  }));
  await page.goto('/gate.html');
  await expect(page.getByRole('heading', { name: 'Gate access required' })).toBeVisible();
  await expect(page.getByRole('alert')).toHaveText(
    'The service is temporarily unavailable. Try again shortly.',
  );
  await expect(page.getByText('Unexpected token')).toHaveCount(0);
});

test('bulk import maps published custom fields without organizer policy identifiers', async ({ page }) => {
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [{ id: 'event-1', slug: 'summit', name: 'Innovation Summit 2026', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1, form_schema: { fields: [{ key: 'meal', label: 'Meal', required: true }] } }] } }));
  await page.route('**/api/v1/events/event-1/registrations**', route => route.fulfill({ json: { registrations: [], next_cursor: null } }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/events/event-1/imports/preview', route => route.fulfill({ status: 201, json: { import_id: 'import-1', row_count: 1, columns: ['full_name','email','phone','meal'], sample: [{ full_name: 'Synthetic Attendee', email: 'synthetic@example.test', phone: '+2348012345678', meal: 'Vegan' }] } }));
  await page.route('**/api/v1/events/event-1/imports/policy', route => route.fulfill({ json: { available: true, message: 'Approved privacy notice available.' } }));
  await page.route('**/api/v1/events/event-1/imports/import-1/validate', async route => {
    const body = route.request().postDataJSON();
    expect(body).toEqual({ mapping: { full_name: 'full_name', email: 'email', phone: 'phone', custom: { meal: 'meal' } } });
    await route.fulfill({ json: { import_id: 'import-1', status: 'validated', row_count: 2, valid_count: 1, invalid_count: 1, duplicate_count: 0, imported_count: 0, progress: 0, errors: [{ row_number: 2, errors: ['INVALID_EMAIL'] }] } });
  });
  await page.goto('/workspace.html#participants');
  await page.getByRole('tab', { name: 'Bulk import' }).click();
  await page.locator('input[type=file]').setInputFiles('tests/fixtures/synthetic-import.csv');
  await page.getByLabel('Meal *').selectOption('meal');
  await page.getByRole('button', { name: 'Validate rows' }).click();
  await expect(page.getByText('Eligible to create')).toBeVisible();
  await expect(page.getByText('Enter a valid email address.')).toBeVisible();
  await expect(page.getByText('INVALID_EMAIL')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Import attendees' })).toBeDisabled();
});

test('bulk import accepts a CSV containing only an email column', async ({ page }) => {
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [{ id: 'event-1', slug: 'summit', name: 'Innovation Summit 2026', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1 }] } }));
  await page.route('**/api/v1/events/event-1/registrations**', route => route.fulfill({ json: { registrations: [], next_cursor: null } }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/events/event-1/imports/preview', route => route.fulfill({ status: 201, json: { import_id: 'import-1', row_count: 1, columns: ['email'], sample: [{ email: 'synthetic@example.test' }] } }));
  await page.route('**/api/v1/events/event-1/imports/policy', route => route.fulfill({ json: { available: true, message: 'Approved privacy notice available.' } }));
  await page.route('**/api/v1/events/event-1/imports/import-1/validate', async route => {
    const body = route.request().postDataJSON();
    expect(body.mapping.phone).toBe('');
    expect(body.mapping.full_name).toBe('');
    expect(body.mapping.email).toBe('email');
    await route.fulfill({ json: { import_id: 'import-1', status: 'validated', row_count: 1, valid_count: 1, invalid_count: 0, duplicate_count: 0, imported_count: 0, progress: 0, errors: [] } });
  });
  await page.goto('/workspace.html#participants');
  await page.getByRole('tab', { name: 'Bulk import' }).click();
  await page.locator('input[type=file]').setInputFiles('tests/fixtures/only-email.csv');
  await page.getByRole('button', { name: 'Validate rows' }).click();
  await expect(page.getByText('Eligible to create')).toBeVisible();
});

test('bulk import explains missing approval and surfaces API validation errors', async ({ page }) => {
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [{ id: 'event-1', slug: 'summit', name: 'Summit', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1 }] } }));
  await page.route('**/api/v1/events/event-1/registrations**', route => route.fulfill({ json: { registrations: [], next_cursor: null } }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/events/event-1/imports/preview', route => route.fulfill({ status: 201, json: { import_id: 'import-1', row_count: 1, columns: ['email'], sample: [{ email: 'synthetic@example.test' }] } }));
  let approved = false;
  await page.route('**/api/v1/events/event-1/imports/policy', route => route.fulfill({ json: approved
    ? { available: true, message: 'Approved privacy notice available.' }
    : { available: false, message: 'No active approved privacy notice is available. Ask a platform administrator to approve and activate one.' } }));
  await page.route('**/api/v1/events/event-1/imports/import-1/validate', route => route.fulfill({ status: 422, json: { detail: [{ loc: ['body', 'mapping', 'email'], msg: 'Email column is invalid' }] } }));
  await page.goto('/workspace.html#participants');
  await page.getByRole('tab', { name: 'Bulk import' }).click();
  await page.locator('input[type=file]').setInputFiles('tests/fixtures/only-email.csv');
  await expect(page.getByText('No active approved privacy notice is available')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Validate rows' })).toBeDisabled();
  approved = true;
  await page.getByRole('button', { name: 'Choose another file' }).click();
  await page.locator('input[type=file]').setInputFiles('tests/fixtures/only-email.csv');
  await page.getByRole('button', { name: 'Validate rows' }).click();
  await expect(page.getByRole('alert')).toContainText('Some information could not be accepted');
});

test('bulk import requires an unchecked authorization before commit', async ({ page }) => {
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [{ id: 'event-1', slug: 'summit', name: 'Summit', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1 }] } }));
  await page.route('**/api/v1/events/event-1/registrations**', route => route.fulfill({ json: { registrations: [], next_cursor: null } }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/events/event-1/imports/preview', route => route.fulfill({ status: 201, json: { import_id: 'import-1', row_count: 1, columns: ['email'], sample: [{ email: 'synthetic@example.test' }] } }));
  await page.route('**/api/v1/events/event-1/imports/policy', route => route.fulfill({ json: { available: true, message: 'Approved privacy notice available.' } }));
  await page.route('**/api/v1/events/event-1/imports/import-1/validate', route => route.fulfill({ json: { import_id: 'import-1', status: 'validated', row_count: 1, valid_count: 1, invalid_count: 0, duplicate_count: 0, imported_count: 0, errors: [] } }));
  let committed = false;
  await page.route('**/api/v1/events/event-1/imports/import-1/commit', route => { committed = true; expect(route.request().postDataJSON()).toEqual({ authorization_confirmed: true }); return route.fulfill({ status: 202, json: { import_id: 'import-1', status: 'queued', row_count: 1, valid_count: 1 } }); });
  await page.route('**/api/v1/events/event-1/imports/import-1', route => route.fulfill({ json: { import_id: 'import-1', status: 'queued', row_count: 1, valid_count: 1 } }));
  await page.goto('/workspace.html#participants');
  await page.getByRole('tab', { name: 'Bulk import' }).click();
  await page.locator('input[type=file]').setInputFiles('tests/fixtures/only-email.csv');
  await page.getByRole('button', { name: 'Validate rows' }).click();
  await expect(page.getByRole('button', { name: 'Import attendees' })).toBeDisabled();
  expect(committed).toBe(false);
  await page.getByRole('checkbox', { name: /appropriate authority and lawful basis/ }).check();
  await page.getByRole('button', { name: 'Import attendees' }).click();
  await expect.poll(() => committed).toBe(true);
});

test('gate network ambiguity never reports admission', async ({ page }) => {
  await page.route('**/api/v1/gate/session', route => route.fulfill({ json: { role: 'gate_scanner', assignments: [{ event_id: 'event-1', event_name: 'Innovation Summit 2026', gate_id: 'gate-1', gate_name: 'Main hall', event_status: 'published' }] } }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/gate/redeem', route => route.abort('failed'));
  await page.goto('/gate.html');
  await page.getByLabel('Secure manual credential').fill('v1.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO');
  await page.getByRole('button', { name: 'Verify with server' }).click();
  await expect(page.getByRole('heading', { name: 'Do not admit' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Retry same credential' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Admission confirmed' })).toHaveCount(0);
});

test('gate camera decodes QR without native BarcodeDetector before server confirmation', async ({ page }) => {
  await page.route('**/synthetic-qr.png', route => route.fulfill({ path: 'tests/fixtures/synthetic-qr.png', contentType: 'image/png' }));
  await page.addInitScript(() => {
    Object.defineProperty(window, 'BarcodeDetector', { value: undefined });
    Object.defineProperty(navigator, 'mediaDevices', { value: { getUserMedia: async () => {
      const canvas = document.createElement('canvas'); canvas.width = 480; canvas.height = 480;
      const image = new Image(); image.src = '/synthetic-qr.png'; await image.decode();
      const context = canvas.getContext('2d')!;
      context.drawImage(image, 0, 0, 480, 480);
      setInterval(() => context.drawImage(image, 0, 0, 480, 480), 100);
      return canvas.captureStream(10);
    } } });
  });
  await page.route('**/api/v1/gate/session', route => route.fulfill({ json: { role: 'gate_scanner', assignments: [{ event_id: 'event-1', event_name: 'Innovation Summit 2026', gate_id: 'gate-1', gate_name: 'Main hall', event_status: 'published' }] } }));
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/gate/redeem', async route => {
    expect((await route.request().postDataJSON()).credential).toBe('v1.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO');
    await route.fulfill({ json: { outcome: 'accepted', confirmed_at: '2026-11-01T09:10:00Z' } });
  });
  await page.goto('/gate.html');
  await expect(page.getByRole('heading', { name: 'Ready to scan' })).toBeVisible();
  await page.getByRole('button', { name: 'Open camera' }).click();
  await expect(page.getByRole('heading', { name: 'Admission confirmed' })).toBeVisible();
});

test('representative product screens reflow and pass automated accessibility checks', async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  const screenshotDir = '../docs/screenshots';
  await page.route('**/api/v1/auth/session', route => route.fulfill({ json: { email: 'organizer@example.test', role: 'tenant_owner', tenant_id: 'tenant-1' } }));
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [] } }));
  await page.route('**/api/v1/gate/session', route => route.fulfill({ status: 401, json: { detail: { message: 'Sign in required' } } }));
  for (const path of ['/workspace.html#dashboard', '/platform-console.html#overview', '/gate.html']) {
    await page.setViewportSize({ width: 320, height: 760 });
    await page.goto(path);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag22aa']).analyze();
    expect(results.violations).toEqual([]);
  }
  await page.route('**/api/v1/events', route => route.fulfill({ json: { events: [{ id: 'event-1', slug: 'summit', name: 'Innovation Summit 2026', status: 'published', starts_at: '2026-11-01T08:00:00Z', ends_at: '2026-11-01T18:00:00Z', revision: 1 }] } }));
  await page.route('**/api/v1/events/event-1/attendance', route => route.fulfill({ json: { event_id: 'event-1', registered: 0, checked_in: 0, remaining: 0, attendance_percent: 0, duplicate_scans: 0, invalid_scans: 0, refreshed_at: '2026-10-26T10:00:00Z', gates: [{ gate_name: 'Main hall', checked_in: 0 }], recent: [] } }));
  await page.route('**/ready', route => route.fulfill({ json: { status: 'ready', checks: { api: 'ready', database: 'ready', worker: 'not_configured' } } }));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/workspace.html#dashboard');
  await expect(page.getByRole('heading', { name: 'Next actions' })).toBeVisible();
  const organizerShot = `${screenshotDir}/organizer-desktop-light.png`;
  await page.screenshot({ path: organizerShot, fullPage: true, animations: 'disabled' });
  await testInfo.attach('organizer-desktop-light', { path: organizerShot, contentType: 'image/png' });
  await page.goto('/platform-console.html#overview');
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
  await page.getByRole('button', { name: 'Use dark theme' }).click();
  const platformShot = `${screenshotDir}/platform-desktop-dark.png`;
  await page.screenshot({ path: platformShot, fullPage: true, animations: 'disabled' });
  await testInfo.attach('platform-desktop-dark', { path: platformShot, contentType: 'image/png' });
  await page.route('**/api/v1/gate/session', route => route.fulfill({ json: { role: 'gate_scanner', assignments: [{ event_id: 'event-1', event_name: 'Innovation Summit 2026', gate_id: 'gate-1', gate_name: 'Main hall', event_status: 'published' }] } }));
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/gate.html');
  await expect(page.getByRole('heading', { name: 'Ready to scan' })).toBeVisible();
  const gateShot = `${screenshotDir}/gate-mobile-dark.png`;
  await page.screenshot({ path: gateShot, fullPage: true, animations: 'disabled' });
  await testInfo.attach('gate-mobile-dark', { path: gateShot, contentType: 'image/png' });
});

test('platform recovery codes render as separate readable rows', async ({ page }) => {
  await page.route('**/api/v1/platform/auth/session', route => route.fulfill({ status: 401, json: {} }));
  await page.route('**/api/v1/platform/auth/csrf', route => route.fulfill({ json: { csrf_token: 'csrf' } }));
  await page.route('**/api/v1/platform/auth/login', route => route.fulfill({ json: { state: 'mfa' } }));
  await page.route('**/api/v1/platform/auth/mfa/verify', route => route.fulfill({ json: { state: 'session', recovery_codes: ['alpha-1234567890', 'bravo-1234567890', 'charlie-1234567890'] } }));
  await page.goto('/platform.html');
  await page.getByLabel('Verified staff email').fill('platform@example.test');
  await page.getByLabel('Password', { exact: true }).fill('local-password');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Authenticator code').fill('123456');
  await page.getByRole('button', { name: 'Verify' }).click();
  await page.getByRole('link', { name: 'Organizations' }).click();
  await expect(page.locator('.recovery-code-list li')).toHaveCount(3);
  await page.setViewportSize({ width: 320, height: 760 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});
