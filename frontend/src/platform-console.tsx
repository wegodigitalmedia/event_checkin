import { StrictMode, useEffect, useState, type FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import { PlatformConsole } from './product/PlatformConsole';
import { capabilities } from './product/capabilities';
import { ButtonLink, CapabilityNotice, PageHeader, RestrictedState, SectionHeader, SuccessState } from './product/components';
import { getJson, mutateJson } from './management-api';
import { OrganizationDirectory } from './product/OrganizationDirectory';
import { Button, Field, Skeleton, Status } from './ui';
import { safeErrorMessage } from './safe-error';
import './product/product.css';

function Organizations() {
  type Created = { organization_id: string; organizer_email: string; invitation_delivery_status: string; event_setup_name: string };
  type PlatformSession = { email: string; permission?: string };
  const [authorized, setAuthorized] = useState(false);
  const [checked, setChecked] = useState(false);
  const [session, setSession] = useState<PlatformSession | null>(null);
  const [name, setName] = useState(''); const [email, setEmail] = useState('');
  const [organizerName, setOrganizerName] = useState(''); const [phone, setPhone] = useState(''); const [eventName, setEventName] = useState('');
  const [key, setKey] = useState(() => crypto.randomUUID());
  const [created, setCreated] = useState<Created | null>(null);
  const [directoryRefresh, setDirectoryRefresh] = useState(0);
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  useEffect(() => { void getJson<PlatformSession>('/api/v1/platform/auth/session').then((value) => { setSession(value); setAuthorized(true); }).catch(() => { setSession(null); setAuthorized(false); }).finally(() => setChecked(true)); }, []);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    try { setCreated(await mutateJson<Created>('/api/v1/platform/organizations', { name, organizer_email: email, organizer_name: organizerName || null, contact_phone: phone || null, event_name: eventName || null, idempotency_key: key }, true)); setDirectoryRefresh(value => value + 1); }
    catch (cause) { setError(safeErrorMessage(cause, 'The organization could not be created.')); }
    finally { setBusy(false); }
  }
  async function resend() { if (!created) return; setBusy(true); setError(''); try { setCreated(await mutateJson<Created>(`/api/v1/platform/organizations/${encodeURIComponent(created.organization_id)}/invitation/resend`, {}, true)); } catch (cause) { setError(safeErrorMessage(cause, 'The account setup invitation could not be resent.')); } finally { setBusy(false); } }
  return <><PageHeader eyebrow="Platform console" title="Organizations" description="Find and manage organizations, or invite a new organizer on the shared application host." />
    <CapabilityNotice capability={capabilities.platformOrganizations}>Platform administrators can create organizations and invite owners. Participant records remain tenant-scoped and unavailable to platform sessions.</CapabilityNotice>
    <OrganizationDirectory authorized={authorized} refreshKey={directoryRefresh}/>
    <div className="organization-layout">
      <section className="panel-section"><SectionHeader title="Create organization" description="Verified membership and MFA protect organizer access. Custom domains remain optional." />
        {!checked ? <Skeleton lines={5} label="Checking platform permissions" /> : !authorized ? <RestrictedState title="Platform administrator access required" description="Sign in with an account holding the tenant.provision grant and complete MFA before creating an organization." action={<ButtonLink href="/">Open shared sign in</ButtonLink>} /> : created ? <SuccessState title={`${name} created`} description="The organization is reserved and the first organizer invitation was requested." action={<div className="organization-success"><dl><div><dt>Organizer</dt><dd>{created.organizer_email}</dd></div><div><dt>Invitation transport</dt><dd>{created.invitation_delivery_status.replaceAll('_', ' ')}</dd></div>{created.event_setup_name && <div><dt>Suggested first event</dt><dd>{created.event_setup_name}</dd></div>}<div><dt>Organization ID</dt><dd><code>{created.organization_id}</code></dd></div></dl><p>Provider acceptance does not prove inbox delivery. The organizer activates membership by accepting the invitation and completing required MFA.</p><div className="page-actions"><Button variant="secondary" loading={busy} loadingText="Sending invitation…" onClick={() => void resend()}>Resend account setup invitation</Button><Button onClick={() => { setCreated(null); setName(''); setEmail(''); setOrganizerName(''); setPhone(''); setEventName(''); setKey(crypto.randomUUID()); }}>Create another organization</Button></div></div>} /> : <form className="organization-create-form" onSubmit={event => void submit(event)}>
          <Field label="Organization name" required maxLength={200} value={name} onChange={event => setName(event.target.value)} />
          <Field label="Organizer email" required type="email" autoComplete="email" value={email} onChange={event => setEmail(event.target.value)} />
          <Field label="Organizer name" hint="Optional" maxLength={160} autoComplete="name" value={organizerName} onChange={event => setOrganizerName(event.target.value)} />
          <Field label="Contact phone" hint="Optional" type="tel" maxLength={40} autoComplete="tel" value={phone} onChange={event => setPhone(event.target.value)} />
          <Field label="First event name" hint="Optional. The organizer sets schedule and publication later." maxLength={200} value={eventName} onChange={event => setEventName(event.target.value)} />
          <Button type="submit" loading={busy} loadingText="Creating organization…">Create and invite organizer</Button>
        </form>}
        {session && <p className="control-note">Authorized as {session.email} · {(session.permission || 'tenant.provision').replace('.', ' ')}</p>}
        {error && <Status tone="danger" title="Organization action failed" instruction={error} announce="assertive" />}
      </section>
      <aside><SectionHeader title="After provisioning" description="Organizer account setup" /><p>The organizer can accept their invitation, complete authenticator setup, and configure their event.</p></aside>
    </div></>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><PlatformConsole provisioning={<Organizations/>}/></StrictMode>);
