import { useEffect, useState, type ReactNode } from 'react';
import { SignOutButton } from './SignOutButton';
import { AppShell, type NavItem } from './AppShell';
import { capabilities } from './capabilities';
import { ButtonLink, CapabilityNotice, ComingSoonState, DataTable, MetricStrip, PageHeader, RestrictedState, SectionHeader, SettingRow, StatusMark, Timeline, UnavailableState } from './components';
import { useHashRoute } from './router';
import { PrivacyNotices } from './PrivacyNotices';

const nav: NavItem[] = [
  {route:'overview',label:'Overview',icon:'overview'}, {route:'organizations',label:'Organizations',icon:'organizations'}, {route:'privacy',label:'Privacy notices',icon:'shield',badge:'Soon'},
  {route:'domains',label:'Domains',icon:'domains'},
  {route:'subscriptions',label:'Subscriptions',icon:'billing',badge:'Soon'},
  {route:'operations',label:'Operations',icon:'operations'}, {route:'settings',label:'Settings',icon:'settings'},
];

type Readiness = { status: string; checks?: { api?: string; database?: string; worker?: string } } | null;
function useReadiness(): Readiness {
  const [readiness, setReadiness] = useState<Readiness>(null);
  useEffect(() => {
    const controller = new AbortController();
    void fetch('/ready', { signal: controller.signal, credentials: 'same-origin' })
      .then(async response => response.ok ? await response.json() as Readiness : { status: 'unavailable', checks: { api: 'unavailable', database: 'unavailable', worker: 'unavailable' } })
      .then(value => setReadiness(value))
      .catch(() => { if (!controller.signal.aborted) setReadiness({ status: 'unavailable', checks: { api: 'unavailable', database: 'unavailable', worker: 'unavailable' } }); });
    return () => controller.abort();
  }, []);
  return readiness;
}
function healthLabel(value: string | undefined) { return value === 'ready' ? 'Ready' : value === 'not_configured' ? 'Not configured' : value ? 'Unavailable' : 'Checking'; }

function Overview({ readiness }: { readiness: Readiness }) { return <><PageHeader eyebrow="Platform console" title="Overview" description="Authoritative service readiness and organization provisioning." actions={<ButtonLink href="#organizations">Create organization</ButtonLink>} /><CapabilityNotice capability={capabilities.platformOverview}>Organization, event, registration, and delivery aggregates are unavailable until the platform exposes an authorized telemetry API.</CapabilityNotice><MetricStrip metrics={[{label:'Service',value:healthLabel(readiness?.status),detail:'Live /ready response'},{label:'API',value:healthLabel(readiness?.checks?.api),detail:'Live /ready response'},{label:'Database',value:healthLabel(readiness?.checks?.database),detail:'Live /ready response'},{label:'Worker',value:healthLabel(readiness?.checks?.worker),detail:'Live /ready response'}]} /><div className="content-grid"><UnavailableState title="Platform activity is unavailable" description="Organization totals, active events, registration activity, delivery backlog, and incident counts need authoritative aggregate endpoints. No estimates are shown." action={<ButtonLink secondary href="#organizations">Open provisioning</ButtonLink>} /><aside className="panel-section"><SectionHeader title="Service status" description="Reported by the readiness endpoint"/><Timeline items={[{time:'Live',title:'API',detail:`Readiness: ${healthLabel(readiness?.checks?.api)}.`},{time:'Live',title:'Database',detail:`Readiness: ${healthLabel(readiness?.checks?.database)}.`},{time:'Live',title:'Worker',detail:`Readiness: ${healthLabel(readiness?.checks?.worker)}.`}]} /></aside></div></>; }

function Domains() { return <><PageHeader eyebrow="Platform console" title="Domains" description="Ownership, DNS, TLS, and routing remain organization scoped." actions={<ButtonLink href="#organizations">Open provisioning</ButtonLink>} /><CapabilityNotice capability={capabilities.platformOrganizations}>The connected domain workflow requires a known organization. A global domain directory API is not available.</CapabilityNotice><UnavailableState title="Choose an organization first" description="Open organization provisioning to create or retrieve an organization, then use its authorized domain workflow. This console does not invent global domain records." action={<ButtonLink secondary href="#organizations">Open organizations</ButtonLink>} /><section className="panel-section"><SectionHeader title="Activation sequence" description="Each boundary is verified independently."/><Timeline items={[{time:'First',title:'Ownership proof',detail:'Verify the one-time DNS TXT challenge.'},{time:'Then',title:'DNS and TLS',detail:'Resolve the hostname and issue a trusted certificate.'},{time:'Then',title:'Routing smoke check',detail:'Confirm the organization is served by the intended ingress.'},{time:'Last',title:'Platform activation',detail:'Approve routing only after all evidence is ready.'}]} /></section></>; }

function Subscriptions() { return <><PageHeader eyebrow="Platform console" title="Subscriptions" description="Commercial plans and provider-reconciled payment activity."/><CapabilityNotice capability={capabilities.subscriptions}/><ComingSoonState title="Subscription management is coming soon" description="Pricing, allowances, renewals, invoices, and Paystack reconciliation are not implemented. Organization provisioning remains available without presenting fictional billing state." detail={<p>Backend dependency: approved plan terms and M2-02 billing contracts.</p>} /></>; }

function Operations({ readiness }: { readiness: Readiness }) { return <><PageHeader eyebrow="Platform console" title="Operations" description="Service readiness without tenant participant data."/><CapabilityNotice capability={capabilities.platformOperations}/><section className="panel-section"><SectionHeader title="Service health" description="Current readiness response"/><DataTable label="Service health" columns={['Service','State','Source']} rows={[["API",<StatusMark tone={readiness?.checks?.api === 'ready' ? 'success' : 'warning'}>{healthLabel(readiness?.checks?.api)}</StatusMark>,'Live readiness endpoint'],["Database",<StatusMark tone={readiness?.checks?.database === 'ready' ? 'success' : 'warning'}>{healthLabel(readiness?.checks?.database)}</StatusMark>,'Live readiness endpoint'],["Worker",<StatusMark tone={readiness?.checks?.worker === 'ready' ? 'success' : 'warning'}>{healthLabel(readiness?.checks?.worker)}</StatusMark>,'Live readiness endpoint']]} /></section><UnavailableState title="Operational telemetry is unavailable" description="Queue depth, delivery backlog, incidents, and provider health require authorized telemetry endpoints. The console shows no estimates or example alerts." /></>; }

function Settings() { return <><PageHeader eyebrow="Platform console" title="Platform settings" description="Authentication policy, administrators, configuration, and integrations."/><SettingRow title="Administrators" description="Current bootstrap grants are authoritative; no administrator directory API exists."><RestrictedState title="Administrator management is restricted" description="Use the approved bootstrap procedure. This browser cannot issue or broaden a platform grant." /></SettingRow><SettingRow title="Security" description="These read-only controls describe enforced server behavior."><label><input type="checkbox" checked readOnly/> MFA required for platform access</label><label><input type="checkbox" checked readOnly/> Secure, host-bound session cookies</label><label><input type="checkbox" checked readOnly/> CSRF and Origin validation</label></SettingRow><SettingRow title="Integrations" description="Operational providers are configured outside the browser."><DataTable label="Platform integrations" columns={['Integration','Management']} rows={[["PostgreSQL",'Environment configuration'],["Redis / Celery",'Environment configuration'],["Private object storage",'Environment configuration'],["Email transport",'Environment configuration']]} /></SettingRow></>; }

export function PlatformConsole({ provisioning }: { provisioning: ReactNode }) {
  const route = useHashRoute('overview');
  const readiness = useReadiness();
  const valid = nav.some(item=>item.route===route) ? route : 'overview';
  const content: Record<string,ReactNode> = { overview:<Overview readiness={readiness}/>, organizations:<>{provisioning}</>, privacy:<PrivacyNotices/>, domains:<Domains/>, subscriptions:<Subscriptions/>, operations:<Operations readiness={readiness}/>, settings:<Settings/> };
  return <AppShell product="Event Check-in" context="Platform" route={valid} nav={nav} utility={<SignOutButton platform />}>{content[valid]}</AppShell>;
}
