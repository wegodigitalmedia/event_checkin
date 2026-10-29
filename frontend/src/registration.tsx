import { StrictMode, useEffect, useState, type FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import { Button, Field, Status, ThemeControl } from './ui';
import { safeMessageForStatus } from './safe-error';
import './registration.css';

type Question = { key: string; label: string; type: 'text' | 'textarea' | 'select' | 'checkbox'; required: boolean; options?: string[] };
type PublicEvent = {
  slug: string; name: string; location: string | null; starts_at: string; ends_at: string;
  timezone: string; available: boolean; form_version: number;
  form_schema: { fields: Question[] };
  privacy_notice: { version: number; body: string } | null;
};
type Answers = Record<string, string | boolean>;
type PublicBrand = { display_name: string; logo_url: string | null; primary_color: string | null;
  accent_color: string | null; action_text_color: string | null; sender_name: string | null; revision: number };

function displayTime(instant: string, zone: string): string {
  return new Intl.DateTimeFormat('en-NG', { dateStyle: 'full', timeStyle: 'short', timeZone: zone }).format(new Date(instant));
}

function App() {
  const [event, setEvent] = useState<PublicEvent | null>(null);
  const [brand, setBrand] = useState<PublicBrand | null>(null);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [complete, setComplete] = useState(false);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [answers, setAnswers] = useState<Answers>({});
  const [acknowledged, setAcknowledged] = useState(false);
  const [marketing, setMarketing] = useState(false);
  const slug = new URLSearchParams(location.search).get('event') ?? '';

  useEffect(() => {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(slug)) {
      setError('This event link is unavailable. Ask the organizer for a current link.');
      setLoading(false);
      return;
    }
    void fetch(`/api/v1/public/events/${encodeURIComponent(slug)}`, { cache: 'no-store', credentials: 'omit' })
      .then(async (response) => {
        if (!response.ok) throw new Error('This event is unavailable. Ask the organizer for a current link.');
        return response.json() as Promise<PublicEvent>;
      })
      .then(setEvent)
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'The event could not be loaded.'))
      .finally(() => setLoading(false));
    void fetch('/api/v1/branding/public', { cache: 'no-store', credentials: 'omit' })
      .then((response) => response.ok ? response.json() as Promise<PublicBrand> : null)
      .then((result) => { if (result) setBrand(result); })
      .catch(() => { /* Event registration retains safe platform styling. */ });
  }, [slug]);

  function submit(form: FormEvent<HTMLFormElement>) {
    form.preventDefault();
    if (!event || !event.available || sending) return;
    setSending(true); setError('');
    void fetch(`/api/v1/public/events/${encodeURIComponent(event.slug)}/registrations`, {
      method: 'POST', cache: 'no-store', credentials: 'omit',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ full_name: name, email, phone, custom_answers: answers,
        form_version: event.form_version, notice_version: event.privacy_notice?.version,
        notice_acknowledged: acknowledged, marketing_opt_in: marketing }),
    }).then(async (response) => {
      if (!response.ok) {
        throw new Error(safeMessageForStatus(response.status, 'Registration could not be completed. Try again.'));
      }
      setComplete(true);
    }).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'Registration could not be completed.'))
      .finally(() => setSending(false));
  }

  return <main className="registration-page">
    <header className="registration-header">
      <span className="registration-mark">{brand?.logo_url && <img src={brand.logo_url} alt="" className="registration-logo" />}
        {brand?.display_name || 'Event Check-in'}</span>
      <ThemeControl compact />
    </header>
    {loading && <Status tone="info" title="Loading event" instruction="Checking registration availability." announce="polite" />}
    {!loading && !event && <Status tone="warning" title="Event unavailable" instruction={error || 'Ask the organizer for a current registration link.'} announce="polite" />}
    {event && <div className="registration-layout">
      <section className="registration-intro" aria-labelledby="event-title">
        <p className="registration-kicker" style={brand?.accent_color ? { borderColor: brand.accent_color } : undefined}>Registration</p>
        <h1 id="event-title">{event.name}</h1>
        <p className="registration-schedule">{displayTime(event.starts_at, event.timezone)}</p>
        <p className="registration-end">Ends {displayTime(event.ends_at, event.timezone)}</p>
        {event.location && <p>{event.location}</p>}
        <div className="registration-assurance"><strong>What happens next</strong><p>We will email your QR ticket if registration can be completed. Keep it private—it is a bearer credential.</p></div>
      </section>
      {complete ? <section className="registration-card"><Status tone="success" title="Request received"
        instruction="If your registration can be completed, your ticket will arrive by email. Check spam or ask the organizer for delivery help."
        announce="polite" /></section>
      : !event.available ? <section className="registration-card"><Status tone="warning" title="Registration unavailable"
        instruction="Registration is not open on this page. Ask the organizer if you need help." announce="polite" /></section>
      : <section className="registration-card" aria-labelledby="register-title">
        <h2 id="register-title">Reserve your place</h2>
        <p className="registration-muted">Enter your own details. Your ticket will be sent to the email address you provide.</p>
        <form onSubmit={submit} className="registration-form">
          <Field label="Full name" autoComplete="name" value={name} onChange={(change) => setName(change.target.value)} required maxLength={160} />
          <Field label="Email address" type="email" autoComplete="email" value={email} onChange={(change) => setEmail(change.target.value)} required maxLength={254} />
          <Field label="Phone number" type="tel" autoComplete="tel" value={phone} onChange={(change) => setPhone(change.target.value)} required
            hint="Use international format, for example +234 801 234 5678." maxLength={40} />
          {event.form_schema.fields.map((field) => <div className="registration-custom" key={field.key}>
            {field.type === 'text' ? <Field label={field.label} value={String(answers[field.key] ?? '')} required={field.required}
              onChange={(change) => setAnswers({ ...answers, [field.key]: change.target.value })} maxLength={500} />
            : field.type === 'textarea' ? <label className="registration-label">{field.label}<textarea value={String(answers[field.key] ?? '')}
              required={field.required} maxLength={2000} onChange={(change) => setAnswers({ ...answers, [field.key]: change.target.value })} /></label>
            : field.type === 'select' ? <label className="registration-label">{field.label}<select value={String(answers[field.key] ?? '')}
              required={field.required} onChange={(change) => setAnswers({ ...answers, [field.key]: change.target.value })}>
              <option value="">Choose an option</option>{field.options?.map((option) => <option key={option}>{option}</option>)}</select></label>
            : <label className="registration-check"><input type="checkbox" checked={answers[field.key] === true} required={field.required}
              onChange={(change) => setAnswers({ ...answers, [field.key]: change.target.checked })} />{field.label}</label>}
          </div>)}
          {event.privacy_notice && <div className="registration-privacy">
            <h3>Privacy notice</h3><p className="registration-notice">{event.privacy_notice.body}</p>
            <label className="registration-check"><input type="checkbox" required checked={acknowledged}
              onChange={(change) => setAcknowledged(change.target.checked)} />I have read the privacy notice.</label>
            <label className="registration-check"><input type="checkbox" checked={marketing}
              onChange={(change) => setMarketing(change.target.checked)} />I would like optional event updates. This choice does not affect registration.</label>
          </div>}
          {error && <Status tone="danger" title="Check your registration" instruction={error} announce="assertive" />}
          <Button type="submit" loading={sending} loadingText="Submitting…" touchCritical
            style={brand?.primary_color && brand.action_text_color ?
              { backgroundColor: brand.primary_color, color: brand.action_text_color,
                borderColor: brand.primary_color } : undefined}>Submit registration</Button>
          <p className="registration-muted">Need help with delivery? Contact the event organizer. Please do not submit again just to check your status.</p>
        </form>
      </section>}
    </div>}
  </main>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
