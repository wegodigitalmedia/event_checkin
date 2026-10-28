import { SignOutButton } from './product/SignOutButton';
import { StrictMode, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import jsQR from 'jsqr';
import { eventApi, type GateSession, type RedemptionResult } from './event-api';
import { ManagementApiError } from './management-api';
import { safeErrorMessage } from './safe-error';
import { ThemeControl } from './ui';
import { StatusMark } from './product/components';
import { Icon } from './product/icons';
import './product/product.css';
import './product/gate.css';

type Assignment = { event_id: string; event_name: string; gate_id: string; gate_name: string; event_status?: string };
type ScannerState = 'loading' | 'unauthorized' | 'ready' | 'scanning' | 'verifying' | 'result' | 'error';
type BarcodeDetectorLike = { detect(source: CanvasImageSource): Promise<{ rawValue: string }[]> };
type BarcodeDetectorConstructor = new (options: { formats: string[] }) => BarcodeDetectorLike;
function readable(error: unknown) { return safeErrorMessage(error, 'The scanner could not complete the request.'); }
function sessionAssignments(session: GateSession | null): Assignment[] {
  if (!session) return [];
  if (session.assignments?.length) return session.assignments;
  return session.event_id && session.gate_id ? [{ event_id: session.event_id, event_name: session.event_name || 'Assigned event', gate_id: session.gate_id, gate_name: session.gate_name || 'Assigned gate' }] : [];
}

function GateApp() {
  const [state, setState] = useState<ScannerState>('loading'); const [session, setSession] = useState<GateSession | null>(null);
  const [assignmentKey, setAssignmentKey] = useState(''); const [credential, setCredential] = useState(''); const [result, setResult] = useState<RedemptionResult | null>(null); const [error, setError] = useState('');
  const [retryCredential, setRetryCredential] = useState('');
  const [networkAvailable, setNetworkAvailable] = useState(navigator.onLine);
  const video = useRef<HTMLVideoElement>(null); const stream = useRef<MediaStream | null>(null); const scanning = useRef(false);
  const available = useMemo(() => sessionAssignments(session), [session]); const active = available.find(item => `${item.event_id}:${item.gate_id}` === assignmentKey) || available[0];

  useEffect(() => { void (async () => { try { const next = await eventApi.gateSession(); const found = sessionAssignments(next); setSession(next); setAssignmentKey(found[0] ? `${found[0].event_id}:${found[0].gate_id}` : ''); setError(found.length ? '' : 'This account has no active event and gate assignment. Ask an organizer or gate supervisor to assign access.'); setState(found.length ? 'ready' : 'unauthorized'); } catch (cause) { setError(readable(cause)); setState('unauthorized'); } })(); return () => { scanning.current = false; stream.current?.getTracks().forEach(track => track.stop()); }; }, []);
  useEffect(() => { const update = () => setNetworkAvailable(navigator.onLine); addEventListener('online', update); addEventListener('offline', update); return () => { removeEventListener('online', update); removeEventListener('offline', update); }; }, []);
  useEffect(() => {
    if (state !== 'scanning' || !video.current || !stream.current) return;
    video.current.srcObject = stream.current;
    void video.current.play().then(() => scanFrames());
  }, [state]);
  async function redeem(value: string) {
    if (!active || !value.trim() || state === 'verifying') return;
    setRetryCredential(value.trim());
    scanning.current = false; stream.current?.getTracks().forEach(track => track.stop()); setState('verifying'); setError(''); setResult(null);
    try { setResult(await eventApi.redeem(active.event_id, active.gate_id, value.trim())); setCredential(''); setRetryCredential(''); setState('result'); } catch (cause) { if (cause instanceof ManagementApiError && [401,403].includes(cause.status)) { setCredential(''); setRetryCredential(''); setError('Your gate session or assignment has expired. Sign in again.'); setState('unauthorized'); } else { setError(readable(cause)); setState('error'); } }
  }
  async function scanFrames() {
    const Detector = (window as typeof window & { BarcodeDetector?: BarcodeDetectorConstructor }).BarcodeDetector;
    let detector: BarcodeDetectorLike | null = null;
    try { if (Detector) detector = new Detector({ formats: ['qr_code'] }); } catch { /* use the bundled decoder */ }
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (!context) { setError('Camera frames cannot be read on this device. Use the secure manual credential field.'); scanning.current = false; stream.current?.getTracks().forEach(track => track.stop()); setState('ready'); return; }
    while (scanning.current && video.current) {
      let found = '';
      if (detector) {
        try { found = (await detector.detect(video.current))[0]?.rawValue || ''; }
        catch { detector = null; }
      }
      if (!found && !detector && video.current.videoWidth && video.current.videoHeight) {
        const width = Math.min(video.current.videoWidth, 960);
        const height = Math.round(video.current.videoHeight * width / video.current.videoWidth);
        canvas.width = width; canvas.height = height;
        context.drawImage(video.current, 0, 0, width, height);
        const frame = context.getImageData(0, 0, width, height);
        found = jsQR(frame.data, width, height, { inversionAttempts: 'attemptBoth' })?.data || '';
      }
      if (found) { await redeem(found); break; }
      await new Promise(resolve => setTimeout(resolve, 180));
    }
  }
  async function openCamera() {
    setError('');
    if (!navigator.mediaDevices?.getUserMedia) { setError('Camera scanning is not supported by this browser. Use the secure manual credential field.'); return; }
    try { stream.current = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false }); scanning.current = true; setState('scanning'); }
    catch (cause) {
      if (cause instanceof DOMException && cause.name === 'NotAllowedError') setError('Camera access was denied. Allow camera permission in the browser or use the secure manual credential field.');
      else if (cause instanceof DOMException && cause.name === 'NotFoundError') setError('No usable camera was found on this device. Use the secure manual credential field.');
      else setError('The camera could not be started. Check device access or use the secure manual credential field.');
    }
  }
  function reset() { setResult(null); setRetryCredential(''); setError(''); setState('ready'); }
  const tone = result?.outcome === 'accepted' ? 'success' : result?.outcome === 'duplicate' ? 'warning' : 'danger';
  const reason = result?.reason_code || (result?.outcome === 'accepted' ? 'ACCEPTED' : result?.outcome === 'duplicate' ? 'DUPLICATE_ADMISSION' : result?.outcome === 'revoked' ? 'REVOKED_TICKET' : 'INVALID_TICKET');
  const resultCopy: Record<RedemptionResult['reason_code'], { title: string; description: string }> = {
    ACCEPTED: { title: 'Admission confirmed', description: 'The server recorded one admission for this ticket.' },
    DUPLICATE_ADMISSION: { title: 'Already checked in', description: 'The server recorded an earlier admission. Do not admit again.' },
    REVOKED_TICKET: { title: 'Ticket revoked', description: 'The server confirmed this credential is revoked. Do not admit.' },
    INVALID_TICKET: { title: 'Ticket not accepted', description: 'The server could not validate this ticket. No admission was recorded.' },
    EVENT_UNAVAILABLE: { title: 'Event unavailable', description: 'This event is not available for admission. Ask an organizer to verify its published state.' },
    GATE_UNAVAILABLE: { title: 'Gate unavailable', description: 'This gate is not active for the selected event. Ask a supervisor to verify the assignment.' },
    CHECKIN_NOT_OPEN: { title: 'Check-in has not opened', description: 'The configured check-in window has not started. Do not admit yet.' },
    CHECKIN_CLOSED: { title: 'Check-in is closed', description: 'The configured check-in window has ended. Ask a supervisor for assistance.' },
    CHECKIN_WINDOW_UNAVAILABLE: { title: 'Check-in window unavailable', description: 'No complete check-in window is configured. Ask an organizer to correct the event.' },
  };
  const { title, description: resultDescription } = resultCopy[reason] ?? resultCopy.INVALID_TICKET;
  const eventAvailable = !active?.event_status || active.event_status === 'published';

  return <main className="gate-app">
    <header className="gate-header"><a href="/workspace.html#check-in" className="wordmark"><span className="wordmark-mark">E</span><span>Gate</span></a><div><StatusMark tone={networkAvailable ? 'success' : 'danger'}>{networkAvailable ? 'Network available' : 'Offline'}</StatusMark><ThemeControl compact />{session && <SignOutButton beforeSignOut={() => { scanning.current = false; stream.current?.getTracks().forEach(track => track.stop()); setCredential(''); setRetryCredential(''); setResult(null); setState('ready'); }} />}</div></header>
    {state === 'loading' && <section className="gate-result gate-result--neutral" aria-live="polite"><span className="gate-spinner"/><h1>Checking assignment</h1><p>Confirming this secure session with the server.</p></section>}
    {state === 'unauthorized' && <section className="gate-panel"><div className="gate-hero"><Icon name="shield"/><h1>Gate access required</h1><p>Sign in with an assigned gate-staff account. Event and gate scope are supplied by the server, not this device.</p><a className="product-button" href="/">Sign in</a>{error && <p role="alert" className="request-error">{error}</p>}</div></section>}
    {active && state !== 'loading' && state !== 'unauthorized' && <section className="gate-context"><div><p>{active.event_name}</p><h1>{active.gate_name}</h1></div>{available.length > 1 ? <label><span className="sr-only">Assigned gate</span><select value={assignmentKey} onChange={event => setAssignmentKey(event.target.value)}>{available.map(item => <option key={`${item.event_id}:${item.gate_id}`} value={`${item.event_id}:${item.gate_id}`}>{item.event_name} · {item.gate_name}</option>)}</select></label> : <StatusMark tone="success">Assigned</StatusMark>}</section>}
    {state === 'ready' && <section className="gate-panel"><div className="gate-hero"><Icon name="camera"/><h2>Ready to scan</h2><p>Admission appears only after the server atomically redeems the ticket for this assigned gate.</p></div><dl className="readiness-list"><div><dt>Secure connection</dt><dd><StatusMark tone={window.isSecureContext ? 'success' : 'danger'}>{window.isSecureContext ? 'Ready' : 'Secure context required'}</StatusMark></dd></div><div><dt>Device network</dt><dd><StatusMark tone={networkAvailable ? 'success' : 'danger'}>{networkAvailable ? 'Available; server checked on scan' : 'Do not admit'}</StatusMark></dd></div><div><dt>Assignment</dt><dd><StatusMark tone="success">Server confirmed</StatusMark></dd></div></dl><div className="gate-actions"><button className="product-button" disabled={!networkAvailable || !window.isSecureContext || !eventAvailable} aria-describedby={!networkAvailable || !window.isSecureContext || !eventAvailable ? 'scanner-disabled-reason' : undefined} onClick={() => void openCamera()}>Open camera</button></div><form className="manual-scan" onSubmit={event => { event.preventDefault(); void redeem(credential); }}><label>Secure manual credential<input value={credential} onChange={event => setCredential(event.target.value)} autoComplete="off" spellCheck={false}/></label><button className="product-button product-button--secondary" disabled={!credential.trim() || !networkAvailable || !eventAvailable} aria-describedby={!networkAvailable || !eventAvailable ? 'scanner-disabled-reason' : undefined}>Verify with server</button></form>{(!networkAvailable || !window.isSecureContext || !eventAvailable) && <p className="gate-disabled-reason" id="scanner-disabled-reason" role="status">{!networkAvailable ? 'Restore the network before scanning. An offline decode is never an admission.' : !window.isSecureContext ? 'Open this scanner over a secure connection before using the camera.' : `This event is ${active?.event_status}. Scanning is available only for a published event.`}</p>}{error && <p className="request-error" role="alert">{error}</p>}</section>}
    {state === 'scanning' && <section className="scanner-panel"><div className="camera-preview"><video ref={video} muted playsInline aria-label="QR camera preview"/><div className="scan-frame"/><p>Hold the QR code inside the frame</p></div><div className="scanner-foot"><p><strong>Online verification active</strong><br/>Waiting for a QR credential.</p><button className="product-button product-button--secondary" onClick={() => { scanning.current = false; stream.current?.getTracks().forEach(track => track.stop()); reset(); }}>Cancel</button></div>{error && <p className="request-error" role="alert">{error}</p>}</section>}
    {state === 'verifying' && <section className="gate-result gate-result--neutral" aria-live="polite"><span className="gate-spinner"/><h2>Verifying with server</h2><p>Do not admit until a confirmed result appears.</p></section>}
    {state === 'result' && result && <section className={`gate-result gate-result--${tone}`} aria-live="assertive"><Icon name={tone === 'success' ? 'checkin' : 'warning'}/><p className="gate-result-label">Server-confirmed result</p><h2>{title}</h2><p>{resultDescription}</p><time>{new Date(result.confirmed_at).toLocaleTimeString()}</time><button className="product-button" onClick={reset}>Scan next ticket</button></section>}
    {state === 'error' && <section className="gate-result gate-result--danger" aria-live="assertive"><Icon name="warning"/><p className="gate-result-label">Confirmation unavailable</p><h2>Do not admit</h2><p>{error || 'Restore the connection and retry this credential. The server may have recorded the first attempt.'}</p><div className="gate-actions"><button className="product-button" disabled={!retryCredential} onClick={() => void redeem(retryCredential)}>Retry same credential</button><button className="product-button product-button--secondary" onClick={reset}>Return to scanner</button></div></section>}
    <footer className="gate-note"><Icon name="shield"/><p>Online server confirmation is mandatory. No participant identity is shown to gate staff.</p></footer>
  </main>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><GateApp/></StrictMode>);
