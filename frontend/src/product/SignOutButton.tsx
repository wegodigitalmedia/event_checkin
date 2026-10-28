import { useRef, useState } from 'react';
import { mutateJson } from '../management-api';
import { Button } from '../ui';

export function SignOutButton({ platform = false, beforeSignOut }: {
  platform?: boolean;
  beforeSignOut?: () => void;
}) {
  const pending = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function signOut() {
    if (pending.current) return;
    pending.current = true; setBusy(true); setError('');
    try {
      beforeSignOut?.();
      await mutateJson(platform ? '/api/v1/platform/auth/logout' : '/api/v1/auth/logout', {}, platform);
      sessionStorage.removeItem('staff_session_seen');
      location.assign('/');
    } catch {
      setError('Could not sign out. Check your connection and try again.');
      pending.current = false; setBusy(false);
    }
  }
  return <div className="sign-out-control">
    <Button variant="secondary" loading={busy} loadingText="Signing out…" onClick={() => void signOut()}>Sign out</Button>
    {error && <p role="alert">{error}</p>}
  </div>;
}
