import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { Organization, OrganizationPage, organizationDetail, organizationPage } from './organization-api';

const PAGE_SIZE = 25;

export function OrganizationDirectory({ authorized, refreshKey }: { authorized: boolean; refreshKey: number }) {
  const [input, setInput] = useState('');
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<OrganizationPage | null>(null);
  const [selected, setSelected] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [copied, setCopied] = useState(false);
  const listRequest = useRef(0);
  const detailRequest = useRef(0);

  const load = useCallback(async () => {
    const request = ++listRequest.current;
    setLoading(true); setError('');
    try { const result = await organizationPage(query, offset, PAGE_SIZE); if (request === listRequest.current) setPage(result); }
    catch (cause) { if (request === listRequest.current) { setPage(null); setError(cause instanceof Error ? cause.message : 'Could not load organizations.'); } }
    finally { if (request === listRequest.current) setLoading(false); }
  }, [query, offset, refreshKey]);
  useEffect(() => { if (authorized) void load(); }, [authorized, load]);

  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setOffset(0);
    setQuery(input.trim());
    if (query === input.trim() && offset === 0) void load();
  }
  async function select(id: string) {
    const request = ++detailRequest.current;
    setDetailLoading(true); setDetailError(''); setCopied(false);
    try { const result = await organizationDetail(id); if (request === detailRequest.current) setSelected(result); }
    catch (cause) { if (request === detailRequest.current) { setSelected(null); setDetailError(cause instanceof Error ? cause.message : 'Could not load organization details.'); } }
    finally { if (request === detailRequest.current) setDetailLoading(false); }
  }
  async function copy() {
    if (!selected) return;
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(selected.id);
      setCopied(true);
    } catch {
      const field = document.createElement('textarea');
      field.value = selected.id;
      field.style.position = 'fixed'; field.style.opacity = '0';
      let copiedWithFallback = false;
      try {
        document.body.append(field); field.select();
        copiedWithFallback = document.execCommand('copy');
      } catch { /* Manual selection remains available. */ }
      finally { field.remove(); }
      if (copiedWithFallback) setCopied(true);
      else setDetailError('Could not copy the ID. Select the text to copy it manually.');
    }
  }

  if (!authorized) return null;
  return <section className="panel-section organization-directory" aria-labelledby="organization-directory-title">
    <div className="section-header"><div><h2 id="organization-directory-title">Existing organizations</h2><p>Search by organization name, internal slug, or organizer email.</p></div><button className="product-button product-button--secondary" disabled={loading} onClick={() => void load()}>Refresh</button></div>
    <form className="organization-search" onSubmit={search} role="search"><label htmlFor="organization-query">Find organization</label><div><input id="organization-query" value={input} maxLength={100} onChange={event => setInput(event.target.value)} placeholder="Name or organizer email"/><button className="product-button" type="submit" disabled={loading}>Search</button></div></form>
    {loading && <p role="status">Loading organizations…</p>}
    {error && <div className="request-error" role="alert">{error} <button className="text-action" onClick={() => void load()}>Retry</button></div>}
    {!loading && !error && page && <>
      <p className="directory-count" role="status">{page.total === 0 ? 'No organizations found' : `Showing ${page.offset + 1}–${page.offset + page.organizations.length} of ${page.total} organizations`}</p>
      {page.total === 0 ? <p>{query ? 'Try a different name or organizer email.' : 'Create an organization to get started.'}</p> : <div className="organization-list" role="list" aria-label="Organizations">{page.organizations.map(organization => <div className="organization-list-row" role="listitem" key={organization.id}>
        <div><strong>{organization.name}</strong><small>{organization.primary_organizer || 'No primary organizer recorded'}</small></div><span className="organization-state">{organization.status}</span><button className="product-button product-button--secondary" onClick={() => void select(organization.id)} aria-label={`View ${organization.name}`}>View details</button>
      </div>)}</div>}
      {page.total > PAGE_SIZE && <div className="page-actions"><button className="product-button product-button--secondary" disabled={loading || offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous</button><button className="product-button product-button--secondary" disabled={loading || !page.has_more} onClick={() => setOffset(offset + PAGE_SIZE)}>Next</button></div>}
    </>}
    {detailLoading && <p role="status">Loading organization details…</p>}
    {detailError && <p className="request-error" role="alert">{detailError}</p>}
    {selected && !detailLoading && <section className="organization-detail" aria-labelledby="selected-organization-title"><h3 id="selected-organization-title">{selected.name}</h3>
      <dl><div><dt>Status</dt><dd>{selected.status}</dd></div><div><dt>Primary organizer</dt><dd>{selected.primary_organizer || 'Not recorded'}</dd></div><div><dt>Invitation transport</dt><dd>{selected.invitation_delivery_status?.replaceAll('_', ' ') || 'Not recorded'}</dd></div><div><dt>Created</dt><dd>{new Date(selected.created_at).toLocaleString()}</dd></div><div><dt>Organization UUID</dt><dd><code>{selected.id}</code></dd></div></dl>
      <div className="page-actions"><button className="product-button product-button--secondary" onClick={() => void copy()}>{copied ? 'Copied' : 'Copy UUID'}</button></div>
    </section>}
  </section>;
}
