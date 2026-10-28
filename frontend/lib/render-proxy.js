import { isIP } from 'node:net';

const REQUEST_HEADERS = ['accept', 'content-type', 'cookie', 'origin', 'user-agent', 'x-csrf-token'];
const RESPONSE_HEADERS = ['content-disposition', 'content-type', 'referrer-policy', 'x-content-type-options'];
const MAX_REQUEST_BYTES = 12 * 1024 * 1024;

function singleHeader(value) {
  return Array.isArray(value) ? value[0] : value;
}

async function body(request) {
  if (request.method === 'GET' || request.method === 'HEAD') return undefined;
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_REQUEST_BYTES) throw new Error('REQUEST_TOO_LARGE');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export async function proxyToRender(request, response, targetPath) {
  response.setHeader('Cache-Control', 'no-store');
  const configuredOrigin = process.env.RENDER_API_ORIGIN;
  let origin;
  try {
    origin = new URL(configuredOrigin);
    if (origin.protocol !== 'https:' || origin.username || origin.password
      || origin.pathname !== '/' || origin.search || origin.hash) throw new Error('INVALID_ORIGIN');
  } catch {
    response.status(503).json({ detail: { code: 'ORIGIN_UNAVAILABLE' } });
    return;
  }
  const originSecret = process.env.ORIGIN_AUTH_SECRET;
  if (!originSecret) {
    response.status(503).json({ detail: { code: 'ORIGIN_UNAVAILABLE' } });
    return;
  }
  const publicHost = typeof request.headers.host === 'string' ? request.headers.host.toLowerCase() : undefined;
  const clientIp = typeof request.headers['x-real-ip'] === 'string' ? request.headers['x-real-ip'] : undefined;
  if (!publicHost || !/^[a-z0-9.-]+$/.test(publicHost) || !clientIp || !isIP(clientIp)) {
    response.status(400).json({ detail: { code: 'INVALID_INGRESS' } });
    return;
  }
  const headers = {};
  for (const name of REQUEST_HEADERS) {
    const value = singleHeader(request.headers[name]);
    if (value) headers[name] = value;
  }
  headers['x-eventcheckin-origin-auth'] = originSecret;
  headers['x-eventcheckin-public-host'] = publicHost;
  headers['x-eventcheckin-client-ip'] = clientIp;
  try {
    const target = new URL(targetPath, origin);
    if (target.origin !== origin.origin || !(target.pathname.startsWith('/api/') || target.pathname === '/ready')) {
      response.status(400).json({ detail: { code: 'INVALID_API_PATH' } });
      return;
    }
    const upstream = await fetch(target, {
      method: request.method,
      headers,
      body: await body(request),
      redirect: 'manual',
    });
    response.status(upstream.status);
    for (const name of RESPONSE_HEADERS) {
      const value = upstream.headers.get(name);
      if (value) response.setHeader(name, value);
    }
    const cookies = upstream.headers.getSetCookie();
    if (cookies.length) response.setHeader('set-cookie', cookies);
    response.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (error) {
    const status = error instanceof Error && error.message === 'REQUEST_TOO_LARGE' ? 413 : 502;
    response.status(status).json({ detail: { code: status === 413 ? 'REQUEST_TOO_LARGE' : 'ORIGIN_UNAVAILABLE' } });
  }
}
