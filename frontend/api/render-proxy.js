import { proxyToRender } from '../lib/render-proxy.js';

export const config = { api: { bodyParser: false } };

export default async function handler(request, response) {
  const path = request.query.__render_path;
  const url = new URL(request.url, 'https://proxy.invalid');
  const routingValues = url.searchParams.getAll('__render_path');
  if (typeof path !== 'string' || !path || routingValues.length > 1
    || (routingValues.length === 1 && routingValues[0] !== path)
    || /[\\?#%\s\x00-\x1f\x7f]/.test(path)
    || path.split('/').some(segment => !segment || segment === '.' || segment === '..')) {
    response.setHeader('Cache-Control', 'no-store');
    return response.status(400).json({ detail: { code: 'INVALID_API_PATH' } });
  }
  url.searchParams.delete('__render_path');
  await proxyToRender(request, response, `/api/${path}${url.search}`);
}
