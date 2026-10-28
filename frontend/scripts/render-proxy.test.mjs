import assert from 'node:assert/strict';
import test from 'node:test';

import { proxyToRender } from '../lib/render-proxy.js';

class Reply {
  headers = {};
  statusCode = 200;
  payload = null;

  status(value) { this.statusCode = value; return this; }
  json(value) { this.payload = value; return this; }
  setHeader(name, value) { this.headers[name.toLowerCase()] = value; }
  send(value) { this.payload = value; }
}

function request(chunks = []) {
  return {
    method: chunks.length ? 'POST' : 'GET',
    url: '/api/v1/test?safe=1',
    headers: {
      host: 'platform.events.example.test',
      'x-real-ip': '203.0.113.8',
      accept: 'application/json',
      authorization: 'must-not-forward',
      cookie: '__Host-session=opaque',
      origin: 'https://platform.events.example.test',
      'x-csrf-token': 'opaque-csrf',
      'content-type': 'application/json',
    },
    async *[Symbol.asyncIterator]() { for (const chunk of chunks) yield chunk; },
  };
}

test('production proxy fails closed when origin configuration is absent', async () => {
  const previousOrigin = process.env.RENDER_API_ORIGIN;
  const previousSecret = process.env.ORIGIN_AUTH_SECRET;
  delete process.env.RENDER_API_ORIGIN;
  delete process.env.ORIGIN_AUTH_SECRET;
  const reply = new Reply();
  await proxyToRender(request(), reply, '/ready');
  assert.equal(reply.statusCode, 503);
  assert.equal(reply.payload.detail.code, 'ORIGIN_UNAVAILABLE');
  if (previousOrigin) process.env.RENDER_API_ORIGIN = previousOrigin;
  if (previousSecret) process.env.ORIGIN_AUTH_SECRET = previousSecret;
});

test('production proxy forwards only approved browser and private ingress headers', async () => {
  process.env.RENDER_API_ORIGIN = 'https://origin.example.test';
  process.env.ORIGIN_AUTH_SECRET = 'synthetic-origin-secret';
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url: String(url), options };
    return new Response('{"ok":true}', {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'set-cookie': '__Host-session=opaque; Secure; HttpOnly; SameSite=Strict',
      },
    });
  };
  try {
    const reply = new Reply();
    await proxyToRender(request([Buffer.from('{"safe":true}')]), reply, '/api/v1/test?safe=1');
    assert.equal(captured.url, 'https://origin.example.test/api/v1/test?safe=1');
    assert.equal(captured.options.headers.authorization, undefined);
    assert.equal(captured.options.headers.cookie, '__Host-session=opaque');
    assert.equal(captured.options.headers['x-eventcheckin-origin-auth'], 'synthetic-origin-secret');
    assert.equal(captured.options.headers['x-eventcheckin-public-host'], 'platform.events.example.test');
    assert.equal(captured.options.headers['x-eventcheckin-client-ip'], '203.0.113.8');
    assert.equal(String(captured.options.body), '{"safe":true}');
    assert.equal(reply.statusCode, 200);
    assert.match(String(reply.headers['set-cookie']), /__Host-session/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('production proxy rejects oversized bodies before contacting Render', async () => {
  process.env.RENDER_API_ORIGIN = 'https://origin.example.test';
  process.env.ORIGIN_AUTH_SECRET = 'synthetic-origin-secret';
  const originalFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; throw new Error('unexpected'); };
  try {
    const reply = new Reply();
    await proxyToRender(request([Buffer.alloc(12 * 1024 * 1024 + 1)]), reply, '/api/v1/import');
    assert.equal(called, false);
    assert.equal(reply.statusCode, 413);
    assert.equal(reply.payload.detail.code, 'REQUEST_TOO_LARGE');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('proxy preserves multiple host-only cookies and browser CSRF headers', async () => {
  process.env.RENDER_API_ORIGIN = 'https://event-checkin-backend-1qd3.onrender.com';
  process.env.ORIGIN_AUTH_SECRET = 'synthetic-origin-secret';
  const originalFetch = globalThis.fetch;
  const cookies = [
    '__Host-ecs_csrf=opaque; Path=/; Secure; HttpOnly; SameSite=Strict',
    '__Host-ecs_session=opaque; Path=/; Secure; HttpOnly; SameSite=Strict; Expires=Wed, 01 Jan 2031 00:00:00 GMT',
  ];
  globalThis.fetch = async (url, options) => {
    assert.equal(new URL(url).hostname, 'event-checkin-backend-1qd3.onrender.com');
    assert.equal(options.headers.origin, 'https://platform.events.example.test');
    assert.equal(options.headers['x-csrf-token'], 'opaque-csrf');
    assert.equal(options.headers.cookie, '__Host-session=opaque');
    assert.equal(options.headers['x-eventcheckin-public-host'], 'platform.events.example.test');
    assert.equal(options.redirect, 'manual');
    return new Response('{}', { headers: [
      ['set-cookie', cookies[0]], ['set-cookie', cookies[1]], ['cache-control', 'public, max-age=60'],
    ] });
  };
  try {
    const reply = new Reply();
    await proxyToRender(request(), reply, '/api/v1/auth/csrf');
    assert.deepEqual(reply.headers['set-cookie'], cookies);
    assert.equal(reply.headers['cache-control'], 'no-store');
    assert.ok(reply.headers['set-cookie'].every(cookie => !/\bdomain=/i.test(cookie)));
    assert.ok(!JSON.stringify(reply).includes(process.env.ORIGIN_AUTH_SECRET));
  } finally { globalThis.fetch = originalFetch; }
});

test('proxy rejects non-origin URLs and ambiguous ingress without fetching', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('must not fetch'); };
  try {
    process.env.ORIGIN_AUTH_SECRET = 'synthetic-origin-secret';
    for (const origin of ['http://backend.test', 'https://user:password@backend.test', 'https://backend.test/api', 'https://backend.test?key=value']) {
      process.env.RENDER_API_ORIGIN = origin;
      const reply = new Reply();
      await proxyToRender(request(), reply, '/api/v1/auth/csrf');
      assert.equal(reply.statusCode, 503);
    }
    process.env.RENDER_API_ORIGIN = 'https://origin.example.test';
    for (const headers of [
      { host: ['one.example', 'two.example'], 'x-real-ip': '203.0.113.8' },
      { host: 'platform.example.test', 'x-real-ip': ['203.0.113.8', '1.2.3.4'] },
      { host: 'platform.example.test', 'x-real-ip': '203.0.113.8, 1.2.3.4' },
    ]) {
      const reply = new Reply();
      await proxyToRender({ ...request(), headers }, reply, '/api/v1/auth/csrf');
      assert.equal(reply.statusCode, 400);
    }
  } finally { globalThis.fetch = originalFetch; }
});

test('named Vercel handler forwards path and query without routing metadata', async () => {
  const { default: handler, config } = await import('../api/render-proxy.js');
  assert.equal(config.api.bodyParser, false);
  process.env.RENDER_API_ORIGIN = 'https://origin.example.test';
  process.env.ORIGIN_AUTH_SECRET = 'synthetic-origin-secret';
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async url => { captured = new URL(url); return new Response('{}'); };
  try {
    const incoming = request();
    incoming.url = '/api/render-proxy?__render_path=v1%2Fevents&limit=25&q=a%2Bb&tag=one&tag=two';
    incoming.query = { __render_path: 'v1/events', limit: '25', q: 'a+b', tag: ['one', 'two'] };
    await handler(incoming, new Reply());
    assert.equal(captured.pathname, '/api/v1/events');
    assert.equal(captured.searchParams.get('limit'), '25');
    assert.equal(captured.searchParams.get('q'), 'a+b');
    assert.deepEqual(captured.searchParams.getAll('tag'), ['one', 'two']);
    assert.equal(captured.searchParams.has('__render_path'), false);
  } finally { globalThis.fetch = originalFetch; }
});

test('named handler rejects traversal and ambiguous routing parameters', async () => {
  const { default: handler } = await import('../api/render-proxy.js');
  for (const path of [undefined, ['v1/auth/csrf', 'ready'], '../health', 'v1/../health', '//hostile.example', 'v1/%2e%2e/health', 'v1/auth?x=1', 'v1\\auth']) {
    const reply = new Reply();
    await handler({ ...request(), query: { __render_path: path } }, reply);
    assert.equal(reply.statusCode, 400);
  }
  const reply = new Reply();
  await handler({ ...request(), url: '/api/render-proxy?__render_path=v1/auth/csrf&__render_path=ready', query: { __render_path: 'v1/auth/csrf' } }, reply);
  assert.equal(reply.statusCode, 400);
});
