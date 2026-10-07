// Gemini API プロキシ (Cloudflare Workers)
// Secret(必須): GEMINI_API_KEY / Secret(任意): ACCESS_TOKEN
// Vars(任意): ALLOWED_ORIGINS, ALLOWED_MODELS (カンマ区切り) / Binding(任意): LIMITER
const UP = 'https://generativelanguage.googleapis.com';
const PATH = /^\/v1beta\/models\/([\w.\-]+):(generateContent|streamGenerateContent)$/;
const list = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    const origins = list(env.ALLOWED_ORIGINS);
    if (origins.length && !origins.includes(origin)) return new Response('forbidden', { status: 403 });
    const cors = {
      'Access-Control-Allow-Origin': origins.length ? origin : '*',
      'Access-Control-Allow-Headers': 'Content-Type, x-access-token',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin',
    };
    const err = (msg, status) => new Response(JSON.stringify({ error: { message: msg } }),
      { status, headers: { ...cors, 'Content-Type': 'application/json' } });

    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (req.method !== 'POST') return err('method not allowed', 405);
    if (env.ACCESS_TOKEN && req.headers.get('x-access-token') !== env.ACCESS_TOKEN) return err('unauthorized', 401);
    if (!env.GEMINI_API_KEY) return err('GEMINI_API_KEY is not set', 500);

    const u = new URL(req.url), m = PATH.exec(u.pathname);
    if (!m) return err('not found', 404);
    const models = list(env.ALLOWED_MODELS);
    if (models.length ? !models.includes(m[1]) : !/^gemini-/.test(m[1])) return err('model not allowed', 403);

    if (env.LIMITER) {
      const { success } = await env.LIMITER.limit({ key: req.headers.get('CF-Connecting-IP') || 'anon' });
      if (!success) return err('rate limited', 429);
    }
    const body = await req.text();
    if (body.length > 262144) return err('payload too large', 413);

    try {
      const up = await fetch(UP + u.pathname + (u.searchParams.get('alt') === 'sse' ? '?alt=sse' : ''), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
        body,
      });
      return new Response(up.body, { status: up.status, headers: {
        ...cors, 'Content-Type': up.headers.get('Content-Type') || 'application/json', 'Cache-Control': 'no-store' } });
    } catch (e) {
      return err('upstream error', 502);
    }
  },
};