/**
 * Tako Insurance Proxy Server
 * Deploy on Railway / Render / VPS / ngrok
 *
 * Routes:
 *   GET  /health          — בדיקת חיים
 *   POST /tako/login      — התחברות + קבלת session cookies
 *   POST /tako/proxy      — כל בקשה לאתר לאחר login
 */

const express = require('express');
const fetch   = require('node-fetch');
const cors    = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.TAKO_API_KEY || 'tako-secret-2024';

app.use(express.json());
app.use(cors());

// ── Auth middleware ─────────────────────────────────────────────────────────
function auth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (key !== API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ── /health ─────────────────────────────────────────────────────────────────
app.get('/health', (_, res) =>
  res.json({ ok: true, ts: new Date().toISOString() })
);

// ── /tako/login ─────────────────────────────────────────────────────────────
app.post('/tako/login', auth, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'email + password required' });

  const BASE = 'https://tako-ins.com';
  const URL  = `${BASE}/users/sign_in`;
  const UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';

  try {
    // ── Step 1: GET login page ──────────────────────────────────────────────
    const g = await fetch(URL, {
      headers: { 'User-Agent': UA, 'Accept': 'text/html,*/*' },
      redirect: 'follow',
    });
    const html      = await g.text();
    const gCookies  = (g.headers.raw()['set-cookie'] || []).map(c => c.split(';')[0]);

    // חלץ CSRF
    let csrf = '';
    for (const re of [
      /name=["']csrf-token["'][^>]+content=["']([^"']+)["']/i,
      /content=["']([^"']+)["'][^>]*name=["']csrf-token["']/i,
      /authenticity_token[^>]+value=["']([^"']+)["']/i,
      /value=["']([^"']+)["'][^>]*authenticity_token/i,
    ]) {
      const m = html.match(re);
      if (m) { csrf = m[1]; break; }
    }

    // ── Step 2: POST credentials ────────────────────────────────────────────
    const body = new URLSearchParams({
      ...(csrf ? { authenticity_token: csrf } : {}),
      'user[email]':       email,
      'user[password]':    password,
      'user[remember_me]': '0',
      commit:              'כניסה',
    });

    const p = await fetch(URL, {
      method:   'POST',
      redirect: 'manual',
      headers: {
        'Content-Type':  'application/x-www-form-urlencoded',
        'Cookie':        gCookies.join('; '),
        'User-Agent':    UA,
        'Referer':       URL,
        'Origin':        BASE,
        'Accept':        'text/html,*/*',
        'Accept-Language': 'he-IL,he;q=0.9',
      },
      body: body.toString(),
    });

    const pCookies = (p.headers.raw()['set-cookie'] || []).map(c => c.split(';')[0]);
    const allCookies = [...new Set([...gCookies, ...pCookies])].join('; ');
    const location   = p.headers.get('location') || '';
    const success    = p.status === 302 || location.includes('employer') || location.includes('home');

    return res.json({
      success,
      status:          p.status,
      location,
      session_cookies: allCookies,
      debug: {
        get_status:   g.status,
        html_length:  html.length,
        csrf_found:   !!csrf,
        csrf_preview: csrf ? csrf.slice(0, 25) + '...' : null,
      },
    });

  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ── /tako/proxy ─────────────────────────────────────────────────────────────
app.post('/tako/proxy', auth, async (req, res) => {
  const { url, method = 'GET', body, session_cookies, headers: xh = {} } = req.body || {};
  if (!url)            return res.status(400).json({ error: 'url required' });
  if (!session_cookies) return res.status(400).json({ error: 'session_cookies required' });

  try {
    const opts = {
      method,
      redirect: 'manual',
      headers: {
        'Cookie':     session_cookies,
        'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36',
        'Accept':     'text/html,application/json,*/*',
        'Referer':    'https://tako-ins.com',
        ...xh,
      },
    };
    if (body && method !== 'GET') {
      opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      opts.body = typeof body === 'string' ? body : new URLSearchParams(body).toString();
    }

    const r    = await fetch(url, opts);
    const text = await r.text();
    const newC = (r.headers.raw()['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');

    return res.json({
      status:      r.status,
      location:    r.headers.get('location') || '',
      new_cookies: newC,
      body:        text.slice(0, 8000),
    });

  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`✅ Tako Proxy on :${PORT}`));
