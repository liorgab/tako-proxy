/**
 * Tako Insurance Proxy Server v2.1 — session cache + 429 circuit breaker
 */
const express = require('express');
const fetch   = require('node-fetch');
const cors    = require('cors');
const app    = express();
const PORT   = process.env.PORT || 3000;
const API_KEY = process.env.TAKO_API_KEY || 'tako-abc123xyz';
app.use(express.json());
app.use(cors());
function auth(req, res, next) {
    const key = req.headers['x-api-key'];
    if (key !== API_KEY) return res.status(401).json({ error: 'Unauthorized' });
    next();
}
// ── Cookie helpers ─────────────────────────────────────────────────────────
// Parse set-cookie header into array of "name=value" strings
function parseCookies(setCookieHeader) {
    if (!setCookieHeader) return [];
    return setCookieHeader
        .split(/,(?=[^;]+=[^;]+)/)
        .map(c => c.split(';')[0].trim())
        .filter(c => c.includes('='));
}
// Merge cookies: later values override earlier ones by cookie NAME
// This prevents sending duplicate _session_id which breaks Rails CSRF
function mergeCookies(...cookieArrays) {
    const map = new Map();
    for (const arr of cookieArrays) {
        for (const cookie of arr) {
            const eqIdx = cookie.indexOf('=');
            if (eqIdx > 0) {
                const name = cookie.substring(0, eqIdx);
                map.set(name, cookie);
            }
        }
    }
    return Array.from(map.values());
}
function cookieString(cookieArray) {
    return cookieArray.join('; ');
}

// ══════════════════════════════════════════════════════════════════════════
// ── Tako session cache + login throttle (fix 429) ─────────────────────────
// ══════════════════════════════════════════════════════════════════════════
// Login once, reuse the Rails session cookies for SESSION_TTL_MS, re-login
// only when Tako redirects to /users/sign_in. One login at a time per user
// (mutex). On 429 from Tako, stop all logins until retry_after has passed.
const TAKO_BASE = process.env.TAKO_BASE || 'https://tako-ins.com';
const TAKO_HOST = new URL(TAKO_BASE).host;
const TAKO_UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
const SESSION_TTL_MS     = 25 * 60 * 1000;
const LOGIN_FAIL_BACKOFF = 60 * 1000;      // after wrong credentials — don't hammer sign_in
const sessions     = new Map();            // email -> { cookies: string[], password, ts }
const loginLocks   = new Map();            // email -> Promise<string[]>
const loginFailed  = new Map();            // email -> until (ms)
let   blockedUntil = 0;                    // circuit breaker after 429
const stats = { logins: 0, login_failures: 0, rate_limited: 0, session_reuses: 0, last_login_at: null };

class TakoRateLimited extends Error {
    constructor(retryAfterSec) { super('TAKO_RATE_LIMITED'); this.retryAfter = retryAfterSec; }
}
class TakoLoginFailed extends Error {
    constructor(info = {}) { super('Login failed'); this.info = info; }
}

function setCookiesOf(r) {
    const raw = r.headers.raw ? r.headers.raw()['set-cookie'] : null;
    if (raw && raw.length) return raw.map(c => c.split(';')[0].trim()).filter(c => c.includes('='));
    return parseCookies(r.headers.get('set-cookie'));
}
function retryAfterOf(r) {
    const h = r.headers.get('retry-after');
    const n = parseInt(h || '', 10);
    if (n > 0) return n;
    const d = h ? Date.parse(h) : NaN;
    if (!isNaN(d)) return Math.max(1, Math.ceil((d - Date.now()) / 1000));
    return 120;
}
function check429(r) {
    if (r.status === 429) {
        const ra = retryAfterOf(r);
        blockedUntil = Math.max(blockedUntil, Date.now() + ra * 1000);
        stats.rate_limited++;
        console.warn(`[tako] 429 from Tako — blocking logins for ${ra}s`);
        throw new TakoRateLimited(ra);
    }
}
function assertNotBlocked() {
    if (Date.now() < blockedUntil)
        throw new TakoRateLimited(Math.ceil((blockedUntil - Date.now()) / 1000));
}
function extractCsrf(html) {
    for (const re of [
        /name=["']csrf-token["'][^>]+content=["']([^"']+)["']/i,
        /content=["']([^"']+)["'][^>]*name=["']csrf-token["']/i,
        /name="authenticity_token"\s+value="([^"]+)"/i,
        /value="([^"]+)"\s+name="authenticity_token"/i,
    ]) {
        const m = html.match(re);
        if (m) return m[1];
    }
    return '';
}
const isSignIn = loc => /\/users\/sign_in/.test(loc || '');

async function doLogin(email, password) {
    assertNotBlocked();
    const failUntil = loginFailed.get(email);
    if (failUntil && Date.now() < failUntil) throw new TakoLoginFailed({ reason: 'recent_login_failure' });

    const LOGIN_URL = `${TAKO_BASE}/users/sign_in`;
    const g = await fetch(LOGIN_URL, {
        method: 'GET', redirect: 'manual',
        headers: { 'User-Agent': TAKO_UA, 'Accept': 'text/html,*/*', 'Accept-Language': 'he-IL,he;q=0.9' },
    });
    check429(g);
    const html = await g.text();
    let cookies = setCookiesOf(g);
    const csrf = extractCsrf(html);

    const body = new URLSearchParams();
    if (csrf) body.append('authenticity_token', csrf);
    body.append('user[email]', email);
    body.append('user[password]', password);
    body.append('user[remember_me]', '1');
    body.append('commit', 'כניסה');
    const p = await fetch(LOGIN_URL, {
        method: 'POST', redirect: 'manual', body: body.toString(),
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': cookieString(cookies),
            'User-Agent': TAKO_UA, 'Referer': LOGIN_URL, 'Origin': TAKO_BASE,
            'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
        },
    });
    check429(p);
    await p.text();
    const loc = p.headers.get('location') || '';
    if (!(p.status === 302 || p.status === 303) || isSignIn(loc)) {
        stats.login_failures++;
        loginFailed.set(email, Date.now() + LOGIN_FAIL_BACKOFF);
        console.warn(`[tako] login FAILED for ${email} (status ${p.status}, location ${loc})`);
        throw new TakoLoginFailed({ status: p.status, location: loc, csrf_found: !!csrf });
    }
    loginFailed.delete(email);
    cookies = mergeCookies(cookies, setCookiesOf(p));
    stats.logins++;
    stats.last_login_at = new Date().toISOString();
    console.log(`[tako] LOGIN #${stats.logins} for ${email} → ${loc}`);
    sessions.set(email, { cookies, password, ts: Date.now(), location: loc });
    return cookies;
}

// Returns valid session cookies (array) — from cache when possible
async function getTakoSession(email, password, { force = false } = {}) {
    const s = sessions.get(email);
    if (!force && s && s.password === password && Date.now() - s.ts < SESSION_TTL_MS) {
        stats.session_reuses++;
        return s.cookies;
    }
    if (loginLocks.has(email)) return loginLocks.get(email);
    const pr = doLogin(email, password).finally(() => loginLocks.delete(email));
    loginLocks.set(email, pr);
    return pr;
}

// Authenticated fetch to Tako. Follows redirects manually (so cookies rolled
// by Rails on every hop are kept). If Tako bounces to sign_in, the cached
// session is dropped and — for GET only — we log in again once and retry.
// Non-Tako hosts (CDN images etc.) are fetched plainly, without cookies.
// Returned response has extra .finalUrl (like node-fetch's res.url).
async function takoFetch(email, password, url, opts = {}) {
    const target = new URL(url, TAKO_BASE);
    if (target.host !== TAKO_HOST) {
        const r = await fetch(target.toString(), opts);
        r.finalUrl = r.url;
        return r;
    }
    assertNotBlocked();
    const method = (opts.method || 'GET').toUpperCase();
    const follow = opts.redirect !== 'manual';
    for (let attempt = 0; attempt < 2; attempt++) {
        let cookies = await getTakoSession(email, password, { force: attempt === 1 });
        let cur = target.toString();
        let curMethod = method;
        let curBody = opts.body;
        let expired = false;
        let r;
        for (let hop = 0; hop < 6; hop++) {
            r = await fetch(cur, {
                method: curMethod, body: curBody, redirect: 'manual',
                headers: {
                    'User-Agent': TAKO_UA, 'Accept-Language': 'he-IL,he;q=0.9',
                    ...(opts.headers || {}), 'Cookie': cookieString(cookies),
                },
            });
            check429(r);
            const newCookies = setCookiesOf(r);
            if (newCookies.length) {
                cookies = mergeCookies(cookies, newCookies);
                const s = sessions.get(email);
                if (s) s.cookies = mergeCookies(s.cookies, newCookies);   // Rails rolls the session cookie
            }
            const loc = r.headers.get('location') || '';
            if (r.status === 401 || (r.status >= 300 && r.status < 400 && isSignIn(loc))) { expired = true; break; }
            if (r.status >= 300 && r.status < 400 && loc && follow) {
                await r.text();
                const next = new URL(loc, cur);
                if (next.host !== TAKO_HOST) { cur = next.toString(); break; }
                cur = next.toString();
                if (r.status !== 307 && r.status !== 308) { curMethod = 'GET'; curBody = undefined; }
                continue;
            }
            break;
        }
        if (expired) {
            await r.text().catch(() => {});
            sessions.delete(email);
            console.log(`[tako] session expired (${method} ${target.pathname})`);
            if (method !== 'GET') throw new Error('TAKO_SESSION_EXPIRED');   // never auto-resubmit a write
            continue;
        }
        r.finalUrl = cur;
        return r;
    }
    throw new Error('TAKO_SESSION_EXPIRED');
}

// Uniform error handler: 429 → HTTP 429 {rate_limited}, bad login → legacy shape
function sendTakoError(res, e, extra = {}) {
    if (e instanceof TakoRateLimited)
        return res.status(429).json({
            success: false, rate_limited: true, retry_after: e.retryAfter, ...extra,
            error: `טאקו חסם זמנית בשל ריבוי בקשות. נסה שוב בעוד ${e.retryAfter} שניות`,
        });
    if (e instanceof TakoLoginFailed)
        return res.json({ success: false, ...extra, error: 'Login failed', ...e.info });
    return res.status(500).json({ success: false, ...extra, error: e.message, stack: e.stack });
}

app.get('/health', (_, res) =>
    res.json({
        ok: true, ts: new Date().toISOString(), version: '2.1-session-cache',
        tako: {
            ...stats,
            cached_sessions: sessions.size,
            blocked_for_sec: Math.max(0, Math.ceil((blockedUntil - Date.now()) / 1000)),
        },
    })
);
// ── /tako/debug — בדיקת גישה בסיסית לטאקו ─────────────────────────────────
app.get('/tako/debug', auth, async (req, res) => {
    const URL = 'https://tako-ins.com/users/sign_in';
    const results = {};
    // ניסיון 1: redirect follow
    try {
        const r = await fetch(URL, {
            method: 'GET',
            redirect: 'follow',
            headers: {
                'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
                'Accept':          'text/html,application/xhtml+xml,*/*;q=0.8',
                'Accept-Language':  'he-IL,he;q=0.9,en-US;q=0.8',
                'Accept-Encoding':  'gzip, deflate, br',
                'Cache-Control':    'no-cache',
                'Connection':       'keep-alive',
            },
        });
        const text = await r.text();
        results.attempt1_follow = {
            status:       r.status,
            final_url:    r.url,
            headers:      Object.fromEntries(r.headers.entries()),
            body_length:  text.length,
            body_preview: text.slice(0, 500),
        };
    } catch (e) { results.attempt1_follow = { error: e.message }; }
    // ניסיון 2: redirect manual
    try {
        const r = await fetch(URL, {
            method: 'GET',
            redirect: 'manual',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,*/*',
            },
        });
        const text = await r.text();
        results.attempt2_manual = {
            status:       r.status,
            location:     r.headers.get('location'),
            set_cookie:   r.headers.get('set-cookie'),
            body_length:  text.length,
            body_preview: text.slice(0, 500),
        };
    } catch (e) { results.attempt2_manual = { error: e.message }; }
    // ניסיון 3: HTTP (לא HTTPS)
    try {
        const r = await fetch('http://tako-ins.com/users/sign_in', {
            method: 'GET',
            redirect: 'manual',
            headers: { 'User-Agent': 'curl/7.88.1', 'Accept': '*/*' },
        });
        results.attempt3_http = {
            status:   r.status,
            location: r.headers.get('location'),
        };
    } catch (e) { results.attempt3_http = { error: e.message }; }
    return res.json(results);
});
// ── /tako/login ─────────────────────────────────────────────────────────────
app.post('/tako/login', auth, async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password)
        return res.status(400).json({ error: 'email + password required' });
    try {
        // שימוש ב-session מה-cache (התחברות אמיתית רק אם אין session תקף)
        const before = stats.logins;
        const cookies = await getTakoSession(email, password, { force: !!req.body.force });
        const s = sessions.get(email) || {};
        return res.json({
            success:         true,
            status:          302,
            location:        s.location || '',
            session_cookies: cookieString(cookies),
            cached:          stats.logins === before,
            debug: {
                cookies_count:    cookies.length,
                session_age_sec:  s.ts ? Math.round((Date.now() - s.ts) / 1000) : null,
            },
        });
    } catch (e) {
        if (e instanceof TakoLoginFailed)
            return res.json({ success: false, status: e.info.status, location: e.info.location || '', session_cookies: '', error: 'Login failed', debug: e.info });
        return sendTakoError(res, e);
    }
});
// ── /tako/create-employee — רישום עובד חדש + פתיחת פוליסה בטאקו ──────────
app.post('/tako/create-employee', auth, async (req, res) => {
    const {
        email, password,
        first_name, last_name, passport, country,
        birth_date, enter_date, occupation, gender,
        street, house_no, city, zip,
        phone_no, send_sms, emp_no, dept,
        from_date, to_date, insurance_company
    } = req.body || {};
    // ולידציה בסיסית
    if (!email || !password)
        return res.status(400).json({ error: 'email + password required' });
    if (!first_name || !last_name || !passport)
        return res.status(400).json({ error: 'first_name, last_name, passport required' });
    if (!from_date || !to_date || !insurance_company)
        return res.status(400).json({ error: 'from_date, to_date, insurance_company required' });
    const BASE = TAKO_BASE;
    const UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
    const dateFormat = req.body.date_format || 'iso';
    function toTakoDate(isoDate) {
        if (!isoDate) return '';
        if (dateFormat === 'il') {
            const parts = isoDate.split('-');
            if (parts.length === 3) return `${parts[2]}/${parts[1]}/${parts[0]}`;
        }
        return isoDate;
    }
    try {
        // ── שלב 1+2: session מה-cache + גישה לטופס רישום עובד ─────────────
        const wizardUrl = `${BASE}/front/employer/new_employee_wizard_2?passport=${encodeURIComponent(passport)}&commit=%D7%97%D7%99%D7%A4%D7%95%D7%A9`;
        let wizardRes;
        try {
            wizardRes = await takoFetch(email, password, wizardUrl, {
                method: 'GET',
                headers: {
                    'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                    'Referer': `${BASE}/front/employer/new_employee_wizard_1`,
                },
            });
        } catch (e) {
            if (e instanceof TakoLoginFailed)
                return res.json({ success: false, step: 'login', error: 'Login failed', status: e.info.status, location: e.info.location || '' });
            throw e;
        }
        const wizardHtml = await wizardRes.text();
        let formCsrf = '';
        for (const re of [
            /name="authenticity_token"\s+value="([^"]+)"/i,
            /value="([^"]+)"\s+name="authenticity_token"/i,
            /name=["']csrf-token["'][^>]+content=["']([^"']+)["']/i,
            /content=["']([^"']+)["'][^>]*name=["']csrf-token["']/i,
        ]) {
            const m = wizardHtml.match(re);
            if (m) { formCsrf = m[1]; break; }
        }
        if (!formCsrf) {
            return res.json({
                success: false, step: 'wizard', error: 'Could not find CSRF token in wizard form',
                wizard_status: wizardRes.status, wizard_url: wizardRes.finalUrl, html_preview: wizardHtml.slice(0, 500),
            });
        }
        // ── שלב 3: שליחת טופס רישום העובד ─────────────────────────────────
        const formData = new URLSearchParams();
        formData.append('authenticity_token', formCsrf);
        formData.append('employee[first_name]', first_name || '');
        formData.append('employee[last_name]', last_name || '');
        formData.append('employee[passport]', passport || '');
        formData.append('employee[country]', country || '');
        formData.append('employee[birth_date]', toTakoDate(birth_date));
        formData.append('employee[enter_date]', toTakoDate(enter_date));
        const validOccupations = ['בניה', 'סיעוד', 'חקלאות', 'אחר'];
        const safeOccupation = validOccupations.includes(occupation) ? occupation : 'בניה';
        formData.append('employee[occupation]', safeOccupation);
        const safeGender = (gender === 'נקבה') ? 'נקבה' : 'זכר';
        formData.append('employee[gender]', safeGender);
        formData.append('employee[street]', street || '');
        formData.append('employee[house_no]', house_no || '');
        formData.append('employee[city]', city || '');
        formData.append('employee[zip]', zip || '');
        formData.append('employee[temp_phone_no]', phone_no || '');
        formData.append('employee[temp_send_sms_str]', send_sms || 'NO');
        formData.append('employee[temp_emp_no]', emp_no || '');
        formData.append('employee[temp_dept]', dept || '');
        formData.append('employee[tmp_from_date]', toTakoDate(from_date));
        formData.append('employee[tmp_to_date]', toTakoDate(to_date));
        formData.append('employee[tmp_insurance_company]', insurance_company || '');
        formData.append('commit', 'שמור');
        const submitRes = await takoFetch(email, password, `${BASE}/front/employer/save_new_employee`, {
            method: 'POST', redirect: 'manual',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': wizardUrl, 'Origin': BASE,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            },
            body: formData.toString(),
        });
        const submitStatus = submitRes.status;
        const submitLocation = submitRes.headers.get('location') || '';
        const submitBody = await submitRes.text();
        if (submitStatus === 302 || submitStatus === 301) {
            let takoEmployeeId = '';
            let takoEmployeeUrl = '';
            const idMatch = submitLocation.match(/[?&]id=(\d+)/);
            if (idMatch) takoEmployeeId = idMatch[1];
            if (submitLocation) {
                try {
                    const redirectUrl = submitLocation.startsWith('http') ? submitLocation : `${BASE}${submitLocation}`;
                    const followRes = await takoFetch(email, password, redirectUrl, {
                        method: 'GET',
                        headers: { 'Accept': 'text/html,*/*' },
                    });
                    const followBody = await followRes.text();
                    const finalUrl = followRes.finalUrl || '';
                    const urlIdMatch = finalUrl.match(/[?&]id=(\d+)/);
                    if (urlIdMatch) takoEmployeeId = urlIdMatch[1];
                    if (!takoEmployeeId) {
                        const contentIdMatch = followBody.match(/employee\?id=(\d+)/);
                        if (contentIdMatch) takoEmployeeId = contentIdMatch[1];
                    }
                    if (takoEmployeeId) takoEmployeeUrl = `${BASE}/front/employer/employee?id=${takoEmployeeId}`;
                } catch (e) { /* Don't fail */ }
            }
            return res.json({
                success: true, step: 'submit', status: submitStatus,
                redirect: submitLocation, tako_employee_id: takoEmployeeId,
                tako_employee_url: takoEmployeeUrl,
                message: 'Employee registered successfully in Tako',
                sent_data: {
                    birth_date: toTakoDate(birth_date), from_date: toTakoDate(from_date),
                    to_date: toTakoDate(to_date), country, occupation: safeOccupation,
                    gender: safeGender, insurance_company, passport, first_name, last_name,
                },
            });
        }
        // ── חילוץ שגיאה ──────────────────────────────────────────────────
        const alertMatch = submitBody.match(/class="alert[^"]*"[^>]*>([\s\S]*?)<\/div>/);
        const exceptionMsgMatch = submitBody.match(/class="message"[^>]*>([\s\S]*?)<\/div>/);
        const h1Match = submitBody.match(/<header[^>]*>[\s\S]*?<h1[^>]*>([\s\S]*?)<\/h1>/);
        const preMatch = submitBody.match(/<pre[^>]*class="box"[^>]*>([\s\S]*?)<\/pre>/);
        const validationErrors = [];
        const errMatches = submitBody.matchAll(/class="field_with_errors"[\s\S]*?<label[^>]*>(.*?)<\/label>/gi);
        for (const m of errMatches) validationErrors.push(m[1]);
        let railsError = '';
        if (alertMatch) {
            railsError = alertMatch[1].replace(/<[^>]+>/g, '').trim();
        } else if (exceptionMsgMatch) {
            railsError = exceptionMsgMatch[1].replace(/<[^>]+>/g, '').trim().slice(0, 500);
        } else if (h1Match) {
            const h1Text = h1Match[1].replace(/<[^>]+>/g, '').trim();
            const preText = preMatch ? preMatch[1].replace(/<[^>]+>/g, '').trim().slice(0, 300) : '';
            railsError = preText ? `${h1Text}: ${preText}` : h1Text;
        }
        if (!railsError) {
            const stripped = submitBody
                .replace(/<style[\s\S]*?<\/style>/gi, '')
                .replace(/<script[\s\S]*?<\/script>/gi, '')
                .replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
            const meaningful = stripped.match(/[a-zA-Zא-ת]{3,}[\s\S]{10,200}/);
            railsError = meaningful ? meaningful[0].trim().slice(0, 300) : 'Unknown error (could not parse Rails response)';
        }
        return res.json({
            success: false, step: 'submit', status: submitStatus,
            redirect: submitLocation, error: railsError,
            validation_errors: validationErrors, body_length: submitBody.length,
            date_format_used: dateFormat,
            sent_data: {
                birth_date: toTakoDate(birth_date), enter_date: toTakoDate(enter_date),
                from_date: toTakoDate(from_date), to_date: toTakoDate(to_date),
                country, occupation: safeOccupation, gender: safeGender,
                insurance_company, passport, first_name, last_name,
            },
        });
    } catch (e) {
        return sendTakoError(res, e, { step: 'exception' });
    }
});
// ── /tako/proxy ─────────────────────────────────────────────────────────────
app.post('/tako/proxy', auth, async (req, res) => {
    const { url, method = 'GET', body, email, password, headers: xh = {} } = req.body || {};
    let { session_cookies } = req.body || {};
    if (!url) return res.status(400).json({ error: 'url required' });
    if (!session_cookies && !(email && password)) return res.status(400).json({ error: 'session_cookies required' });
    try {
        if (!session_cookies) session_cookies = cookieString(await getTakoSession(email, password));
        const opts = {
            method, redirect: 'manual',
            headers: {
                'Cookie': session_cookies,
                'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/json,*/*',
                'Referer': 'https://tako-ins.com',
                ...xh,
            },
        };
        if (body && method !== 'GET') {
            opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            opts.body = typeof body === 'string' ? body : new URLSearchParams(body).toString();
        }
        const r    = await fetch(url, opts);
        check429(r);
        const text = await r.text();
        return res.json({ status: r.status, location: r.headers.get('location') || '', body: text.slice(0, 8000) });
    } catch (e) {
        if (e instanceof TakoRateLimited || e instanceof TakoLoginFailed) return sendTakoError(res, e);
        return res.status(500).json({ error: e.message });
    }
});
// ── /tako/search-employee — חיפוש עובד בטאקו לפי דרכון ─────────────────
app.post('/tako/search-employee', auth, async (req, res) => {
    const { email, password, passport } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email + password required' });
    if (!passport) return res.status(400).json({ error: 'passport required' });
    const BASE = TAKO_BASE;
    const UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
    try {
        // ── שלב 0: בדיקת קיום דרך דף החיפוש (read-only) ─────────────────
        // חשוב: new_employee_wizard_2 עם דרכון שלא קיים **יוצר עובד ריק בטאקו**,
        // לכן ניגשים ל-wizard רק אחרי שהחיפוש אישר שהעובד קיים.
        const searchRes = await takoFetch(email, password, `${BASE}/front/employer/search?q=${encodeURIComponent(passport)}`, {
            method: 'GET', headers: { 'Accept': 'text/html,*/*' },
        });
        const searchHtml = await searchRes.text();
        const wantedPassport = String(passport).trim().toUpperCase();
        let searchEmployeeId = '';
        for (const row of (searchHtml.match(/<tr[\s\S]*?<\/tr>/gi) || [])) {
            const cells = (row.match(/<td[^>]*>[\s\S]*?<\/td>/gi) || [])
                .map(td => td.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').trim().toUpperCase());
            if (!cells.includes(wantedPassport)) continue;
            const m = row.match(/employee\?id=(\d+)/);
            if (m) { searchEmployeeId = m[1]; break; }
        }
        if (!searchEmployeeId) {
            return res.json({
                success: false, not_found: true, passport,
                tako_employee_id: '', tako_employee_url: '',
                employee_data: { is_existing: false },
                error: 'Employee not found in Tako',
            });
        }

        // ── שלב 1+2: חיפוש עובד בדף wizard (העובד קיים — לא נוצר חדש) ──
        const wizardUrl = `${BASE}/front/employer/new_employee_wizard_2?passport=${encodeURIComponent(passport)}&commit=%D7%97%D7%99%D7%A4%D7%95%D7%A9`;
        const wizardRes = await takoFetch(email, password, wizardUrl, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,*/*',
                'Referer': `${BASE}/front/employer/new_employee_wizard_1`,
            },
        });
        const wizardHtml = await wizardRes.text();
        let takoEmployeeId = '';
        let takoEmployeeUrl = '';
        let employeeData = {};
        // Pattern 1 (PRIMARY): form id="edit_employee_107778"
        const editFormMatch = wizardHtml.match(/id=["']edit_employee_(\d+)["']/i);
        if (editFormMatch) takoEmployeeId = editFormMatch[1];
        // Pattern 2: class="edit_employee" with nearby ID
        if (!takoEmployeeId) {
            const classMatch = wizardHtml.match(/class=["'][^"']*edit_employee[^"']*["'][^>]*id=["'](\d+)["']/i);
            if (classMatch) takoEmployeeId = classMatch[1];
        }
        // Pattern 3: employee?id=XXXXX links
        if (!takoEmployeeId) {
            const idMatches = wizardHtml.matchAll(/employee\?id=(\d+)/gi);
            for (const m of idMatches) takoEmployeeId = m[1];
        }
        // Pattern 4: data-id attributes
        if (!takoEmployeeId) {
            const dataIdMatch = wizardHtml.match(/data-id=["'](\d+)["']/);
            if (dataIdMatch) takoEmployeeId = dataIdMatch[1];
        }
        // Pattern 5: hidden field with employee_id
        if (!takoEmployeeId) {
            const hiddenIdMatch = wizardHtml.match(/employee_id.*?value=["'](\d+)["']/i);
            if (hiddenIdMatch) takoEmployeeId = hiddenIdMatch[1];
        }
        // Pattern 6: showEmployeeDetails(ID)
        if (!takoEmployeeId) {
            const showMatch = wizardHtml.match(/showEmployeeDetails\((\d+)\)/);
            if (showMatch) takoEmployeeId = showMatch[1];
        }
        // Fallback: the ID from the read-only search page
        if (!takoEmployeeId) takoEmployeeId = searchEmployeeId;
        const isExistingEmployee = wizardHtml.includes('edit_employee');
        const firstNameMatch = wizardHtml.match(/employee\[first_name\].*?value=["']([^"']+)["']/i);
        const lastNameMatch = wizardHtml.match(/employee\[last_name\].*?value=["']([^"']+)["']/i);
        if (firstNameMatch) employeeData.first_name = firstNameMatch[1];
        if (lastNameMatch) employeeData.last_name = lastNameMatch[1];
        employeeData.is_existing = isExistingEmployee;
        const policyMatch = wizardHtml.match(/policy_number.*?["'](\d+)["']/i);
        if (policyMatch) employeeData.policy_number = policyMatch[1];
        if (takoEmployeeId) {
            takoEmployeeUrl = `${BASE}/front/employer/employee?id=${takoEmployeeId}`;
            // ── שלב 3: גישה לדף העובד לחילוץ פרטים נוספים ──────────
            try {
                const empPageRes = await takoFetch(email, password, takoEmployeeUrl, {
                    method: 'GET',
                    headers: { 'Accept': 'text/html,*/*' },
                });
                const empPageHtml = await empPageRes.text();

                // ══════════════════════════════════════════════════════════
                // ── חילוץ נתונים מטבלת פוליסות (v3 — מפרסר כל השורות) ──
                // ══════════════════════════════════════════════════════════
                // מפרסר את כל שורות הטבלה ובוחר את הפוליסה הנכונה
                // עדיפות: פעילה > בקשת חידוש > פתיחה > מבוטלת
                const policiesStart = empPageHtml.indexOf('פוליסות לעובד');
                const policiesEnd = empPageHtml.indexOf('שאלונים רפואיים', policiesStart > -1 ? policiesStart : 0);
                const policiesSection = policiesStart > -1
                    ? empPageHtml.substring(policiesStart, policiesEnd > policiesStart ? policiesEnd : empPageHtml.length)
                    : '';

                if (policiesSection) {
                    // פרסור כל שורות הטבלה
                    const rows = policiesSection.match(/<tr[\s\S]*?<\/tr>/gi) || [];
                    const policies = [];

                    for (const row of rows) {
                        const policy = {};

                        // סטטוס מתוך span.label
                        const statusMatch = row.match(/<span[^>]*class=["'][^"']*label[^"']*["'][^>]*>\s*(פעילה|פתיחה|מבוטלת|בתהליך|ממתינה|הוקפאה|לא פעילה|בבירור|בקשת חידוש|בקשת ביטול)\s*<\/span>/i);
                        if (statusMatch) policy.status = statusMatch[1].trim();

                        // קישור פוליסה (eid + מספר פוליסה)
                        const linkMatch = row.match(/<a\s+href="\/front\/employer\/employment\?eid=(\d+)">\s*(\d+)\s*<\/a>/);
                        if (linkMatch) {
                            policy.eid = linkMatch[1];
                            policy.number = linkMatch[2];
                        }

                        // חברת ביטוח
                        const insurerMatch = row.match(/<td>\s*(מנורה|איילון|הראל|הכשרה|כלל|מגדל|ביטוח ישיר|פניקס|הפניקס)\s*<\/td>/);
                        if (insurerMatch) policy.insurer = insurerMatch[1];

                        // מס. קופת חולים (HMO number) — מספר 7-13 ספרות בתא רגיל (לא בתוך לינק)
                        const hmoMatch = row.match(/<td>\s*(\d{7,13})\s*<\/td>/);
                        if (hmoMatch) policy.hmo_number = hmoMatch[1];

                        // תאריכים - פורמט ISO (YYYY-MM-DD)
                        const dates = [];
                        const dateMatches = row.matchAll(/<td>\s*(\d{4}-\d{2}-\d{2})\s*<\/td>/g);
                        for (const dm of dateMatches) dates.push(dm[1]);
                        if (dates.length >= 2) {
                            policy.start_date = dates[0];
                            policy.end_date = dates[1];
                        } else if (dates.length === 1) {
                            policy.start_date = dates[0];
                        }

                        // גם לנסות פורמט DD/MM/YYYY
                        if (!policy.start_date) {
                            const datesEU = [];
                            const dateMatchesEU = row.matchAll(/<td>\s*(\d{2}\/\d{2}\/\d{4})\s*<\/td>/g);
                            for (const dm of dateMatchesEU) datesEU.push(dm[1]);
                            if (datesEU.length >= 2) {
                                policy.start_date = datesEU[0];
                                policy.end_date = datesEU[1];
                            }
                        }

                        // רק שורות עם סטטוס או קישור (מדלגים על header)
                        if (policy.status || policy.eid) {
                            policies.push(policy);
                        }
                    }

                    // בחירת הפוליסה הנכונה: עדיפות לפי סטטוס, אח"כ תאריך התחלה מאוחר
                    const STATUS_PRIORITY = {
                        'פעילה': 1,
                        'בקשת חידוש': 2,
                        'פתיחה': 3,
                        'בתהליך': 4,
                        'ממתינה': 5,
                        'בקשת ביטול': 6,
                        'הוקפאה': 7,
                        'מבוטלת': 8,
                        'לא פעילה': 9,
                        'בבירור': 10,
                    };

                    if (policies.length > 0) {
                        policies.sort((a, b) => {
                            const pa = STATUS_PRIORITY[a.status] || 99;
                            const pb = STATUS_PRIORITY[b.status] || 99;
                            if (pa !== pb) return pa - pb;
                            // אותה עדיפות - תאריך התחלה מאוחר יותר מנצח
                            return (b.start_date || '').localeCompare(a.start_date || '');
                        });

                        const best = policies[0];
                        if (best.status) employeeData.policy_status = best.status;
                        if (best.insurer) employeeData.insurer = best.insurer;
                        if (best.eid) employeeData.policy_eid = best.eid;
                        if (best.number) employeeData.policy_number = best.number;
                        if (best.hmo_number) employeeData.hmo_number = best.hmo_number;
                        if (best.start_date) employeeData.start_date = best.start_date;
                        if (best.end_date) employeeData.end_date = best.end_date;
                    }

                    // שמירת כל הפוליסות למטרות debug
                    employeeData.all_policies = policies;
                }
                // ══════════════════════════════════════════════════════════

                // ══════════════════════════════════════════════════════════
                // ── חילוץ נתוני שאלונים רפואיים ─────────────────────────
                // ══════════════════════════════════════════════════════════
                const medicalStart = empPageHtml.lastIndexOf('שאלונים רפואיים');
                if (medicalStart > -1) {
                    // מחפשים את הטבלה הבאה אחרי הכותרת
                    const medicalSection = empPageHtml.substring(medicalStart, medicalStart + 5000);
                    const medicalRows = medicalSection.match(/<tr[\s\S]*?<\/tr>/gi) || [];
                    const questionnaires = [];

                    for (const row of medicalRows) {
                        const q = {};

                        // סטטוס: מולא / לא מולא
                        if (row.includes('מולא')) {
                            q.status = row.includes('לא מולא') ? 'לא מולא' : 'מולא';
                        }

                        // Form ID — מתוך לינקים /medical_forms/{id}/preview או /medical_forms/{id}/edit
                        const formIdMatch = row.match(/\/medical_forms\/(\d+)\/(preview|edit)/);
                        if (formIdMatch) {
                            q.form_id = formIdMatch[1];
                            q.form_type = formIdMatch[2]; // preview = ממולא, edit = לא ממולא
                        }

                        // גם מ-checkbox: <input type="checkbox" id="133811" value="133811">
                        if (!q.form_id) {
                            const checkboxMatch = row.match(/medical_forms\[\].*?value=["'](\d+)["']/);
                            if (checkboxMatch) q.form_id = checkboxMatch[1];
                        }

                        // גם מ-send_medical_form_link parameter
                        if (!q.form_id) {
                            const sendLinkMatch = row.match(/send_medical_form_link=(\d+)/);
                            if (sendLinkMatch) q.form_id = sendLinkMatch[1];
                        }

                        // תאריך חתימה
                        const dateMatch = row.match(/(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}/);
                        if (dateMatch) q.signed_date = dateMatch[1];

                        // מספר פוליסה
                        const polNumMatch = row.match(/<td>\s*(\d{4,})\s*<\/td>/);
                        if (polNumMatch) q.policy_number = polNumMatch[1];

                        // רק שורות עם מידע רלוונטי
                        if (q.status || q.form_id) {
                            questionnaires.push(q);
                        }
                    }

                    // מיון: "לא מולא" קודם (דורש פעולה), אח"כ לפי תאריך חתימה יורד
                    if (questionnaires.length > 0) {
                        questionnaires.sort((a, b) => {
                            // עדיפות ראשונה: "לא מולא" לפני "מולא"
                            const aUnfilled = (a.status === 'לא מולא') ? 0 : 1;
                            const bUnfilled = (b.status === 'לא מולא') ? 0 : 1;
                            if (aUnfilled !== bUnfilled) return aUnfilled - bUnfilled;
                            // עדיפות שנייה: תאריך חתימה יורד
                            return (b.signed_date || '').localeCompare(a.signed_date || '');
                        });

                        // השאלון הרלוונטי ביותר — "לא מולא" אם קיים, אחרת האחרון שמולא
                        const latest = questionnaires[0];
                        employeeData.medical_form_id = latest.form_id || '';
                        employeeData.medical_form_status = latest.status || '';
                        employeeData.medical_form_signed_date = latest.signed_date || '';
                        if (latest.form_id) {
                            if (latest.status === 'מולא') {
                                employeeData.medical_form_url = `${BASE}/medical_forms/${latest.form_id}/preview`;
                            } else {
                                employeeData.medical_form_url = `${BASE}/medical_forms/${latest.form_id}/edit`;
                            }
                        }
                    }

                    // שמירת כל השאלונים למטרות debug
                    employeeData.all_questionnaires = questionnaires;
                }
                // ══════════════════════════════════════════════════════════

            } catch (e) {
                // Don't fail if employee page can't be parsed — but never hide
                // auth/rate-limit errors (partial data would wipe fields in Base44)
                if (e instanceof TakoRateLimited || e instanceof TakoLoginFailed || /^TAKO_/.test(e.message)) throw e;
            }
        }
        return res.json({
            success: !!takoEmployeeId,
            passport,
            tako_employee_id: takoEmployeeId,
            tako_employee_url: takoEmployeeUrl,
            employee_data: employeeData,
            wizard_url: wizardRes.finalUrl,
        });
    } catch (e) {
        return sendTakoError(res, e);
    }
});
// ── /tako/get-card — הורדת כרטיס קופת חולים מטאקו ───────────────────────
// URL pattern: https://tako-ins.com/employees/{tako_employee_id}/card_{hmo}
// מחזיר את כל ה-HTML של דף הכרטיס עם תמונות inline כ-data URI
// hmo options: leumit, clalit, maccabi, meuchedet
app.post('/tako/get-card', auth, async (req, res) => {
    const { email, password, tako_employee_id, policy_eid } = req.body || {};
    if (!email || !password) return res.status(400).json({ success: false, error: 'email + password required' });
    if (!tako_employee_id) return res.status(400).json({ success: false, error: 'tako_employee_id required' });

    const BASE = TAKO_BASE;
    const UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';

    try {
        // ── שלב 1: session מה-cache (נוצר אוטומטית ב-takoFetch) ─────────

        // ── שלב 2: ניסיון ישיר — /employees/{id}/card_{hmo} ────────────
        // ננסה את כל קופות החולים ונחזיר HTML מלא עם תמונות inline
        const HMO_SLUGS = ['leumit', 'clalit', 'maccabi', 'meuchedet'];

        for (const hmo of HMO_SLUGS) {
            const cardUrl = `${BASE}/employees/${tako_employee_id}/card_${hmo}`;
            try {
                const cardRes = await takoFetch(email, password, cardUrl, {
                    method: 'GET',
                    headers: { 'Accept': 'text/html,image/*,*/*' },
                });
                const ct = cardRes.headers.get('content-type') || '';

                // אם קיבלנו תמונה ישירות (לא צפוי אבל לטיפול)
                if (ct.includes('image')) {
                    const arrayBuffer = await cardRes.arrayBuffer();
                    const buffer = Buffer.from(arrayBuffer);
                    return res.json({
                        success: true,
                        type: 'image',
                        image_base64: buffer.toString('base64'),
                        content_type: ct,
                        source_url: cardUrl,
                        hmo,
                    });
                }

                // קיבלנו HTML — זה המצב הנפוץ
                let html = await cardRes.text();

                // דלג על דפי login או שגיאה
                if (html.includes('sign_in') || html.includes('404') || html.length < 200) {
                    continue;
                }

                // ── Inline כל התמונות ב-HTML כ-data URI ──
                const imgRegex = /<img([^>]+)src=["']([^"']+)["']/gi;
                const imgReplacements = [];
                let imgMatch;
                while ((imgMatch = imgRegex.exec(html)) !== null) {
                    const fullMatch = imgMatch[0];
                    const imgSrc = imgMatch[2];
                    const imgUrl = imgSrc.startsWith('http') ? imgSrc
                        : imgSrc.startsWith('//') ? `https:${imgSrc}`
                        : `${BASE}${imgSrc}`;
                    imgReplacements.push({ fullMatch, imgSrc, imgUrl });
                }

                // CSS background-image URLs
                const bgRegex = /background(?:-image)?\s*:\s*url\(["']?([^"')]+)["']?\)/gi;
                const bgReplacements = [];
                let bgMatch;
                while ((bgMatch = bgRegex.exec(html)) !== null) {
                    const fullMatch = bgMatch[0];
                    const bgSrc = bgMatch[1];
                    const bgUrl = bgSrc.startsWith('http') ? bgSrc
                        : bgSrc.startsWith('//') ? `https:${bgSrc}`
                        : `${BASE}${bgSrc}`;
                    bgReplacements.push({ fullMatch, bgSrc, bgUrl });
                }

                // הורדה והמרה של כל התמונות
                for (const rep of imgReplacements) {
                    try {
                        const r = await takoFetch(email, password, rep.imgUrl, {
                            method: 'GET',
                            headers: { 'Accept': 'image/*,*/*' },
                        });
                        const imgCt = r.headers.get('content-type') || 'image/png';
                        const buf = Buffer.from(await r.arrayBuffer());
                        const dataUri = `data:${imgCt};base64,${buf.toString('base64')}`;
                        html = html.split(rep.imgSrc).join(dataUri);
                    } catch (e) { /* skip failed images */ }
                }

                for (const rep of bgReplacements) {
                    try {
                        const r = await takoFetch(email, password, rep.bgUrl, {
                            method: 'GET',
                            headers: { 'Accept': 'image/*,*/*' },
                        });
                        const bgCt = r.headers.get('content-type') || 'image/png';
                        const buf = Buffer.from(await r.arrayBuffer());
                        const dataUri = `data:${bgCt};base64,${buf.toString('base64')}`;
                        html = html.split(rep.bgSrc).join(dataUri);
                    } catch (e) { /* skip failed bg images */ }
                }

                // ── Inline CSS חיצוני ──
                const cssRegex = /<link[^>]+href=["']([^"']+\.css[^"']*)["'][^>]*>/gi;
                let cssMatch;
                while ((cssMatch = cssRegex.exec(html)) !== null) {
                    const cssHref = cssMatch[1];
                    const cssUrl = cssHref.startsWith('http') ? cssHref
                        : cssHref.startsWith('//') ? `https:${cssHref}`
                        : `${BASE}${cssHref}`;
                    try {
                        const r = await takoFetch(email, password, cssUrl, { method: 'GET' });
                        const cssText = await r.text();
                        html = html.replace(cssMatch[0], `<style>${cssText}</style>`);
                    } catch (e) { /* skip failed CSS */ }
                }

                return res.json({
                    success: true,
                    type: 'html',
                    card_html: html,
                    source_url: cardUrl,
                    hmo,
                });

            } catch (e) {
                // ממשיכים לקופת חולים הבאה — אבל לא מסתירים חסימה/התחברות כושלת
                if (e instanceof TakoRateLimited || e instanceof TakoLoginFailed || /^TAKO_/.test(e.message)) throw e;
            }
        }

        return res.json({
            success: false,
            error: 'Card not found for any HMO',
            debug: {
                tako_employee_id,
                tried_urls: HMO_SLUGS.map(h => `${BASE}/employees/${tako_employee_id}/card_${h}`),
            },
        });

    } catch (e) {
        return sendTakoError(res, e);
    }
});
// ── /tako/cancel-policy — ביטול פוליסה בטאקו ────────────────────────────
// שולח בקשת ביטול דרך HTTP — PATCH ל-/employments/{eid}
// מקבל tako_employee_id (מספר עובד בטאקו) ומחפש את ה-employment ID מדף העובד
app.post('/tako/cancel-policy', auth, async (req, res) => {
    const { email, password, tako_employee_id, cancel_date } = req.body || {};
    if (!email || !password) return res.status(400).json({ success: false, error: 'email + password required' });
    if (!tako_employee_id) return res.status(400).json({ success: false, error: 'tako_employee_id required' });

    const BASE = TAKO_BASE;
    const UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';

    try {
        // ── שלב 1: session מה-cache (נוצר אוטומטית ב-takoFetch) ─────────

        // ── שלב 2: דף העובד — חילוץ employment ID ──────────────────────
        const employeeUrl = `${BASE}/front/employer/employee?id=${tako_employee_id}`;
        const employeeRes = await takoFetch(email, password, employeeUrl, {
            method: 'GET',
            headers: { 'Accept': 'text/html,*/*' },
        });
        const employeeHtml = await employeeRes.text();

        // חיפוש לינק employment עם eid
        const eidMatch = employeeHtml.match(/\/front\/employer\/employment\?eid=(\d+)/);
        if (!eidMatch) {
            return res.json({
                success: false,
                error: 'Could not find employment ID on employee page',
                debug: {
                    employee_url: employeeUrl,
                    page_length: employeeHtml.length,
                    page_title: (employeeHtml.match(/<title>([^<]*)<\/title>/i) || [])[1] || '',
                },
            });
        }
        const employmentId = eidMatch[1];

        // ── שלב 3: דף הפוליסה — חילוץ CSRF וטופס ביטול ─────────────────
        const empUrl = `${BASE}/front/employer/employment?eid=${employmentId}`;
        const empRes = await takoFetch(email, password, empUrl, {
            method: 'GET',
            headers: { 'Accept': 'text/html,*/*' },
        });
        const empHtml = await empRes.text();

        // חילוץ CSRF token
        let pageCsrf = '';
        for (const re of [
            /name=["']csrf-token["'][^>]+content=["']([^"']+)["']/i,
            /content=["']([^"']+)["'][^>]*name=["']csrf-token["']/i,
        ]) {
            const m = empHtml.match(re);
            if (m) { pageCsrf = m[1]; break; }
        }

        // חילוץ authenticity_token מהטופס
        const formTokenMatch = empHtml.match(/edit_employment[\s\S]*?name="authenticity_token"\s+value="([^"]+)"/i);
        const formToken = formTokenMatch ? formTokenMatch[1] : pageCsrf;

        if (!formToken) {
            return res.json({
                success: false,
                error: 'Could not find CSRF token on employment page',
                debug: { employment_url: empUrl, employment_id: employmentId },
            });
        }

        // ── שלב 4: שליחת PATCH לביטול ──────────────────────────────────
        // הטופס בטאקו: PATCH /employments/{eid}
        // שדות: _method=patch, authenticity_token, employment[id], employment[req_cancel_date], commit
        const cancelUrl = `${BASE}/employments/${employmentId}`;
        const cancelBody = new URLSearchParams();
        cancelBody.append('_method', 'patch');
        cancelBody.append('authenticity_token', formToken);
        cancelBody.append('employment[id]', employmentId);
        // תאריך ביטול — הטופס משתמש ב-type="date" כלומר YYYY-MM-DD
        if (cancel_date) {
            cancelBody.append('employment[req_cancel_date]', cancel_date);
        }
        cancelBody.append('commit', 'ביטול הפוליסה');

        const cancelRes = await takoFetch(email, password, cancelUrl, {
            method: 'POST',  // Rails PATCH = POST + _method=patch (redirect followed as GET)
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': empUrl,
                'Origin': BASE,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            },
            body: cancelBody.toString(),
        });
        const cancelResultHtml = await cancelRes.text();

        // בדיקת הצלחה
        const hasCancel = cancelResultHtml.includes('בקשת ביטול')
            || cancelResultHtml.includes('ביטול בוצע')
            || cancelResultHtml.includes('cancel');
        const isRedirect = cancelRes.status === 302 || cancelRes.status === 301;
        const isSuccess = hasCancel || isRedirect || cancelRes.status === 200;

        // חילוץ סטטוס מהתגובה
        const statusMatch = cancelResultHtml.match(/<span[^>]*class="[^"]*label[^"]*"[^>]*>([^<]+)<\/span>/i);
        const resultStatus = statusMatch ? statusMatch[1].trim() : '';

        return res.json({
            success: isSuccess,
            message: isSuccess ? 'Cancel request submitted successfully' : 'Cancel submitted but status unclear',
            employment_id: employmentId,
            result_status: resultStatus,
            debug: {
                cancel_url: cancelUrl,
                cancel_date: cancel_date,
                status: cancelRes.status,
                final_url: cancelRes.finalUrl,
                has_cancel_text: hasCancel,
                response_preview: cancelResultHtml.slice(0, 500),
            },
        });

    } catch (e) {
        return sendTakoError(res, e);
    }
});
app.listen(PORT, () => console.log(`✅ Tako Proxy v2.1 (session cache) on :${PORT}`));
