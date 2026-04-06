/**
 * Tako Insurance Proxy Server v2 — with full debug
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

app.get('/health', (_, res) =>
    res.json({ ok: true, ts: new Date().toISOString() })
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

    const BASE      = 'https://tako-ins.com';
    const LOGIN_URL = `${BASE}/users/sign_in`;
    const UA        = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';

    try {
        // ── Step 1: GET ──────────────────────────────────────────────────────
        const g = await fetch(LOGIN_URL, {
            method: 'GET',
            redirect: 'follow',
            headers: {
                'User-Agent':      UA,
                'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language':  'he-IL,he;q=0.9,en-US;q=0.8',
                'Accept-Encoding':  'gzip, deflate, br',
                'Connection':       'keep-alive',
                'Cache-Control':    'no-cache',
                'Pragma':           'no-cache',
            },
        });
        const html = await g.text();

        // cookies
        const setCookie = g.headers.get('set-cookie') || '';
        const gCookies = setCookie
            .split(/,(?=[^;]+=[^;]+)/)
            .map(c => c.split(';')[0].trim())
            .filter(c => c.includes('='));
        const cookieStr = gCookies.join('; ');

        // CSRF
        let csrf = '';
        for (const re of [
            /name=["']csrf-token["'][^>]+content=["']([^"']+)["']/i,
            /content=["']([^"']+)["'][^>]*name=["']csrf-token["']/i,
            /name="authenticity_token"\s+value="([^"]+)"/i,
            /value="([^"]+)"\s+name="authenticity_token"/i,
            /"authenticity_token","([^"]+)"/i,
            /authenticity_token.*?value[=:]["'\s]+([A-Za-z0-9+/=_\-]{20,})/i,
        ]) {
            const m = html.match(re);
            if (m) { csrf = m[1]; break; }
        }

        // ── Step 2: POST ─────────────────────────────────────────────────────
        const body = new URLSearchParams();
        if (csrf) body.append('authenticity_token', csrf);
        body.append('user[email]',       email);
        body.append('user[password]',    password);
        body.append('user[remember_me]', '0');
        body.append('commit',            'כניסה');

        const p = await fetch(LOGIN_URL, {
            method: 'POST',
            redirect: 'manual',
            headers: {
                'Content-Type':    'application/x-www-form-urlencoded',
                'Cookie':          cookieStr,
                'User-Agent':      UA,
                'Referer':         LOGIN_URL,
                'Origin':          BASE,
                'Accept':          'text/html,application/xhtml+xml,*/*;q=0.8',
                'Accept-Language':  'he-IL,he;q=0.9',
                'Connection':       'keep-alive',
            },
            body: body.toString(),
        });

        const pCookies = (p.headers.get('set-cookie') || '')
            .split(/,(?=[^;]+=[^;]+)/)
            .map(c => c.split(';')[0].trim())
            .filter(c => c.includes('='));

        const allCookies = [...new Set([...gCookies, ...pCookies])].join('; ');
        const location   = p.headers.get('location') || '';
        const pBody      = await p.text();

        const success = p.status === 302
            || location.includes('employer')
            || location.includes('home');

        return res.json({
            success,
            status:          p.status,
            location,
            session_cookies: allCookies,
            debug: {
                get_status:     g.status,
                get_final_url:  g.url,
                html_length:    html.length,
                html_preview:   html.slice(0, 300),
                csrf_found:     !!csrf,
                csrf_preview:   csrf ? csrf.slice(0, 25) + '...' : null,
                cookies_count:  gCookies.length,
                post_body_preview: pBody.slice(0, 300),
            },
        });
    } catch (e) {
        return res.status(500).json({ error: e.message, stack: e.stack });
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

    const BASE = 'https://tako-ins.com';
    const UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';

    try {
        // ── שלב 1: התחברות לטאקו ────────────────────────────────────────────
        const LOGIN_URL = `${BASE}/users/sign_in`;

        const g = await fetch(LOGIN_URL, {
            method: 'GET', redirect: 'follow',
            headers: {
                'User-Agent': UA,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                'Accept-Language': 'he-IL,he;q=0.9,en-US;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
            },
        });
        const loginHtml = await g.text();

        const setCookie = g.headers.get('set-cookie') || '';
        const gCookies = setCookie
            .split(/,(?=[^;]+=[^;]+)/)
            .map(c => c.split(';')[0].trim())
            .filter(c => c.includes('='));

        // CSRF for login
        let loginCsrf = '';
        for (const re of [
            /name=["']csrf-token["'][^>]+content=["']([^"']+)["']/i,
            /content=["']([^"']+)["'][^>]*name=["']csrf-token["']/i,
            /name="authenticity_token"\s+value="([^"]+)"/i,
            /authenticity_token.*?value[=:]["'\s]+([A-Za-z0-9+/=_\-]{20,})/i,
        ]) {
            const m = loginHtml.match(re);
            if (m) { loginCsrf = m[1]; break; }
        }

        const loginBody = new URLSearchParams();
        if (loginCsrf) loginBody.append('authenticity_token', loginCsrf);
        loginBody.append('user[email]', email);
        loginBody.append('user[password]', password);
        loginBody.append('user[remember_me]', '0');
        loginBody.append('commit', 'כניסה');

        const loginRes = await fetch(LOGIN_URL, {
            method: 'POST', redirect: 'manual',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': gCookies.join('; '),
                'User-Agent': UA,
                'Referer': LOGIN_URL,
                'Origin': BASE,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            },
            body: loginBody.toString(),
        });

        const loginPostCookies = (loginRes.headers.get('set-cookie') || '')
            .split(/,(?=[^;]+=[^;]+)/)
            .map(c => c.split(';')[0].trim())
            .filter(c => c.includes('='));

        const sessionCookies = [...new Set([...gCookies, ...loginPostCookies])].join('; ');
        const loginLocation = loginRes.headers.get('location') || '';

        const loginSuccess = loginRes.status === 302
            || loginLocation.includes('employer')
            || loginLocation.includes('home');

        if (!loginSuccess) {
            return res.json({
                success: false,
                step: 'login',
                error: 'Login failed',
                status: loginRes.status,
                location: loginLocation,
            });
        }

        // ── שלב 2: גישה לטופס רישום עובד (לקבלת CSRF token) ──────────────
        const wizardUrl = `${BASE}/front/employer/new_employee_wizard_2?passport=${encodeURIComponent(passport)}&commit=%D7%97%D7%99%D7%A4%D7%95%D7%A9`;

        const wizardRes = await fetch(wizardUrl, {
            method: 'GET', redirect: 'follow',
            headers: {
                'Cookie': sessionCookies,
                'User-Agent': UA,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                'Referer': `${BASE}/front/employer/new_employee_wizard_1`,
            },
        });

        const wizardHtml = await wizardRes.text();

        // CSRF token from the form
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
                success: false,
                step: 'wizard',
                error: 'Could not find CSRF token in wizard form',
                wizard_status: wizardRes.status,
                html_preview: wizardHtml.slice(0, 500),
            });
        }

        // Update cookies from wizard response
        const wizardCookies = (wizardRes.headers.get('set-cookie') || '')
            .split(/,(?=[^;]+=[^;]+)/)
            .map(c => c.split(';')[0].trim())
            .filter(c => c.includes('='));

        const finalCookies = wizardCookies.length > 0
            ? [...new Set([...sessionCookies.split('; '), ...wizardCookies])].join('; ')
            : sessionCookies;

        // ── שלב 3: שליחת טופס רישום העובד ─────────────────────────────────
        const formData = new URLSearchParams();
        formData.append('authenticity_token', formCsrf);
        formData.append('employee[first_name]', first_name || '');
        formData.append('employee[last_name]', last_name || '');
        formData.append('employee[passport]', passport || '');
        formData.append('employee[country]', country || '');
        formData.append('employee[birth_date]', birth_date || '');
        formData.append('employee[enter_date]', enter_date || '');
        formData.append('employee[occupation]', occupation || 'אחר');
        formData.append('employee[gender]', gender || 'זכר');
        formData.append('employee[street]', street || '');
        formData.append('employee[house_no]', house_no || '');
        formData.append('employee[city]', city || '');
        formData.append('employee[zip]', zip || '');
        formData.append('employee[temp_phone_no]', phone_no || '');
        formData.append('employee[temp_send_sms_str]', send_sms || 'NO');
        formData.append('employee[temp_emp_no]', emp_no || '');
        formData.append('employee[temp_dept]', dept || '');
        formData.append('employee[tmp_from_date]', from_date || '');
        formData.append('employee[tmp_to_date]', to_date || '');
        formData.append('employee[tmp_insurance_company]', insurance_company || '');
        formData.append('commit', 'שמור');

        const submitRes = await fetch(`${BASE}/front/employer/save_new_employee`, {
            method: 'POST', redirect: 'manual',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': finalCookies,
                'User-Agent': UA,
                'Referer': wizardUrl,
                'Origin': BASE,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            },
            body: formData.toString(),
        });

        const submitStatus = submitRes.status;
        const submitLocation = submitRes.headers.get('location') || '';
        const submitBody = await submitRes.text();

        // Redirect 302 = success
        if (submitStatus === 302 || submitStatus === 301) {
            return res.json({
                success: true,
                step: 'submit',
                status: submitStatus,
                redirect: submitLocation,
                message: 'Employee registered successfully in Tako',
            });
        }

        // Check for errors in response HTML
        const errorMatch = submitBody.match(/class="alert[^"]*"[^>]*>([\s\S]*?)<\/div>/);
        const validationErrors = [];
        const errMatches = submitBody.matchAll(/class="field_with_errors"[\s\S]*?<label[^>]*>(.*?)<\/label>/gi);
        for (const m of errMatches) {
            validationErrors.push(m[1]);
        }

        return res.json({
            success: false,
            step: 'submit',
            status: submitStatus,
            redirect: submitLocation,
            error: errorMatch ? errorMatch[1].replace(/<[^>]+>/g, '').trim() : 'Unknown error',
            validation_errors: validationErrors,
            html_preview: submitBody.slice(0, 1500),
        });

    } catch (e) {
        return res.status(500).json({
            success: false,
            step: 'exception',
            error: e.message,
            stack: e.stack,
        });
    }
});

// ── /tako/proxy ─────────────────────────────────────────────────────────────
app.post('/tako/proxy', auth, async (req, res) => {
    const { url, method = 'GET', body, session_cookies, headers: xh = {} } = req.body || {};
    if (!url) return res.status(400).json({ error: 'url required' });
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

        return res.json({
            status:   r.status,
            location: r.headers.get('location') || '',
            body:     text.slice(0, 8000),
        });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

app.listen(PORT, () => console.log(`✅ Tako Proxy v2 on :${PORT}`));
