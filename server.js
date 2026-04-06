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

    // התאריך נשלח כמו שהוא (YYYY-MM-DD) - זה הפורמט שדפדפנים שולחים מ-input type="date"
    // אם date_format=il נשלח בפורמט DD/MM/YYYY
    const dateFormat = req.body.date_format || 'iso'; // 'iso' = YYYY-MM-DD, 'il' = DD/MM/YYYY
    function toTakoDate(isoDate) {
        if (!isoDate) return '';
        if (dateFormat === 'il') {
            const parts = isoDate.split('-');
            if (parts.length === 3) return `${parts[2]}/${parts[1]}/${parts[0]}`;
        }
        return isoDate; // send as-is (YYYY-MM-DD)
    }

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

        const gCookies = parseCookies(g.headers.get('set-cookie'));

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
                'Cookie': cookieString(gCookies),
                'User-Agent': UA,
                'Referer': LOGIN_URL,
                'Origin': BASE,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            },
            body: loginBody.toString(),
        });

        const loginPostCookies = parseCookies(loginRes.headers.get('set-cookie'));

        // Merge: login POST cookies override GET cookies (newer _session_id wins)
        const sessionCookieArr = mergeCookies(gCookies, loginPostCookies);
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

        // Follow the login redirect first to establish session properly
        if (loginLocation) {
            const redirectUrl = loginLocation.startsWith('http') ? loginLocation : `${BASE}${loginLocation}`;
            const followRes = await fetch(redirectUrl, {
                method: 'GET', redirect: 'follow',
                headers: {
                    'Cookie': cookieString(sessionCookieArr),
                    'User-Agent': UA,
                    'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                },
            });
            await followRes.text(); // consume body
            const followCookies = parseCookies(followRes.headers.get('set-cookie'));
            if (followCookies.length > 0) {
                // Update session cookies with any new ones from the redirect
                const updatedArr = mergeCookies(sessionCookieArr, followCookies);
                sessionCookieArr.length = 0;
                updatedArr.forEach(c => sessionCookieArr.push(c));
            }
        }

        const wizardRes = await fetch(wizardUrl, {
            method: 'GET', redirect: 'follow',
            headers: {
                'Cookie': cookieString(sessionCookieArr),
                'User-Agent': UA,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                'Referer': `${BASE}/front/employer/new_employee_wizard_1`,
            },
        });

        const wizardHtml = await wizardRes.text();
        const wizardCookiesNew = parseCookies(wizardRes.headers.get('set-cookie'));

        // Merge wizard cookies - wizard's session takes priority
        const afterWizardCookies = mergeCookies(sessionCookieArr, wizardCookiesNew);

        // CSRF token from the form - try form hidden field first, then meta tag
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
                wizard_url: wizardRes.url,
                html_preview: wizardHtml.slice(0, 500),
            });
        }

        // Use properly merged cookies for form submission
        const finalCookies = cookieString(afterWizardCookies);

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

        // Redirect 302 = success — follow redirect to get Tako employee ID
        if (submitStatus === 302 || submitStatus === 301) {
            let takoEmployeeId = '';
            let takoEmployeeUrl = '';

            // Try to extract employee ID from redirect URL
            const idMatch = submitLocation.match(/[?&]id=(\d+)/);
            if (idMatch) {
                takoEmployeeId = idMatch[1];
            }

            // Follow the redirect to find the employee page
            if (submitLocation) {
                try {
                    const redirectUrl = submitLocation.startsWith('http')
                        ? submitLocation
                        : `${BASE}${submitLocation}`;
                    const followRes = await fetch(redirectUrl, {
                        method: 'GET', redirect: 'follow',
                        headers: {
                            'Cookie': finalCookies,
                            'User-Agent': UA,
                            'Accept': 'text/html,*/*',
                        },
                    });
                    const followBody = await followRes.text();
                    // Try to find employee ID from the final page URL or content
                    const finalUrl = followRes.url || '';
                    const urlIdMatch = finalUrl.match(/[?&]id=(\d+)/);
                    if (urlIdMatch) takoEmployeeId = urlIdMatch[1];
                    // Also search the page content for the employee link
                    if (!takoEmployeeId) {
                        const contentIdMatch = followBody.match(/employee\?id=(\d+)/);
                        if (contentIdMatch) takoEmployeeId = contentIdMatch[1];
                    }
                    if (takoEmployeeId) {
                        takoEmployeeUrl = `${BASE}/front/employer/employee?id=${takoEmployeeId}`;
                    }
                } catch (e) {
                    // Don't fail the whole request if redirect follow fails
                }
            }

            return res.json({
                success: true,
                step: 'submit',
                status: submitStatus,
                redirect: submitLocation,
                tako_employee_id: takoEmployeeId,
                tako_employee_url: takoEmployeeUrl,
                message: 'Employee registered successfully in Tako',
                sent_data: {
                    birth_date: toTakoDate(birth_date),
                    from_date: toTakoDate(from_date),
                    to_date: toTakoDate(to_date),
                    country, occupation: safeOccupation, gender: safeGender,
                    insurance_company, passport, first_name, last_name,
                },
            });
        }

        // ── חילוץ שגיאה מתוך ה-HTML המלא ──────────────────────────────
        // Rails alert box
        const alertMatch = submitBody.match(/class="alert[^"]*"[^>]*>([\s\S]*?)<\/div>/);
        // Rails exception page - search the FULL body, not truncated
        const exceptionMsgMatch = submitBody.match(/class="message"[^>]*>([\s\S]*?)<\/div>/);
        const h1Match = submitBody.match(/<header[^>]*>[\s\S]*?<h1[^>]*>([\s\S]*?)<\/h1>/);
        const preMatch = submitBody.match(/<pre[^>]*class="box"[^>]*>([\s\S]*?)<\/pre>/);
        // Validation errors
        const validationErrors = [];
        const errMatches = submitBody.matchAll(/class="field_with_errors"[\s\S]*?<label[^>]*>(.*?)<\/label>/gi);
        for (const m of errMatches) {
            validationErrors.push(m[1]);
        }

        // Build the most useful error message possible
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

        // Fallback: strip ALL html tags from body and grab first meaningful text
        if (!railsError) {
            const stripped = submitBody
                .replace(/<style[\s\S]*?<\/style>/gi, '')
                .replace(/<script[\s\S]*?<\/script>/gi, '')
                .replace(/<[^>]+>/g, ' ')
                .replace(/\s+/g, ' ')
                .trim();
            // Find first chunk of text that isn't just numbers/whitespace
            const meaningful = stripped.match(/[a-zA-Zא-ת]{3,}[\s\S]{10,200}/);
            railsError = meaningful ? meaningful[0].trim().slice(0, 300) : 'Unknown error (could not parse Rails response)';
        }

        return res.json({
            success: false,
            step: 'submit',
            status: submitStatus,
            redirect: submitLocation,
            error: railsError,
            validation_errors: validationErrors,
            body_length: submitBody.length,
            date_format_used: dateFormat,
            sent_data: {
                birth_date: toTakoDate(birth_date),
                enter_date: toTakoDate(enter_date),
                from_date: toTakoDate(from_date),
                to_date: toTakoDate(to_date),
                country, occupation: safeOccupation, gender: safeGender,
                insurance_company, passport, first_name, last_name,
            },
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

// ── /tako/search-employee — חיפוש עובד בטאקו לפי דרכון ─────────────────
app.post('/tako/search-employee', auth, async (req, res) => {
    const { email, password, passport } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email + password required' });
    if (!passport) return res.status(400).json({ error: 'passport required' });

    const BASE = 'https://tako-ins.com';
    const UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';

    try {
        // ── שלב 1: התחברות ─────────────────────────────────────────────
        const LOGIN_URL = `${BASE}/users/sign_in`;
        const g = await fetch(LOGIN_URL, {
            method: 'GET', redirect: 'follow',
            headers: { 'User-Agent': UA, 'Accept': 'text/html,*/*' },
        });
        const loginHtml = await g.text();
        const gCookies = parseCookies(g.headers.get('set-cookie'));

        let loginCsrf = '';
        for (const re of [
            /name=["']csrf-token["'][^>]+content=["']([^"']+)["']/i,
            /content=["']([^"']+)["'][^>]*name=["']csrf-token["']/i,
            /name="authenticity_token"\s+value="([^"]+)"/i,
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
                'Cookie': cookieString(gCookies),
                'User-Agent': UA, 'Referer': LOGIN_URL, 'Origin': BASE,
            },
            body: loginBody.toString(),
        });

        const loginPostCookies = parseCookies(loginRes.headers.get('set-cookie'));
        const sessionCookieArr = mergeCookies(gCookies, loginPostCookies);
        const loginLocation = loginRes.headers.get('location') || '';

        if (!(loginRes.status === 302 || loginLocation.includes('employer') || loginLocation.includes('home'))) {
            return res.json({ success: false, error: 'Login failed' });
        }

        // Follow login redirect
        if (loginLocation) {
            const redirectUrl = loginLocation.startsWith('http') ? loginLocation : `${BASE}${loginLocation}`;
            const followRes = await fetch(redirectUrl, {
                method: 'GET', redirect: 'follow',
                headers: { 'Cookie': cookieString(sessionCookieArr), 'User-Agent': UA },
            });
            await followRes.text();
            const followCookies = parseCookies(followRes.headers.get('set-cookie'));
            if (followCookies.length > 0) {
                const updatedArr = mergeCookies(sessionCookieArr, followCookies);
                sessionCookieArr.length = 0;
                updatedArr.forEach(c => sessionCookieArr.push(c));
            }
        }

        // ── שלב 2: חיפוש עובד בדף wizard ──────────────────────────────
        const wizardUrl = `${BASE}/front/employer/new_employee_wizard_2?passport=${encodeURIComponent(passport)}&commit=%D7%97%D7%99%D7%A4%D7%95%D7%A9`;
        const wizardRes = await fetch(wizardUrl, {
            method: 'GET', redirect: 'follow',
            headers: {
                'Cookie': cookieString(sessionCookieArr),
                'User-Agent': UA, 'Accept': 'text/html,*/*',
                'Referer': `${BASE}/front/employer/new_employee_wizard_1`,
            },
        });

        const wizardHtml = await wizardRes.text();

        // חיפוש מזהה העובד בתוך ה-HTML
        let takoEmployeeId = '';
        let takoEmployeeUrl = '';
        let employeeData = {};

        // Pattern 1 (PRIMARY): form id="edit_employee_107778" class="edit_employee"
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

        // זיהוי אם העובד קיים (edit) או חדש (new)
        const isExistingEmployee = wizardHtml.includes('edit_employee');

        // חילוץ שם העובד מהטופס
        const firstNameMatch = wizardHtml.match(/employee\[first_name\].*?value=["']([^"']+)["']/i);
        const lastNameMatch = wizardHtml.match(/employee\[last_name\].*?value=["']([^"']+)["']/i);
        if (firstNameMatch) employeeData.first_name = firstNameMatch[1];
        if (lastNameMatch) employeeData.last_name = lastNameMatch[1];
        employeeData.is_existing = isExistingEmployee;

        // חיפוש מספר פוליסה
        const policyMatch = wizardHtml.match(/policy_number.*?["'](\d+)["']/i);
        if (policyMatch) employeeData.policy_number = policyMatch[1];

        if (takoEmployeeId) {
            takoEmployeeUrl = `${BASE}/front/employer/employee?id=${takoEmployeeId}`;

            // ── שלב 3: גישה לדף העובד לחילוץ פרטים נוספים ──────────
            try {
                const empPageRes = await fetch(takoEmployeeUrl, {
                    method: 'GET', redirect: 'follow',
                    headers: {
                        'Cookie': cookieString(sessionCookieArr),
                        'User-Agent': UA, 'Accept': 'text/html,*/*',
                    },
                });
                const empPageHtml = await empPageRes.text();

// ── חילוץ נתונים מטבלת פוליסות ──
                // חשוב: מחפשים רק בתוך סקשן "פוליסות לעובד" כדי לא לתפוס תאריך לידה או מילים מחלקים אחרים
                // טבלת הפוליסות (DOM סדר שמאל לימין): סטטוס | מספר פוליסה | שם העובד | מספר העובד | חברת ביטוח | מס. קופת חולים | תאריך התחלה | תאריך סיום

                // חילוץ סקשן הפוליסות בלבד
                const policiesStart = empPageHtml.indexOf('פוליסות לעובד');
                const policiesEnd = empPageHtml.indexOf('שאלונים רפואיים', policiesStart > -1 ? policiesStart : 0);
                const policiesSection = policiesStart > -1
                    ? empPageHtml.substring(policiesStart, policiesEnd > policiesStart ? policiesEnd : empPageHtml.length)
                    : '';

                if (policiesSection) {
                    // חיפוש סטטוס מתוך span.label בסקשן הפוליסות בלבד
                    const statusLabelMatch = policiesSection.match(/<span[^>]*class=["'][^"']*label[^"']*["'][^>]*>\s*(פעילה|פתיחה|מבוטלת|בתהליך|ממתינה|הוקפאה|לא פעילה|בבירור)\s*<\/span>/i);
                    if (statusLabelMatch) employeeData.policy_status = statusLabelMatch[1].trim();

                    // חיפוש חברת ביטוח בתוך <td> בסקשן הפוליסות בלבד
                    const insurerMatch = policiesSection.match(/<td>\s*(מנורה|איילון|הראל|הכשרה|כלל|מגדל|ביטוח ישיר|פניקס|הפניקס)\s*<\/td>/);
                    if (insurerMatch) employeeData.insurer = insurerMatch[1];

                    // חיפוש תאריכים בתוך <td> בסקשן הפוליסות בלבד - פורמט YYYY-MM-DD
                    const dateMatchesISO = policiesSection.matchAll(/<td>\s*(\d{4}-\d{2}-\d{2})\s*<\/td>/g);
                    const datesISO = [];
                    for (const dm of dateMatchesISO) datesISO.push(dm[1]);
                    if (datesISO.length >= 2) {
                        employeeData.start_date = datesISO[0];
                        employeeData.end_date = datesISO[1];
                    } else if (datesISO.length === 1) {
                        employeeData.start_date = datesISO[0];
                    }

                    // גם לנסות פורמט DD/MM/YYYY אם ISO לא נמצא
                    if (!employeeData.start_date) {
                        const dateMatchesEU = policiesSection.matchAll(/<td>\s*(\d{2}\/\d{2}\/\d{4})\s*<\/td>/g);
                        const datesEU = [];
                        for (const dm of dateMatchesEU) datesEU.push(dm[1]);
                        if (datesEU.length >= 2) {
                            employeeData.start_date = datesEU[0];
                            employeeData.end_date = datesEU[1];
                        }
                    }
                }

                // חיפוש מספר פוליסה + policy_eid מתוך טבלת פוליסות לעובד
                // המבנה: <td><a href="/front/employer/employment?eid=265523">5297002616250</a></td>
                if (policiesSection) {
                    const policyLinkMatch = policiesSection.match(/<a\s+href="\/front\/employer\/employment\?eid=(\d+)">\s*(\d+)\s*<\/a>/);
                    if (policyLinkMatch) {
                        employeeData.policy_eid = policyLinkMatch[1];
                        employeeData.policy_number = policyLinkMatch[2];
                    }
                }            } catch (e) {
                // Don't fail if employee page can't be read
            }
        }

        return res.json({
            success: !!takoEmployeeId,
            passport,
            tako_employee_id: takoEmployeeId,
            tako_employee_url: takoEmployeeUrl,
            employee_data: employeeData,
            wizard_url: wizardRes.url,
        });

    } catch (e) {
        return res.status(500).json({ success: false, error: e.message, stack: e.stack });
    }
});

app.listen(PORT, () => console.log(`✅ Tako Proxy v2 on :${PORT}`));
