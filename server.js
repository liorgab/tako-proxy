/**
 * Tako Insurance Proxy Server v2 â with full debug
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
// ââ Cookie helpers âââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
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
// ââ /tako/debug â ××××§×ª ×××©× ××¡××¡××ª ××××§× âââââââââââââââââââââââââââââââââ
app.get('/tako/debug', auth, async (req, res) => {
    const URL = 'https://tako-ins.com/users/sign_in';
    const results = {};
    // × ××¡××× 1: redirect follow
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
    // × ××¡××× 2: redirect manual
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
    // × ××¡××× 3: HTTP (×× HTTPS)
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
// ââ /tako/login âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
app.post('/tako/login', auth, async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password)
        return res.status(400).json({ error: 'email + password required' });
    const BASE      = 'https://tako-ins.com';
    const LOGIN_URL = `${BASE}/users/sign_in`;
    const UA        = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
    try {
        // ââ Step 1: GET ââââââââââââââââââââââââââââââââââââââââââââââââââââââ
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
        // ââ Step 2: POST âââââââââââââââââââââââââââââââââââââââââââââââââââââ
        const body = new URLSearchParams();
        if (csrf) body.append('authenticity_token', csrf);
        body.append('user[email]',       email);
        body.append('user[password]',    password);
        body.append('user[remember_me]', '0');
        body.append('commit',            '×× ××¡×');
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
// ââ /tako/create-employee â ×¨××©×× ×¢××× ×××© + ×¤×ª×××ª ×¤××××¡× ××××§× ââââââââââ
app.post('/tako/create-employee', auth, async (req, res) => {
    const {
        email, password,
        first_name, last_name, passport, country,
        birth_date, enter_date, occupation, gender,
        street, house_no, city, zip,
        phone_no, send_sms, emp_no, dept,
        from_date, to_date, insurance_company
    } = req.body || {};
    // ×××××¦×× ××¡××¡××ª
    if (!email || !password)
        return res.status(400).json({ error: 'email + password required' });
    if (!first_name || !last_name || !passport)
        return res.status(400).json({ error: 'first_name, last_name, passport required' });
    if (!from_date || !to_date || !insurance_company)
        return res.status(400).json({ error: 'from_date, to_date, insurance_company required' });
    const BASE = 'https://tako-ins.com';
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
        // ââ ×©×× 1: ××ª×××¨××ª ××××§× ââââââââââââââââââââââââââââââââââââââââââââ
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
        loginBody.append('commit', '×× ××¡×');
        const loginRes = await fetch(LOGIN_URL, {
            method: 'POST', redirect: 'manual',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': cookieString(gCookies),
                'User-Agent': UA, 'Referer': LOGIN_URL, 'Origin': BASE,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            },
            body: loginBody.toString(),
        });
        const loginPostCookies = parseCookies(loginRes.headers.get('set-cookie'));
        const sessionCookieArr = mergeCookies(gCookies, loginPostCookies);
        const loginLocation = loginRes.headers.get('location') || '';
        const loginSuccess = loginRes.status === 302
            || loginLocation.includes('employer')
            || loginLocation.includes('home');
        if (!loginSuccess) {
            return res.json({
                success: false, step: 'login', error: 'Login failed',
                status: loginRes.status, location: loginLocation,
            });
        }
        // ââ ×©×× 2: ×××©× ××××¤×¡ ×¨××©×× ×¢××× ââââââââââââââââââââââââââââââââââ
        const wizardUrl = `${BASE}/front/employer/new_employee_wizard_2?passport=${encodeURIComponent(passport)}&commit=%D7%97%D7%99%D7%A4%D7%95%D7%A9`;
        if (loginLocation) {
            const redirectUrl = loginLocation.startsWith('http') ? loginLocation : `${BASE}${loginLocation}`;
            const followRes = await fetch(redirectUrl, {
                method: 'GET', redirect: 'follow',
                headers: { 'Cookie': cookieString(sessionCookieArr), 'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8' },
            });
            await followRes.text();
            const followCookies = parseCookies(followRes.headers.get('set-cookie'));
            if (followCookies.length > 0) {
                const updatedArr = mergeCookies(sessionCookieArr, followCookies);
                sessionCookieArr.length = 0;
                updatedArr.forEach(c => sessionCookieArr.push(c));
            }
        }
        const wizardRes = await fetch(wizardUrl, {
            method: 'GET', redirect: 'follow',
            headers: {
                'Cookie': cookieString(sessionCookieArr), 'User-Agent': UA,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                'Referer': `${BASE}/front/employer/new_employee_wizard_1`,
            },
        });
        const wizardHtml = await wizardRes.text();
        const wizardCookiesNew = parseCookies(wizardRes.headers.get('set-cookie'));
        const afterWizardCookies = mergeCookies(sessionCookieArr, wizardCookiesNew);
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
                wizard_status: wizardRes.status, wizard_url: wizardRes.url, html_preview: wizardHtml.slice(0, 500),
            });
        }
        const finalCookies = cookieString(afterWizardCookies);
        // ââ ×©×× 3: ×©××××ª ×××¤×¡ ×¨××©×× ××¢××× âââââââââââââââââââââââââââââââââ
        const formData = new URLSearchParams();
        formData.append('authenticity_token', formCsrf);
        formData.append('employee[first_name]', first_name || '');
        formData.append('employee[last_name]', last_name || '');
        formData.append('employee[passport]', passport || '');
        formData.append('employee[country]', country || '');
        formData.append('employee[birth_date]', toTakoDate(birth_date));
        formData.append('employee[enter_date]', toTakoDate(enter_date));
        const validOccupations = ['×× ××', '×¡××¢××', '××§××××ª', '×××¨'];
        const safeOccupation = validOccupations.includes(occupation) ? occupation : '×× ××';
        formData.append('employee[occupation]', safeOccupation);
        const safeGender = (gender === '× ×§××') ? '× ×§××' : '×××¨';
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
        formData.append('commit', '×©×××¨');
        const submitRes = await fetch(`${BASE}/front/employer/save_new_employee`, {
            method: 'POST', redirect: 'manual',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': finalCookies, 'User-Agent': UA,
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
                    const followRes = await fetch(redirectUrl, {
                        method: 'GET', redirect: 'follow',
                        headers: { 'Cookie': finalCookies, 'User-Agent': UA, 'Accept': 'text/html,*/*' },
                    });
                    const followBody = await followRes.text();
                    const finalUrl = followRes.url || '';
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
        // ââ ×××××¥ ×©×××× ââââââââââââââââââââââââââââââââââââââââââââââââââ
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
            const meaningful = stripped.match(/[a-zA-Z×-×ª]{3,}[\s\S]{10,200}/);
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
        return res.status(500).json({ success: false, step: 'exception', error: e.message, stack: e.stack });
    }
});
// ââ /tako/proxy âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
app.post('/tako/proxy', auth, async (req, res) => {
    const { url, method = 'GET', body, session_cookies, headers: xh = {} } = req.body || {};
    if (!url) return res.status(400).json({ error: 'url required' });
    if (!session_cookies) return res.status(400).json({ error: 'session_cookies required' });
    try {
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
        const text = await r.text();
        return res.json({ status: r.status, location: r.headers.get('location') || '', body: text.slice(0, 8000) });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});
// ââ /tako/search-employee â ×××¤××© ×¢××× ××××§× ××¤× ××¨××× âââââââââââââââââ
app.post('/tako/search-employee', auth, async (req, res) => {
    const { email, password, passport } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email + password required' });
    if (!passport) return res.status(400).json({ error: 'passport required' });
    const BASE = 'https://tako-ins.com';
    const UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
    try {
        // ââ ×©×× 1: ××ª×××¨××ª âââââââââââââââââââââââââââââââââââââââââââââ
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
        loginBody.append('commit', '×× ××¡×');
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
        // ââ ×©×× 2: ×××¤××© ×¢××× ×××£ wizard ââââââââââââââââââââââââââââââ
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
            // ââ ×©×× 3: ×××©× ×××£ ××¢××× ××××××¥ ×¤×¨××× × ××¡×¤×× ââââââââââ
            try {
                const empPageRes = await fetch(takoEmployeeUrl, {
                    method: 'GET', redirect: 'follow',
                    headers: {
                        'Cookie': cookieString(sessionCookieArr),
                        'User-Agent': UA, 'Accept': 'text/html,*/*',
                    },
                });
                const empPageHtml = await empPageRes.text();

                // ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
                // ââ ×××××¥ × ×ª×× ×× ×××××ª ×¤××××¡××ª (v3 â ××¤×¨×¡×¨ ×× ××©××¨××ª) ââ
                // ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
                // ××¤×¨×¡×¨ ××ª ×× ×©××¨××ª ××××× ×××××¨ ××ª ××¤××××¡× ×× ××× ×
                // ×¢×××¤××ª: ×¤×¢××× > ××§×©×ª ×××××© > ×¤×ª××× > ××××××ª
                const policiesStart = empPageHtml.indexOf('×¤××××¡××ª ××¢×××');
                const policiesEnd = empPageHtml.indexOf('×©×××× ×× ×¨×¤×××××', policiesStart > -1 ? policiesStart : 0);
                const policiesSection = policiesStart > -1
                    ? empPageHtml.substring(policiesStart, policiesEnd > policiesStart ? policiesEnd : empPageHtml.length)
                    : '';

                if (policiesSection) {
                    // ×¤×¨×¡××¨ ×× ×©××¨××ª ×××××
                    const rows = policiesSection.match(/<tr[\s\S]*?<\/tr>/gi) || [];
                    const policies = [];

                    for (const row of rows) {
                        const policy = {};

                        // ×¡××××¡ ××ª×× span.label
                        const statusMatch = row.match(/<span[^>]*class=["'][^"']*label[^"']*["'][^>]*>\s*(×¤×¢×××|×¤×ª×××|××××××ª|××ª××××|×××ª×× ×|×××§×¤××|×× ×¤×¢×××|××××¨××¨|××§×©×ª ×××××©|××§×©×ª ×××××)\s*<\/span>/i);
                        if (statusMatch) policy.status = statusMatch[1].trim();

                        // ×§××©××¨ ×¤××××¡× (eid + ××¡×¤×¨ ×¤××××¡×)
                        const linkMatch = row.match(/<a\s+href="\/front\/employer\/employment\?eid=(\d+)">\s*(\d+)\s*<\/a>/);
                        if (linkMatch) {
                            policy.eid = linkMatch[1];
                            policy.number = linkMatch[2];
                        }

                        // ×××¨×ª ×××××
                        const insurerMatch = row.match(/<td>\s*(×× ××¨×|××××××|××¨××|×××©×¨×|×××|××××|××××× ××©××¨|×¤× ××§×¡|××¤× ××§×¡)\s*<\/td>/);
                        if (insurerMatch) policy.insurer = insurerMatch[1];

                        // HMO number - unique per employee (7-13 digits in plain td)
                        const hmoMatch = row.match(/<td>\s*(\d{7,13})\s*<\/td>/);
                        if (hmoMatch) policy.hmo_number = hmoMatch[1];

                        // ×ª××¨×××× - ×¤××¨×× ISO (YYYY-MM-DD)
                        const dates = [];
                        const dateMatches = row.matchAll(/<td>\s*(\d{4}-\d{2}-\d{2})\s*<\/td>/g);
                        for (const dm of dateMatches) dates.push(dm[1]);
                        if (dates.length >= 2) {
                            policy.start_date = dates[0];
                            policy.end_date = dates[1];
                        } else if (dates.length === 1) {
                            policy.start_date = dates[0];
                        }

                        // ×× ×× ×¡××ª ×¤××¨×× DD/MM/YYYY
                        if (!policy.start_date) {
                            const datesEU = [];
                            const dateMatchesEU = row.matchAll(/<td>\s*(\d{2}\/\d{2}\/\d{4})\s*<\/td>/g);
                            for (const dm of dateMatchesEU) datesEU.push(dm[1]);
                            if (datesEU.length >= 2) {
                                policy.start_date = datesEU[0];
                                policy.end_date = datesEU[1];
                            }
                        }

                        // ×¨×§ ×©××¨××ª ×¢× ×¡××××¡ ×× ×§××©××¨ (×××××× ×¢× header)
                        if (policy.status || policy.eid) {
                            policies.push(policy);
                        }
                    }

                    // ××××¨×ª ××¤××××¡× ×× ××× ×: ×¢×××¤××ª ××¤× ×¡××××¡, ××"× ×ª××¨×× ××ª××× ×××××¨
                    const STATUS_PRIORITY = {
                        '×¤×¢×××': 1,
                        '××§×©×ª ×××××©': 2,
                        '×¤×ª×××': 3,
                        '××ª××××': 4,
                        '×××ª×× ×': 5,
                        '××§×©×ª ×××××': 6,
                        '×××§×¤××': 7,
                        '××××××ª': 8,
                        '×× ×¤×¢×××': 9,
                        '××××¨××¨': 10,
                    };

                    if (policies.length > 0) {
                        policies.sort((a, b) => {
                            const pa = STATUS_PRIORITY[a.status] || 99;
                            const pb = STATUS_PRIORITY[b.status] || 99;
                            if (pa !== pb) return pa - pb;
                            // ×××ª× ×¢×××¤××ª - ×ª××¨×× ××ª××× ×××××¨ ×××ª×¨ ×× ×¦×
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

                    // ×©×××¨×ª ×× ××¤××××¡××ª ××××¨××ª debug
                    employeeData.all_policies = policies;
                }
                // ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

                // ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
                // ââ ×××××¥ × ×ª×× × ×©×××× ×× ×¨×¤××××× âââââââââââââââââââââââââ
                // ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
                const medicalStart = empPageHtml.lastIndexOf('×©×××× ×× ×¨×¤×××××');
                if (medicalStart > -1) {
                    // ×××¤×©×× ××ª ××××× ×××× ×××¨× ××××ª×¨×ª
                    const medicalSection = empPageHtml.substring(medicalStart, medicalStart + 5000);
                    const medicalRows = medicalSection.match(/<tr[\s\S]*?<\/tr>/gi) || [];
                    const questionnaires = [];

                    for (const row of medicalRows) {
                        const q = {};

                        // ×¡××××¡: ×××× / ×× ××××
                        if (row.includes('××××')) {
                            q.status = row.includes('×× ××××') ? '×× ××××' : '××××';
                        }

                        // Form ID â ××ª×× ××× ×§×× /medical_forms/{id}/preview ×× /medical_forms/{id}/edit
                        const formIdMatch = row.match(/\/medical_forms\/(\d+)\/(preview|edit)/);
                        if (formIdMatch) {
                            q.form_id = formIdMatch[1];
                            q.form_type = formIdMatch[2]; // preview = ×××××, edit = ×× ×××××
                        }

                        // ×× ×-checkbox: <input type="checkbox" id="133811" value="133811">
                        if (!q.form_id) {
                            const checkboxMatch = row.match(/medical_forms\[\].*?value=["'](\d+)["']/);
                            if (checkboxMatch) q.form_id = checkboxMatch[1];
                        }

                        // ×× ×-send_medical_form_link parameter
                        if (!q.form_id) {
                            const sendLinkMatch = row.match(/send_medical_form_link=(\d+)/);
                            if (sendLinkMatch) q.form_id = sendLinkMatch[1];
                        }

                        // ×ª××¨×× ××ª×××
                        const dateMatch = row.match(/(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}/);
                        if (dateMatch) q.signed_date = dateMatch[1];

                        // ××¡×¤×¨ ×¤××××¡×
                        const polNumMatch = row.match(/<td>\s*(\d{4,})\s*<\/td>/);
                        if (polNumMatch) q.policy_number = polNumMatch[1];

                        // ×¨×§ ×©××¨××ª ×¢× ××××¢ ×¨×××× ××
                        if (q.status || q.form_id) {
                            questionnaires.push(q);
                        }
                    }

                    // ××××: "×× ××××" ×§××× (×××¨×© ×¤×¢×××), ××"× ××¤× ×ª××¨×× ××ª××× ×××¨×
                    if (questionnaires.length > 0) {
                        questionnaires.sort((a, b) => {
                            // ×¢×××¤××ª ×¨××©×× ×: "×× ××××" ××¤× × "××××"
                            const aUnfilled = (a.status === '×× ××××') ? 0 : 1;
                            const bUnfilled = (b.status === '×× ××××') ? 0 : 1;
                            if (aUnfilled !== bUnfilled) return aUnfilled - bUnfilled;
                            // ×¢×××¤××ª ×©× ×××: ×ª××¨×× ××ª××× ×××¨×
                            return (b.signed_date || '').localeCompare(a.signed_date || '');
                        });

                        // ××©×××× ××¨×××× ×× ××××ª×¨ â "×× ××××" ×× ×§×××, ×××¨×ª ××××¨×× ×©××××
                        const latest = questionnaires[0];
                        employeeData.medical_form_id = latest.form_id || '';
                        employeeData.medical_form_status = latest.status || '';
                        employeeData.medical_form_signed_date = latest.signed_date || '';
                        if (latest.form_id) {
                            if (latest.status === '××××') {
                                employeeData.medical_form_url = `${BASE}/medical_forms/${latest.form_id}/preview`;
                            } else {
                                employeeData.medical_form_url = `${BASE}/medical_forms/${latest.form_id}/edit`;
                            }
                        }
                    }

                    // ×©×××¨×ª ×× ××©×××× ×× ××××¨××ª debug
                    employeeData.all_questionnaires = questionnaires;
                }
                // ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

            } catch (e) {
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
app.listen(PORT, () => console.log(`â Tako Proxy v2 on :${PORT}`));
