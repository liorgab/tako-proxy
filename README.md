# Tako Proxy Server

פרוקסי בין Base44 לאתר tako-ins.com

---

## פריסה על Railway (מומלץ — חינם)

1. לך ל https://railway.app → New Project → Deploy from GitHub
2. העלה את התיקייה הזו ל-GitHub repo חדש
3. Railway יזהה Node.js ויבנה אוטומטית
4. הוסף Environment Variable:
   - `TAKO_API_KEY` = מפתח סודי לבחירתך (לדוג': `tako-abc123xyz`)
5. קבל את ה-URL (לדוג': `https://tako-proxy.up.railway.app`)

---

## פריסה עם ngrok (לבדיקה מהירה מהמחשב)

```bash
# התקנה
npm install
node server.js   # פתח terminal 1

# terminal 2
npx ngrok http 3000
# תקבל URL כמו: https://abc123.ngrok.io
```

---

## API

### POST /tako/login
```json
Headers: { "x-api-key": "tako-abc123xyz" }
Body: { "email": "...", "password": "..." }

Response: {
  "success": true,
  "session_cookies": "...",
  "location": "/front/employer/home"
}
```

### POST /tako/proxy
```json
Headers: { "x-api-key": "tako-abc123xyz" }
Body: {
  "url": "https://tako-ins.com/...",
  "method": "GET",
  "session_cookies": "..."
}

Response: {
  "status": 200,
  "body": "..."
}
```

---

## פרומפט ל-Base44 לאחר הפריסה

```
עדכן את ה-Backend Function "takoLogin":

const PROXY_URL = 'https://YOUR-RAILWAY-URL.up.railway.app';
const API_KEY   = 'tako-abc123xyz';  // אותו מפתח שהגדרת

export default async function takoLogin({ email, password }) {
  const res = await fetch(`${PROXY_URL}/tako/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': API_KEY,
    },
    body: JSON.stringify({ email, password }),
  });
  return await res.json();
}
```
