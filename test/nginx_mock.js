/**
 * nginx_mock.js — NGINX OIDC モジュールの動作を再現する Express サーバー
 * 
 * 今回修正した2つのロジックを再現する:
 *  1. redirect_issued フラグ: コールバック処理後は proxy_pass を実行せず 302 で完了する
 *  2. groups クレーム: UserInfo から文字列として受け取りヘッダに設定する
 */
const express = require('express');
const crypto = require('crypto');
const http = require('http');

const app = express();
const HMAC_SECRET = 'test-secret-key-1234567890';
const IDP_BASE = 'http://127.0.0.1:3000';

// ─── helper: HTTP GET/POST ────────────────────────────────────────────────
function fetchUrl(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const options = {
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: opts.method || 'GET',
      headers: opts.headers || {}
    };
    const req = http.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// ─── HMAC cookie helpers ──────────────────────────────────────────────────
function signCookie(payload) {
  const mac = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  return mac + payload;
}
function verifyCookie(cookie) {
  if (!cookie || cookie.length < 64) return null;
  const mac = cookie.slice(0, 64);
  const payload = cookie.slice(64);
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  return payload;
}
function encodePayload(claims, extra) {
  const sub   = Buffer.from(claims.sub   || '').toString('base64');
  const email = Buffer.from(claims.email || '').toString('base64');
  const name  = Buffer.from(claims.name  || '').toString('base64');
  let payload = `${sub}:${email}:${name}:${Math.floor(Date.now()/1000)}`;
  for (const [k, v] of Object.entries(extra)) {
    const kb = Buffer.from(k).toString('base64');
    const vb = Buffer.from(v).toString('base64');
    payload += `|${kb}:${vb}`;
  }
  return payload;
}
function decodePayload(payload) {
  const claims = {}; const extra = {};
  const [base, ...parts] = payload.split('|');
  const fields = base.split(':');
  claims.sub   = Buffer.from(fields[0] || '', 'base64').toString();
  claims.email = Buffer.from(fields[1] || '', 'base64').toString();
  claims.name  = Buffer.from(fields[2] || '', 'base64').toString();
  for (const p of parts) {
    const [k, v] = p.split(':');
    extra[Buffer.from(k, 'base64').toString()] = Buffer.from(v || '', 'base64').toString();
  }
  return { claims, extra };
}

// ─── Provider metadata (cached) ─────────────────────────────────────────
let metadata = null;
async function getMetadata() {
  if (metadata) return metadata;
  const r = await fetchUrl(`${IDP_BASE}/.well-known/openid-configuration`);
  metadata = JSON.parse(r.body);
  return metadata;
}

// ─── Access phase logic (mirrors the C module) ───────────────────────────
app.use(async (req, res, next) => {
  try {
  // Parse cookies
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k.trim()] = v.join('=');
  });
  console.log(`[mock] ${req.method} ${req.path} cookies:`, Object.keys(cookies));

  const md = await getMetadata();

  // ── Callback path (/callback) ────────────────────────────────────────
  if (req.path === '/callback') {
    const code  = new URL(req.url, 'http://x').searchParams.get('code');
    const state = new URL(req.url, 'http://x').searchParams.get('state');

    // State verification
    console.log(`[mock] callback: code=${code?.slice(0,8)}, state match=${state === cookies['oidc_state']}`);
    if (!code || !state || state !== cookies['oidc_state']) {
      return res.status(403).send('State mismatch');
    }

    // Token exchange
    const tokenResp = await fetchUrl(md.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=authorization_code&code=${code}&client_id=test-client-id&client_secret=test-secret&redirect_uri=%2Fcallback`
    });
    const tokens = JSON.parse(tokenResp.body);

    // Decode JWT (simplified - skip signature verification for mock)
    const jwtPayload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString());

    // Nonce verification
    if (jwtPayload.nonce !== cookies['oidc_nonce']) {
      return res.status(403).send('Nonce mismatch');
    }

    // UserInfo request (oidc_use_userinfo on)
    const uiResp = await fetchUrl(md.userinfo_endpoint, {
      headers: { 'Authorization': `Bearer ${tokens.access_token}` }
    });
    const userinfo = JSON.parse(uiResp.body);

    // Build extra claims from UserInfo (string values only, mirroring C module)
    const extra = {};
    for (const [k, v] of Object.entries(userinfo)) {
      if (['sub','email','name'].includes(k)) continue;
      if (typeof v === 'string' || typeof v === 'number') {
        extra[k] = String(v);
      }
      // Arrays are skipped — same as C module behaviour
    }

    const claims = {
      sub:   userinfo.sub   || jwtPayload.sub,
      email: userinfo.email || jwtPayload.email,
      name:  userinfo.name  || jwtPayload.name
    };

    const payload  = encodePayload(claims, extra);
    const authCookie = signCookie(payload);

    const returnTo = cookies['oidc_return_to'] || '/';

    // ── KEY FIX BEING TESTED ─────────────────────────────────────────
    // redirect_issued: send 302 immediately instead of falling through
    // to the proxy (backend) handler. This is what the C fix does.
    res.setHeader('Set-Cookie', [
      `oidc_auth=${authCookie}; HttpOnly; SameSite=Lax; Path=/`,
      `oidc_state=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/`,
      `oidc_nonce=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/`,
      `oidc_return_to=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/`,
    ]);
    res.redirect(302, returnTo);
    return;
    // ─────────────────────────────────────────────────────────────────
    // Without the fix, execution would fall through to the backend proxy below
    // (next()) and cause "header already sent" conflict.
  }

  // ── Cookie authentication ────────────────────────────────────────────
  const authCookieVal = cookies['oidc_auth'];
  if (authCookieVal) {
    const payload = verifyCookie(authCookieVal);
    if (payload) {
      const { claims, extra } = decodePayload(payload);
      req._oidcClaims = claims;
      req._oidcExtra  = extra;
      return next();   // authenticated
    }
  }

  // ── Unauthenticated: redirect to IdP ────────────────────────────────
  const state = crypto.randomBytes(32).toString('hex');
  const nonce = crypto.randomBytes(32).toString('hex');
  const authUrl = `${md.authorization_endpoint}?response_type=code&scope=openid+profile+email` +
    `&client_id=test-client-id&redirect_uri=%2Fcallback` +
    `&state=${state}&nonce=${nonce}`;

  res.setHeader('Set-Cookie', [
    `oidc_state=${state}; HttpOnly; SameSite=Lax; Path=/`,
    `oidc_nonce=${nonce}; HttpOnly; SameSite=Lax; Path=/`,
    `oidc_return_to=${req.path}; HttpOnly; SameSite=Lax; Path=/`,
  ]);
  res.redirect(302, authUrl);
  } catch (err) {
    console.error('[mock] error in middleware:', err);
    if (!res.headersSent) res.status(500).send(String(err));
  }
});

// ─── Backend: echo claims as JSON (mirrors nginx.conf /backend location) ─
app.get('*', (req, res) => {
  const c = req._oidcClaims || {};
  const e = req._oidcExtra  || {};
  res.json({
    sub:       c.sub       || '',
    email:     c.email     || '',
    name:      c.name      || '',
    groups:    e.groups    || '',
    tenant_id: e.tenant_id || ''
  });
});

app.listen(8080, () => console.log('nginx_mock listening on :8080'));
