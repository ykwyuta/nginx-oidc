/**
 * mock-idp.js — E2E テスト用のモック OpenID Provider。
 *
 * - Discovery / JWKS / 認可 / トークン / UserInfo を提供する
 * - ID トークンは RS256 で署名する（モジュール側の署名検証を実際に通す）
 * - トークンエンドポイントは client_secret_basic のみを受け付ける
 */
const express = require('express');
const fs = require('fs');
const https = require('https');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = Number(process.env.MOCK_IDP_PORT || 3000);

// Discovery / iss で公開するベース URL。NGINX 側の oidc_provider と一致させる。
const ISSUER = process.env.MOCK_IDP_ISSUER || `http://127.0.0.1:${port}`;

const CLIENT_ID = process.env.MOCK_IDP_CLIENT_ID || 'test-client-id';
const CLIENT_SECRET = process.env.MOCK_IDP_CLIENT_SECRET || 'test-client-secret';

app.use(express.urlencoded({ extended: true }));

// 署名アルゴリズム。ES256 を指定すると EC 鍵で署名する（EC の JWKS 経路の検証用）。
const ALG = process.env.MOCK_IDP_ALG || 'RS256';

const { privateKey, publicKey } = ALG === 'ES256'
  ? crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    })
  : crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
const kid = 'test-key-1';

// JWKS には載せない鍵。?bad_sig=1 のときだけ使い、署名検証が効いていることを確かめる。
const rogueKey = (ALG === 'ES256'
  ? crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    })
  : crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    })).privateKey;

app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/auth`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/certs`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    end_session_endpoint: `${ISSUER}/logout`,
    pushed_authorization_request_endpoint: `${ISSUER}/par`,
    dpop_signing_alg_values_supported: ['ES256'],
    backchannel_logout_supported: true,
    backchannel_logout_session_supported: true,
    frontchannel_logout_supported: true,
    frontchannel_logout_session_supported: true,
    introspection_endpoint: `${ISSUER}/introspect`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: [ALG],
    token_endpoint_auth_methods_supported: ['client_secret_basic',
                                            'client_secret_post',
                                            'client_secret_jwt',
                                            'private_key_jwt']
  });
});

app.get('/certs', (req, res) => {
  const key = ALG === 'ES256'
    ? { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }
    : { kty: jwk.kty, n: jwk.n, e: jwk.e };

  res.json({ keys: [{ ...key, use: 'sig', kid: kid, alg: ALG }] });
});

// request_uri -> pushed parameters
const parRequests = new Map();

/* RFC 9126: Pushed Authorization Request */
app.post('/par', (req, res) => {
  const auth = checkClientAuth(req);
  if (auth.error) {
    return res.status(401).json({ error: 'invalid_client', details: auth.error });
  }

  if (!req.body.response_type || !req.body.code_challenge) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  const id = 'urn:ietf:params:oauth:request_uri:'
             + crypto.randomBytes(16).toString('hex');
  parRequests.set(id, { ...req.body, auth: auth.method });

  console.log(`[IdP] authorization request pushed (auth=${auth.method})`);
  res.status(201).json({ request_uri: id, expires_in: 60 });
});

app.get('/auth', (req, res) => {
  // 事前送信されたリクエストは request_uri から取り出す
  if (req.query.request_uri) {
    const pushed = parRequests.get(req.query.request_uri);
    if (!pushed) {
      return res.status(400).send('unknown request_uri');
    }
    parRequests.delete(req.query.request_uri);
    req.query = { ...pushed, ...req.query };
  }

  const { redirect_uri, state, nonce, client_id, code_challenge,
          code_challenge_method } = req.query;
  // テスト用のフラグ（不正な署名 / 不正な aud / 短命なアクセストークン）
  const badSig = req.query.bad_sig === '1' ? '1' : '';
  const badAud = req.query.bad_aud === '1' ? '1' : '';
  const shortToken = req.query.short_token === '1' ? '1' : '';

  if (client_id !== CLIENT_ID) {
    return res.status(400).send('unknown client_id');
  }
  if (code_challenge_method !== 'S256' || !code_challenge) {
    return res.status(400).send('PKCE S256 is required');
  }

  res.send(`
    <html>
      <body>
        <h1>Mock IdP Login</h1>
        <form method="POST" action="/auth/submit">
          <input type="hidden" name="redirect_uri" value="${redirect_uri}">
          <input type="hidden" name="state" value="${state}">
          <input type="hidden" name="nonce" value="${nonce}">
          <input type="hidden" name="client_id" value="${client_id}">
          <input type="hidden" name="code_challenge" value="${code_challenge}">
          <input type="hidden" name="bad_sig" value="${badSig}">
          <input type="hidden" name="bad_aud" value="${badAud}">
          <input type="hidden" name="short_token" value="${shortToken}">
          <label>Username: <input type="text" name="username" value="testuser"></label><br>
          <label>Password: <input type="password" name="password" value="password"></label><br>
          <button type="submit" id="login-button">Login</button>
        </form>
      </body>
    </html>
  `);
});

const authCodes = new Map();

app.post('/auth/submit', (req, res) => {
  const { redirect_uri, state, nonce, username, password,
          code_challenge, bad_sig, bad_aud, short_token } = req.body;

  if (username !== 'testuser' || password !== 'password') {
    return res.status(401).send('Invalid credentials');
  }

  const code = crypto.randomBytes(16).toString('hex');
  authCodes.set(code, { nonce, username, code_challenge, redirect_uri,
                        badSig: bad_sig === '1', badAud: bad_aud === '1',
                        shortToken: short_token === '1' });

  const target = /^https?:\/\//.test(redirect_uri)
    ? redirect_uri
    : `http://localhost:8080${redirect_uri}`;

  console.log(`[IdP] login ok, code=${code} -> ${target}`);
  res.redirect(`${target}?code=${code}&state=${state}`);
});

function base64url(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/*
 * client_secret_basic (RFC 6749 2.3.1) と client_secret_post を受け付ける。
 * 使われた方式を返し、テストから検証できるようにする。
 */
function checkClientAuth(req) {
  const header = req.headers['authorization'];

  if (header && header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep < 0) {
      return { error: 'malformed Basic credentials' };
    }

    const id = decodeURIComponent(decoded.slice(0, sep));
    const secret = decodeURIComponent(decoded.slice(sep + 1));

    if (id !== CLIENT_ID || secret !== CLIENT_SECRET) {
      return { error: 'invalid client credentials' };
    }

    return { method: 'basic' };
  }

  // RFC 8705: 証明書を提示していれば client_id だけで足りる
  const cert = req.socket.getPeerCertificate
               ? req.socket.getPeerCertificate() : null;

  if (cert && cert.subject && !req.body.client_secret
      && !req.body.client_assertion)
  {
    if (req.body.client_id !== CLIENT_ID) {
      return { error: 'invalid client_id for mTLS' };
    }
    return { method: 'mtls' };
  }

  if (req.body.client_assertion) {
    if (req.body.client_assertion_type
        !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
      return { error: 'unexpected client_assertion_type' };
    }

    const header = JSON.parse(
      Buffer.from(req.body.client_assertion.split('.')[0], 'base64url')
        .toString('utf8'));

    const usesSecret = header.alg.startsWith('HS');
    const key = usesSecret ? CLIENT_SECRET : clientPublicKey;

    if (!key) {
      return { error: 'no key to verify the client assertion' };
    }

    try {
      const claims = jwt.verify(req.body.client_assertion, key, {
        algorithms: [header.alg],
        issuer: CLIENT_ID,
        audience: `${ISSUER}/token`
      });

      if (claims.sub !== CLIENT_ID || !claims.jti) {
        return { error: 'malformed client assertion' };
      }

    } catch (e) {
      return { error: `client assertion rejected: ${e.message}` };
    }

    return { method: usesSecret ? 'client_secret_jwt' : 'private_key_jwt' };
  }

  if (req.body.client_id !== undefined || req.body.client_secret !== undefined) {
    if (req.body.client_id !== CLIENT_ID
        || req.body.client_secret !== CLIENT_SECRET) {
      return { error: 'invalid client credentials' };
    }

    return { method: 'post' };
  }

  return { error: 'no client credentials' };
}

// private_key_jwt の検証に使うクライアント公開鍵（テストランナーが生成する）
const clientPublicKey = process.env.MOCK_IDP_CLIENT_PUBKEY
  ? fs.readFileSync(process.env.MOCK_IDP_CLIENT_PUBKEY, 'utf8')
  : null;

/*
 * DPoP (RFC 9449) の proof を検証する。
 * 成功すると public JWK のサムプリント代わりに JWK を返す。
 */
function checkDpop(req, expectedHtm, expectedHtu, accessToken) {
  const proof = req.headers['dpop'];
  if (!proof) {
    return { error: 'missing DPoP header' };
  }

  const header = JSON.parse(
    Buffer.from(proof.split('.')[0], 'base64url').toString('utf8'));

  if (header.typ !== 'dpop+jwt' || !header.jwk) {
    return { error: 'malformed DPoP header' };
  }

  let claims;
  try {
    const key = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
    claims = jwt.verify(proof, key, { algorithms: [header.alg] });
  } catch (e) {
    return { error: `DPoP proof rejected: ${e.message}` };
  }

  if (claims.htm !== expectedHtm) {
    return { error: `DPoP htm is ${claims.htm}` };
  }
  if (claims.htu !== expectedHtu) {
    return { error: `DPoP htu is ${claims.htu}` };
  }
  if (!claims.jti || !claims.iat
      || Math.abs(Math.floor(Date.now() / 1000) - claims.iat) > 300) {
    return { error: 'DPoP jti/iat is not acceptable' };
  }

  if (accessToken) {
    const ath = crypto.createHash('sha256').update(accessToken)
                      .digest('base64url');
    if (claims.ath !== ath) {
      return { error: 'DPoP ath does not match the access token' };
    }
  }

  return { jwk: header.jwk };
}

// 発行済みのアクセストークン: token -> { active }
const accessTokens = new Map();
// 発行済みのリフレッシュトークン: token -> context
const refreshTokens = new Map();

function issueTokens(context, authMethod, refreshed) {
  const now = Math.floor(Date.now() / 1000);

  if (!context.sid) {
    context.sid = crypto.randomBytes(8).toString('hex');
  }

  const accessToken = crypto.randomBytes(16).toString('hex');
  accessTokens.set(accessToken, { active: true });

  const refreshToken = crypto.randomBytes(16).toString('hex');
  refreshTokens.set(refreshToken, { ...context, refreshed: true });

  const idToken = jwt.sign({
    iss: ISSUER,
    sub: 'user-123',
    aud: context.badAud ? 'some-other-client' : CLIENT_ID,
    exp: now + 3600,
    iat: now,
    nonce: context.nonce,
    sid: context.sid,
    email: 'testuser@example.com',
    // リフレッシュされたことをテストから見えるようにする
    name: refreshed ? 'Test User (refreshed)' : 'Test User',
    token_auth: authMethod
  }, context.badSig ? rogueKey : privateKey, { algorithm: ALG, keyid: kid });

  return {
    access_token: accessToken,
    token_type: context.dpop ? 'DPoP' : 'Bearer',
    expires_in: context.shortToken && !refreshed ? 1 : 3600,
    refresh_token: refreshToken,
    id_token: idToken
  };
}

app.post('/token', (req, res) => {
  const auth = checkClientAuth(req);
  if (auth.error) {
    console.log(`[IdP] token request rejected: ${auth.error}`);
    return res.status(401).json({ error: 'invalid_client', details: auth.error });
  }

  // 認可コードや client_secret がクエリに載っていないことをテストで担保する
  if (Object.keys(req.query).length > 0) {
    console.log('[IdP] token request has query parameters:', req.query);
    return res.status(400).json({ error: 'invalid_request',
                                  details: 'parameters must be sent in the body' });
  }

  const { grant_type, code, code_verifier, refresh_token } = req.body;

  // DPoP の proof が付いていれば検証する
  let dpop = false;
  if (req.headers['dpop']) {
    const check = checkDpop(req, 'POST', `${ISSUER}/token`, null);
    if (check.error) {
      console.log(`[IdP] ${check.error}`);
      return res.status(400).json({ error: 'invalid_dpop_proof',
                                    details: check.error });
    }
    dpop = true;
    console.log('[IdP] DPoP proof accepted on the token request');
  }

  if (grant_type === 'refresh_token') {
    const context = refreshTokens.get(refresh_token);
    if (!context) {
      console.log('[IdP] invalid refresh_token');
      return res.status(400).json({ error: 'invalid_grant' });
    }
    refreshTokens.delete(refresh_token);

    context.dpop = dpop;
    console.log(`[IdP] tokens refreshed (auth=${auth.method})`);
    return res.json(issueTokens(context, auth.method, true));
  }

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const context = authCodes.get(code);
  if (!context) {
    console.log(`[IdP] invalid_grant for code ${code}`);
    return res.status(400).json({ error: 'invalid_grant' });
  }
  authCodes.delete(code);

  // PKCE の検証
  const challenge = base64url(
    crypto.createHash('sha256').update(code_verifier || '').digest());
  if (challenge !== context.code_challenge) {
    console.log('[IdP] PKCE verification failed');
    return res.status(400).json({ error: 'invalid_grant', details: 'PKCE' });
  }

  context.dpop = dpop;
  console.log(`[IdP] token issued (auth=${auth.method}, dpop=${dpop}, `
              + `bad_sig=${!!context.badSig}, bad_aud=${!!context.badAud})`);
  res.json(issueTokens(context, auth.method, false));
});

/* RFC 7662 Token Introspection */
app.post('/introspect', (req, res) => {
  const auth = checkClientAuth(req);
  if (auth.error) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  const state = accessTokens.get(req.body.token);
  const active = !!(state && state.active);

  console.log(`[IdP] introspect -> active=${active}`);
  res.json(active
    ? { active: true, sub: 'user-123', client_id: CLIENT_ID }
    : { active: false });
});

/* RP-Initiated Logout */
app.get('/logout', (req, res) => {
  const { id_token_hint, post_logout_redirect_uri, client_id } = req.query;

  console.log(`[IdP] logout (client_id=${client_id}, `
              + `id_token_hint=${id_token_hint ? 'yes' : 'no'})`);

  if (id_token_hint) {
    try {
      jwt.verify(id_token_hint, publicKey, { algorithms: [ALG],
                                             audience: CLIENT_ID });
    } catch (e) {
      return res.status(400).send(`invalid id_token_hint: ${e.message}`);
    }
  }

  if (post_logout_redirect_uri) {
    return res.redirect(post_logout_redirect_uri);
  }

  res.send('<html><body><h1>Logged out</h1></body></html>');
});

/*
 * テスト用: Back-Channel Logout のロゴアウトトークンを発行する。
 * 実際の IdP は RP のエンドポイントへ自分で POST するが、テストからは
 * トークンだけ受け取って任意の RP へ POST できた方が扱いやすい。
 */
app.get('/test/logout_token', (req, res) => {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: ISSUER,
    aud: CLIENT_ID,
    iat: now,
    jti: crypto.randomBytes(8).toString('hex'),
    events: { 'http://schemas.openid.net/event/backchannel-logout': {} }
  };

  if (req.query.sub) { claims.sub = req.query.sub; }
  if (req.query.sid) { claims.sid = req.query.sid; }
  if (req.query.nonce) { claims.nonce = req.query.nonce; }

  const key = req.query.bad_sig === '1' ? rogueKey : privateKey;

  res.type('text/plain').send(
    jwt.sign(claims, key, { algorithm: ALG, keyid: kid }));
});

/* テスト用: 発行済みのアクセストークンをすべて失効させる */
app.post('/test/revoke', (req, res) => {
  let n = 0;
  for (const state of accessTokens.values()) {
    state.active = false;
    n++;
  }
  console.log(`[IdP] revoked ${n} access token(s)`);
  res.json({ revoked: n });
});

app.get('/userinfo', (req, res) => {
  const header = req.headers['authorization'] || '';
  const dpopScheme = header.startsWith('DPoP ');
  const token = (dpopScheme || header.startsWith('Bearer '))
                ? header.slice(header.indexOf(' ') + 1) : null;

  if (!token || !accessTokens.has(token)) {
    return res.status(401).send('Unauthorized');
  }

  if (dpopScheme) {
    const check = checkDpop(req, 'GET', `${ISSUER}/userinfo`, token);
    if (check.error) {
      console.log(`[IdP] userinfo ${check.error}`);
      return res.status(401).send(check.error);
    }
    console.log('[IdP] DPoP proof accepted on the UserInfo request');
  }

  // groups は配列で返す（モジュール側が配列クレームを扱えることの検証）
  res.json({
    sub: 'user-123',
    email: 'testuser@example.com',
    name: 'Test User',
    groups: ['admin', 'user'],
    tenant_id: 'tenant-456'
  });
});

if (process.env.MOCK_IDP_TLS_CERT) {
  https.createServer({
    key:  fs.readFileSync(process.env.MOCK_IDP_TLS_KEY),
    cert: fs.readFileSync(process.env.MOCK_IDP_TLS_CERT),
    ca:   fs.readFileSync(process.env.MOCK_IDP_TLS_CA),
    requestCert: true,
    rejectUnauthorized: false
  }, app).listen(port, () => {
    console.log(`Mock IdP listening at ${ISSUER} (TLS, client certs requested)`);
  });

} else {
  app.listen(port, () => {
    console.log(`Mock IdP listening at ${ISSUER}`);
  });
}
