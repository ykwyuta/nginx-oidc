/**
 * mock-idp.js — E2E テスト用のモック OpenID Provider。
 *
 * - Discovery / JWKS / 認可 / トークン / UserInfo を提供する
 * - ID トークンは RS256 で署名する（モジュール側の署名検証を実際に通す）
 * - トークンエンドポイントは client_secret_basic のみを受け付ける
 */
const express = require('express');
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
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: [ALG],
    token_endpoint_auth_methods_supported: ['client_secret_basic']
  });
});

app.get('/certs', (req, res) => {
  const key = ALG === 'ES256'
    ? { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }
    : { kty: jwk.kty, n: jwk.n, e: jwk.e };

  res.json({ keys: [{ ...key, use: 'sig', kid: kid, alg: ALG }] });
});

app.get('/auth', (req, res) => {
  const { redirect_uri, state, nonce, client_id, code_challenge,
          code_challenge_method } = req.query;
  // テスト用のフラグ（不正な署名 / 不正な aud の ID トークンを発行させる）
  const badSig = req.query.bad_sig === '1' ? '1' : '';
  const badAud = req.query.bad_aud === '1' ? '1' : '';

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
          code_challenge, bad_sig, bad_aud } = req.body;

  if (username !== 'testuser' || password !== 'password') {
    return res.status(401).send('Invalid credentials');
  }

  const code = crypto.randomBytes(16).toString('hex');
  authCodes.set(code, { nonce, username, code_challenge, redirect_uri,
                        badSig: bad_sig === '1', badAud: bad_aud === '1' });

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

/* client_secret_basic (RFC 6749 2.3.1) のみを受け付ける */
function checkClientAuth(req) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Basic ')) {
    return 'missing Basic authorization header';
  }

  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const sep = decoded.indexOf(':');
  if (sep < 0) {
    return 'malformed Basic credentials';
  }

  const id = decodeURIComponent(decoded.slice(0, sep));
  const secret = decodeURIComponent(decoded.slice(sep + 1));

  if (id !== CLIENT_ID || secret !== CLIENT_SECRET) {
    return 'invalid client credentials';
  }

  return null;
}

app.post('/token', (req, res) => {
  const authError = checkClientAuth(req);
  if (authError) {
    console.log(`[IdP] token request rejected: ${authError}`);
    return res.status(401).json({ error: 'invalid_client', details: authError });
  }

  // 認可コードや client_secret がクエリに載っていないことをテストで担保する
  if (Object.keys(req.query).length > 0) {
    console.log('[IdP] token request has query parameters:', req.query);
    return res.status(400).json({ error: 'invalid_request',
                                  details: 'parameters must be sent in the body' });
  }

  const { grant_type, code, code_verifier } = req.body;

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

  const now = Math.floor(Date.now() / 1000);
  const idToken = jwt.sign({
    iss: ISSUER,
    sub: 'user-123',
    aud: context.badAud ? 'some-other-client' : CLIENT_ID,
    exp: now + 3600,
    iat: now,
    nonce: context.nonce,
    email: 'testuser@example.com',
    name: 'Test User'
  }, context.badSig ? rogueKey : privateKey, { algorithm: ALG, keyid: kid });

  console.log(`[IdP] token issued (bad_sig=${!!context.badSig}, `
              + `bad_aud=${!!context.badAud})`);
  res.json({
    access_token: 'dummy_access_token',
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken
  });
});

app.get('/userinfo', (req, res) => {
  const header = req.headers['authorization'];
  if (header !== 'Bearer dummy_access_token') {
    return res.status(401).send('Unauthorized');
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

app.listen(port, () => {
  console.log(`Mock IdP listening at ${ISSUER}`);
});
