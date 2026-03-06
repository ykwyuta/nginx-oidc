const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = 3000;

// Use express's built-in urlencoded parser instead of custom middleware
app.use(express.urlencoded({ extended: true }));

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const pubKeyObject = crypto.createPublicKey(publicKey);
const jwk = pubKeyObject.export({ format: 'jwk' });
const kid = 'test-key-1';

app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: `http://localhost:${port}`,
    authorization_endpoint: `http://localhost:${port}/auth`,
    token_endpoint: `http://localhost:${port}/token`,
    jwks_uri: `http://localhost:${port}/certs`,
    userinfo_endpoint: `http://localhost:${port}/userinfo`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256']
  });
});

app.get('/certs', (req, res) => {
  res.json({ keys: [{ kty: jwk.kty, n: jwk.n, e: jwk.e, use: 'sig', kid: kid, alg: 'RS256' }] });
});

app.get('/auth', (req, res) => {
  const { redirect_uri, state, nonce, client_id } = req.query;
  res.send(`
    <html>
      <body>
        <h1>Mock IdP Login</h1>
        <form method="POST" action="/auth/submit">
          <input type="hidden" name="redirect_uri" value="${redirect_uri}">
          <input type="hidden" name="state" value="${state}">
          <input type="hidden" name="nonce" value="${nonce}">
          <input type="hidden" name="client_id" value="${client_id}">
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
  const { redirect_uri, state, nonce, client_id, username, password } = req.body;
  if (username === 'testuser' && password === 'password') {
    const code = crypto.randomBytes(16).toString('hex');
    // Store in global variable because token requests might hit a different instance or have a race condition?
    // Map is sync, so it shouldn't be an issue, but let's log the map after setting
    authCodes.set(code, { nonce, username });
    console.log(`[IdP] Login successful, generated code: ${code}, redirecting to ${redirect_uri}`);
    console.log(`[IdP] Current authCodes:`, Array.from(authCodes.keys()));
    res.redirect(`http://localhost:8080${redirect_uri}?code=${code}&state=${state}`);
  } else {
    res.status(401).send('Invalid credentials');
  }
});

app.post('/token', (req, res) => {
  console.log('[IdP] Token request URL:', req.url);
  console.log('[IdP] Token request Query:', req.query);
  console.log('[IdP] Token request Body:', req.body);
  console.log('[IdP] Token request RawBody:', req.rawBody);

  // Fallback: NGINX subrequests with proxy_pass pass args in req.query sometimes
  // based on the configuration if proxy_set_body $args isn't taking effect properly.
  const payloadData = Object.keys(req.body).length > 0 ? req.body : req.query;

  const { grant_type, code, client_id, client_secret, redirect_uri } = payloadData;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type', details: payloadData });
  }

  const context = authCodes.get(code);
  if (!context) {
    console.log(`[IdP] Invalid grant for code: ${code}. Known codes:`, Array.from(authCodes.keys()));
    return res.status(400).json({ error: 'invalid_grant' });
  }

  authCodes.delete(code);

  const payload = {
    iss: `http://localhost:${port}`,
    sub: 'user-123',
    aud: client_id,
    exp: Math.floor(Date.now() / 1000) + (60 * 60),
    iat: Math.floor(Date.now() / 1000),
    nonce: context ? context.nonce : 'dummy_nonce',
    email: 'testuser@example.com',
    name: 'Test User'
  };

  const idToken = jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: kid });

  res.json({
    access_token: 'dummy_access_token',
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken
  });
});

app.get('/userinfo', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized');
  }
  res.json({
    sub: 'user-123',
    email: 'testuser@example.com',
    name: 'Test User',
    groups: 'admin,user',
    tenant_id: 'tenant-456'
  });
});

app.listen(port, () => {
  console.log(`Mock IdP listening at http://localhost:${port}`);
});
