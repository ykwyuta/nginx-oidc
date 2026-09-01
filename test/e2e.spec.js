const { test, expect } = require('@playwright/test');

const BASE = process.env.OIDC_TEST_BASE_URL || 'http://localhost:8080';

// run-e2e.sh はストアあり (store) と Cookie のみ (cookie) の両方で実行する
const MODE = process.env.OIDC_TEST_MODE || 'store';
const STORE = MODE === 'store';

/** IdP の認可 URL にテスト用フラグを足してログインする */
async function loginWithFlag(page, target, flag) {
  await page.goto(target);
  const authUrl = new URL(page.url());
  if (flag) {
    authUrl.searchParams.set(flag, '1');
  }
  await page.goto(authUrl.toString());
  return page.click('button#login-button');
}

test.describe('NGINX OIDC module (real dynamic module)', () => {

  test('authenticates and exposes the claims to the backend', async ({ page, context }) => {
    const target = `${BASE}/protected-resource`;

    // 1. 未認証アクセスは IdP へリダイレクトされる
    await page.goto(target);
    await expect(page.locator('h1')).toContainText('Mock IdP Login');

    const url = new URL(page.url());
    expect(url.pathname).toBe('/auth');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe('test-client-id');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('state')).toBeTruthy();
    expect(url.searchParams.get('nonce')).toBeTruthy();
    expect(url.searchParams.get('redirect_uri')).toBe(`${BASE}/callback`);

    // 2. ログイン → コールバック → 元 URL へ戻る
    const [response] = await Promise.all([
      page.waitForResponse(resp => resp.url() === target && resp.status() === 200),
      page.click('button#login-button')
    ]);

    expect(page.url()).toBe(target);

    // 3. ID トークン + UserInfo のクレームがバックエンドへ渡っている
    const body = await response.json();
    expect(body.sub).toBe('user-123');
    expect(body.email).toBe('testuser@example.com');
    expect(body.name).toBe('Test User');
    // UserInfo が配列で返す groups がカンマ区切りに展開される
    expect(body.groups).toBe('admin,user');
    expect(body.tenant_id).toBe('tenant-456');

    // 4. セッション Cookie だけで別パスにもアクセスできる
    const second = await page.goto(`${BASE}/another-path`);
    expect(second.status()).toBe(200);

    const secondBody = await second.json();
    expect(secondBody.sub).toBe('user-123');
    expect(secondBody.groups).toBe('admin,user');
    expect(secondBody.tenant_id).toBe('tenant-456');

    // 5. セッション Cookie の中身
    const cookies = await context.cookies();
    const session = cookies.find(c => c.name === 'oidc_auth');
    expect(session).toBeTruthy();

    if (STORE) {
      // ストア有効時はセッション ID だけを持つ
      expect(session.value).toMatch(/^[0-9a-f]{64}$/);
    } else {
      // Cookie モードではクレームを載せるが、プロトコルクレームは含めない
      const payload = decodeURIComponent(session.value).slice(64);
      const [base, ...extras] = payload.split('|');
      expect(base.split(':')).toHaveLength(4);

      const keys = extras.map(e =>
        Buffer.from(e.split(':')[0], 'base64').toString());

      expect(keys).toContain('groups');
      expect(keys).toContain('tenant_id');

      for (const proto of ['iss', 'aud', 'exp', 'iat', 'nonce', 'azp',
                           'at_hash', 'jti', 'sub', 'email', 'name']) {
        expect(keys).not.toContain(proto);
      }
    }
  });

  test('rejects a tampered session cookie', async ({ page, context }) => {
    const target = `${BASE}/protected-resource`;

    await page.goto(target);
    await page.click('button#login-button');
    await page.waitForURL(target);

    const cookies = await context.cookies();
    const session = cookies.find(c => c.name === 'oidc_auth');
    expect(session).toBeTruthy();

    // 署名部分（先頭 64 文字の HMAC）を書き換える
    const forged = 'f'.repeat(64) + session.value.slice(64);
    await context.clearCookies();
    await context.addCookies([{ ...session, value: forged }]);

    // 署名が合わないので認証済みとして通らず、IdP へ差し戻される
    await page.goto(target);
    await expect(page.locator('h1')).toContainText('Mock IdP Login');
  });

  test('rejects a callback whose state does not match', async ({ request }) => {
    const resp = await request.get(
      `${BASE}/callback?code=abc&state=does-not-match`,
      { maxRedirects: 0 });
    expect(resp.status()).toBe(403);
  });

  test('rejects an ID token signed with an unknown key', async ({ page }) => {
    const target = `${BASE}/protected-resource`;

    await page.goto(target);
    // モジュールが組み立てた認可 URL に、不正な鍵で署名させるフラグを足す
    const authUrl = new URL(page.url());
    authUrl.searchParams.set('bad_sig', '1');
    await page.goto(authUrl.toString());

    const [response] = await Promise.all([
      page.waitForResponse(resp => resp.url().startsWith(`${BASE}/callback`)),
      page.click('button#login-button')
    ]);

    expect(response.status()).toBe(401);
  });

  test('rejects an ID token whose aud is another client', async ({ page }) => {
    const target = `${BASE}/protected-resource`;

    await page.goto(target);
    const authUrl = new URL(page.url());
    authUrl.searchParams.set('bad_aud', '1');
    await page.goto(authUrl.toString());

    const [response] = await Promise.all([
      page.waitForResponse(resp => resp.url().startsWith(`${BASE}/callback`)),
      page.click('button#login-button')
    ]);

    expect(response.status()).toBe(401);
  });

  test('re-authenticates once the session has expired', async ({ page }) => {
    const target = `${BASE}/short-session/page`;

    await page.goto(target);
    await page.click('button#login-button');
    await page.waitForURL(target);

    // oidc_session_timeout 1s なので、待てば Cookie があっても再認証になる
    await page.waitForTimeout(2000);
    await page.goto(target);
    await expect(page.locator('h1')).toContainText('Mock IdP Login');
  });

  test('keeps a second location on its own provider', async ({ page }) => {
    const target = `${BASE}/tenant-b/page`;

    await page.goto(target);
    await expect(page.locator('h1')).toContainText('Mock IdP Login');

    // ロケーションごとにメタデータを持つので、別ポートの IdP に飛ぶ
    const url = new URL(page.url());
    expect(url.port).toBe('3001');
    expect(url.searchParams.get('client_id')).toBe('tenant-b-client');

    const [response] = await Promise.all([
      page.waitForResponse(resp => resp.url() === target && resp.status() === 200),
      page.click('button#login-button')
    ]);

    const body = await response.json();
    expect(body.sub).toBe('user-123');
    // このロケーションは oidc_claims groups なので tenant_id は取り込まれない
    expect(body.tenant_id).toBe('');
  });

  test('treats the callback path as an exact match', async ({ request }) => {
    const resp = await request.get(`${BASE}/callback-not-really`,
                                   { maxRedirects: 0 });
    // コールバック扱いではないので、通常の未認証アクセスとして IdP へ飛ばされる
    expect(resp.status()).toBe(302);
    expect(resp.headers()['location']).toContain('/auth?');
  });

  test('adds oidc_auth_request_args to the authorization request', async ({ page }) => {
    await page.goto(`${BASE}/session/page`);

    const url = new URL(page.url());
    expect(url.searchParams.get('prompt')).toBe('consent');
    expect(url.searchParams.get('login_hint')).toBe('testuser@example.com');
  });

  test('authenticates the client with client_secret_post', async ({ page }) => {
    const target = `${BASE}/session/page`;

    const [response] = await Promise.all([
      page.waitForResponse(resp => resp.url() === target && resp.status() === 200),
      loginWithFlag(page, target, null)
    ]);

    const body = await response.json();
    expect(body.sub).toBe('user-123');
    // モック IdP が使われた認証方式を ID トークンのクレームで返す
    expect(body.token_auth).toBe('post');
  });

  test('exposes $oidc_id_token on later requests', async ({ page }) => {
    test.skip(!STORE, 'the ID token is only kept by the session store');

    const target = `${BASE}/session/page`;

    await Promise.all([
      page.waitForResponse(resp => resp.url() === target && resp.status() === 200),
      loginWithFlag(page, target, null)
    ]);

    // セッション Cookie だけのリクエストでも ID トークンが取り出せる
    const response = await page.goto(`${BASE}/session/other`);
    const body = await response.json();
    expect(body.id_token.split('.')).toHaveLength(3);
  });

  test('renews the tokens with the refresh token', async ({ page }) => {
    test.skip(!STORE, 'refreshing needs the session store');

    const target = `${BASE}/session/page`;

    // short_token=1 で expires_in=1 のアクセストークンを発行させる
    const [first] = await Promise.all([
      page.waitForResponse(resp => resp.url() === target && resp.status() === 200),
      loginWithFlag(page, target, 'short_token')
    ]);

    expect((await first.json()).sub).toBe('user-123');

    await page.waitForTimeout(2000);

    // アクセストークンが期限切れなので、モジュールが裏で更新してから通す
    const second = await page.goto(target);
    expect(second.status()).toBe(200);

    const body = await second.json();
    expect(body.sub).toBe('user-123');
    // 更新後の ID トークンから復元された名前になっている
    expect(body.name).toBe('Test User (refreshed)');
  });

  test('drops the session when introspection reports the token inactive',
       async ({ page, request }) => {
    test.skip(!STORE, 'introspection needs the session store');

    const target = `${BASE}/session/page`;

    await Promise.all([
      page.waitForResponse(resp => resp.url() === target && resp.status() === 200),
      loginWithFlag(page, target, null)
    ]);

    // IdP 側でアクセストークンを失効させる
    const revoked = await request.post('http://127.0.0.1:3000/test/revoke');
    expect(revoked.ok()).toBeTruthy();

    // oidc_introspection_interval 1s なので、待てば次のリクエストで検出される
    await page.waitForTimeout(1500);

    await page.goto(target);
    await expect(page.locator('h1')).toContainText('Mock IdP Login');
  });

  test('performs RP-Initiated Logout', async ({ page, context }) => {
    const target = `${BASE}/session/page`;

    await Promise.all([
      page.waitForResponse(resp => resp.url() === target && resp.status() === 200),
      loginWithFlag(page, target, null)
    ]);

    // /session/logout -> IdP の end_session_endpoint -> post_logout_redirect_uri
    await page.goto(`${BASE}/session/logout`);
    await expect(page.locator('body')).toContainText('bye');
    expect(page.url()).toBe(`${BASE}/bye`);

    const session = (await context.cookies())
      .find(c => c.name === 'oidc_auth' && c.value !== '');
    expect(session).toBeFalsy();

    // セッションが消えているので再度ログインを求められる
    await page.goto(target);
    await expect(page.locator('h1')).toContainText('Mock IdP Login');
  });

});
