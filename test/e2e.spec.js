const { test, expect } = require('@playwright/test');

const BASE = process.env.OIDC_TEST_BASE_URL || 'http://localhost:8080';

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

    // 5. セッション Cookie にはプロトコルクレームを載せない
    const cookies = await context.cookies();
    const session = cookies.find(c => c.name === 'oidc_auth');
    expect(session).toBeTruthy();

    const payload = decodeURIComponent(session.value).slice(64);
    const [base, ...extras] = payload.split('|');
    expect(base.split(':')).toHaveLength(4);

    const keys = extras.map(e => Buffer.from(e.split(':')[0], 'base64').toString());
    expect(keys.sort()).toEqual(['groups', 'tenant_id']);
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

});
