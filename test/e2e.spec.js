const { test, expect } = require('@playwright/test');

test.describe('NGINX OIDC Module E2E Test', () => {

  test('should redirect to IdP, login, and access protected resource with claims', async ({ page }) => {

    // 1. Visit the protected NGINX URL
    const nginxUrl = 'http://localhost:8080/protected-resource';
    console.log(`Navigating to ${nginxUrl}`);

    // The browser should be redirected to the Mock IdP
    await page.goto(nginxUrl);

    // 2. Verify we are on the Mock IdP login page
    await expect(page.locator('h1')).toContainText('Mock IdP Login');

    // Check if the URL contains the expected OIDC parameters
    const url = new URL(page.url());
    expect(url.pathname).toBe('/auth');
    expect(url.searchParams.has('redirect_uri')).toBeTruthy();
    expect(url.searchParams.has('state')).toBeTruthy();
    expect(url.searchParams.has('nonce')).toBeTruthy();
    expect(url.searchParams.has('client_id')).toBeTruthy();

    // 3. Fill out the login form
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'password');

    // 4. Submit the form
    // The Mock IdP will handle the POST, generate a code, and redirect back to NGINX (/callback)
    // NGINX will exchange the code for tokens, fetch JWKS, verify JWT, set cookie, and redirect to original URL
    console.log('Submitting login form...');

    const [response] = await Promise.all([
        page.waitForResponse(resp => resp.url() === nginxUrl && resp.status() === 200),
        page.click('button#login-button')
    ]);

    // 5. Verify the final response
    console.log(`Final redirect landed on: ${page.url()}`);
    expect(page.url()).toBe(nginxUrl);

    // Parse the JSON body returned by our mock backend
    const body = await response.json();
    console.log('Received claims:', body);

    // Verify the claims were properly extracted from the JWT and passed as headers
    expect(body.sub).toBe('user-123');
    expect(body.email).toBe('testuser@example.com');
    expect(body.name).toBe('Test User');
    expect(body.groups).toBe('admin,user');
    expect(body.tenant_id).toBe('tenant-456');

    // 6. Verify subsequent requests work with the session cookie (without full redirect)
    console.log('Making subsequent request to verify session cookie...');
    const secondResponse = await page.goto('http://localhost:8080/another-path');
    expect(secondResponse.status()).toBe(200);

    const secondBody = await secondResponse.json();
    expect(secondBody.sub).toBe('user-123');
    expect(secondBody.groups).toBe('admin,user'); // Ensure extra claims are preserved in the session
    console.log('Session cookie verified successfully.');
  });
});