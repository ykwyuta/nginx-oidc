const { defineConfig } = require('@playwright/test');

// Chromium の場所は Playwright の既定の解決に任せる。
// 別の場所のバイナリを使う場合は PLAYWRIGHT_CHROMIUM_PATH か
// PLAYWRIGHT_BROWSERS_PATH を設定する。
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: 'e2e.spec.js',
  timeout: 30000,
  reporter: 'line',
  use: {
    baseURL: process.env.OIDC_TEST_BASE_URL || 'http://localhost:8080',
    launchOptions: executablePath ? { executablePath } : {},
  },
});
