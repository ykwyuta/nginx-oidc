const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  use: {
    launchOptions: {
      executablePath: '/root/.cache/ms-playwright/chromium-1194/chrome-linux/chrome'
    }
  },
  timeout: 30000,
});
