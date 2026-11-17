// Captura el panel de consulta por ID del dashboard al pedir la cuenta 3 (Maria) como Carlos.
// Uso: node idor_check.js <archivo_png>
const { chromium } = require('playwright-core');

(async () => {
  const [png] = process.argv.slice(2);
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  await page.goto('http://localhost:4200/login');
  await page.fill('#username', 'carlos_mora');
  await page.fill('#password', 'carlos123');
  await page.click('button[type=submit]');
  await page.waitForURL('**/dashboard');
  await page.waitForTimeout(800);
  await page.fill('#cuentaId', '3');
  await page.click('text=Consultar por IDOR');
  await page.waitForTimeout(1500);
  const resultado = await page.locator('.alert-danger, .badge-danger').allInnerTexts();
  console.log('Resultado en pantalla:', resultado.join(' | '));
  await page.screenshot({ path: png, fullPage: true });
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
