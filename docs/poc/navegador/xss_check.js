// Verifica en un navegador real (Edge headless) si el comprobante ejecuta el XSS almacenado.
// Uso: node xss_check.js <archivo_png> <archivo_txt>
const { chromium } = require('playwright-core');
const fs = require('fs');

(async () => {
  const [png, txt] = process.argv.slice(2);
  const log = [];
  const out = (l) => { console.log(l); log.push(l); };

  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 1100 } });
  const dialogos = [];
  page.on('dialog', async (d) => { dialogos.push(d.message()); await d.dismiss(); });

  out(`# Verificacion en navegador (Google Chrome headless + Playwright) - ${new Date().toISOString()}`);
  await page.goto('http://localhost:4200/login');
  await page.fill('#username', 'carlos_mora');
  await page.fill('#password', 'carlos123');
  await page.click('button[type=submit]');
  await page.waitForURL('**/dashboard');
  out('1. Login como carlos_mora -> dashboard OK');

  await page.goto('http://localhost:4200/transacciones');
  await page.waitForSelector('tbody tr');
  const filas = page.locator('tbody tr');
  const n = await filas.count();
  const ultima = filas.nth(n - 1);
  out(`2. Movimientos visibles: ${n}. Se abre el comprobante de la transaccion ${await ultima.locator('td').first().innerText()}`);
  await ultima.locator('button').click();
  await page.waitForTimeout(2000);

  const concepto = await page.evaluate(() => {
    const label = [...document.querySelectorAll('label')].find(l => l.textContent.includes('Detalle del Concepto'));
    const div = label && label.nextElementSibling;
    return div ? { innerHTML: div.innerHTML.trim(), texto: div.textContent.trim() } : null;
  });
  out(`3. innerHTML del contenedor del concepto: ${concepto && concepto.innerHTML}`);
  out(`4. Elementos <img> inyectados en el comprobante: ${await page.locator('img[src="x"]').count()}`);
  if (dialogos.length > 0) {
    out(`5. RESULTADO: JavaScript EJECUTADO. alert() mostro: ${dialogos[0]}`);
  } else {
    out('5. RESULTADO: ningun alert() se ejecuto; el payload se muestra como texto plano.');
  }

  await page.screenshot({ path: png, fullPage: true });
  fs.writeFileSync(txt, log.join('\n') + '\n');
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
