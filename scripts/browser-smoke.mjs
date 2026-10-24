import {fileURLToPath} from 'node:url';
// Optional integration test: npm install --no-save --package-lock=false playwright
// Then: npx playwright install chromium && npm run test:browser
import assert from 'node:assert/strict';
import {mkdtemp, readFile, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createServer} from '../src/server.js';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const dir = await mkdtemp(join(tmpdir(),'veildrop-browser-'));
const server = createServer(); await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({headless:true});
try {
  const context = await browser.newContext({viewport:{width:1440,height:1200},permissions:['clipboard-read','clipboard-write']});
  const page = await context.newPage(); const errors = [], external = [];
  page.on('pageerror',e => errors.push(e.message));
  page.on('request',r => { if (!r.url().startsWith(base)) external.push(r.url()); });
  await page.goto(base); await page.locator('#demo').click();
  assert.match(await page.locator('#result').inputValue(), /\[EMAIL_1\]/);
  assert.ok(!(await page.locator('#result').inputValue()).includes('demo_secret'));
  await page.locator('#copy').click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), await page.locator('#result').inputValue());
  if (process.env.VEILDROP_SCREENSHOT) await page.screenshot({path:process.env.VEILDROP_SCREENSHOT,fullPage:true});
  await page.locator('#seal-details summary').click(); await page.locator('#generate').click();
  const password = await page.locator('#passphrase').inputValue(), draft = await page.locator('#result').inputValue();
  const pending = page.waitForEvent('download'); await page.locator('#seal').click();
  const download = await pending, capsule = join(dir,'browser.veil'); await download.saveAs(capsule);
  const pass = join(dir,'password'), cliOutput = join(dir,'opened'); await writeFile(pass,password);
  const cli = spawnSync(process.execPath,[fileURLToPath(new URL('../src/cli.js',import.meta.url)),'open',capsule,cliOutput,'--passphrase-file',pass],{encoding:'utf8'});
  assert.equal(cli.status,0,cli.stderr); assert.equal(await readFile(cliOutput,'utf8'),draft);
  await page.locator('#open-tab').click(); await page.locator('#capsule-file').setInputFiles(capsule);
  await page.locator('#unlock-password').fill('a deliberately wrong passphrase'); await page.locator('#unlock').click();
  await page.waitForFunction(() => document.getElementById('status').textContent.includes('Cannot unlock'));
  assert.equal(await page.locator('#opened').inputValue(),'');
  await page.locator('#unlock-password').fill(password); await page.locator('#unlock').click();
  await page.waitForFunction(() => document.getElementById('opened').value.length > 0);
  assert.equal(await page.locator('#opened').inputValue(),draft);
  // Reverse interoperability: CLI-produced capsules must open in the browser.
  const cliCapsule = join(dir,'cli.veil');
  assert.equal(spawnSync(process.execPath,[fileURLToPath(new URL('../src/cli.js',import.meta.url)),'seal',cliOutput,cliCapsule,'--passphrase-file',pass]).status,0);
  await page.locator('#capsule-file').setInputFiles(cliCapsule); await page.locator('#unlock-password').fill(password); await page.locator('#unlock').click();
  await page.waitForFunction(() => document.getElementById('opened').value.length > 0);
  assert.equal(await page.locator('#opened').inputValue(),draft);
  await page.locator('#clear-opened').click(); assert.equal(await page.locator('#opened').inputValue(),'');
  await page.locator('#redact-tab').click(); await page.locator('#custom').fill('ab');
  assert.equal(await page.locator('#seal').isDisabled(),true); assert.equal(await page.locator('#result').inputValue(),'');
  await page.locator('#clear').click(); assert.equal(await page.locator('#source').inputValue(),'');
  const malicious = '<img src=x onerror="alert(1)"> API_KEY=demo123';
  await page.locator('#source').fill(malicious); assert.equal(await page.locator('img').count(),0);
  await page.setViewportSize({width:390,height:844});
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await page.reload(); assert.equal(await page.locator('#source').inputValue(),'');
  assert.deepEqual(errors,[]); assert.deepEqual(external,[]);
  console.log('Browser smoke passed: redact, copy, capsule round trips in both directions, wrong password, clear, invalid custom rules, inert HTML, mobile layout, no external requests.');
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)); await rm(dir,{recursive:true,force:true}); }
