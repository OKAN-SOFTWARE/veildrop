import {fileURLToPath} from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, readFile, writeFile, rm, stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
const cli = new URL('../src/cli.js', import.meta.url);
function run(args, input) { return spawnSync(process.execPath, [fileURLToPath(cli), ...args], {input, encoding:'utf8'}); }

test('CLI stdin redaction and no secret values in report', () => {
  const result = run(['redact','-','-'], 'API_KEY=supersecret');
  assert.equal(result.status, 0); assert.equal(result.stdout, 'API_KEY=[SECRET_1]'); assert.ok(!result.stderr.includes('supersecret'));
});
test('CLI encrypt/decrypt round trip, secure file mode and refuses overwrite', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'veil-test-')); t.after(() => rm(dir,{recursive:true,force:true}));
  const input = join(dir,'input'), pass = join(dir,'pass'), capsule = join(dir,'capsule'), output = join(dir,'output');
  await writeFile(input, 'hello 👋'); await writeFile(pass, 'a test-only long passphrase\n');
  assert.equal(run(['seal',input,capsule,'--passphrase-file',pass]).status,0);
  assert.equal(run(['open',capsule,output,'--passphrase-file',pass]).status,0);
  assert.equal(await readFile(output,'utf8'),'hello 👋');
  if (process.platform !== 'win32') assert.equal((await stat(output)).mode & 0o777,0o600);
  assert.equal(run(['seal',input,capsule,'--passphrase-file',pass]).status,1);
  await writeFile(pass,'the wrong long passphrase');
  const failed = run(['open',capsule,join(dir,'failed'),'--passphrase-file',pass]); assert.equal(failed.status,1);
  await assert.rejects(stat(join(dir,'failed')));
});
test('CLI rejects unknown options and malformed secret JSON without logging its contents', async t => {
  const dir = await mkdtemp(join(tmpdir(),'veil-test-')); t.after(() => rm(dir,{recursive:true,force:true}));
  const literals = join(dir,'literals'); await writeFile(literals,'secret-not-valid-json');
  const result = run(['redact','-','-','--literals',literals],'hello');
  assert.equal(result.status,1); assert.ok(!result.stderr.includes('secret-not-valid-json'));
  assert.equal(run(['redact','-','-','--wat'],'hello').status,1);
});
