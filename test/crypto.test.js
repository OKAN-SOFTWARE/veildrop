import test from 'node:test';
import assert from 'node:assert/strict';
import {seal, unseal, generatePassphrase} from '../src/crypto.js';
import {MAX_BYTES} from '../src/core.js';
const password = 'correct horse battery staple / test only';
test('round trips Unicode, newlines, and empty text', async () => {
  for (const text of ['', 'hello\nİzmir 👋 東京\u0000']) assert.equal(await unseal(await seal(text, password), password), text);
});
test('fresh salt and IV give different ciphertext for identical input', async () => {
  const a = JSON.parse(await seal('hello', password)), b = JSON.parse(await seal('hello', password));
  for (const field of ['salt', 'iv', 'ciphertext']) assert.notEqual(a[field], b[field]);
});
test('wrong password and tampered ciphertext fail closed', async () => {
  const capsule = await seal('sensitive content', password);
  await assert.rejects(unseal(capsule, 'a different long password'), /Cannot unlock/);
  const data = JSON.parse(capsule), bytes = Buffer.from(data.ciphertext, 'base64'); bytes[0] ^= 1;
  data.ciphertext = bytes.toString('base64');
  await assert.rejects(unseal(JSON.stringify(data), password), /Cannot unlock/);
});
test('tampered salt and IV fail authentication', async () => {
  const original = await seal('hello', password);
  for (const field of ['salt', 'iv']) {
    const data = JSON.parse(original), bytes = Buffer.from(data[field], 'base64'); bytes[0] ^= 1; data[field] = bytes.toString('base64');
    await assert.rejects(unseal(JSON.stringify(data), password), /Cannot unlock/);
  }
});
test('rejects malformed, oversized, and unsupported envelopes before KDF work', async () => {
  for (const value of ['null', '[]', '{}', 'not-json', 'x'.repeat(1500001)]) await assert.rejects(unseal(value, password));
  const original = JSON.parse(await seal('hello', password));
  for (const change of [{iterations: 1}, {iterations: 999999999}, {format:'VEILDROP/2'}, {kdf:'unknown'}, {iv:'AAAA'}, {salt:'!!!!'}, {extra:'value'}, {ciphertext:''}]) await assert.rejects(unseal(JSON.stringify({...original, ...change}), password));
});
test('generated passphrases contain 192 random bits encoded as 32 URL-safe characters', () => {
  const values = Array.from({length: 100}, generatePassphrase);
  assert.equal(new Set(values).size, 100);
  for (const value of values) assert.match(value, /^[A-Za-z0-9_-]{32}$/);
});
test('password and text limits are enforced', async () => {
  for (const value of ['', 'short', 'x'.repeat(1025)]) await assert.rejects(seal('text', value));
  await assert.rejects(seal('x'.repeat(MAX_BYTES + 1), password));
});
test('maximum supported capsule round trips', async () => {
  const text = 'x'.repeat(MAX_BYTES); assert.equal(await unseal(await seal(text, password), password), text);
});

test('envelope interoperates with independent Node crypto primitives', async () => {
  const {pbkdf2Sync, createDecipheriv, createCipheriv, randomBytes} = await import('node:crypto');
  const text = 'Independent crypto interoperability 👋';
  const envelope = JSON.parse(await seal(text, password));
  const key = pbkdf2Sync(password, Buffer.from(envelope.salt,'base64'),600000,32,'sha256');
  const bytes = Buffer.from(envelope.ciphertext,'base64');
  const decipher = createDecipheriv('aes-256-gcm',key,Buffer.from(envelope.iv,'base64'));
  decipher.setAAD(Buffer.from('VEILDROP/1')); decipher.setAuthTag(bytes.subarray(-16));
  assert.equal(Buffer.concat([decipher.update(bytes.subarray(0,-16)),decipher.final()]).toString(),text);
  const salt = randomBytes(16), iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm',pbkdf2Sync(password,salt,600000,32,'sha256'),iv);
  cipher.setAAD(Buffer.from('VEILDROP/1'));
  const encrypted = Buffer.concat([cipher.update(text,'utf8'),cipher.final(),cipher.getAuthTag()]);
  const capsule = JSON.stringify({format:'VEILDROP/1',kdf:'PBKDF2-SHA256',iterations:600000,salt:salt.toString('base64'),iv:iv.toString('base64'),ciphertext:encrypted.toString('base64')});
  assert.equal(await unseal(capsule,password),text);
});
