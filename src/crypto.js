import {assertText, MAX_BYTES} from './core.js';
const enc = new TextEncoder();
const VERSION = 'VEILDROP/1';
const ITERATIONS = 600000;
export const MAX_CAPSULE_BYTES = 1500000;
function encode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function decode(value, expected) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error('Invalid capsule encoding.');
  const bytes = Uint8Array.from(atob(value), x => x.charCodeAt(0));
  if (encode(bytes) !== value || (expected && bytes.length !== expected)) throw new Error('Invalid capsule encoding.');
  return bytes;
}
function checkPassword(password) {
  if (typeof password !== 'string' || password.length < 16 || password.length > 1024) throw new Error('Use a passphrase of 16–1024 characters. A long, unique passphrase is essential.');
}
async function derive(password, salt, usage) {
  checkPassword(password);
  const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS}, material, {name: 'AES-GCM', length: 256}, false, [usage]);
}
export function generatePassphrase() {
  return encode(crypto.getRandomValues(new Uint8Array(24))).replaceAll('+', '-').replaceAll('/', '_');
}
export async function seal(text, password) {
  assertText(text);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derive(password, salt, 'encrypt');
  const ciphertext = await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: enc.encode(VERSION), tagLength: 128}, key, enc.encode(text));
  return JSON.stringify({format: VERSION, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, salt: encode(salt), iv: encode(iv), ciphertext: encode(new Uint8Array(ciphertext))});
}
export async function unseal(capsule, password) {
  if (typeof capsule !== 'string' || enc.encode(capsule).length > MAX_CAPSULE_BYTES) throw new Error('Capsule exceeds the size limit.');
  let data;
  try { data = JSON.parse(capsule); } catch { throw new Error('Not a valid VeilDrop capsule.'); }
  if (!data || Array.isArray(data) || Object.keys(data).sort().join(',') !== 'ciphertext,format,iterations,iv,kdf,salt' || data.format !== VERSION || data.kdf !== 'PBKDF2-SHA256' || data.iterations !== ITERATIONS) throw new Error('Unsupported capsule format.');
  const salt = decode(data.salt, 16), iv = decode(data.iv, 12), ciphertext = decode(data.ciphertext);
  if (ciphertext.length < 16 || ciphertext.length > MAX_BYTES + 16) throw new Error('Invalid ciphertext size.');
  const key = await derive(password, salt, 'decrypt');
  try {
    const plaintext = await crypto.subtle.decrypt({name: 'AES-GCM', iv, additionalData: enc.encode(VERSION), tagLength: 128}, key, ciphertext);
    return new TextDecoder('utf-8', {fatal: true}).decode(plaintext);
  } catch { throw new Error('Cannot unlock: wrong passphrase or a damaged capsule.'); }
}
