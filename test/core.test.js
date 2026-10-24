import test from 'node:test';
import assert from 'node:assert/strict';
import {redact, MAX_BYTES} from '../src/core.js';

test('keeps debugging context and replaces repeated identities consistently', () => {
  const input = 'user=okan@example.com status=500\nuser=okan@example.com retry=3';
  const result = redact(input);
  assert.equal(result.text, 'user=[EMAIL_1] status=500\nuser=[EMAIL_1] retry=3');
  assert.equal(result.count, 2); assert.equal(result.uniqueCount, 1);
  assert.ok(!JSON.stringify(result).includes('okan@example.com'));
});
test('detects supported credential families', () => {
  const examples = [
    ['PRIVATE_KEY', '-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----'],
    ['GITHUB_TOKEN', 'ghp_' + 'a'.repeat(36)], ['AWS_ACCESS_KEY', 'AKIA' + 'A'.repeat(16)],
    ['STRIPE_KEY', 'sk_live_' + 'a'.repeat(24)], ['SLACK_TOKEN', 'xoxb-1234567890-abcdef'],
    ['JWT', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk'],
    ['BEARER_TOKEN', 'Authorization: Bearer token_with-dashes.123'],
    ['URL_CREDENTIALS', 'postgres://phoenix:p%40ss@db.internal:5432/app'],
  ];
  for (const [type, input] of examples) {
    const result = redact(input); assert.equal(result.count, 1, type); assert.equal(result.findings[0].type, type);
  }
});
test('handles env, JSON, YAML, quoted whitespace, and case variations', () => {
  for (const input of ['API_KEY=hello123', '"password": "hello123"', "client_secret: 'hello123'", 'export api_key = "hello123"', 'PASSWORD="hello 123"']) {
    const output = redact(input).text; assert.ok(!output.includes('hello'), output); assert.match(output, /\[SECRET_1\]/);
  }
});
test('does not redact ordinary debugging fields', () => {
  const text = 'status=500\nrequest_id=req_123\nretry=3\nversion=1.2.3\n';
  assert.equal(redact(text).text, text);
});
test('personal rules can be disabled', () => {
  const text = 'okan@example.com 192.168.1.1 PASSWORD=hello';
  const output = redact(text, {personal: false}).text;
  assert.equal(output, 'okan@example.com 192.168.1.1 PASSWORD=[SECRET_1]');
});
test('merges overlapping detections without leaking credential suffixes', () => {
  const text = 'PASSWORD=abcdef@example.com';
  const result = redact(text, {literals: ['abc']});
  assert.equal(result.text, 'PASSWORD=[SECRET_1]');
  assert.equal(result.count, 1);
});
test('literal matching is exact, not regex; Unicode preserved', () => {
  assert.equal(redact('hello a.*b 👋 a.*b', {literals:['a.*b']}).text, 'hello [CUSTOM_1] 👋 [CUSTOM_1]');
  assert.equal(redact('İzmir → 東京').text, 'İzmir → 東京');
});
test('redaction is idempotent for generated placeholders', () => {
  const first = redact('API_KEY=one EMAIL=okan@example.com postgres://a:b@host').text;
  assert.equal(redact(first).text, first);
});
test('limits input by UTF-8 bytes and rejects invalid custom secrets', () => {
  assert.throws(() => redact('é'.repeat(MAX_BYTES / 2 + 1)), /at most/);
  for (const literals of [null, ['ab'], [42], Array(101).fill('abc')]) assert.throws(() => redact('hello', {literals}));
});
test('large ordinary text and boundary input remain intact', () => {
  const text = 'x'.repeat(MAX_BYTES); assert.equal(redact(text).text.length, MAX_BYTES);
});
