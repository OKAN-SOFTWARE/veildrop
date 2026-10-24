import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createServer} from '../src/server.js';

test('server exposes only static allowlist, blocks rebinding and has defensive headers', async t => {
  const server = createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const port = server.address().port;
  async function request(path, {host = `127.0.0.1:${port}`, method = 'GET'} = {}) {
    return new Promise((resolve, reject) => {
      const req = http.request({host:'127.0.0.1', port, path, method, headers:{Host:host}}, res => {
        let text = ''; res.setEncoding('utf8'); res.on('data', chunk => text += chunk); res.on('end', () => resolve({status:res.statusCode, headers:res.headers, text}));
      }); req.on('error', reject); req.end();
    });
  }
  const home = await request('/'); assert.equal(home.status, 200); assert.match(home.text, /Share the bug/);
  assert.match(home.headers['content-security-policy'], /connect-src 'none'/);
  assert.equal(home.headers['cache-control'], 'no-store');
  for (const path of ['/src/core.js', '/src/crypto.js', '/app.js', '/style.css']) assert.equal((await request(path)).status, 200);
  for (const path of ['/package.json', '/../package.json', '/%2e%2e/package.json', '/src/cli.js', '/?x=1']) assert.equal((await request(path)).status, 404);
  assert.equal((await request('/', {host:'attacker.example'})).status, 403);
  assert.equal((await request('/', {method:'POST'})).status, 405);
  assert.equal((await request('/', {method:'HEAD'})).text, '');
});
