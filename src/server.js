import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
const routes = new Map([
  ['/', ['web/index.html', 'text/html; charset=utf-8']],
  ['/style.css', ['web/style.css', 'text/css; charset=utf-8']],
  ['/app.js', ['web/app.js', 'text/javascript; charset=utf-8']],
  ['/src/core.js', ['src/core.js', 'text/javascript; charset=utf-8']],
  ['/src/crypto.js', ['src/crypto.js', 'text/javascript; charset=utf-8']],
]);
export function createServer() {
  return http.createServer(async (req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    // Reject arbitrary Host values to mitigate DNS rebinding; bind only to loopback.
    if (!/^(?:127\.0\.0\.1|localhost):\d+$/.test(req.headers.host ?? '')) { res.writeHead(403).end(); return; }
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, {Allow: 'GET, HEAD'}).end(); return; }
    const route = routes.get(req.url);
    if (!route) { res.writeHead(404).end('Not found'); return; }
    try {
      const body = await readFile(path.join(root, route[0]));
      res.writeHead(200, {'Content-Type': route[1]});
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch { res.writeHead(500).end('Unable to load application.'); }
  });
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4317);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be 1–65535.');
  const server = createServer();
  server.on('error', error => { console.error(`Cannot start: ${error.code}`); process.exitCode = 1; });
  server.listen(port, '127.0.0.1', () => console.log(`VeilDrop → http://127.0.0.1:${port}\nCtrl+C to stop. No content is sent to this server.`));
}
