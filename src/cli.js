#!/usr/bin/env node
import {readFile, writeFile, stat} from 'node:fs/promises';
import {redact, MAX_BYTES} from './core.js';
import {seal, unseal, MAX_CAPSULE_BYTES} from './crypto.js';
const help = `VeilDrop — Share the bug. Keep the secrets.

node src/cli.js redact INPUT OUTPUT [--no-personal] [--literals FILE]
node src/cli.js seal INPUT OUTPUT --passphrase-file FILE
node src/cli.js open INPUT OUTPUT --passphrase-file FILE

Use - as INPUT for stdin or OUTPUT for stdout. Output files never overwrite.
Redact before seal: seal encrypts the exact input. Passphrases: 16+ characters.
--literals FILE: JSON array of exact strings to remove. Keep this file private.
Passphrase files: UTF-8, one trailing newline removed. Never pass secrets as arguments.
`;
async function readLimited(filename, limit) {
  if (filename !== '-') {
    if ((await stat(filename)).size > limit) throw new Error('Input exceeds the size limit.');
    const data = await readFile(filename);
    if (data.length > limit) throw new Error('Input exceeds the size limit.');
    return new TextDecoder('utf-8', {fatal: true}).decode(data);
  }
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > limit) throw new Error('Input exceeds the size limit.');
    chunks.push(chunk);
  }
  return new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(chunks));
}
async function main() {
  const [command, input, output, ...args] = process.argv.slice(2);
  if (!command || command === '--help') { console.log(help); return; }
  if (!['redact', 'seal', 'open'].includes(command) || !input || !output) throw new Error('Invalid command. Use --help.');
  const options = new Map();
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (options.has(flag)) throw new Error('Duplicate option.');
    if (flag === '--no-personal' && command === 'redact') options.set(flag, true);
    else if ((flag === '--literals' && command === 'redact') || (flag === '--passphrase-file' && command !== 'redact')) {
      if (!args[i + 1] || args[i + 1].startsWith('--') || args[i + 1] === '-') throw new Error('Option requires a file path.');
      options.set(flag, args[++i]);
    } else throw new Error('Unknown option. Use --help.');
  }
  const text = await readLimited(input, command === 'open' ? MAX_CAPSULE_BYTES : MAX_BYTES);
  let result;
  if (command === 'redact') {
    const literals = options.has('--literals') ? JSON.parse(await readLimited(options.get('--literals'), 110000)) : [];
    const redacted = redact(text, {personal: !options.has('--no-personal'), literals});
    result = redacted.text;
    console.error(`${redacted.count} matches redacted. Review the output before sharing.`);
  } else {
    if (!options.has('--passphrase-file')) throw new Error('--passphrase-file is required.');
    const password = (await readLimited(options.get('--passphrase-file'), 4098)).replace(/\r?\n$/, '');
    result = await (command === 'seal' ? seal : unseal)(text, password);
  }
  if (output === '-') process.stdout.write(result);
  else await writeFile(output, result, {flag: 'wx', mode: 0o600});
}
main().catch(error => {
  // Avoid echoing parser errors that could include source credentials.
  const message = error instanceof SyntaxError ? 'Invalid JSON input.' : error.code ? `File operation failed (${error.code}).` : error.message;
  console.error(`VeilDrop: ${message}`); process.exitCode = 1;
});
