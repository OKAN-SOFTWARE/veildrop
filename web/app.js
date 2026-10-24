import {redact, MAX_BYTES} from '/src/core.js';
import {seal, unseal, generatePassphrase, MAX_CAPSULE_BYTES} from '/src/crypto.js';
const $ = id => document.getElementById(id);
let draft = null, revision = 0, opened = null, unlockRevision = 0;
const sample = `# checkout-service / incident 042\n# Fictional credentials for demonstration only\n\nAPI_KEY="demo_secret_9f83ca281"\nDATABASE_URL=postgres://okan:demo_password@db.internal:5432/shop\n\n2026-10-24T09:42:01Z ERROR payment timeout\n  customer=okan@example.com\n  client_ip=192.168.1.42\n  Authorization: Bearer demo_token_123456789\n  retry=3 duration_ms=5021\n\n2026-10-24T09:42:06Z INFO retry scheduled\n  customer=okan@example.com\n  request_id=req_8f31a\n  status=retrying`;
function status(message, error = false) { $('status').textContent = message; $('status').classList.toggle('error', error); }
function download(text, filename) {
  const url = URL.createObjectURL(new Blob([text], {type: 'text/plain;charset=utf-8'}));
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function refresh() {
  revision++; draft = null;
  $('result').value = ''; $('findings').replaceChildren();
  $('match-count').textContent = '0 MATCHES'; $('unique-count').textContent = 'Pattern-based protection';
  const bytes = new TextEncoder().encode($('source').value).length;
  $('source-size').textContent = `${bytes.toLocaleString()} bytes / 1 MiB`;
  try {
    const literals = $('custom').value.split(/\r?\n/).filter(x => x.length > 0);
    draft = redact($('source').value, {personal: $('personal').checked, literals});
    $('result').value = draft.text;
    $('match-count').textContent = `${draft.count} MATCHES`;
    $('unique-count').textContent = `${draft.uniqueCount} distinct values replaced`;
    const totals = {};
    for (const finding of draft.findings) totals[finding.type] = (totals[finding.type] ?? 0) + 1;
    for (const [name, count] of Object.entries(totals)) {
      const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = `${name} × ${count}`; $('findings').append(badge);
    }
    if (!draft.count) $('findings').textContent = 'No pattern matches. This does not guarantee the text is safe.';
    status('Draft updated locally. Review before copying, downloading, or encrypting.');
  } catch (error) { status(error.message, true); }
  for (const id of ['copy', 'download', 'seal']) $(id).disabled = !draft || !$('source').value;
}
async function action(button, operation) {
  button.disabled = true;
  try { await operation(); } catch (error) { status(error.message, true); }
  finally { button.disabled = ['copy', 'download', 'seal'].includes(button.id) ? !draft || !$('source').value : false; }
}
for (const id of ['source', 'custom', 'personal']) $(id).addEventListener('input', refresh);
$('demo').onclick = () => { $('source').value = sample; refresh(); };
$('import').onchange = () => action($('demo'), async () => {
  const file = $('import').files[0]; if (!file) return;
  if (file.size > MAX_BYTES) throw new Error('Text files are limited to 1 MiB.');
  const token = revision;
  const text = new TextDecoder('utf-8', {fatal: true}).decode(await file.arrayBuffer());
  if (token !== revision) throw new Error('Import cancelled because the draft changed.');
  $('source').value = text; refresh(); $('import').value = '';
});
$('copy').onclick = () => action($('copy'), async () => {
  if (!draft) throw new Error('Fix the input first.');
  await navigator.clipboard.writeText(draft.text); status('Draft copied. Your clipboard now contains the redacted text.');
});
$('download').onclick = () => { if (draft) { download(draft.text, 'veildrop-draft.txt'); status('Redacted draft downloaded.'); } };
$('generate').onclick = () => {
  $('passphrase').value = generatePassphrase(); $('show-password').checked = true; $('passphrase').type = 'text';
  status('Random passphrase generated. Save it separately before creating the capsule.');
};
$('show-password').onchange = () => { $('passphrase').type = $('show-password').checked ? 'text' : 'password'; };
$('seal').onclick = () => action($('seal'), async () => {
  if (!draft) throw new Error('Fix the input first.');
  const token = revision;
  const password = $('passphrase').value;
  const capsule = await seal(draft.text, password);
  if (revision !== token || password !== $('passphrase').value) throw new Error('Draft changed during encryption. Create a new capsule.');
  download(capsule, 'veildrop-capsule.veil'); status('Encrypted draft downloaded. Send the passphrase through a separate channel.');
});
function clearOpened() { unlockRevision++; opened = null; $('opened').value = ''; $('unlock-password').value = ''; $('capsule-file').value = ''; }
$('clear').onclick = () => {
  for (const id of ['source', 'custom', 'passphrase', 'import']) $(id).value = '';
  clearOpened(); $('show-password').checked = false; $('passphrase').type = 'password'; refresh();
  status('Session fields cleared. Downloaded files and clipboard contents are not erased.');
};
$('clear-opened').onclick = () => { clearOpened(); status('Decrypted fields cleared.'); };
$('capsule-file').onchange = () => { unlockRevision++; opened = null; $('opened').value = ''; };
$('unlock').onclick = () => action($('unlock'), async () => {
  opened = null; $('opened').value = '';
  const token = ++unlockRevision, file = $('capsule-file').files[0];
  if (!file) throw new Error('Choose a .veil file first.');
  if (file.size > MAX_CAPSULE_BYTES) throw new Error('Capsule exceeds the size limit.');
  const password = $('unlock-password').value;
  const result = await unseal(await file.text(), password);
  if (token !== unlockRevision) throw new Error('Unlock cancelled because the session changed.');
  opened = result; $('opened').value = result; $('unlock-password').value = '';
  status('Capsule unlocked locally. Decrypted text remains here until cleared or reloaded.');
});
$('save-opened').onclick = () => { if (opened === null) status('Unlock a capsule first.', true); else download(opened, 'veildrop-decrypted.txt'); };
function mode(open) {
  $('redact-panel').hidden = open; $('open-panel').hidden = !open;
  for (const [id, active] of [['redact-tab', !open], ['open-tab', open]]) { $(id).classList.toggle('active', active); $(id).setAttribute('aria-pressed', String(active)); }
}
$('redact-tab').onclick = () => mode(false); $('open-tab').onclick = () => mode(true);
refresh();
