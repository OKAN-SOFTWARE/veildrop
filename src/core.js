/** Conservative, deterministic pattern redaction. Not a complete secret detector. */
export const MAX_BYTES = 1024 * 1024;
const encoder = new TextEncoder();
export function assertText(text) {
  if (typeof text !== 'string' || encoder.encode(text).length > MAX_BYTES) {
    throw new Error('Text must be a string of at most 1 MiB.');
  }
}
const rules = [
  ['PRIVATE_KEY', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g],
  ['GITHUB_TOKEN', /\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g],
  ['AWS_ACCESS_KEY', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['STRIPE_KEY', /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,255}\b/g],
  ['SLACK_TOKEN', /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/g],
  ['JWT', /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g],
  ['BEARER_TOKEN', /\bBearer[ \t]+([^\s"'`,;<>]+)/gi, 1],
  ['URL_CREDENTIALS', /\b[a-z][a-z0-9+.-]*:\/\/([^\s/@]+(?::[^\s/@]*)?)@/gi, 1],
  ['SECRET', /\b(?:[A-Z0-9_]*(?:API[_-]?KEY|SECRET|PASSWORD|PASSWD|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|CLIENT[_-]?TOKEN)[A-Z0-9_]*)["']?[ \t]*[:=][ \t]*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s,;#}\]]+))/gi, 'value'],
];
const personalRules = [
  ['EMAIL', /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
  ['IP_ADDRESS', /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g],
];
export function redact(text, {personal = true, literals = []} = {}) {
  assertText(text);
  if (!Array.isArray(literals) || literals.length > 100 || literals.some(x => typeof x !== 'string' || x.length < 3 || x.length > 1024)) {
    throw new Error('Use at most 100 custom secrets, each 3–1024 characters.');
  }
  const candidates = [];
  function add(start, end, type) { candidates.push({start, end, type}); }
  // Exact literals participate in overlap merging with automatic findings.
  for (const literal of [...new Set(literals)]) {
    let offset = 0;
    while ((offset = text.indexOf(literal, offset)) !== -1) {
      add(offset, offset + literal.length, 'CUSTOM'); offset += literal.length;
    }
  }
  for (const [type, regex, group] of [...rules, ...(personal ? personalRules : [])]) {
    for (const match of text.matchAll(regex)) {
      const value = group === 'value' ? (match[1] ?? match[2] ?? match[3]) : group ? match[group] : match[0];
      if (/^\[[A-Z_]+_\d+\]$/.test(value)) continue;
      if (/^\[[A-Z_]+_\d+$/.test(value) && text[match.index + match[0].lastIndexOf(value) + value.length] === ']') continue;
      // Captures are suffixes (except quotes); lastIndexOf avoids matching the key name.
      const start = match.index + (group ? match[0].lastIndexOf(value) : 0);
      add(start, start + value.length, type);
    }
  }
  // Merge overlapping spans rather than accidentally leaving pieces of a credential behind.
  candidates.sort((a, b) => a.start - b.start || b.end - a.end);
  const spans = [];
  for (const item of candidates) {
    const previous = spans.at(-1);
    if (previous && item.start < previous.end) {
      previous.end = Math.max(previous.end, item.end);
    } else spans.push({...item});
  }
  const identities = new Map(), counts = {}, findings = [];
  let output = '', cursor = 0;
  for (const span of spans) {
    const secret = text.slice(span.start, span.end);
    const identity = `${span.type}\0${secret}`;
    if (!identities.has(identity)) {
      counts[span.type] = (counts[span.type] ?? 0) + 1;
      identities.set(identity, `[${span.type}_${counts[span.type]}]`);
    }
    const placeholder = identities.get(identity);
    output += text.slice(cursor, span.start) + placeholder;
    // Reports deliberately never contain original values or a reversible mapping.
    findings.push({type: span.type, start: span.start, end: span.end, placeholder});
    cursor = span.end;
  }
  return {text: output + text.slice(cursor), findings, count: findings.length, uniqueCount: identities.size};
}
