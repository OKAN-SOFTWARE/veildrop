# Security model

VeilDrop 0.1 is an initial release, not independently audited security software. Tests demonstrate covered behavior, not universal correctness. Use reviewed, established secret-management systems for high-assurance production secret distribution.

## What is protected

The redaction engine replaces recognized substrings and explicit user-supplied literals. The browser never sends source text to the local server. The loopback server exposes only five hardcoded static paths, rejects nonlocal Host values and write methods, and emits a restrictive Content Security Policy. No CORS permission is emitted. File inputs are bounded. Decrypted content is rendered as textarea values, not executable markup. No source text, passphrase, or reverse map is persisted in browser storage.

Capsules encrypt text using authenticated AES-256-GCM. Per-capsule random salts and IVs come from the platform RNG. PBKDF2-SHA256 uses a fixed 600,000 iterations; the parser refuses attacker-supplied work factors. AES keys are nonextractable Web Crypto keys. Format validation and the authentication tag reject corrupted or incorrectly unlocked ciphertext. Authentication does not establish the sender's identity.

## What is not protected

- Unknown, encoded, split, escaped, or unsupported secrets; redaction is heuristic.
- A compromised browser, OS, extension, dependency used during development, or modified repository.
- Someone watching the screen or inspecting process memory. JavaScript cannot promise secure zeroization. Clearing fields releases references but does not prove erasure from memory or swap.
- Browser history/session restoration, OS crash dumps, clipboard managers, backups, downloaded files, and password-manager behavior.
- Weak passphrases and offline dictionary attacks. PBKDF2 is not memory-hard. Minimum length is not a strength score.
- File-size metadata, the public capsule format, and the public salt/IV. No padding conceals text length.
- An attacker who already has the plaintext, or a recipient who can copy or forward it.
- Expiration, revocation, recovery, one-time access, or proof of sender identity. None are implemented.
- Browser UI denial of service from pathological text or a very large number of matches. Inputs are capped at 1 MiB, but scanning is synchronous; this app is intended for deliberate local use, not untrusted bulk ingestion.

The app is a local tool. Do not expose its server to a public interface, reverse proxy it into a shared service, or add telemetry without revisiting the security design. The Host guard is a defense against rebinding, not authentication against local software.

## Safe handling

Review all drafts. Use generated passphrases and communicate them through a separate channel. Keep actual logs, source files, custom-rule files and passphrase files outside the repository. The `.gitignore` is a convenience, not a security boundary. Downloaded decrypted files are plaintext. Clearing a session does not erase downloads or the clipboard. The CLI refuses to overwrite existing destinations and uses mode `0600` on POSIX; protect Windows paths with appropriate ACLs.

No remote APIs are called at runtime. Installing Node.js, optional browser-test tools, and GitHub Actions still involves their own software supply chains.

## Reporting

Do not post real secrets or working private attack data in public issues. If the repository maintainer enables GitHub private vulnerability reporting, use **Security → Report a vulnerability**. Otherwise ask for a private reporting channel in a minimal public issue without sensitive details. Maintainer: enable private vulnerability reporting before a public launch.

Only the latest released version is intended to receive fixes. No response-time guarantee is promised.

## References

- [Web Crypto AES-GCM parameters](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams)
- [Web Crypto deriveKey](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey)
