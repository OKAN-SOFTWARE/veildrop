# Capsule format v1

A `.veil` file is UTF-8 JSON with exactly these six fields, in any order:

| Field | Required value |
| --- | --- |
| `format` | `VEILDROP/1` |
| `kdf` | `PBKDF2-SHA256` |
| `iterations` | integer `600000` |
| `salt` | canonical standard base64 of 16 random bytes |
| `iv` | canonical standard base64 of 12 random bytes |
| `ciphertext` | canonical standard base64 of ciphertext followed by its 16-byte GCM tag |

No filename, timestamp, source document, redaction findings, or passphrase is added to the envelope. The passphrase is UTF-8 encoded as supplied, with **no Unicode normalization**. Only the CLI removes one final LF or CRLF from a passphrase file.

Derive 32 bytes using PBKDF2-HMAC-SHA256 with the supplied password bytes, salt, and fixed iteration count. Encrypt the UTF-8 plaintext with AES-256-GCM using the IV and the literal UTF-8 bytes `VEILDROP/1` as additional authenticated data. Use a 128-bit tag. Web Crypto appends this tag to the ciphertext automatically.

Plaintext is at most 1,048,576 bytes. The complete input capsule is at most 1,500,000 bytes. Ciphertext plus tag must be 16–1,048,592 bytes. Unknown fields, versions, algorithms, lengths, and iteration counts are rejected. JSON property order and whitespace do not matter. JSON parsing follows the platform parser, including its last-value behavior for duplicate member names; no security decision depends on raw JSON byte order.

There is no streaming, compression, key escrow, expiry, sender signature, attachment support, or backward-compatibility promise beyond v1. Any future cryptographic changes require a new format identifier and a migration plan.
