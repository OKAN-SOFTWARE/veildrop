# Changelog

## 0.1.0 — 2026-10-24

Initial release:

- Local browser workspace with live redaction, custom literals, findings categories, copy, and text import/export.
- Password-encrypted portable text capsules with browser and CLI implementations sharing Web Crypto code.
- CLI redaction, encryption, decryption, standard input/output, bounded input, and refusal to overwrite files.
- Static loopback server, restrictive CSP, and explicit public route allowlist.
- Automated engine/CLI/server tests, optional browser integration suite, and GitHub Actions configuration.
- Security model, capsule specification, contribution guidance, and launch kit.

Known limits: heuristic detection, synchronous scanning, text-only 1 MiB maximum, no independent audit. Browser suite could not be executed in the creation environment; see docs/VALIDATION.md.
