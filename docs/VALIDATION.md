# Validation record

Validated on 2026-10-24 in a Linux environment with Node.js v24.22.1.

## Completed

`npm test`: **23 tests passed, 0 failed**.

- Every supported credential pattern, assignment syntax, repeated identity mapping, overlapping spans, optional personal data, literal custom rules, Unicode, byte limits, and idempotent generated placeholders.
- Unicode and empty-text encryption round trips, fresh per-capsule randomness, wrong passwords, tampered ciphertext/salt/IV, strict format checks, password guards, and the full 1 MiB boundary.
- Independent interoperability with Node's `pbkdf2Sync`, `createCipheriv`, and `createDecipheriv`, not just encrypting and decrypting with the same shared wrapper.
- CLI piping, encryption/decryption, POSIX output permissions, refusal to overwrite, failure without output creation, and suppression of sensitive malformed JSON details.
- HTTP route allowlist, traversal rejection, Host guard, methods, and defensive response headers.

`npm run check`: syntax checks passed for application JavaScript.

An idempotence defect found during the first run was corrected and covered by a regression test before packaging.

## Not completed here

The Playwright browser suite is included at `scripts/browser-smoke.mjs`, but **could not run**: no browser binary was installed and the download returned an invalid archive. Therefore browser rendering, clipboard behavior, browser↔CLI handoffs, and mobile layout have not been verified in a real browser in this environment. `docs/banner.svg` is a project cover, not a screenshot of a tested browser session.

The Windows/Linux Node 22/24 CI matrix is configured but has not run on GitHub. No independent security audit, fuzzing campaign, load benchmark, browser compatibility certification, or accessibility audit has been completed.

## Before wider release

Run `npm run test:browser` after installing its optional Playwright dependency and Chromium. Manually check Firefox, Edge, keyboard navigation, focus visibility, screen-reader labels, file download/import, and a 390-pixel-wide viewport. Test with fictional data only. Review the security model and enable private vulnerability reporting.

A passing suite is evidence for its covered cases, not a claim of bug-free software or comprehensive secret detection.
