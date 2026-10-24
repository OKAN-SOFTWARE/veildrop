# Launch kit

Popularity cannot be engineered or guaranteed. The strongest reason to share this project is a useful, easy-to-understand demonstration.

## Repository setup

Suggested repository name: `veildrop`

Description: `Share the bug. Keep the secrets. Local log redaction + encrypted text capsules. Zero runtime dependencies.`

Topics: `privacy`, `developer-tools`, `redaction`, `encryption`, `local-first`, `javascript`, `security-tools`, `cli`, `webcrypto`.

Upload the **contents** of the extracted `veildrop` folder to the repository root, including `.github` and `.gitignore`. Do not upload the ZIP as your source repository. Alternatively, create an empty GitHub repository and run these commands inside the extracted folder, replacing the final URL with your actual repository URL:

```sh
git init
git add .
git commit -m "Initial release: VeilDrop local redaction and encrypted handoffs"
git branch -M main
git remote add origin YOUR_REPOSITORY_URL
git push -u origin main
```

Confirm the Actions workflow passes. Enable private vulnerability reporting in repository settings. The README includes `docs/banner.svg` as its project cover. After running browser tests, you can capture `docs/workspace.png` and add the actual app screenshot too. Record a short clip with the built-in fictional sample: load → review repeated placeholders → generate passphrase → download capsule → unlock.

## Suggested announcement

I built VeilDrop because sharing a bug report shouldn't mean sharing your API keys.

Paste a log, review the redacted draft, and copy it into your issue or AI prompt. Need a private handoff? Export a password-encrypted capsule. Everything runs locally, with a browser UI and CLI using the same engine. No account, upload API, telemetry, or runtime packages.

It's an early release. Pattern matching can miss secrets, and the cryptography has not been independently audited. I'd especially appreciate synthetic edge cases, accessibility feedback, and security review.

Source: [add your repository URL]

## A practical first week

- Share a clear 20–30 second fictional-data demonstration where developer-tool sharing is welcome.
- Ask for one concrete kind of feedback: “What log format does this miss?”
- Fix reproducible problems and add regression fixtures.
- Publish a small changelog with each release.
- Never buy stars, spam communities, invent adoption figures, or claim perfect secret detection.

## Possible next releases (not implemented)

1. Worker-based scanning to keep the interface responsive on worst-case inputs.
2. User-selectable detector profiles and a larger synthetic fixture corpus.
3. A reviewed binary-file capsule format with explicit compatibility guarantees.
4. Independent security review before promoting high-assurance uses.

Keep the promise narrow: reviewable redaction and encrypted text handoffs.
