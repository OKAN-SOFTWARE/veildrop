# Contributing to VeilDrop

Thanks for helping make developer handoffs less risky.

1. Start with an issue describing the concrete problem using entirely fictional data.
2. Keep runtime dependency count at zero unless a reviewed security or usability need justifies a change.
3. Add a regression test that demonstrates the actual bug. For detector changes, include both a true positive and a nearby false positive.
4. Run `npm test` and `npm run check`. Run the optional browser check for UI or integration changes.
5. Describe the behavior change and limitations in the pull request. Keep PRs focused.

Never submit active keys, real customer data, private logs, or password files. Do not add an automatic telemetry service. Cryptographic format changes need a versioned specification and independent review. Never replace Web Crypto with custom encryption primitives.

Good first contributions: tests for quoted configuration values, accessibility improvements, and synthetic examples of missed secrets. Avoid claiming that adding a regex makes all secrets detectable.

By contributing, you agree that your contributions are licensed under MIT.
