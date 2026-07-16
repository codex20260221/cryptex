# Changelog

## [Unreleased]

### Security

- Rejects invalid salt lengths, malformed hexadecimal ciphertext, and decoded payloads that are too short before running Argon2id during decryption.
- Adds explicit regression coverage for nonce, ciphertext, and authentication-tag tampering.

### Changed

- Makes every public exception class independently PSR-4 autoloadable while preserving its name and inheritance.
- Adds a fixed v4 ciphertext compatibility fixture.
- Adds PHPStan, PHP_CodeSniffer, dependency auditing, and the corresponding CI checks.
- Removes the documentation branch force-push and deploys GitHub Pages from an artifact with least-privilege job permissions.

### Compatibility

- Preserves the public API, namespaces, exception behavior, v4/v5 hexadecimal ciphertext format, external salts, and decryption of the fixed v4-format compatibility fixture.
- Does not add a ciphertext-size limit; applications should enforce suitable limits on untrusted input.

## [5.0.0] - 2026-05-08

Cryptex 5.0.0 is a modernization and hardening release. It raises the supported runtime floor while preserving the existing cryptographic behavior and public API.

### Changed

- Requires PHP 8.3 or newer.
- Requires `ext-sodium`.
- Standardizes the test baseline on PHPUnit 12.
- Expands behavior coverage for success and failure cases.
- Includes hardening work in the v4 implementation.
- Reflects the repository main-branch rename to `main`.
- Aligns with the current GitHub Actions and GitHub Pages workflow setup.

### Compatibility

- The v4 public API is preserved.
- The v4 hex ciphertext format is preserved.
- External salt semantics are preserved.
- Existing v4-style ciphertext remains supported.

### Not Introduced

- No versioned ciphertext envelope.
- No base64url encoding.
- No embedded salts.
- No AAD support.
- No new public API.

### Release Notes

This release is a modernization and hardening update, not a ciphertext-format migration.
