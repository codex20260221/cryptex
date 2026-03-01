# Cryptex refactor instructions (AGENTS.md)

Goal: Refactor the Cryptex PHP class to modern PHP (2026) standards, improve correctness/security, and keep behavior well-defined.

Non-negotiables:
- Add `declare(strict_types=1);`
- Fix namespaced exception catching: use `\Throwable` or fully-qualified `\Exception`
- Do NOT `sodium_memzero()` any value that will be returned to the caller
- Guard memzero calls (only when variable is set and is a string)
- Avoid mbstring dependency for binary slicing; use `substr()` for binary-safe slicing
- Decrypt must validate minimum ciphertext length = NONCE + TAG
- Prefer base64 (URL-safe) payloads and include versioning (v1), salt, nonce, ciphertext in the encoded payload
- Keep backward compatibility if there is existing hex format in use (either provide a decode path or explicitly add `decryptLegacyHex()`)

Engineering expectations:
- Follow existing project conventions (autoloading, namespaces, formatting)
- Add tests: round-trip encrypt/decrypt, tamper detection, wrong key, wrong salt length, malformed payload
- Run the project's test and lint commands. If unknown, detect them from composer.json; otherwise propose the minimal standard set (phpunit, phpstan/psalm) as dev dependencies.
- Provide a summary of changes + security rationale.
