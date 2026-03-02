# Security Guidance

## Threat model

Cryptex provides confidentiality and integrity for payloads at rest and in transit when used with a strong secret and proper key/salt handling.

### In scope

- Passive attackers reading stored or transmitted ciphertext.
- Active attackers modifying ciphertext to induce malformed plaintext.
- Replay/tamper attempts against authenticated ciphertext.

### Out of scope

- Endpoint compromise (malware, memory scraping, RCE on the host process).
- Secret exfiltration from environment variables, logs, source code, or backups.
- Weak operational practices (reused secrets, poor access controls).

## Key handling

- Prefer high-entropy secrets from a secrets manager.
- If using passphrases, enforce strong entropy and rotation policy.
- Keep encryption secrets out of logs and error messages.
- Treat decrypted plaintext as sensitive and erase when practical.

## AAD guidance

Cryptex currently uses an empty AAD string (`''`) for compatibility.

If your protocol needs context binding (e.g., tenant ID, object ID, schema version), you should:

1. Keep metadata immutable and authenticated by your application protocol.
2. Version your payload contract.
3. Plan migration to explicit AAD parameters in a future API revision.

## KDF guidance

Cryptex derives encryption material with `sodium_crypto_pwhash(..., ARGON2ID13)`.

- Generate a **fresh random salt per encryption**.
- Never reuse salts deliberately for bulk encryption under the same passphrase.
- Keep interactive ops/mem limits unless you have profiling data to justify changes.
- For high-throughput machine-to-machine systems, evaluate direct key mode or pre-derived key lifecycle management.

## Tamper behavior

Any authentication failure must be treated as a hard failure:

- wrong key/passphrase,
- corrupted payload,
- unsupported version,
- modified nonce/ciphertext/tag.

Cryptex throws a decryption-related exception and does **not** return unauthenticated plaintext.
