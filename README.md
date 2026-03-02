<img src="https://michaelmawhinney.com/cryptex/logo.gif" width="300px">

# Cryptex: 2-way Authenticated Encryption Class

Cryptex is a small PHP library for authenticated encryption with libsodium (`XChaCha20-Poly1305`).

## Requirements

- PHP 8.2+
- `ext-sodium`

## Installation

Install with Composer:

```bash
composer require michaelmawhinney/cryptex
```

You can also clone/download the repository and include `src/Cryptex.php` manually.

## Quick start

```php
<?php
require 'vendor/autoload.php';

use cryptex\Cryptex;

$plaintext = "You're a certified prince.";
$passphrase = 'correct horse battery staple';
$salt = Cryptex::generateSalt();

$ciphertext = Cryptex::encrypt($plaintext, $passphrase, $salt);
$decrypted = Cryptex::decrypt($ciphertext, $passphrase, '');

var_dump(hash_equals($plaintext, $decrypted)); // true
```

## Recommended usage

### A) Passphrase mode (salt embedded in ciphertext)

Use a user-provided passphrase or high-entropy secret string. Generate a fresh salt per message with `Cryptex::generateSalt()` and pass it to `encrypt()`.

For `v1` payloads, salt is embedded in the ciphertext envelope. `decrypt()` ignores the provided `$salt` for `v1`, so pass `''`.

```php
$salt = Cryptex::generateSalt();
$ciphertext = Cryptex::encrypt($message, $passphrase, $salt);
$plaintext = Cryptex::decrypt($ciphertext, $passphrase, '');
```

### B) Optional AAD usage

Cryptex v5 currently binds an empty AAD string internally for compatibility. If your threat model needs context binding (tenant IDs, record IDs, protocol metadata), keep this metadata stable and authenticated at the application layer, and plan migration to a future API variant that accepts explicit AAD.

See [docs/security.md](docs/security.md) for AAD guidance and caveats.

### Planned for v6: raw-key mode (not implemented in v5)

Direct raw-key API ergonomics are planned for a future major release. In v5, `encrypt()`/`decrypt()` accept a `string $key` input and derive encryption material through the configured KDF path.

## Ciphertext formats

Cryptex supports a versioned base64url envelope for current payloads, plus a legacy hex decoder path:

- `v1` base64url envelope (current)
- `v2` planned/reserved (not implemented yet)
- legacy hex (`nonce || ciphertext+tag`, hex encoded)

Salt behavior during decryption:

- `v1`: embedded salt is used; passed `$salt` argument is ignored (pass `''`).
- legacy hex: no embedded salt; caller must provide the original external salt.

See [docs/format.md](docs/format.md) for field layout, sizes, and versioning rules.

## Security notes

- Use unique salts and nonces per encryption operation (Cryptex handles nonce generation).
- Authentication failures indicate tampering, wrong key, wrong passphrase, or corrupt payload.
- Do not treat decrypted plaintext as trusted unless decryption succeeded without exception.
- Store secrets in a dedicated secret manager where possible.

See [docs/security.md](docs/security.md) for the full threat model and key-management guidance.

## Testing

```bash
composer test
```

Additional project commands:

```bash
composer lint
composer stan
composer cs-check
composer cs-fix
```
