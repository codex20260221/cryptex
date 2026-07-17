<img src="https://michaelmawhinney.com/cryptex/logo.gif" width="300" alt="Cryptex">

# Cryptex

Cryptex is a small PHP library for authenticated symmetric encryption using XChaCha20-Poly1305 and Argon2id through PHP's Sodium extension.

## Features

- Encrypts and authenticates plaintext with libsodium's XChaCha20-Poly1305 implementation.
- Derives an encryption key from caller-supplied key material and a salt with Argon2id.
- Uses a fresh random nonce for every encryption, so encrypting the same plaintext twice produces different ciphertext.
- Fails closed: tampered data, a wrong key, or a wrong salt cannot produce unauthenticated plaintext.
- Provides a small API: `Cryptex::encrypt()`, `Cryptex::decrypt()`, and `Cryptex::generateSalt()`.

## Requirements

- PHP 8.3 or newer
- `ext-sodium`

## Installation

Install Cryptex with Composer:

```console
composer require michaelmawhinney/cryptex
```

## Quick start

Generate key material once, keep it protected, and retain the salt used for each ciphertext.

```php
<?php

declare(strict_types=1);

require 'vendor/autoload.php';

use cryptex\Cryptex;

// Generate this once and store it in a secret manager or equivalent protected store.
$key = sodium_bin2hex(
    random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)
);

$plaintext = "You're a certified prince.";
$salt = Cryptex::generateSalt();
$ciphertext = Cryptex::encrypt($plaintext, $key, $salt);
$decrypted = Cryptex::decrypt($ciphertext, $key, $salt);

if (!hash_equals($plaintext, $decrypted)) {
    throw new RuntimeException('Round trip failed.');
}
```

Decryption requires the exact same key and salt used for encryption. Store the salt with its ciphertext; it is not embedded in the encrypted output.

## Key and salt handling

Prefer high-entropy random key material when your application can generate and protect it. Cryptex also accepts passphrases and derives a key with Argon2id, but Argon2id does not add entropy: weak or reused passphrases remain vulnerable to guessing. Passphrase quality, key rotation, and secret storage are application responsibilities.

`Cryptex::generateSalt()` returns a random salt of `SODIUM_CRYPTO_PWHASH_SALTBYTES` bytes. A salt is not secret, but its exact bytes must be retained and supplied at decryption. Generate a new salt for each encrypted value in normal use. If a storage system only accepts text, encode the salt for storage and decode it before calling Cryptex.

## Error handling

Encryption and decryption can fail, so handle exceptions at the appropriate application boundary. Authentication failures, including modified ciphertext, nonce, or tag, and a wrong key or salt, cause `Cryptex::decrypt()` to throw `cryptex\DecryptionException`; it never returns unverified plaintext.

Cryptex also exposes `EncryptionException`, `EncodingException`, `NonceLengthException`, and `SaltLengthException`. Invalid hexadecimal input or an underlying Sodium operation can raise `SodiumException`; malformed or untrusted input should always be treated as a failed decryption attempt.

For strict scalar argument enforcement, add `declare(strict_types=1);` to the application file that calls Cryptex, as shown above.

## Security considerations and limitations

Cryptex provides confidentiality and integrity for data encrypted with a protected key. It does not provide key storage, secret management, password policy, protection for a compromised host, or protection after an attacker obtains your application's secrets.

Keep keys out of source control, logs, and client-visible storage. Store ciphertext and its associated salt together, but store keys separately in a suitable secret manager or protected configuration system. Never log plaintext or key material. Avoid logging ciphertext, salts, and nonces unless they are genuinely needed for operations and protected by an appropriate retention and access policy.

The ciphertext is hexadecimal text containing the generated nonce and authenticated encrypted payload; the salt is external. Applications that accept untrusted ciphertext should set request and field-size limits appropriate to their resource budget before calling `decrypt()`.

## Compatibility

`decrypt()` supports the established v4-style hexadecimal ciphertext format when used with the same key and external salt. The format is not self-versioned, and the current API does not use embedded salts or additional authenticated data. See [RELEASE_NOTES.md](RELEASE_NOTES.md) for compatibility details and [CHANGELOG.md](CHANGELOG.md) for version history.

## Development and documentation

The generated [API documentation](https://michaelmawhinney.github.io/cryptex/) describes the public classes and methods. Release history and migration context are in [CHANGELOG.md](CHANGELOG.md) and [RELEASE_NOTES.md](RELEASE_NOTES.md).

From the repository root, the available development checks are:

```console
composer validate --strict
composer audit --locked
composer lint
composer cs-check
composer stan
composer test
```

## License

Cryptex is released under the [MIT License](LICENSE).
