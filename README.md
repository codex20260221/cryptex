<img src="https://michaelmawhinney.com/cryptex/logo.gif" width="300" alt="Cryptex">

# Cryptex: authenticated symmetric encryption

Cryptex is a small PHP library for authenticated encryption using XChaCha20-Poly1305 and Argon2id from PHP's Sodium extension.

Version 5 preserves the v4 public API, hex ciphertext format, and external-salt behavior. Existing v4-style ciphertext remains decryptable with the same key and salt.

## Requirements

- PHP 8.3 or newer
- `ext-sodium`

## Installation

Install the package with Composer:

```console
composer require michaelmawhinney/cryptex
```

Composer autoloading is recommended. If Composer is unavailable, `src/Cryptex.php` can still be required directly; it loads the public exception classes it needs.

## Usage

Generate random key material once and store it in a secret manager or another protected location. Generate and retain the external salt for each encrypted value because the salt is required for decryption.

```php
<?php

declare(strict_types=1);

require 'vendor/autoload.php';

use cryptex\Cryptex;

$plaintext = "You're a certified prince.";

// Generate once, store securely, and reuse for decryption.
$key = sodium_bin2hex(
    random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)
);

// Store this salt with the ciphertext; it is not embedded in the output.
$salt = Cryptex::generateSalt();
$ciphertext = Cryptex::encrypt($plaintext, $key, $salt);
$decrypted = Cryptex::decrypt($ciphertext, $key, $salt);

if (!hash_equals($plaintext, $decrypted)) {
    throw new RuntimeException('Round trip failed');
}
```

Do not generate a new key or salt when decrypting stored ciphertext. Retrieve the exact values used during encryption.

### Random keys and human passphrases

Cryptex processes the supplied `$key` through Argon2id whether it contains random key material or a human passphrase. High-entropy random key material is preferred when the application can generate and store it safely.

Argon2id makes passphrase guessing more expensive, but it does not add entropy or make a weak passphrase strong. Password policy, passphrase quality, key rotation, and secure key storage are caller responsibilities. This release deliberately does not reject previously accepted key strings.

### Salt handling

`Cryptex::generateSalt()` returns `SODIUM_CRYPTO_PWHASH_SALTBYTES` random bytes. The salt is not a secret, but it must be stored without alteration and supplied again for decryption. A newly generated salt should normally be retained alongside each ciphertext.

### Ciphertext format and compatibility

`encrypt()` returns lowercase hexadecimal encoding of:

```text
24-byte nonce || ciphertext || 16-byte authentication tag
```

The salt is external and is not included in the ciphertext. The minimum decoded payload is 40 bytes (80 hexadecimal characters), representing an empty plaintext. v4 and v5 use this same unversioned format. Authentication failure, including a modified nonce, ciphertext, tag, wrong key, or wrong salt, throws `cryptex\DecryptionException` and never returns plaintext.

A future major version may introduce a versioned envelope or additional authenticated data (AAD), but neither is part of the current API.

### Strict scalar types

PHP decides scalar argument coercion from the file that calls a function, not from the file that declares it. Cryptex declares strict types internally, but callers that require strict scalar enforcement should also begin their PHP files with:

```php
declare(strict_types=1);
```

### Untrusted input and payload limits

Cryptex rejects invalid salt lengths, malformed hex, and decoded payloads that are too short before running Argon2id. It intentionally does not impose an arbitrary maximum ciphertext size because doing so would change the existing API.

Applications accepting untrusted input should enforce suitable HTTP request, field, and ciphertext-size limits before calling `decrypt()`. Choose limits from the application's maximum expected plaintext size and resource budget so oversized input cannot consume unbounded decoding memory or request time.

## Exceptions

The public exception classes are PSR-4 autoloadable under the `cryptex\` namespace:

- `EncryptionException`
- `EncodingException`
- `NonceLengthException`
- `DecryptionException`
- `SaltLengthException`

Their names and existing inheritance hierarchy remain compatible with v4 and v5.

## Development checks

Run the following commands from the repository root:

```console
composer validate --strict
composer audit --locked
composer lint
composer cs-check
composer stan
composer test
```

## Release notes

See [CHANGELOG.md](CHANGELOG.md) and [RELEASE_NOTES.md](RELEASE_NOTES.md) for release and compatibility notes.

## Generating documentation

The API documentation is generated with phpDocumentor and published at <https://michaelmawhinney.github.io/cryptex/>. To generate it locally with Docker:

```console
docker run --rm -v "$(pwd):/data" phpdoc/phpdoc:3 -d src,tests -t docs
```
