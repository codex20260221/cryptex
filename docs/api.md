# API Reference

Namespace: `cryptex`

## Current API (v5)

```php
public static function encrypt(string $plaintext, string $key, string $salt): string
public static function decrypt(string $ciphertext, string $key, string $salt): string
public static function decryptLegacyHex(string $ciphertext, string $key, string $salt): string
public static function generateSalt(): string
```

## Options and parameter behavior

| Method | Parameter | Type | Required | Notes |
|---|---|---:|:---:|---|
| `encrypt` | `$plaintext` | `string` | yes | Data to encrypt. |
| `encrypt` | `$key` | `string` | yes | Passphrase/key input to KDF in v5. |
| `encrypt` | `$salt` | `string` | yes | Must be exactly 16 bytes. |
| `decrypt` | `$ciphertext` | `string` | yes | v1 base64url or legacy hex payload. |
| `decrypt` | `$key` | `string` | yes | Must match key input used for encryption. |
| `decrypt` | `$salt` | `string` | yes* | For v1, ignored because salt is embedded (pass `''`). For legacy hex, required externally. |
| `decryptLegacyHex` | `$ciphertext` | `string` | yes | Legacy hex only. |
| `decryptLegacyHex` | `$key` | `string` | yes | Key/passphrase input. |
| `decryptLegacyHex` | `$salt` | `string` | yes | Salt used at encryption time. |
| `generateSalt` | *(none)* | - | - | Returns cryptographically random 16-byte salt. |

## Examples

### Encrypt and decrypt with embedded-salt v1 payload

```php
use cryptex\Cryptex;

$key = 'correct horse battery staple';
$salt = Cryptex::generateSalt();
$ciphertext = Cryptex::encrypt('secret message', $key, $salt);
$plaintext = Cryptex::decrypt($ciphertext, $key, '');
```

### Decrypt legacy hex payload

```php
use cryptex\Cryptex;

$plaintext = Cryptex::decryptLegacyHex($legacyHexCiphertext, $key, $legacySalt);
```

## Planned API direction (v6)

The following are planned ideas and are **not implemented in v5**:

- explicit AAD parameters in encrypt/decrypt methods,
- first-class raw-key mode ergonomics,
- possible `v2` ciphertext handling APIs.

## Exceptions

- `EncryptionException`
- `DecryptionException`
- `NonceLengthException`
- `SaltLengthException`

Callers should treat any exception as a failed cryptographic operation.
