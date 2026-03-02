# Ciphertext Formats

Cryptex v5 accepts multiple input formats for decryption and emits a versioned base64url format for modern ciphertexts.

## Base64url variant

Cryptex uses URL-safe Base64 **without padding** (`SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING`).

## v1 format (current, implemented)

Binary envelope layout before encoding:

```
[1 byte version][16 bytes salt][24 bytes nonce][ciphertext || 16-byte tag]
```

- `version`: `0x01`
- `salt`: `SODIUM_CRYPTO_PWHASH_SALTBYTES` (16)
- `nonce`: `SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES` (24)
- `tag`: `SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES` (16, appended by libsodium)

### Minimum payload length (decoded binary)

`1 + 16 + 24 + 16 = 57 bytes`

### Salt behavior in `decrypt()`

For `v1` payloads, the embedded envelope salt is used. The `decrypt(..., $salt)` argument is ignored for this path; pass `''` for clarity.

## v2 format (planned/reserved, not implemented)

`v2` is reserved for future extension and may ship in a later major release.

Forward-compatibility rules:

- Unknown version bytes MUST fail closed (reject decrypt).
- New versions MUST include a clear version prefix and self-describing field layout.

## Legacy hex format (backward compatibility, implemented)

Legacy payloads are hex encoded and decoded by `decryptLegacyHex()` (and auto-detected in `decrypt()`):

```
hex( [24-byte nonce][ciphertext || 16-byte tag] )
```

- No embedded version byte.
- No embedded salt.
- Caller must provide the original salt externally.

## Versioning rules

1. Encryption emits the latest stable implemented version (`v1` today).
2. Decryption accepts supported versions plus legacy compatibility paths.
3. Unsupported versions fail closed.
4. Migration should be handled by decrypt-then-re-encrypt during normal write traffic.
