<?php

declare(strict_types=1);

namespace cryptex;

/**
 * Cryptex performs 2-way authenticated encryption using XChaCha20 + Poly1305.
 *
 * This class leverages the Sodium crypto library, added to PHP in version 7.2.
 *
 * @category Encryption/Decryption
 * @package Cryptex
 * @author Michael Mawhinney
 * @copyright 2023
 * @license https://opensource.org/licenses/MIT/ MIT
 * @version 5.0.0
 */
final class Cryptex
{
    /**
     * @var int Required length of the nonce value.
     */
    private const NONCE_LENGTH = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    /**
     * @var int Required length of the salt value.
     */
    private const SALT_LENGTH = \SODIUM_CRYPTO_PWHASH_SALTBYTES;

    /**
     * @var int Auth tag length for XChaCha20-Poly1305.
     */
    private const TAG_LENGTH = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

    /**
     * @var int Envelope version byte for base64url payloads.
     */
    private const ENVELOPE_VERSION_V1 = 0x01;

    /**
     * Encrypts data using XChaCha20 + Poly1305 (from the Sodium crypto library).
     *
     * Output format (v1, base64url): [version byte][salt][nonce][ciphertext+tag]
     *
     * @param string $plaintext Unencrypted data.
     * @param string $key Encryption key.
     * @param string $salt Salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @return string Encrypted data (base64url encoded envelope).
     *
     * @throws EncryptionException If the data encryption fails.
     */
    public static function encrypt(string $plaintext, string $key, string $salt): string
    {
        $derivedKey = null;
        $nonce = null;

        try {
            $derivedKey = self::generateDerivedKey($key, $salt);
            $nonce = random_bytes(self::NONCE_LENGTH);

            $encryptedData = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                '',
                $nonce,
                $derivedKey
            );

            if ($encryptedData === false) {
                throw new EncryptionException('Failed to encrypt the data');
            }

            $envelope = chr(self::ENVELOPE_VERSION_V1) . $salt . $nonce . $encryptedData;

            return sodium_bin2base64($envelope, \SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\Throwable $e) {
            if ($e instanceof EncryptionException || $e instanceof SaltLengthException) {
                throw $e;
            }

            throw new EncryptionException('Encryption failed', previous: $e);
        } finally {
            self::wipeString($derivedKey);
            self::wipeString($nonce);
        }
    }

    /**
     * Authenticates and decrypts data encrypted by Cryptex (XChaCha20+Poly1305).
     *
     * Supports both the v1 base64url envelope and the legacy hex format.
     *
     * @param string $ciphertext Encrypted data.
     * @param string $key Encryption key.
     * @param string $salt Salt value for legacy hex payloads.
     * @return string Unencrypted data.
     *
     * @throws NonceLengthException If payload contents are not the expected length.
     * @throws DecryptionException If data decryption fails.
     */
    public static function decrypt(string $ciphertext, string $key, string $salt): string
    {
        if (self::looksLikeLegacyHex($ciphertext)) {
            return self::decryptLegacyHex($ciphertext, $key, $salt);
        }

        $derivedKey = null;
        $decoded = null;
        $nonce = null;
        $ciphertextBody = null;
        $envelopeSalt = null;

        try {
            $decoded = sodium_base642bin(
                $ciphertext,
                \SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
                ''
            );

            $minimumLength = 1 + self::SALT_LENGTH + self::NONCE_LENGTH + self::TAG_LENGTH;
            if (strlen($decoded) < $minimumLength) {
                throw new NonceLengthException('Decoded data is not the expected length');
            }

            $version = ord($decoded[0]);
            if ($version !== self::ENVELOPE_VERSION_V1) {
                throw new DecryptionException('Unsupported ciphertext version');
            }

            $offset = 1;
            $envelopeSalt = substr($decoded, $offset, self::SALT_LENGTH);
            $offset += self::SALT_LENGTH;

            $nonce = substr($decoded, $offset, self::NONCE_LENGTH);
            $offset += self::NONCE_LENGTH;

            $ciphertextBody = substr($decoded, $offset);
            if (strlen($ciphertextBody) < self::TAG_LENGTH) {
                throw new NonceLengthException('Ciphertext is not the expected length');
            }

            $derivedKey = self::generateDerivedKey($key, $envelopeSalt);

            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertextBody,
                '',
                $nonce,
                $derivedKey
            );

            if ($plaintext === false) {
                throw new DecryptionException('Failed to decrypt the data');
            }

            return $plaintext;
        } catch (\Throwable $e) {
            if ($e instanceof EncryptionException) {
                throw $e;
            }

            throw new DecryptionException('Decryption failed', previous: $e);
        } finally {
            self::wipeString($derivedKey);
            self::wipeString($decoded);
            self::wipeString($nonce);
            self::wipeString($ciphertextBody);
            self::wipeString($envelopeSalt);
        }
    }

    /**
     * Decrypts legacy ciphertext payloads in hex format: [nonce][ciphertext+tag] (hex encoded).
     *
     * @param string $ciphertext Legacy hex ciphertext.
     * @param string $key Encryption key.
     * @param string $salt Salt value.
     * @return string Unencrypted data.
     *
     * @throws DecryptionException If data decryption fails.
     */
    public static function decryptLegacyHex(string $ciphertext, string $key, string $salt): string
    {
        $derivedKey = null;
        $decoded = null;
        $nonce = null;
        $ciphertextBody = null;

        try {
            $derivedKey = self::generateDerivedKey($key, $salt);
            $decoded = sodium_hex2bin($ciphertext);

            $minimumLength = self::NONCE_LENGTH + self::TAG_LENGTH;
            if (strlen($decoded) < $minimumLength) {
                throw new NonceLengthException('Decoded data is not the expected length');
            }

            $nonce = substr($decoded, 0, self::NONCE_LENGTH);
            $ciphertextBody = substr($decoded, self::NONCE_LENGTH);
            if (strlen($ciphertextBody) < self::TAG_LENGTH) {
                throw new NonceLengthException('Ciphertext is not the expected length');
            }

            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertextBody,
                '',
                $nonce,
                $derivedKey
            );

            if ($plaintext === false) {
                throw new DecryptionException('Failed to decrypt the data');
            }

            return $plaintext;
        } catch (\Throwable $e) {
            if ($e instanceof EncryptionException) {
                throw $e;
            }

            throw new DecryptionException('Legacy decryption failed', previous: $e);
        } finally {
            self::wipeString($derivedKey);
            self::wipeString($decoded);
            self::wipeString($nonce);
            self::wipeString($ciphertextBody);
        }
    }

    /**
     * Generates a salt value.
     *
     * @return string Random salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     *
     * @throws \Exception If an error occurs while generating the salt value.
     */
    public static function generateSalt(): string
    {
        return random_bytes(self::SALT_LENGTH);
    }

    /**
     * Generates a derived binary key using Argon2id v1.3.
     *
     * @param string $key Encryption key.
     * @param string $salt Salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @return string Derived binary key.
     *
     * @throws SaltLengthException If the salt is not the expected length.
     * @throws EncryptionException If key derivation fails.
     */
    private static function generateDerivedKey(string $key, string $salt): string
    {
        if (strlen($salt) !== self::SALT_LENGTH) {
            throw new SaltLengthException('Salt is not the expected length');
        }

        try {
            return sodium_crypto_pwhash(
                \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
                $key,
                $salt,
                \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                \SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
            );
        } catch (\Throwable $e) {
            throw new EncryptionException('Failed to derive encryption key', previous: $e);
        }
    }

    /**
     * Heuristic detection for the legacy hex payload format.
     */
    private static function looksLikeLegacyHex(string $ciphertext): bool
    {
        return $ciphertext !== ''
            && (strlen($ciphertext) % 2 === 0)
            && ctype_xdigit($ciphertext);
    }

    /**
     * Securely wipe a string when possible.
     */
    private static function wipeString(mixed &$value): void
    {
        if (isset($value) && is_string($value)) {
            sodium_memzero($value);
        }
    }
}

/**
 * Class EncryptionException
 * Custom exception class for encryption errors.
 */
class EncryptionException extends \Exception {}

/**
 * Class NonceLengthException
 * Custom exception class for nonce length errors.
 */
class NonceLengthException extends EncryptionException {}

/**
 * Class DecryptionException
 * Custom exception class for decryption errors.
 */
class DecryptionException extends EncryptionException {}

/**
 * Class SaltLengthException
 * Custom exception class for salt length errors.
 */
class SaltLengthException extends EncryptionException {}
