<?php

declare(strict_types=1);

namespace cryptex;

use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * CryptexTest performs unit testing for the Cryptex class.
 */
final class CryptexTest extends TestCase
{
    private string $key;
    private string $salt;
    private int $saltLength;
    private int $nonceLength;
    private int $tagLength;
    private string $plaintext;
    private string $ciphertext;

    protected function setUp(): void
    {
        $reflection = new ReflectionClass(Cryptex::class);
        $this->saltLength = $reflection->getReflectionConstant('SALT_LENGTH')->getValue();
        $this->nonceLength = $reflection->getReflectionConstant('NONCE_LENGTH')->getValue();
        $this->tagLength = $reflection->getReflectionConstant('TAG_LENGTH')->getValue();

        $this->key = '1-2-3-4-5';
        $this->salt = Cryptex::generateSalt();
        $this->plaintext = "You're a certified prince.";
        $this->ciphertext = Cryptex::encrypt($this->plaintext, $this->key, $this->salt);
    }

    public function testGenerateSalt(): void
    {
        $this->assertIsString($this->salt);
        $this->assertSame($this->saltLength, strlen($this->salt));
    }

    public function testEncryptDecryptRoundTripV1Envelope(): void
    {
        $this->assertIsString($this->ciphertext);
        $this->assertNotSame($this->plaintext, $this->ciphertext);

        $decoded = sodium_base642bin($this->ciphertext, \SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, '');

        $this->assertSame(1, ord($decoded[0]));
        $this->assertSame($this->salt, substr($decoded, 1, $this->saltLength));

        $decrypted = Cryptex::decrypt($this->ciphertext, $this->key, random_bytes($this->saltLength));
        $this->assertSame($this->plaintext, $decrypted);
    }

    public function testTamperedPayloadFails(): void
    {
        $decoded = sodium_base642bin($this->ciphertext, \SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, '');
        $decoded[strlen($decoded) - 1] = $decoded[strlen($decoded) - 1] ^ "\x01";
        $tampered = sodium_bin2base64($decoded, \SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

        $this->expectException(DecryptionException::class);
        Cryptex::decrypt($tampered, $this->key, $this->salt);
    }

    public function testWrongKeyFailsDecryption(): void
    {
        $this->expectException(DecryptionException::class);
        Cryptex::decrypt($this->ciphertext, 'definitely-not-the-right-key', $this->salt);
    }

    public function testWrongSaltLengthOnEncryptThrows(): void
    {
        $this->expectException(SaltLengthException::class);
        Cryptex::encrypt($this->plaintext, $this->key, 'short');
    }

    public function testMalformedPayloadThrows(): void
    {
        $minimumLength = 1 + $this->saltLength + $this->nonceLength + $this->tagLength;
        $shortEnvelope = str_repeat("\x00", $minimumLength - 1);
        $payload = sodium_bin2base64($shortEnvelope, \SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

        $this->expectException(NonceLengthException::class);
        Cryptex::decrypt($payload, $this->key, $this->salt);
    }

    public function testLegacyHexDecryptStillSupported(): void
    {
        $derivedKey = sodium_crypto_pwhash(
            \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            $this->key,
            $this->salt,
            \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            \SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );

        $nonce = random_bytes($this->nonceLength);
        $encrypted = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($this->plaintext, '', $nonce, $derivedKey);
        $legacyPayload = sodium_bin2hex($nonce . $encrypted);

        $decrypted = Cryptex::decrypt($legacyPayload, $this->key, $this->salt);
        $this->assertSame($this->plaintext, $decrypted);

        sodium_memzero($derivedKey);
        sodium_memzero($nonce);
    }
}
