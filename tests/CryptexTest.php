<?php

declare(strict_types=1);

namespace cryptex;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SodiumException;

final class CryptexTest extends TestCase
{
    private string $key;

    private string $salt;

    private string $plaintext;

    private string $ciphertext;

    protected function setUp(): void
    {
        $this->key = 'test-only-key-material';
        $this->salt = Cryptex::generateSalt();
        $this->plaintext = "You're a certified prince.";
        $this->ciphertext = Cryptex::encrypt($this->plaintext, $this->key, $this->salt);
    }

    public function testGenerateSaltReturnsExpectedLength(): void
    {
        $salt = Cryptex::generateSalt();

        $this->assertSame(SODIUM_CRYPTO_PWHASH_SALTBYTES, strlen($salt));
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $decrypted = Cryptex::decrypt($this->ciphertext, $this->key, $this->salt);

        $this->assertNotSame($this->plaintext, $this->ciphertext);
        $this->assertSame($this->plaintext, $decrypted);
    }

    public function testRepeatedEncryptionProducesDifferentCiphertext(): void
    {
        $otherCiphertext = Cryptex::encrypt($this->plaintext, $this->key, $this->salt);

        $this->assertNotSame($this->ciphertext, $otherCiphertext);
    }

    #[DataProvider('invalidSaltLengthProvider')]
    public function testEncryptRejectsInvalidSaltLength(string $salt): void
    {
        $this->expectException(SaltLengthException::class);

        Cryptex::encrypt($this->plaintext, $this->key, $salt);
    }

    #[DataProvider('invalidSaltLengthProvider')]
    public function testDecryptRejectsInvalidSaltLength(string $salt): void
    {
        $this->expectException(SaltLengthException::class);

        Cryptex::decrypt($this->ciphertext, $this->key, $salt);
    }

    public function testDecryptRejectsWrongKey(): void
    {
        $this->expectException(DecryptionException::class);

        Cryptex::decrypt($this->ciphertext, 'wrong-key', $this->salt);
    }

    public function testDecryptRejectsWrongSalt(): void
    {
        $this->expectException(DecryptionException::class);

        Cryptex::decrypt($this->ciphertext, $this->key, Cryptex::generateSalt());
    }

    public function testDecryptRejectsTamperedNonce(): void
    {
        $tamperedCiphertext = $this->flipDecodedByte($this->ciphertext, 0);

        $this->expectException(DecryptionException::class);

        Cryptex::decrypt($tamperedCiphertext, $this->key, $this->salt);
    }

    public function testDecryptRejectsTamperedCiphertext(): void
    {
        $tamperedCiphertext = $this->flipDecodedByte(
            $this->ciphertext,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );

        $this->expectException(DecryptionException::class);

        Cryptex::decrypt($tamperedCiphertext, $this->key, $this->salt);
    }

    public function testDecryptRejectsTamperedAuthenticationTag(): void
    {
        $decodedLength = strlen(sodium_hex2bin($this->ciphertext));
        $tamperedCiphertext = $this->flipDecodedByte($this->ciphertext, $decodedLength - 1);

        $this->expectException(DecryptionException::class);

        Cryptex::decrypt($tamperedCiphertext, $this->key, $this->salt);
    }

    public function testDecryptRejectsMalformedHexCiphertext(): void
    {
        $this->expectException(SodiumException::class);

        Cryptex::decrypt('invalid ciphertext', $this->key, $this->salt);
    }

    public function testDecryptRejectsOddLengthHexCiphertext(): void
    {
        $this->expectException(SodiumException::class);

        Cryptex::decrypt('abc', $this->key, $this->salt);
    }

    public function testDecryptValidatesSaltBeforeCiphertext(): void
    {
        $this->expectException(SaltLengthException::class);

        Cryptex::decrypt('invalid ciphertext', $this->key, 'short');
    }

    public function testDecryptRejectsTooShortPayload(): void
    {
        $this->expectException(NonceLengthException::class);

        Cryptex::decrypt('aa', $this->key, $this->salt);
    }

    public function testDecryptRejectsNonceOnlyPayload(): void
    {
        $nonceOnlyPayload = sodium_bin2hex(random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES));

        $this->expectException(NonceLengthException::class);

        Cryptex::decrypt($nonceOnlyPayload, $this->key, $this->salt);
    }

    public function testDecryptRejectsNoncePlusTooShortTagPayload(): void
    {
        $payload = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)
            . str_repeat("\x00", SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES - 1);

        $this->expectException(NonceLengthException::class);

        Cryptex::decrypt(sodium_bin2hex($payload), $this->key, $this->salt);
    }

    public function testEncryptDecryptEmptyPlaintext(): void
    {
        $plaintext = '';
        $ciphertext = Cryptex::encrypt($plaintext, $this->key, $this->salt);

        $this->assertSame($plaintext, Cryptex::decrypt($ciphertext, $this->key, $this->salt));
    }

    public function testEncryptDecryptBinaryPlaintext(): void
    {
        $plaintext = "\x00\x01\x02binary\x00text\xff";
        $ciphertext = Cryptex::encrypt($plaintext, $this->key, $this->salt);

        $this->assertSame($plaintext, Cryptex::decrypt($ciphertext, $this->key, $this->salt));
    }

    public function testEncryptDecryptNonAsciiPlaintext(): void
    {
        $plaintext = 'naive cafe 漢字';
        $ciphertext = Cryptex::encrypt($plaintext, $this->key, $this->salt);

        $this->assertSame($plaintext, Cryptex::decrypt($ciphertext, $this->key, $this->salt));
    }

    public function testEncryptDecryptLargePlaintext(): void
    {
        $plaintext = str_repeat('x', 1000000);
        $ciphertext = Cryptex::encrypt($plaintext, $this->key, $this->salt);

        $this->assertSame($plaintext, Cryptex::decrypt($ciphertext, $this->key, $this->salt));
    }

    public function testDecryptsFixedLegacyV4Ciphertext(): void
    {
        // Pre-generated v4-format fixture; this test must not call encrypt().
        $salt = sodium_hex2bin('000102030405060708090a0b0c0d0e0f');
        $key = 'legacy-v4-fixture-passphrase';
        $ciphertext = '101112131415161718191a1b1c1d1e1f2021222324252627'
            . '10c5138293480a1f0baff8559cc7df6ae15d86183676a72a83b7da8b996f66c04aa46fa59961d597b117f41b0ab6d008';

        $plaintext = Cryptex::decrypt($ciphertext, $key, $salt);

        $this->assertSame('Cryptex v4 compatibility fixture', $plaintext);
    }

    #[DataProvider('invalidPlaintextProvider')]
    public function testEncryptRejectsInvalidPlaintextTypes(mixed $plaintext): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::encrypt($plaintext, $this->key, $this->salt);
    }

    #[DataProvider('invalidCiphertextProvider')]
    public function testDecryptRejectsInvalidCiphertextTypes(mixed $ciphertext): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::decrypt($ciphertext, $this->key, $this->salt);
    }

    #[DataProvider('invalidKeyProvider')]
    public function testEncryptRejectsInvalidKeyTypes(mixed $key): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::encrypt($this->plaintext, $key, $this->salt);
    }

    #[DataProvider('invalidKeyProvider')]
    public function testDecryptRejectsInvalidKeyTypes(mixed $key): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::decrypt($this->ciphertext, $key, $this->salt);
    }

    #[DataProvider('invalidSaltTypeProvider')]
    public function testEncryptRejectsInvalidSaltTypes(mixed $salt): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::encrypt($this->plaintext, $this->key, $salt);
    }

    #[DataProvider('invalidSaltTypeProvider')]
    public function testDecryptRejectsInvalidSaltTypes(mixed $salt): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::decrypt($this->ciphertext, $this->key, $salt);
    }

    /** @return array<string, array{mixed}> */
    public static function invalidPlaintextProvider(): array
    {
        return [
            'null' => [null],
            'array' => [[]],
            'object' => [new \stdClass()],
        ];
    }

    /** @return array<string, array{mixed}> */
    public static function invalidCiphertextProvider(): array
    {
        return [
            'null' => [null],
            'array' => [[]],
            'object' => [new \stdClass()],
        ];
    }

    /** @return array<string, array{mixed}> */
    public static function invalidKeyProvider(): array
    {
        return [
            'null' => [null],
            'array' => [[]],
            'object' => [new \stdClass()],
        ];
    }

    /** @return array<string, array{mixed}> */
    public static function invalidSaltTypeProvider(): array
    {
        return [
            'null' => [null],
            'array' => [[]],
            'object' => [new \stdClass()],
        ];
    }

    /** @return array<string, array{string}> */
    public static function invalidSaltLengthProvider(): array
    {
        return [
            'empty' => [''],
            'short' => ['short'],
            'long' => [str_repeat('a', SODIUM_CRYPTO_PWHASH_SALTBYTES + 1)],
        ];
    }

    private function flipDecodedByte(string $hex, int $offset): string
    {
        $decoded = sodium_hex2bin($hex);
        $decoded[$offset] = chr(ord($decoded[$offset]) ^ 1);

        return sodium_bin2hex($decoded);
    }
}
