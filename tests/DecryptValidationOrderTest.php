<?php

declare(strict_types=1);

namespace cryptex;

use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class DecryptValidationOrderTest extends TestCase
{
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testTooShortPayloadIsRejectedBeforeKeyDerivation(): void
    {
        require __DIR__ . '/Fixtures/KdfGuard.php';

        $payload = str_repeat(
            "\x00",
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
                + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
                - 1
        );
        $salt = str_repeat("\x00", SODIUM_CRYPTO_PWHASH_SALTBYTES);

        $this->expectException(NonceLengthException::class);

        Cryptex::decrypt(sodium_bin2hex($payload), 'test-only-key-material', $salt);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testMalformedHexIsRejectedBeforeKeyDerivation(): void
    {
        require __DIR__ . '/Fixtures/KdfGuard.php';

        $salt = str_repeat("\x00", SODIUM_CRYPTO_PWHASH_SALTBYTES);

        $this->expectException(\SodiumException::class);

        Cryptex::decrypt('zz', 'test-only-key-material', $salt);
    }
}
